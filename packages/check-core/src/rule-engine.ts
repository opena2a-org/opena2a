/**
 * Deterministic rule engine for `check` rich-context.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§5)
 *
 * Pure function: `(RuleEngineInput) -> { verdictReasoning, nextSteps }`.
 * Same inputs always produce the same outputs — there is no NanoMind
 * call, no I/O, and no time-of-day dependency in this path.
 *
 * Lives in @opena2a/check-core so HMA, opena2a-cli, and ai-trust share
 * one implementation. Output is consumed by `renderCheckRichBlock` in
 * @opena2a/cli-ui (session 3) and embedded in the registry-stored
 * `PackageNarrative` so re-renders are byte-stable across CLIs.
 *
 * The hardcoded-secrets enrichment path (rotationUrl / rotationCommand)
 * also lives here so callers can run a single `runRuleEngine` to get a
 * fully-populated narrative skeleton ready to ship to the registry.
 */
import type {
  HardcodedSecret,
  HardcodedSecretsBlock,
  McpNarrative,
  NextStep,
  PermissionStatus,
  SkillNarrative,
  VerdictReasoningStatement,
} from "./narrative.js";
import { enrichSecretRotation } from "./secret-rotation.js";

/**
 * Trust verdict produced by the registry. Mirrors the user-facing trust
 * tier labels rendered in the `check` block header. `LISTED_UNSCANNED`
 * is the LISTED-with-no-scan state (mockup 3.3). `NOT_FOUND` returns
 * an entirely different render path; the rule engine still produces
 * spelling-suggestion next-steps for it.
 */
export type TrustVerdict =
  | "VERIFIED"
  | "LISTED"
  | "LISTED_UNSCANNED"
  | "BLOCKED"
  | "NOT_FOUND";

/**
 * Scan-status dimension. Drives the action-gradient branch.
 *   - `completed` = scan ran and produced a result (clean or with findings).
 *   - `pending`   = scan queued, not yet executed.
 *   - `never`     = no scan has ever run for this artifact / version.
 *   - `failed`    = scan attempted and errored (download failure, parse error).
 */
export type ScanStatus = "completed" | "pending" | "never" | "failed";

/**
 * Artifact type dimension for the action gradient. v1 only renders the
 * rich block for `skill` and `mcp`; the others fall through to the
 * legacy renderer. The rule engine still emits a graceful gradient for
 * them so callers don't have to special-case absence.
 */
export type RuleArtifactType = "skill" | "mcp" | "npm" | "pypi" | "a2a";

/**
 * Minimal finding shape consumed by the rule engine. Each consumer
 * already has a richer finding shape; the engine asks for only what it
 * needs to compose the [critical] reasoning entries on BLOCKED tier.
 */
export interface RuleFinding {
  ruleId: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  /** Single-line description rendered inline with the rule id. */
  description?: string;
  /** file:line locator. Empty string when unanchored. */
  locator?: string;
}

/**
 * Provenance attestation summary. v1 only checks `predicateType`
 * matches SLSA v1; future schemas can extend this.
 */
export interface AttestationSummary {
  /** e.g. `https://slsa.dev/provenance/v1`. Empty/undefined = no attestation. */
  predicateType?: string;
}

/**
 * Publisher trust signals. `verified` covers org-verification on the
 * source registry (npm verified org, GitHub verified org, etc.).
 */
export interface PublisherSignals {
  verified: boolean;
  /** True when npm publishes via Trusted Publishing / provenance. */
  hasNpmProvenance: boolean;
  /** True when the publisher has a non-trivial maintainer history. */
  hasMaintainerHistory: boolean;
}

/**
 * Full input to the rule engine. Every field is required for
 * deterministic output; callers fill in defaults explicitly rather
 * than relying on optionality where it would change the output set.
 */
export interface RuleEngineInput {
  packageName: string;
  /** Latest version string used in pin commands. Empty string when unknown. */
  latestVersion: string;
  /**
   * Last known clean version, used in the LISTED skill "pin to last
   * clean" secondary action. Empty string when no clean version is
   * known — the action falls back to a generic "pin to <latest>".
   */
  lastCleanVersion: string;
  artifactType: RuleArtifactType;
  verdict: TrustVerdict;
  scanStatus: ScanStatus;
  publisher: PublisherSignals;
  attestations: AttestationSummary;
  /** Total community-scan count used for the "5+ community scans" rule. */
  communityScans: number;
  /** Subset of community scans that produced zero findings. */
  cleanCommunityScans: number;
  /** True when SOUL.md governance file was detected at scan time. */
  hasSoulFile: boolean;
  /** Findings produced by the local scan. Empty when scan never ran. */
  findings: RuleFinding[];
  /**
   * Hardcoded-secrets findings, separated from `findings` so the engine
   * can both enrich them with rotation info and emit a `[critical]`
   * reasoning entry per leaked credential.
   */
  hardcodedSecrets: HardcodedSecret[];
  /** True when scan covered hardcoded-secret detection. */
  scanCovered: boolean;
  /** Skill narrative (when artifactType === "skill"). */
  skill?: SkillNarrative;
  /** MCP narrative (when artifactType === "mcp"). */
  mcp?: McpNarrative;
  /**
   * True when the MCP exposes destructive tools but ALSO ships safety
   * affordances (write-confirmation, dry-run flag, allowedDirectories
   * realpath enforcement, etc.). Drives the inverse of the [gap]
   * "destructive tools without safety affordances" rule.
   */
  mcpHasSafetyAffordances: boolean;
  /**
   * Suggestion list for NOT_FOUND tier — spelling alternatives. Empty
   * array is the "no near match" case; the gradient still emits the
   * "try other artifact type" + "search by capability" entries.
   */
  notFoundSuggestions: string[];
}

/**
 * Top-level output. `verdictReasoning` lands under "Why <tier>" and
 * `nextSteps` lands under "Next" / "Recovery path" / equivalent in
 * the renderer. `enrichedSecrets` is the input `hardcodedSecrets`
 * with rotation guidance backfilled, exposed so callers can build
 * the full HardcodedSecretsBlock without a second pass.
 */
export interface RuleEngineOutput {
  verdictReasoning: VerdictReasoningStatement[];
  nextSteps: NextStep[];
  enrichedSecrets: HardcodedSecret[];
  hardcodedSecretsBlock: HardcodedSecretsBlock;
}

/**
 * Run the deterministic rule engine.
 */
export function runRuleEngine(input: RuleEngineInput): RuleEngineOutput {
  const enrichedSecrets = input.hardcodedSecrets.map(enrichSecretRotation);
  return {
    verdictReasoning: buildVerdictReasoning(input, enrichedSecrets),
    nextSteps: buildNextSteps(input, enrichedSecrets),
    enrichedSecrets,
    hardcodedSecretsBlock: {
      detected: enrichedSecrets,
      scanCovered: input.scanCovered,
    },
  };
}

// ---- Verdict reasoning ---------------------------------------------------

/**
 * Compose the verdict-reasoning statement list. Entries appear in the
 * order they are pushed; the renderer renders verbatim, no sorting.
 *
 * Per brief §5.1:
 *   VERIFIED → positives only (the gaps are absent or upgraded away)
 *   LISTED   → gaps that block VERIFIED, with optional positives that
 *              still hold (registry-confirmed publisher, etc.)
 *   BLOCKED  → critical entries naming specific blocking findings
 *   LISTED_UNSCANNED → single explanation
 *   NOT_FOUND → empty list (the renderer prints a different section)
 */
function buildVerdictReasoning(
  input: RuleEngineInput,
  enrichedSecrets: HardcodedSecret[],
): VerdictReasoningStatement[] {
  const out: VerdictReasoningStatement[] = [];

  if (input.verdict === "NOT_FOUND") {
    return out;
  }

  if (input.verdict === "LISTED_UNSCANNED") {
    out.push({
      kind: "gap",
      text:
        "No scan has been run on this artifact. A score and findings require a scan; without one we can verify identity but not behavior.",
    });
    return out;
  }

  if (input.verdict === "BLOCKED") {
    const criticals = input.findings.filter((f) => f.severity === "critical");
    const totalCount = input.findings.length;
    out.push({
      kind: "critical",
      text:
        `${totalCount} finding${totalCount === 1 ? "" : "s"}, ${criticals.length} critical.`,
    });
    for (const f of criticals) {
      const locator = f.locator ? ` at ${f.locator}` : "";
      const desc = f.description ? ` — ${f.description}` : "";
      out.push({
        kind: "critical",
        text: `${f.ruleId}${locator}${desc}`,
      });
    }
    for (const s of enrichedSecrets) {
      if (s.severity === "critical" || s.severity === "high") {
        const locator = s.line ? `${s.file}:${s.line}` : s.file;
        out.push({
          kind: "critical",
          text: `${s.typeLabel} hardcoded at ${locator}`,
        });
      }
    }
    if (!input.publisher.hasMaintainerHistory) {
      out.push({
        kind: "critical",
        text: "No maintainer history (typo-squat / drive-by profile).",
      });
    }
    if (!input.attestations.predicateType) {
      out.push({
        kind: "critical",
        text: "No provenance attestation.",
      });
    }
    return out;
  }

  // VERIFIED + LISTED tiers share the positive-and-gap composition.
  // The set of positives that hold is the same; only the gaps differ —
  // VERIFIED has no gaps that block its tier (any remaining gaps are
  // best-practice nudges, not blockers).
  appendPositives(out, input);
  appendGaps(out, input, enrichedSecrets);
  return out;
}

function appendPositives(
  out: VerdictReasoningStatement[],
  input: RuleEngineInput,
): void {
  if (input.publisher.verified) {
    out.push({
      kind: "positive",
      text: "Publisher is a verified organization",
    });
  }
  if (input.attestations.predicateType?.includes("slsa.dev")) {
    out.push({
      kind: "positive",
      text: "npm provenance attestation present (SLSA v1)",
    });
  }
  if (input.skill && permissionsMatchExactly(input.skill.permissions)) {
    out.push({
      kind: "positive",
      text: "Declared permissions match observed tool usage exactly",
    });
  }
  if (input.hasSoulFile) {
    out.push({
      kind: "positive",
      text: "SOUL.md governance file present",
    });
  }
  if (
    input.communityScans >= 5 &&
    input.cleanCommunityScans === input.communityScans
  ) {
    out.push({
      kind: "positive",
      text: `${input.communityScans} community scans, all clean`,
    });
  }
  if (input.hardcodedSecrets.length === 0 && input.scanCovered) {
    out.push({
      kind: "positive",
      text: "No hardcoded credentials, no external service surprises",
    });
  }
}

function appendGaps(
  out: VerdictReasoningStatement[],
  input: RuleEngineInput,
  enrichedSecrets: HardcodedSecret[],
): void {
  if (input.skill) {
    for (const p of input.skill.permissions) {
      if (p.status === "unused") {
        out.push({
          kind: "gap",
          text: `${p.name} permission declared but unused (overreach above)`,
        });
      } else if (p.status === "undeclared") {
        out.push({
          kind: "gap",
          text: `${p.name} used but not declared (undeclared scope expansion)`,
        });
      }
    }
  }
  if (
    input.mcp &&
    input.mcp.tools.some((t) => t.destructive) &&
    !input.mcpHasSafetyAffordances
  ) {
    out.push({
      kind: "gap",
      text: "Exposes destructive tools without safety affordances",
    });
  }
  if (!input.hasSoulFile && input.artifactType === "skill") {
    out.push({
      kind: "gap",
      text: "No SOUL.md governance file in repo",
    });
  }
  if (input.communityScans < 5) {
    out.push({
      kind: "gap",
      text: "Fewer than 5 community scans (5+ required for VERIFIED)",
    });
  }
  if (!input.attestations.predicateType) {
    out.push({
      kind: "gap",
      text: "No provenance attestation",
    });
  }
  for (const s of enrichedSecrets) {
    if (s.severity === "critical" || s.severity === "high") {
      const locator = s.line ? `${s.file}:${s.line}` : s.file;
      out.push({
        kind: "gap",
        text: `${s.typeLabel} hardcoded at ${locator} (rotate regardless of install decision)`,
      });
    }
  }
}

function permissionsMatchExactly(perms: PermissionStatus[]): boolean {
  return perms.every((p) => p.status === "used");
}

// ---- Action gradient -----------------------------------------------------

/**
 * Compose the action gradient. Branches on `verdict × scanStatus ×
 * artifactType`. Brief §5.2 lists the canonical combinations; the
 * function falls through to a sane default when an unexpected tuple
 * shows up rather than throwing.
 */
function buildNextSteps(
  input: RuleEngineInput,
  enrichedSecrets: HardcodedSecret[],
): NextStep[] {
  if (input.verdict === "NOT_FOUND") {
    return notFoundGradient(input);
  }
  if (input.verdict === "BLOCKED") {
    return blockedGradient(input, enrichedSecrets);
  }
  if (input.verdict === "LISTED_UNSCANNED" || input.scanStatus === "never") {
    return unscannedGradient(input);
  }
  if (input.verdict === "VERIFIED") {
    return verifiedGradient(input);
  }
  if (input.verdict === "LISTED") {
    return listedGradient(input);
  }
  // Defensive default — keeps the renderer alive for unexpected combos.
  return [
    {
      weight: "primary",
      label: "Re-run check",
      command: `hackmyagent check ${input.packageName}`,
    },
  ];
}

function verifiedGradient(input: RuleEngineInput): NextStep[] {
  const steps: NextStep[] = [];
  if (input.artifactType === "skill") {
    steps.push({
      weight: "primary",
      label: "Install confidently",
      command: `opena2a install ${input.packageName}`,
    });
    if (input.latestVersion) {
      steps.push({
        weight: "secondary",
        label: `Pin to ${input.latestVersion}`,
        command: `opena2a install ${input.packageName}@${input.latestVersion}`,
      });
    }
    steps.push({
      weight: "secondary",
      label: "Re-verify locally",
      command: `hackmyagent secure --skill ${input.packageName}`,
    });
    return steps;
  }
  if (input.artifactType === "mcp") {
    steps.push({
      weight: "primary",
      label: "Install with recommended config",
      command: `npm i ${input.packageName}`,
    });
    steps.push({
      weight: "secondary",
      label: "Review findings",
      command: `hackmyagent secure node_modules/${input.packageName} --details`,
    });
    steps.push({
      weight: "secondary",
      label: "See alternative MCPs",
      command: `ai-trust suggest mcp ${input.packageName} --read-only`,
    });
    return steps;
  }
  // npm/pypi/a2a fall through to a generic install primary.
  steps.push({
    weight: "primary",
    label: "Install",
    command: installCommandForType(input),
  });
  steps.push({
    weight: "secondary",
    label: "Re-verify",
    command: `hackmyagent secure ${input.packageName}`,
  });
  return steps;
}

function listedGradient(input: RuleEngineInput): NextStep[] {
  const steps: NextStep[] = [];
  steps.push({
    weight: "primary",
    label: "Review findings",
    command: `hackmyagent secure ${input.packageName} --details`,
  });
  if (input.lastCleanVersion) {
    steps.push({
      weight: "secondary",
      label: `Pin to last clean version (${input.lastCleanVersion})`,
      command: pinCommand(input, input.lastCleanVersion),
    });
  } else if (input.latestVersion) {
    steps.push({
      weight: "secondary",
      label: `Pin to current version (${input.latestVersion})`,
      command: pinCommand(input, input.latestVersion),
    });
  }
  steps.push({
    weight: "secondary",
    label: "Re-scan locally",
    command: `hackmyagent secure ${input.packageName}`,
  });
  return steps;
}

function unscannedGradient(input: RuleEngineInput): NextStep[] {
  const flag = input.artifactType === "skill" ? "--skill" : "";
  return [
    {
      weight: "primary",
      label: "Scan locally",
      command: `hackmyagent secure ${flag} ${input.packageName}`.replace(/\s+/g, " ").trim(),
    },
    {
      weight: "secondary",
      label: "Queue community scan",
      command: `ai-trust check ${input.packageName} --scan-if-missing`,
    },
  ];
}

function blockedGradient(
  input: RuleEngineInput,
  enrichedSecrets: HardcodedSecret[],
): NextStep[] {
  const steps: NextStep[] = [
    {
      weight: "primary",
      label: "Do NOT install",
    },
  ];
  for (const s of enrichedSecrets) {
    if (s.rotationUrl) {
      steps.push({
        weight: "primary",
        label: `Rotate ${s.typeLabel}`,
        url: s.rotationUrl,
      });
    } else if (s.rotationCommand) {
      steps.push({
        weight: "primary",
        label: `Rotate ${s.typeLabel}`,
        command: s.rotationCommand,
      });
    }
  }
  steps.push({
    weight: "secondary",
    label: "Find alternative",
    command: `ai-trust suggest ${suggestionScope(input.artifactType)} ${input.packageName}`,
  });
  steps.push({
    weight: "secondary",
    label: "Report",
    command: `hackmyagent report ${input.packageName}`,
  });
  return steps;
}

function notFoundGradient(input: RuleEngineInput): NextStep[] {
  const steps: NextStep[] = [];
  if (input.notFoundSuggestions.length > 0) {
    steps.push({
      weight: "primary",
      label: "Did you mean",
      // Render commands for the top suggestion; renderer can list
      // additional suggestions from input.notFoundSuggestions itself.
      command: `hackmyagent check ${input.notFoundSuggestions[0]}`,
    });
  }
  steps.push({
    weight: "secondary",
    label: "Try as the other artifact type",
    command: `hackmyagent check skill:${input.packageName}`,
  });
  steps.push({
    weight: "secondary",
    label: "Try as the other artifact type",
    command: `hackmyagent check mcp:${input.packageName}`,
  });
  steps.push({
    weight: "secondary",
    label: "Search by capability",
    command: `ai-trust suggest ${input.packageName}`,
  });
  return steps;
}

function suggestionScope(artifactType: RuleArtifactType): string {
  if (artifactType === "skill") return "skill";
  if (artifactType === "mcp") return "mcp";
  return "package";
}

function installCommandForType(input: RuleEngineInput): string {
  if (input.artifactType === "pypi") return `pip install ${input.packageName}`;
  if (input.artifactType === "skill")
    return `opena2a install ${input.packageName}`;
  if (input.artifactType === "a2a")
    return `opena2a a2a install ${input.packageName}`;
  return `npm i ${input.packageName}`;
}

function pinCommand(input: RuleEngineInput, version: string): string {
  if (input.artifactType === "pypi")
    return `pip install ${input.packageName}==${version}`;
  if (input.artifactType === "skill")
    return `opena2a install ${input.packageName}@${version}`;
  return `npm i ${input.packageName}@${version}`;
}
