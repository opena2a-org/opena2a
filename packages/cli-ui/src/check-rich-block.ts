/**
 * Rich-context check block — orchestrates the v1 "skill" / "mcp" view.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§3).
 *
 * Returns a structured `RenderedRichBlock` that the CLI consumer
 * iterates to emit dividers + labelled lines + tone-applied colors.
 * Section ordering matches the brief mockups byte-for-byte on the
 * must_match fields (header section names, severity prefixes, status
 * markers, tier labels). Field-level wording inside sections may
 * evolve; layout / structure may not.
 *
 * Pure rendering — no I/O, no NanoMind calls. The orchestrator
 * consumes the registry-stored `PackageNarrative` payload (passed
 * structurally so cli-ui has no runtime dependency on check-core).
 */

import {
  renderActionGradientBlock,
  type ActionGradientTier,
  type NextStepLike,
} from "./action-gradient-block.js";
import {
  renderHardcodedSecretsBlock,
  type SecretLike,
} from "./hardcoded-secrets-block.js";
import {
  renderMcpNarrativeBlock,
  type McpNarrativeLike,
} from "./mcp-narrative-block.js";
import {
  renderSkillMisuseNarrative,
  renderSkillNarrativeBlock,
  type SkillNarrativeLike,
} from "./skill-narrative-block.js";
import {
  threatModelQuestionsFor,
  type ThreatModelArtifactType,
} from "./threat-model-questions.js";
import { sanitizeForTerminal } from "./terminal-safe.js";
import {
  renderVerdictReasoningBlock,
  type VerdictReasoningStatementLike,
  type VerdictTier,
} from "./verdict-reasoning-block.js";

export type RichBlockTone =
  | "default"
  | "good"
  | "warning"
  | "critical"
  | "dim";

export type RichArtifactType = "skill" | "mcp";

/**
 * One observation entry rendered under "What we observed". Mirrors the
 * shape produced by HMA's local-scan finding records, but trimmed to
 * the fields the renderer actually emits. Description + fix wrap
 * across continuation lines in the rendered output.
 */
export interface RichObservationFinding {
  severity: "critical" | "high" | "medium" | "low";
  ruleId: string;
  /** file:line locator. Empty string when unanchored. */
  locator: string;
  description: string;
  /** Optional fix instruction (renders as a "Fix:" continuation). */
  fix?: string;
}

/**
 * Alternative-package suggestion shown under "If you intended a
 * different MCP" / "Did you mean" on BLOCKED tier. Emit-only;
 * rendering is rate-limited to the top 3 entries.
 */
export interface RichAlternativeSuggestion {
  name: string;
  tier: string;
  score?: number;
}

/**
 * Header signals composed into the meta-line block.
 */
export interface RichBlockHeaderSignals {
  trustVerdict: VerdictTier;
  /** 0-100 integer. Omit / set to undefined for LISTED_UNSCANNED. */
  trustScore?: number;
  /** Human-readable scan-age, e.g. "14d ago". Empty when never scanned. */
  lastScanAge?: string;
  /** Human-readable latest-version label, e.g. "0.3.1 (5d ago)". */
  latestVersionLabel?: string;
  publisher?: { name: string; verified: boolean; kind?: string };
  license?: string;
  maintainerCount?: number;
  /** Downloads/week + trend. Renderer drops the row when undefined. */
  downloads?: { perWeek: number; trend?: "rising" | "steady" | "declining" };
  communityScans?: number;
  findingsCount?: number;
}

export interface CheckRichBlockInput {
  /** Package name as the user typed it. */
  name: string;
  artifactType: RichArtifactType;
  header: RichBlockHeaderSignals;

  /** Hardcoded-secrets payload from the narrative. Always required (3-state block). */
  hardcodedSecrets: {
    detected: SecretLike[];
    scanCovered: boolean;
  };
  /** Latest version for the secrets-block count line. */
  latestVersion?: string;

  /** Skill narrative payload, present when artifactType === "skill". */
  skill?: SkillNarrativeLike;
  /** MCP narrative payload, present when artifactType === "mcp". */
  mcp?: McpNarrativeLike;

  /** Findings list for "What we observed". Empty array → "No findings." */
  findings: RichObservationFinding[];

  /** Rule-engine output. */
  verdictReasoning: VerdictReasoningStatementLike[];
  nextSteps: NextStepLike[];

  /** Alternative-package suggestions for BLOCKED tier. */
  alternatives?: RichAlternativeSuggestion[];

  /** Tool name for the secrets-block report command (e.g. "hackmyagent"). */
  reportTool?: string;
}

export interface RichBlockMetaLine {
  text: string;
  tone: RichBlockTone;
}

export interface RichBlockSectionLine {
  text: string;
  tone: RichBlockTone;
  indent: 0 | 1 | 2;
}

export interface RichBlockSection {
  divider: string;
  dividerTone: RichBlockTone;
  lines: RichBlockSectionLine[];
}

export interface RenderedRichBlock {
  header: {
    name: string;
    metaLines: RichBlockMetaLine[];
  };
  sections: RichBlockSection[];
}

/** Severity prefix for "What we observed" findings. */
const SEVERITY_PREFIX: Record<RichObservationFinding["severity"], string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
};

const SEVERITY_TONE: Record<RichObservationFinding["severity"], RichBlockTone> =
  {
    critical: "critical",
    high: "critical",
    medium: "warning",
    low: "warning",
  };

const VERDICT_TONE: Record<VerdictTier, RichBlockTone> = {
  VERIFIED: "good",
  LISTED: "default",
  LISTED_UNSCANNED: "warning",
  BLOCKED: "critical",
  NOT_FOUND: "dim",
};

function verdictLabel(tier: VerdictTier): string {
  if (tier === "LISTED_UNSCANNED") return "LISTED (UNSCANNED)";
  if (tier === "NOT_FOUND") return "NOT FOUND";
  return tier;
}

/**
 * Build the meta-lines under the package name in the header. Order
 * mirrors brief mockup 3.1 / 3.4: artifactType + verdict, then score
 * line, then publisher, license, downloads, community-scans.
 */
function buildHeaderMetaLines(input: CheckRichBlockInput): RichBlockMetaLine[] {
  const { artifactType, header } = input;
  const out: RichBlockMetaLine[] = [];

  // First meta line: "skill  ·  LISTED" (or equivalent verdict label).
  // artifactType is a typed enum ('skill' | 'mcp') so no sanitization
  // needed; verdictLabel returns hardcoded strings.
  out.push({
    text: `${artifactType}  ·  ${verdictLabel(header.trustVerdict)}`,
    tone: VERDICT_TONE[header.trustVerdict],
  });

  // Score / scan-age / latest-version line.
  const parts2: string[] = [];
  if (typeof header.trustScore === "number") {
    parts2.push(`Score: ${header.trustScore}/100`);
  } else if (
    header.trustVerdict === "LISTED_UNSCANNED" ||
    !header.lastScanAge
  ) {
    parts2.push("Score: [—]");
  }
  if (header.lastScanAge && header.lastScanAge.length > 0) {
    parts2.push(`Last scan: ${sanitizeForTerminal(header.lastScanAge)}`);
  } else if (header.trustVerdict === "LISTED_UNSCANNED") {
    parts2.push("Never scanned");
  }
  if (header.latestVersionLabel && header.latestVersionLabel.length > 0) {
    parts2.push(`Latest: ${sanitizeForTerminal(header.latestVersionLabel)}`);
  }
  if (parts2.length > 0) {
    out.push({ text: parts2.join("  ·  "), tone: "default" });
  }

  // Publisher line.
  if (header.publisher && header.publisher.name && header.publisher.name.length > 0) {
    const safeName = sanitizeForTerminal(header.publisher.name);
    const safeKind = header.publisher.kind
      ? sanitizeForTerminal(header.publisher.kind)
      : "";
    const verifiedKind = safeKind
      ? `(${safeKind})`
      : header.publisher.verified
        ? "(verified)"
        : "(unverified)";
    out.push({
      text: `Publisher: ${safeName} ${verifiedKind}`,
      tone: header.publisher.verified ? "good" : "warning",
    });
  }

  // License + maintainers.
  const parts4: string[] = [];
  if (header.license) parts4.push(`License: ${sanitizeForTerminal(header.license)}`);
  if (typeof header.maintainerCount === "number") {
    parts4.push(
      `${header.maintainerCount} maintainer${header.maintainerCount === 1 ? "" : "s"}`,
    );
  }
  if (parts4.length > 0) {
    out.push({ text: parts4.join("  ·  "), tone: "default" });
  }

  // Downloads + community scans + findings count.
  const parts5: string[] = [];
  if (header.downloads) {
    const trend = header.downloads.trend ? ` (${header.downloads.trend})` : "";
    parts5.push(`${formatDownloads(header.downloads.perWeek)} downloads/wk${trend}`);
  }
  if (typeof header.communityScans === "number") {
    parts5.push(
      `${header.communityScans} community scan${header.communityScans === 1 ? "" : "s"}`,
    );
  }
  if (typeof header.findingsCount === "number") {
    parts5.push(
      `${header.findingsCount} finding${header.findingsCount === 1 ? "" : "s"}`,
    );
  }
  if (parts5.length > 0) {
    out.push({ text: parts5.join(" · "), tone: "default" });
  }

  return out;
}

function formatDownloads(n: number): string {
  if (n >= 1000) {
    const k = (n / 1000).toFixed(n >= 10000 ? 0 : 1);
    return `${k}K`;
  }
  return String(n);
}

/**
 * Build the "What we observed" section. Empty findings list → single
 * "No findings." line. Otherwise, one block per finding: severity
 * prefix + ruleId + locator on the first row, description on a
 * continuation row, fix on a third continuation row when present.
 */
const SEVERITY_ORDER: Record<RichObservationFinding["severity"], number> = {
  critical: 3,
  high: 2,
  medium: 1,
  low: 0,
};

function buildObservationsSection(
  findings: RichObservationFinding[],
): RichBlockSection {
  if (findings.length === 0) {
    return {
      divider: "What we observed",
      dividerTone: "good",
      lines: [{ indent: 0, text: "No findings.", tone: "good" }],
    };
  }

  // Sort by severity descending (stable on input order within a tier)
  // so CRITICAL findings render first and never get buried below
  // softer signals. Caller-supplied array order is preserved within
  // each severity bucket.
  const sorted = findings
    .map((f, i) => ({ f, i }))
    .sort((a, b) => {
      const sevDiff = SEVERITY_ORDER[b.f.severity] - SEVERITY_ORDER[a.f.severity];
      return sevDiff !== 0 ? sevDiff : a.i - b.i;
    })
    .map((x) => x.f);

  const top = sorted[0].severity;

  const lines: RichBlockSectionLine[] = [];
  for (const f of sorted) {
    const prefix = SEVERITY_PREFIX[f.severity];
    const safeRuleId = sanitizeForTerminal(f.ruleId);
    const safeLocator = sanitizeForTerminal(f.locator);
    const locatorPart =
      safeLocator && safeLocator.length > 0 ? ` at ${safeLocator}` : "";
    lines.push({
      indent: 0,
      text: `${prefix}   ${safeRuleId}${locatorPart}`,
      tone: SEVERITY_TONE[f.severity],
    });
    if (f.description && f.description.length > 0) {
      lines.push({
        indent: 1,
        text: sanitizeForTerminal(f.description),
        tone: "default",
      });
    }
    if (f.fix && f.fix.length > 0) {
      lines.push({
        indent: 1,
        text: `Fix: ${sanitizeForTerminal(f.fix)}`,
        tone: "default",
      });
    }
  }

  return {
    divider: "What we observed",
    dividerTone: SEVERITY_TONE[top],
    lines,
  };
}

/**
 * Build the threat-model questions section — numbered list of static
 * template strings. Static per artifact type (brief §6).
 */
function buildThreatModelSection(
  artifactType: ThreatModelArtifactType,
): RichBlockSection {
  const questions = threatModelQuestionsFor(artifactType);
  const lines: RichBlockSectionLine[] = questions.map((q, i) => ({
    indent: 0,
    text: `${i + 1}. ${q}`,
    tone: "default",
  }));
  return {
    divider: "Threat-model questions to consider",
    dividerTone: "default",
    lines,
  };
}

/**
 * Build the BLOCKED-tier "If you intended a different <type>" suggestions
 * section. Caps at 3 entries.
 */
function buildAlternativesSection(
  artifactType: RichArtifactType,
  alternatives: RichAlternativeSuggestion[],
): RichBlockSection | null {
  if (alternatives.length === 0) return null;
  const top3 = alternatives.slice(0, 3).map((a) => ({
    name: sanitizeForTerminal(a.name),
    tier: sanitizeForTerminal(a.tier),
    score: a.score,
  }));
  const nameWidth = Math.min(
    24,
    top3.reduce((m, a) => Math.max(m, a.name.length), 0) + 2,
  );
  const lines: RichBlockSectionLine[] = [
    { indent: 0, text: "Did you mean:", tone: "default" },
  ];
  for (const alt of top3) {
    const padded = alt.name.padEnd(nameWidth, " ");
    const score = typeof alt.score === "number" ? `, ${alt.score}` : "";
    lines.push({
      indent: 1,
      text: `${padded} (${alt.tier}${score})`,
      tone: "default",
    });
  }
  return {
    divider: `If you intended a different ${artifactType}`,
    dividerTone: "default",
    lines,
  };
}

/**
 * Lift sub-renderer output into `RichBlockSectionLine[]`. Each
 * sub-renderer returns its own line shape; we normalise here.
 */
function liftSecretsLines(
  out: ReturnType<typeof renderHardcodedSecretsBlock>,
): RichBlockSectionLine[] {
  return out.lines.map((l) => ({ indent: l.indent, text: l.text, tone: l.tone }));
}

function liftSkillLines(
  out: ReturnType<typeof renderSkillNarrativeBlock>,
): RichBlockSectionLine[] {
  return out.lines.map((l) => ({
    indent: l.indent,
    text: l.label.length > 0 ? `${l.label}${l.value}` : l.value,
    tone: l.tone,
  }));
}

function liftMcpLines(
  out: ReturnType<typeof renderMcpNarrativeBlock>,
): RichBlockSectionLine[] {
  return out.lines.map((l) => ({
    indent: l.indent,
    text: l.label.length > 0 ? `${l.label}${l.value}` : l.value,
    tone: l.tone,
  }));
}

function liftVerdictLines(
  out: ReturnType<typeof renderVerdictReasoningBlock>,
): RichBlockSectionLine[] {
  return out.lines.map((l) => ({ indent: 0, text: l.text, tone: l.tone }));
}

function liftActionLines(
  out: ReturnType<typeof renderActionGradientBlock>,
): RichBlockSectionLine[] {
  return out.lines.map((l) => ({ indent: 0, text: l.text, tone: l.tone }));
}

/**
 * Resolve the action-gradient tier from the verdict tier — the two
 * domains are isomorphic but typed separately so cli-ui modules don't
 * cross-import each other's enums.
 */
function actionTierFor(tier: VerdictTier): ActionGradientTier {
  return tier;
}

export function renderCheckRichBlock(
  input: CheckRichBlockInput,
): RenderedRichBlock {
  const tier = input.header.trustVerdict;
  const sections: RichBlockSection[] = [];

  // -- Hardcoded secrets (always renders, 3 states) -----------------------
  // Sub-renderer sanitizes its own input fields; `name` and
  // `reportTool` are passed through and sanitized inside.
  const secretsOut = renderHardcodedSecretsBlock({
    detected: input.hardcodedSecrets.detected,
    scanCovered: input.hardcodedSecrets.scanCovered,
    latestVersion: input.latestVersion,
    packageName: input.name,
    reportTool: input.reportTool,
  });
  sections.push({
    divider: "Hardcoded secrets",
    dividerTone: secretsOut.headerTone,
    lines: liftSecretsLines(secretsOut),
  });

  // -- What is this skill? / What is this MCP? ---------------------------
  if (input.artifactType === "skill" && input.skill) {
    const skillOut = renderSkillNarrativeBlock(input.skill);
    sections.push({
      divider: skillOut.header,
      dividerTone: "default",
      lines: liftSkillLines(skillOut),
    });
  } else if (input.artifactType === "mcp" && input.mcp) {
    const mcpOut = renderMcpNarrativeBlock(input.mcp);
    sections.push({
      divider: mcpOut.header,
      dividerTone: "default",
      lines: liftMcpLines(mcpOut),
    });
  }

  // -- What we observed (findings list) -----------------------------------
  // Suppressed on LISTED_UNSCANNED + NOT_FOUND (no scan to surface).
  if (tier !== "LISTED_UNSCANNED" && tier !== "NOT_FOUND") {
    sections.push(buildObservationsSection(input.findings));
  }

  // -- Why <tier> ---------------------------------------------------------
  if (tier !== "NOT_FOUND") {
    const verdictOut = renderVerdictReasoningBlock({
      tier,
      statements: input.verdictReasoning,
    });
    if (verdictOut.header.length > 0) {
      sections.push({
        divider: verdictOut.header,
        dividerTone: VERDICT_TONE[tier],
        lines: liftVerdictLines(verdictOut),
      });
    }
  }

  // -- BLOCKED-tier extras: Recovery path + alternatives ------------------
  if (tier === "BLOCKED") {
    sections.push({
      divider: "Recovery path",
      dividerTone: "critical",
      lines: [
        {
          indent: 0,
          text: "None. Blocked packages do not have a fix path because the threat is the package itself, not a configuration issue.",
          tone: "critical",
        },
      ],
    });
    const altSection = buildAlternativesSection(
      input.artifactType,
      input.alternatives ?? [],
    );
    if (altSection) sections.push(altSection);
  }

  // -- How this skill could be misused (skill only, when narrative present)
  if (input.artifactType === "skill" && input.skill) {
    const misuse = renderSkillMisuseNarrative(input.skill);
    if (misuse) {
      sections.push({
        divider: misuse.header,
        dividerTone: "warning",
        lines: [{ indent: 0, text: misuse.paragraph, tone: "default" }],
      });
    }
  }

  // -- Threat-model questions (skill + mcp only) --------------------------
  if (tier !== "NOT_FOUND") {
    sections.push(buildThreatModelSection(input.artifactType));
  }

  // -- Next ---------------------------------------------------------------
  const actionOut = renderActionGradientBlock({
    tier: actionTierFor(tier),
    steps: input.nextSteps,
  });
  sections.push({
    divider: "Next",
    dividerTone: VERDICT_TONE[tier],
    lines: liftActionLines(actionOut),
  });

  return {
    header: {
      name: sanitizeForTerminal(input.name),
      metaLines: buildHeaderMetaLines(input),
    },
    sections,
  };
}
