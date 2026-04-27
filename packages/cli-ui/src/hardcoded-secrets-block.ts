/**
 * Hardcoded-secrets block — always renders. Three states per brief §7:
 *   - !scanCovered             → "Not yet analyzed."
 *   - scanCovered, empty list  → "None detected on the latest version."
 *   - scanCovered, non-empty   → severity-grouped credential list +
 *                                 rotation URLs + report command.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§7).
 *
 * Pure rendering; no chalk imports here. Returns `RenderedSecretsBlock`
 * tuples; the caller applies tones from its own palette. Severity
 * prefixes (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) are baked into the
 * value strings so a piped/`--json` consumer can grep for them.
 *
 * All caller-supplied strings are sanitized via `sanitizeForTerminal`
 * before they enter the rendered output — registry values are
 * untrusted and could otherwise embed ANSI / OSC-8 / control bytes.
 */
import { sanitizeForTerminal } from "./terminal-safe.js";

/**
 * Local mirror of `HardcodedSecret` from `@opena2a/check-core`. cli-ui
 * stays dependency-light (chalk only); structural typing means the
 * registry-sourced narrative passes through without conversion.
 */
export interface SecretLike {
  type: string;
  typeLabel: string;
  file: string;
  line?: number;
  maskedValue: string;
  shownChars: number;
  totalChars: number;
  shipsInArtifact: boolean;
  severity: "critical" | "high" | "medium" | "low";
  rotationUrl?: string;
  rotationCommand?: string;
}

export type SecretsTone = "default" | "good" | "warning" | "critical" | "dim";

/**
 * Input shape for `renderHardcodedSecretsBlock`. The version field is
 * the package's latest version — used in the "None detected on the
 * latest version (<version>)" clean-state line. Empty string when the
 * caller doesn't have it (the line drops the `(<version>)` suffix).
 */
export interface SecretsBlockInput {
  detected: SecretLike[];
  scanCovered: boolean;
  /** Latest version string for the clean / detected count line. */
  latestVersion?: string;
  /**
   * Package name — used in the "report" CLI hint command. Optional;
   * when absent the report command falls back to a generic placeholder.
   */
  packageName?: string;
  /**
   * Tool that owns the report command (e.g. "hackmyagent"). Defaults
   * to "hackmyagent" since report-secret-leak is HMA's command.
   */
  reportTool?: string;
}

export interface SecretsBlockLine {
  /**
   * Indentation level. 0 = section-level (e.g. count line). 1 =
   * credential entry. 2 = sub-entry (masked value, ships note,
   * rotation URL).
   */
  indent: 0 | 1 | 2;
  text: string;
  tone: SecretsTone;
}

export interface RenderedSecretsBlock {
  /**
   * Section header tone — driven by the max severity of any detected
   * secret. Used by the caller to color the divider that precedes
   * the block.
   */
  headerTone: SecretsTone;
  lines: SecretsBlockLine[];
}

const SEVERITY_RANK: Record<SecretLike["severity"], number> = {
  critical: 3,
  high: 2,
  medium: 1,
  low: 0,
};

const SEVERITY_TONE: Record<SecretLike["severity"], SecretsTone> = {
  critical: "critical",
  high: "critical",
  medium: "warning",
  low: "warning",
};

const SEVERITY_PREFIX: Record<SecretLike["severity"], string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
};

function maxSeverity(secrets: SecretLike[]): SecretLike["severity"] | null {
  if (secrets.length === 0) return null;
  let best: SecretLike["severity"] = "low";
  for (const s of secrets) {
    if (SEVERITY_RANK[s.severity] > SEVERITY_RANK[best]) best = s.severity;
  }
  return best;
}

/**
 * Build the version-suffix used in the count and clean lines. When
 * `latestVersion` is empty/undefined, returns an empty string so the
 * caller can drop the parenthetical entirely.
 */
function versionSuffix(latestVersion?: string): string {
  if (!latestVersion) return "";
  return ` (${sanitizeForTerminal(latestVersion)})`;
}

/**
 * Build the dedup'd list of rotation URLs. The brief renders them
 * one per credential type (not per credential), so multiple AWS keys
 * collapse to one "Rotate (AWS): ..." line.
 */
function dedupRotationLines(secrets: SecretLike[]): SecretsBlockLine[] {
  const seen = new Set<string>();
  const out: SecretsBlockLine[] = [];
  for (const s of secrets) {
    if (!s.rotationUrl && !s.rotationCommand) continue;
    const key = `${s.type}|${s.rotationUrl ?? ""}|${s.rotationCommand ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const safeLabel = sanitizeForTerminal(s.typeLabel);
    if (s.rotationUrl) {
      out.push({
        indent: 0,
        text: `Rotate (${safeLabel}): ${sanitizeForTerminal(s.rotationUrl)}`,
        tone: "default",
      });
    }
    if (s.rotationCommand) {
      out.push({
        indent: 0,
        text: `Rotate (${safeLabel}): ${sanitizeForTerminal(s.rotationCommand)}`,
        tone: "default",
      });
    }
  }
  return out;
}

export function renderHardcodedSecretsBlock(
  input: SecretsBlockInput,
): RenderedSecretsBlock {
  const { detected, scanCovered, latestVersion, packageName, reportTool } =
    input;

  if (!scanCovered) {
    return {
      headerTone: "dim",
      lines: [
        {
          indent: 0,
          text: "Not yet analyzed. A scan is required to detect hardcoded secrets.",
          tone: "dim",
        },
      ],
    };
  }

  if (detected.length === 0) {
    return {
      headerTone: "good",
      lines: [
        {
          indent: 0,
          text: `None detected on the latest version${versionSuffix(latestVersion)}`,
          tone: "good",
        },
      ],
    };
  }

  const top = maxSeverity(detected);
  const headerTone: SecretsTone = top
    ? SEVERITY_TONE[top]
    : "warning";

  const lines: SecretsBlockLine[] = [];

  // Count line — "<SEVERITY>  N credential(s) detected on the latest version (<v>)".
  const prefix = top ? SEVERITY_PREFIX[top] : "INFO";
  const countWord = detected.length === 1 ? "credential" : "credentials";
  lines.push({
    indent: 0,
    text: `${prefix}  ${detected.length} ${countWord} detected on the latest version${versionSuffix(latestVersion)}`,
    tone: headerTone,
  });

  // One block per credential — type + locator, masked + char count, ships note.
  for (const s of detected) {
    const safeFile = sanitizeForTerminal(s.file);
    const locator = s.line ? `${safeFile}:${s.line}` : safeFile;
    lines.push({
      indent: 1,
      text: `${sanitizeForTerminal(s.typeLabel)}  at  ${locator}`,
      tone: SEVERITY_TONE[s.severity],
    });
    lines.push({
      indent: 2,
      text: `${sanitizeForTerminal(s.maskedValue)} (${s.shownChars} of ${s.totalChars} chars)`,
      tone: "default",
    });
    if (s.shipsInArtifact) {
      lines.push({
        indent: 2,
        text: "File ships in package tarball.",
        tone: "warning",
      });
    }
  }

  // Trailing rotation block.
  const anyShipsInArtifact = detected.some((s) => s.shipsInArtifact);
  if (anyShipsInArtifact) {
    lines.push({
      indent: 0,
      text: "Note: these keys must be rotated regardless of whether you install this package. They are already public on the registry.",
      tone: "warning",
    });
  }

  for (const line of dedupRotationLines(detected)) {
    lines.push(line);
  }

  // Report command.
  const tool =
    reportTool && reportTool.length > 0
      ? sanitizeForTerminal(reportTool)
      : "hackmyagent";
  const target =
    packageName && packageName.length > 0
      ? sanitizeForTerminal(packageName)
      : "<pkg>";
  lines.push({
    indent: 0,
    text: `Report:  ${tool} report ${target} --secret-leak`,
    tone: "default",
  });

  return { headerTone, lines };
}
