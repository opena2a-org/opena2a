/**
 * Check block — unified output schema for the `check <pkg>` command.
 *
 * Shared across hackmyagent, opena2a-cli (via hma delegation), and ai-trust.
 * Closes F5/F6 from briefs/check-command-divergence.md:
 *   - F5: one canonical output schema, conditional sections, missing = hidden
 *   - F6: trust/security meter suppressed when `scanStatus !== completed|warnings`
 *         ("a number implies measurement")
 *
 * Returns structured lines. The CLI applies its own chalk palette so the
 * package stays a rendering library, not a color library. Values that
 * require the shared meter / legend helpers are pre-rendered by those
 * helpers (which own their own chalk) and passed through as `value`.
 */

import { scoreMeter } from "./meters.js";
import { trustLevelLabel, trustLevelLegend } from "./trust-level.js";
import { formatScanAge } from "./scan-age.js";
import { normalizeVerdict } from "./verdict.js";

export type CheckTone = "default" | "good" | "warning" | "critical" | "dim";

/**
 * Input shape for `renderCheckBlock`.
 *
 * Required fields mirror what `@opena2a/registry-client`'s `TrustAnswer`
 * always populates for a registered package. Optional fields cover the
 * extended surface described in F5 — publisher, permissions, revocation.
 * These are stubs for v0.3.0: the caller passes them when available
 * (e.g. agent / skill paths), otherwise the renderer hides the row.
 */
export interface CheckBlockInput {
  /** Package name as the user typed it (used in the header). */
  name: string;
  /** Package type from the registry — "mcp_server", "ai_tool", "library", "skill", etc. */
  packageType?: string;
  /** Optional package version, shown in header meta when present. */
  version?: string;
  /** Trust level 0-4. Always shown. */
  trustLevel: number;
  /** Trust score 0-1 (the registry's canonical scale). Rendered 0-100 for the meter. */
  trustScore: number;
  /** Registry verdict string: "passed" | "warning" | "warnings" | "blocked" | "listed" | ... */
  verdict: string;
  /**
   * Scan status from the registry — controls whether the Trust meter is rendered.
   * Meter shown iff `completed` or `warnings`. Other values (`pending`, `unscanned`,
   * undefined) hide the meter and emit a "not scanned" line instead.
   */
  scanStatus?: string;
  /** Count of independent community scans backing the score. */
  communityScans?: number;
  /** ISO timestamp of the most recent scan. Rendered via `formatScanAge`. */
  lastScannedAt?: string;
  /**
   * Publisher identity. Stub for v0.3.0 — most call sites won't populate this yet.
   * When `undefined`, the row is hidden. M3 expands the registry surface to
   * provide verified-publisher data consistently.
   */
  publisher?: { name: string; verified?: boolean };
  /**
   * Permissions declared by the artifact (agents / skills only).
   * When `undefined` or empty, the row is hidden. Libraries don't have
   * permissions; this block is only emitted for agent-shaped artifacts.
   */
  permissions?: string[];
  /**
   * Revocation signal. `listed: true` means "on the blocklist" (critical).
   * `listed: false` is rendered as a positive "not on blocklist" signal.
   * When `undefined`, the row is hidden (unknown state, don't fake it).
   */
  revocation?: { listed: boolean };
}

/** One rendered line in the check block. */
export interface CheckBlockLine {
  label: string;
  /**
   * Pre-composed value string. May contain chalk ANSI for the Trust meter
   * and trust-level legend, which own their own color internally. The CLI
   * applies its own chalk only to the `label` and to plain values.
   */
  value: string;
  tone: CheckTone;
}

/** Rendered check block — the shape `check` commands consume. */
export interface RenderedCheck {
  /** Header line components. CLI composes `<name>  <meta.join(' · ')>`. */
  header: { name: string; meta: string[] };
  /** Plain-English verdict ("No known issues", "Warning — review...", "Blocked by registry"). */
  verdict: { text: string; tone: CheckTone };
  /** Rendering-ordered lines. Empty when a given field is undefined (F5 "missing = hidden"). */
  lines: CheckBlockLine[];
  /**
   * True when the Trust meter line was emitted. Useful for callers
   * that want a structural assertion in parity tests (F6 regression).
   */
  meterShown: boolean;
}

/** Normalize a score from the registry's 0-1 scale to the meter's 0-100 scale. */
function normalizeScore(raw: number): number {
  if (raw <= 1) return Math.round(raw * 100);
  return Math.round(raw);
}

/** Decide whether the Trust meter should render based on scan status. */
function shouldShowMeter(scanStatus?: string): boolean {
  if (!scanStatus) return false;
  return scanStatus === "completed" || scanStatus === "warnings";
}

/** Build the verdict line from the registry verdict string. */
function buildVerdict(verdict: string): { text: string; tone: CheckTone } {
  const normalized = normalizeVerdict(verdict);
  switch (normalized) {
    case "safe":
      return { text: "No known issues", tone: "good" };
    case "warning":
      return { text: "Warning — review before installing", tone: "warning" };
    case "blocked":
      return { text: "Blocked by registry", tone: "critical" };
    case "listed":
      return { text: "Listed — limited signal", tone: "default" };
    default:
      return { text: "Unknown verdict", tone: "dim" };
  }
}

export function renderCheckBlock(input: CheckBlockInput): RenderedCheck {
  const {
    name,
    packageType,
    version,
    trustLevel,
    trustScore,
    verdict,
    scanStatus,
    communityScans,
    lastScannedAt,
    publisher,
    permissions,
    revocation,
  } = input;

  // --- Header ----------------------------------------------------------------
  const meta: string[] = [];
  if (version) meta.push(`v${version}`);
  if (packageType) meta.push(packageType.replace(/_/g, " "));

  // --- Verdict ---------------------------------------------------------------
  const verdictLine = buildVerdict(verdict);

  // --- Lines -----------------------------------------------------------------
  const lines: CheckBlockLine[] = [];

  // Trust meter — governed by scanStatus (F6).
  const meterShown = shouldShowMeter(scanStatus);
  if (meterShown) {
    const score = normalizeScore(trustScore);
    lines.push({
      label: "Trust",
      value: scoreMeter(score, 100),
      tone: score >= 70 ? "good" : score >= 40 ? "warning" : "critical",
    });
  } else {
    lines.push({
      label: "Trust",
      value: "not scanned — request a scan to see a score",
      tone: "dim",
    });
  }

  // Trust level is always shown (matches F5 schema: "Level always present; one truth").
  lines.push({
    label: "Level",
    value: `${trustLevelLabel(trustLevel)}  ${trustLevelLegend(trustLevel)}`,
    tone: trustLevel >= 3 ? "good" : trustLevel >= 1 ? "warning" : "critical",
  });

  // Publisher — shown only when known (F5 "missing = hidden").
  if (publisher && publisher.name) {
    const verifiedSuffix =
      publisher.verified === true
        ? " · verified"
        : publisher.verified === false
          ? " · unverified"
          : "";
    lines.push({
      label: "Publisher",
      value: `${publisher.name}${verifiedSuffix}`,
      tone: publisher.verified === true ? "good" : publisher.verified === false ? "warning" : "default",
    });
  }

  // Permissions — agents/skills only.
  if (permissions && permissions.length > 0) {
    lines.push({
      label: "Permissions",
      value: permissions.join(", "),
      tone: "default",
    });
  }

  // Revocation — shown when we have a definitive answer.
  if (revocation) {
    if (revocation.listed) {
      lines.push({
        label: "Revocation",
        value: "on blocklist — do not install",
        tone: "critical",
      });
    } else {
      lines.push({
        label: "Revocation",
        value: "not on blocklist",
        tone: "good",
      });
    }
  }

  // Community scans — shown when > 0.
  if (typeof communityScans === "number" && communityScans > 0) {
    lines.push({
      label: "Scans",
      value: `${communityScans} community scan${communityScans === 1 ? "" : "s"}`,
      tone: "default",
    });
  }

  // Last scanned — shown when known.
  const age = formatScanAge(lastScannedAt);
  if (age) {
    const isStale = age.includes("stale");
    lines.push({
      label: "Last scan",
      value: age,
      tone: isStale ? "warning" : "default",
    });
  }

  return { header: { name, meta }, verdict: verdictLine, lines, meterShown };
}
