import type {
  CheckOutput,
  NotFoundOutput,
  PackageEcosystem,
  PackageTarget,
  ScanResult,
  TrustData,
} from "./types.js";

/**
 * Input to `buildCheckOutput`. At least one of `scan` or `registry`
 * (with `found === true`) should be present; both together means the
 * local-scan finished and the registry also has trust data to merge.
 */
export interface BuildCheckOutputInput {
  name: string;
  type: PackageTarget;
  scan?: ScanResult;
  registry?: TrustData | null;
}

/**
 * Build the canonical `check` output object.
 *
 * Key order is load-bearing — the opena2a-parity harness compares the
 * byte shape across CLIs, and changing the emission order would break
 * `hackmyagent check --json` outputs consumers rely on. Order matches
 * hackmyagent@0.18.3's legacy `buildCheckJsonOutput`:
 *
 *   name, type, source,
 *   projectType, score, maxScore, findings, version,     (scan path)
 *   trustLevel, trustScore, verdict, scanStatus,          (registry)
 *   packageType, lastScannedAt, communityScans, cveCount,
 *   analystFindings
 */
export function buildCheckOutput(input: BuildCheckOutputInput): CheckOutput {
  const { name, type, scan, registry } = input;
  const out: CheckOutput = {
    name,
    type,
    source: scan ? "local-scan" : "registry",
  };

  if (scan) {
    if (scan.projectType !== undefined) out.projectType = scan.projectType;
    out.score = scan.score;
    out.maxScore = scan.maxScore;
    out.findings = scan.findings;
    if (scan.version !== undefined) out.version = scan.version;
  }

  if (registry?.found) {
    out.trustLevel = registry.trustLevel;
    out.trustScore = registry.trustScore;
    out.verdict = registry.verdict;
    if (registry.scanStatus !== undefined) out.scanStatus = registry.scanStatus;
    if (registry.packageType !== undefined) out.packageType = registry.packageType;
    if (registry.lastScannedAt !== undefined) out.lastScannedAt = registry.lastScannedAt;
    if (registry.communityScans !== undefined) out.communityScans = registry.communityScans;
    if (registry.cveCount !== undefined) out.cveCount = registry.cveCount;
  }

  if (scan?.analystFindings && scan.analystFindings.length) {
    out.analystFindings = scan.analystFindings;
  }

  return out;
}

export interface BuildNotFoundInput {
  name: string;
  ecosystem?: PackageEcosystem;
  errorHint?: string;
  suggestions?: string[];
  error?: string;
  nextSteps?: string[];
}

/**
 * Build the canonical not-found JSON shape. Closes F2 (three different
 * not-found shapes) by giving all consumers a single builder.
 */
export function buildNotFoundOutput(input: BuildNotFoundInput): NotFoundOutput {
  const { name, ecosystem, errorHint, suggestions, error, nextSteps } = input;
  const out: NotFoundOutput = {
    name,
    found: false,
  };
  if (error !== undefined) out.error = error;
  if (errorHint !== undefined) out.errorHint = errorHint;
  if (suggestions && suggestions.length) out.suggestions = suggestions;
  if (nextSteps && nextSteps.length) out.nextSteps = nextSteps;
  if (ecosystem !== undefined) out.ecosystem = ecosystem;
  return out;
}
