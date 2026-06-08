/**
 * The documented, machine-readable contract for `check --json` output.
 *
 * Issue #124 surfaced that a `check --json` payload can carry three
 * score-shaped numbers on different scales from two different sources,
 * with no documented relationship — so a consumer cannot tell which one
 * to gate CI on without reading source. This module IS that documentation:
 * an exported field guide + JSON Schema, plus a drift-guard test that
 * keeps it consistent with what `buildCheckOutput` actually emits.
 *
 * ## The three axes (they are orthogonal, not contradictory)
 *
 *   1. LOCAL-SCAN axis — `score` / `maxScore` / `findings` (and
 *      `projectType`, `version`, `analystFindings`). These describe what
 *      the *local static scan* measured on the fetched artifact. `score`
 *      is 0..100 where 100 = the local scan found nothing. It is NOT a
 *      registry trust verdict: a freshly-published package with no issues
 *      a local scanner can see will read `score: 100` even though the
 *      registry has never deep-scanned it.
 *
 *   2. REGISTRY-TRUST axis — `trustScore`, `trustLevel`, and `verdict`.
 *      These are NOT three independent numbers, nor are they all the same
 *      signal — the relationship is specific (verified against the
 *      registry's `DetermineTrustLevel`, registry_trust_calculator.go):
 *        - `trustScore` (0..1) is the continuous registry trust *input*.
 *        - `trustLevel` (0..4 ordinal: Blocked, Warning, Listed, Scanned,
 *          Verified) is DERIVED from `trustScore` PLUS hard gates — a
 *          critical finding forces Blocked(0), behavioral/high-sev forces
 *          Warning(1), and Verified(4) additionally requires SLSA L2+,
 *          30+ days observation, and a verified signature. So a package
 *          can have a high `trustScore` and still a low `trustLevel`.
 *        - `verdict` is the string label of `trustLevel`
 *          (0→"blocked", 1→"warning", 2→"listed", 3→"scanned", 4→"verified")
 *          — the genuine redundant pair is `verdict` ↔ `trustLevel`.
 *
 *   3. REGISTRY-SCAN-STATE axis — `scanStatus`. Whether the *registry's*
 *      server-side scan has run (`pending`, `completed`, `warnings`,
 *      `failed`, …). `scanStatus: "pending"` alongside `score: 100` is
 *      not a contradiction: the local scan ran (hence the score), the
 *      registry's has not (hence pending).
 *
 * ## Which field do I gate CI on?
 *
 *   - "Did my local static checks pass on this artifact?" → gate on
 *     `score` / `maxScore` (and inspect `findings`). Only meaningful when
 *     `source === "local-scan"`.
 *   - "Does the registry trust this package?" → gate on `trustLevel`
 *     (or equivalently `verdict`). Prefer it over a raw `trustScore`
 *     threshold: `trustLevel` folds in hard security gates (critical
 *     findings, signature, SLSA, observation window) that a bare score
 *     cutoff would miss — a package with `trustScore: 0.9` can still be
 *     `trustLevel: 0` (Blocked) on a critical finding. Present only when
 *     registry data was found.
 *   - Do NOT treat `score: 100` as a trust signal, and do NOT compare a
 *     0..100 `score` against a 0..1 `trustScore`.
 *
 * ## 1.0.0 migration (deferred breaking change — CHIEF-CA + CHIEF-CPO)
 *
 * The flat object lumps both layers together, which is the root of the
 * ambiguity. The 1.0.0 restructure namespaces them:
 *
 *   { localScan: { score, maxScore, findings, … },
 *     registry:  { trustScore, trustLevel, verdict, scanStatus, … } }
 *
 * Whether to keep both `verdict` and `trustLevel` (string vs ordinal of
 * one signal) is a separate 1.0.0 decision. Until then the wire shape is
 * frozen for the byte-equality parity contract and this guide is the contract.
 */

/** Which conceptual layer a field belongs to. */
export type CheckFieldSource = "meta" | "local-scan" | "registry";

/** Documentation for one field of the `check --json` output. */
export interface CheckFieldDoc {
  /** The conceptual axis this field belongs to (see module docs). */
  source: CheckFieldSource;
  /** Human description of what the field means. */
  description: string;
  /** The value's scale/domain, e.g. `"0..100"`, `"1..5 ordinal"`. */
  scale?: string;
  /** Whether a consumer should gate CI on this field, and for what question. */
  gating?: string;
}

/**
 * The canonical field guide. Every key `buildCheckOutput` can emit MUST
 * appear here — `check-json-schema.test.ts` asserts the two never drift.
 * Keys are listed in emission order (the byte-equality parity order).
 */
export const CHECK_FIELD_GUIDE: Record<string, CheckFieldDoc> = {
  name: {
    source: "meta",
    description: "The package / repo / resource the check ran against.",
  },
  type: {
    source: "meta",
    description: "The kind of target checked.",
    scale: '"npm-package" | "github-repo" | "pypi-package" | "skill"',
  },
  source: {
    source: "meta",
    description:
      "Which path produced this result. Determines which other fields are present.",
    scale: '"registry" | "local-scan" | "skill"',
    gating:
      'Branch on this first: `score` is only meaningful when source === "local-scan".',
  },
  projectType: {
    source: "local-scan",
    description: "Project type the local scanner detected (e.g. mcp-server).",
  },
  score: {
    source: "local-scan",
    description:
      "Local static-scan result. 100 = the local scan found nothing. NOT a registry trust verdict.",
    scale: "0..100",
    gating:
      'Gate on this for "did my local static checks pass". Only present when source === "local-scan".',
  },
  maxScore: {
    source: "local-scan",
    description: "Denominator for `score` (always 100 today; kept for forward-compat).",
    scale: "0..100",
  },
  findings: {
    source: "local-scan",
    description: "Local-scan findings array. Empty when the scan found nothing.",
  },
  version: {
    source: "local-scan",
    description: "Resolved version of the scanned artifact, when known.",
  },
  trustLevel: {
    source: "registry",
    description:
      "Canonical registry trust ordinal (Blocked, Warning, Listed, Scanned, Verified). Derived from trustScore PLUS hard gates (critical findings, behavioral violations, SLSA level, signature, observation window) — so it can be low even when trustScore is high.",
    scale: "0..4 ordinal",
    gating:
      'Gate on this for "does the registry trust this package" — it folds in hard security gates a raw trustScore threshold would miss. Present only when registry data was found.',
  },
  trustScore: {
    source: "registry",
    description:
      "Continuous registry trust score — the INPUT that (with hard gates) yields trustLevel. Not a standalone gate: a high trustScore does not imply a high trustLevel.",
    scale: "0..1",
    gating:
      "Prefer trustLevel for gating. Use trustScore only for a finer-grained continuous threshold, and never alone.",
  },
  verdict: {
    source: "registry",
    description:
      'String label of trustLevel ("blocked"/"warning"/"listed"/"scanned"/"verified") — the same signal as trustLevel, in words.',
  },
  scanStatus: {
    source: "registry",
    description:
      "State of the registry's server-side scan (pending, completed, warnings, failed). Orthogonal to the local `score`.",
  },
  packageType: {
    source: "registry",
    description: "Registry's classification of the package.",
  },
  lastScannedAt: {
    source: "registry",
    description: "ISO timestamp of the registry's most recent scan, when available.",
  },
  communityScans: {
    source: "registry",
    description: "Count of community-contributed scans the registry has aggregated.",
  },
  cveCount: {
    source: "registry",
    description: "Number of known CVEs the registry associates with the package.",
  },
  analystFindings: {
    source: "local-scan",
    description: "Optional NanoMind analyst annotations layered on the local scan.",
  },
  narrative: {
    source: "meta",
    description:
      "Optional rich-context narrative (skill + mcp v1). Always the last key so byte-equality holds when absent.",
  },
};

/**
 * JSON Schema (draft-07) for the `check --json` found-result object.
 * Mechanically derivable from CHECK_FIELD_GUIDE — exported so machine
 * consumers can validate payloads and read the per-field guidance from
 * `description`.
 */
export const checkJsonSchema = {
  $schema: "http://json-schema.org/draft-07/schema#",
  $id: "https://opena2a.org/schemas/check-json.json",
  title: "check --json (found result)",
  description:
    "Output of `check <target> --json` when the target was found. Carries up to three orthogonal axes: local-scan (score/maxScore/findings), registry-trust (trustLevel/trustScore/verdict), and registry-scan-state (scanStatus). See CHECK_FIELD_GUIDE for which field to gate CI on.",
  type: "object",
  required: ["name", "source"],
  additionalProperties: true,
  properties: Object.fromEntries(
    Object.entries(CHECK_FIELD_GUIDE).map(([field, doc]) => [
      field,
      {
        description: `[${doc.source}] ${doc.description}${doc.scale ? ` (scale: ${doc.scale})` : ""}${doc.gating ? ` Gating: ${doc.gating}` : ""}`,
      },
    ]),
  ),
} as const;
