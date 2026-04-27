/**
 * Canonical types for the `check` flow.
 *
 * These are the shapes that every OpenA2A CLI agrees on when emitting a
 * `check --json` result. Extras may be layered on top by a specific CLI
 * (see the `may_differ` section of opena2a-parity's contracts) but the
 * fields declared here are the cross-CLI invariant.
 */
import type { PackageNarrative } from "./narrative.js";

/**
 * Structural subset of the Registry's TrustAnswer (see
 * `@opena2a/registry-client`). Duplicated here so check-core stays lean
 * at the type level — consumers pass a compatible object, nothing more.
 */
export interface TrustData {
  found: boolean;
  name: string;
  trustScore: number;
  trustLevel: number;
  verdict: string;
  scanStatus?: string;
  lastScannedAt?: string;
  packageType?: string;
  recommendation?: string;
  cveCount?: number;
  communityScans?: number;
  dependencies?: {
    totalDeps?: number;
    vulnerableDeps?: number;
    minTrustLevel?: number;
    riskSummary?: Record<string, unknown>;
  };
}

/**
 * A generic local-scan result. Each CLI ships its own finding shape; the
 * orchestrator is shape-agnostic below the top-level score/max/findings
 * triple.
 */
export interface ScanResult {
  projectType?: string;
  score: number;
  maxScore: number;
  findings: unknown[];
  analystFindings?: Array<Record<string, unknown>>;
  version?: string;
}

/**
 * A skill-resolver result — HMA's `@anthropic/code-review` fallback path.
 * ai-trust and opena2a-cli do not inject a skill adapter in 0.1.0
 * (skill handling is HMA-only per F4 of the check-command-divergence brief).
 */
export interface SkillResult {
  name: string;
  [key: string]: unknown;
}

export type ScanAdapter = (target: string) => Promise<ScanResult>;
export type SkillAdapter = (target: string) => Promise<SkillResult | null>;
export type RegistryAdapter = (
  target: string,
  type?: string,
) => Promise<TrustData>;

export type PackageEcosystem = "npm" | "pypi" | "github" | "local" | "url" | "unknown";
export type PackageTarget = "npm-package" | "github-repo" | "pypi-package" | "skill";

/**
 * Classifier output for a raw `check <target>` argument.
 */
export interface ParsedCheckInput {
  /** The original user-provided string. */
  raw: string;
  /** Ecosystem inferred from shape. */
  ecosystem: PackageEcosystem;
  /** Normalized package/resource name (e.g. `pip:requests` → `requests`). */
  normalizedName: string;
  /** True when the shape looks like a git shorthand (`user/repo`) that
   * npm's downloader will try to clone (F3 of the divergence brief). */
  isGitShorthand: boolean;
  /** True when the raw input had the `@scope/` npm prefix. */
  isScoped: boolean;
}

/**
 * Input to the high-level `checkPackage` orchestrator.
 */
export interface CheckInput {
  /** Raw target (e.g. `@modelcontextprotocol/server-filesystem`). */
  target: string;
  /** registry-only = skip scan on miss; scan-on-miss = try scan adapter if
   * the registry says "not found". */
  mode: "registry-only" | "scan-on-miss";
  /** Package type filter forwarded to the registry (optional). */
  type?: string;
  /** Registry adapter — caller injects so the orchestrator stays HTTP-free. */
  registry: RegistryAdapter;
  /** Scan adapter — called on miss when mode = scan-on-miss. */
  scan?: ScanAdapter;
  /** Skill-fallback adapter — HMA-only in 0.1.0. */
  skillFallback?: SkillAdapter;
}

/**
 * Canonical `check` output. Emitted as JSON directly by each CLI's
 * `--json` path. Matches hackmyagent's buildCheckJsonOutput order so the
 * byte-equality parity contract holds.
 */
export interface CheckOutput {
  name: string;
  type?: PackageTarget;
  source: "registry" | "local-scan" | "skill";

  /** Scan-sourced fields (present when scan data is attached). */
  projectType?: string;
  score?: number;
  maxScore?: number;
  findings?: unknown[];
  version?: string;

  /** Registry-sourced fields (present when registry.found === true). */
  trustLevel?: number;
  trustScore?: number;
  verdict?: string;
  scanStatus?: string;
  packageType?: string;
  lastScannedAt?: string;
  communityScans?: number;
  cveCount?: number;

  /** Optional analyst annotations from NanoMind. */
  analystFindings?: Array<Record<string, unknown>>;

  /**
   * Optional rich-context narrative (skill + mcp v1). Always emitted
   * AFTER `analystFindings` so the existing 0.1.0 byte-equality parity
   * contract holds when narrative is absent.
   *
   * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§4)
   *
   * Renderers that don't know about narrative ignore the field. cli-ui
   * 0.4.0 (session 3) introduces `renderCheckRichBlock` to consume it.
   */
  narrative?: PackageNarrative;
}

/**
 * Canonical `check` not-found output. Emitted as JSON on misses the
 * orchestrator couldn't recover (no skill fallback, no scan adapter,
 * or all adapters rejected).
 */
export interface NotFoundOutput {
  name: string;
  found: false;
  error?: string;
  errorHint?: string;
  suggestions?: string[];
  nextSteps?: string[];
  ecosystem?: PackageEcosystem;
}

/** Translator output — feeds renderNotFoundBlock. */
export interface TranslatedError {
  errorHint?: string;
  suggestions?: string[];
}
