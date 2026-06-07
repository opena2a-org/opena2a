export interface TrustAnswer {
  packageId?: string;
  name: string;
  type?: string;
  packageType?: string;
  trustLevel: number;
  trustScore: number;
  verdict: string;
  scanStatus?: string;
  communityScans?: number;
  cveCount?: number;
  recommendation?: string;
  dependencies?: DependencyInfo;
  confidence?: number;
  lastScannedAt?: string;
  found: boolean;
}

export interface DependencyRiskSummary {
  blocked: number;
  warning: number;
  safe: number;
}

export interface DependencyInfo {
  direct?: number;
  transitive?: number;
  totalDeps: number;
  vulnerableDeps: number;
  minTrustLevel: number;
  minTrustScore: number;
  maxDepth: number;
  riskSummary?: DependencyRiskSummary;
}

export interface BatchResponse {
  results: TrustAnswer[];
  meta: {
    total: number;
    found: number;
    notFound: number;
  };
}

export interface PackageQuery {
  name: string;
  type?: string;
  ecosystem?: "npm" | "pypi";
}

export interface ScanFinding {
  checkId: string;
  name: string;
  severity: string;
  passed: boolean;
  message: string;
  category?: string;
  attackClass?: string;
}

export interface ScanSubmission {
  name: string;
  /**
   * Package version. Bound by the first-party signature (it is part of the strong
   * canonical), so it MUST match what is sent in the body. Omit for unversioned scans.
   */
  version?: string;
  score: number;
  maxScore: number;
  findings: ScanFinding[];
  tool: string;
  toolVersion: string;
  type?: string;
  projectType?: string;
  ecosystem?: string;
  verdict?: string;
  scanTimestamp: string;
  durationMs?: number;
  signature?: string;
  publicKey?: string;
  /**
   * Provenance class. Privileged values (first_party_scanner|ci|partner) are honored by
   * the registry ONLY when the publish is first-party-signed (source/nonce/signedAt bound
   * by the signature). Anything else, or an unsigned privileged claim, is recorded as
   * community (fail-closed). Omit for organic community scans.
   */
  source?: string;
  /** Single-use anti-replay nonce, set by the first-party signer. */
  nonce?: string;
  /** Unix time in seconds at signing, set by the first-party signer. */
  signedAt?: number;
}

export interface PublishResponse {
  accepted: boolean;
  publishId?: string;
  packageId?: string | null;
  consensusStatus?: string;
  weight?: number;
  idempotent?: boolean;
}
