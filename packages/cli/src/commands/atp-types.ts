/**
 * Agent Trust Protocol (ATP) types.
 * TypeScript interfaces for the public trust lookup and claim APIs
 * on the OpenA2A Registry.
 */

// --- Trust Lookup ---

export interface TrustPosture {
  hardeningPassRate: number;
  oasbCompliance: number;
  soulConformance: string;
  attackSurfaceRisk: string;
  supplyChainHealth: number;
  a2asCertified: boolean;
}

export interface TrustFactors {
  verification: number;
  uptime: number;
  actionSuccess: number;
  securityAlerts: number;
  compliance: number;
  age: number;
  drift: number;
  feedback: number;
}

/**
 * The lookup maps the Registry's live trust level onto these strings. Its
 * Warning and Listed levels both arrive as 'discovered'; Blocked arrives as
 * 'blocked'.
 */
export type TrustLevel = 'blocked' | 'discovered' | 'scanned' | 'claimed' | 'verified' | 'certified';

export interface SupplyChainInfo {
  totalDependencies?: number;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  mediumVulnerabilities?: number;
  lowVulnerabilities?: number;
  /**
   * Not a package publish date. For a package the lookup answers from
   * `registry_packages`, the Registry fills it from `latest_published_at`, the
   * time the Registry created its latest version record; the response does not
   * say which column it came from, so `trust` does not print it.
   */
  lastPublished?: string;
  maintainerCount: number;
  weeklyDownloads?: number;
}

/**
 * `status` is `not_scanned` when the Registry has no scan on record, the
 * latest version's scan status (`passed`, `warnings`, `failed`, `scanning`,
 * `error`) when it has one, or `clean`, `warnings` or `critical` from the
 * package's known-vulnerability counts.
 */
export interface ScanSummary {
  status: string;
  lastScannedAt?: string;
  findingsCount?: number;
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
  actionRequired?: string;
}

export interface TrustLookupResponse {
  agentId: string;
  name: string;
  source: string;
  version: string;
  publisher: string;
  publisherVerified: boolean;
  trustScore: number;
  trustLevel: TrustLevel;
  packageType?: string;
  displayType?: string;
  description?: string;
  repositoryUrl?: string;
  posture?: TrustPosture;
  factors?: TrustFactors;
  capabilities?: string[];
  supplyChain?: SupplyChainInfo;
  scanSummary?: ScanSummary;
  lastScanned?: string;
  profileUrl: string;
}

// --- Claim ---

export interface OwnershipProof {
  method: 'npm' | 'github' | 'pypi';
  /** npm: username, github: owner/repo, pypi: token prefix */
  identity: string;
  /** Opaque proof payload (varies by method) */
  evidence: string;
}

export interface ClaimRequest {
  agentId: string;
  proof: OwnershipProof;
  publicKey: string;
}

export interface ClaimResponse {
  success: boolean;
  agentId: string;
  previousTrustLevel: TrustLevel;
  newTrustLevel: TrustLevel;
  previousTrustScore: number;
  newTrustScore: number;
  profileUrl: string;
  error?: string;
}
