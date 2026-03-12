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

export type TrustLevel = 'discovered' | 'scanned' | 'claimed' | 'verified' | 'certified';

export interface SupplyChainInfo {
  totalDependencies: number;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  lastPublished: string;
  maintainerCount: number;
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
  posture?: TrustPosture;
  factors?: TrustFactors;
  capabilities?: string[];
  supplyChain?: SupplyChainInfo;
  lastScanned: string;
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
