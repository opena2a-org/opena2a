export { RegistryClient, type RegistryClientOptions } from "./client.js";
export {
  PackageNotFoundError,
  RegistryApiError,
  type RegistryErrorCode,
} from "./errors.js";
export type {
  BatchResponse,
  DependencyInfo,
  DependencyRiskSummary,
  PackageQuery,
  PublishResponse,
  ScanFinding,
  ScanSubmission,
  TrustAnswer,
} from "./types.js";
export {
  FirstPartySigner,
  firstPartySignerFromEnv,
  decodeSecretKey,
  strongCanonical,
  type FirstPartyProvenance,
  type FirstPartySignerOptions,
  type SignableScan,
  type SignerFromEnvOptions,
  type PrivilegedSource,
  type ScanSource,
} from "./signer.js";
