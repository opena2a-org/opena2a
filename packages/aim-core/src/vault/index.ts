// Vault module — identity-native encrypted credential storage
//
// CR-001: credential never in agent context
// CR-005: zero plaintext on disk
// CR-006: fail closed

// Types
export type {
  VaultNamespace,
  VaultFile,
  EncryptedBlob,
  VaultResolutionRequest,
  VaultResolutionResult,
  VaultAuditEvent,
  VaultAuditEventInput,
  VaultAuditReadOptions,
  VaultOperation,
  NamespaceStatus,
  VaultAuditOperation,
} from './types';

// Crypto
export {
  ed25519PublicKeyToX25519,
  ed25519SecretKeyToX25519,
  deriveVaultKey,
  generateEphemeralKeypair,
  encrypt,
  decrypt,
  zeroize,
} from './crypto';

// Store
export { VaultStore } from './store';

// Namespaces
export {
  createNamespace,
  listNamespaces,
  getNamespace,
  updateNamespace,
  revokeNamespace,
  type CreateNamespaceOptions,
  type UpdateNamespaceOptions,
} from './namespaces';

// Audit
export { logVaultEvent, readVaultAudit } from './audit';

// Resolution
export {
  createResolutionRequest,
  resolveWithPolicy,
  type ResolutionContext,
} from './resolution';
