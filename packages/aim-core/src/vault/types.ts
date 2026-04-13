/** Status of a vault namespace */
export type NamespaceStatus = 'active' | 'revoked';

/** Operations a namespace credential can be used for */
export type VaultOperation = 'read' | 'write' | 'delete' | 'admin';

/** A namespace groups credentials by service/purpose */
export interface VaultNamespace {
  /** Unique namespace identifier (e.g., "github", "aws-prod") */
  id: string;
  /** Human-readable description */
  description: string;
  /** Agent ID that owns this namespace */
  agentId: string;
  /** Allowed operations */
  operations: VaultOperation[];
  /** URL patterns this namespace applies to (e.g., "https://api.github.com/*") */
  urlPatterns: string[];
  /** Current status */
  status: NamespaceStatus;
  /** ISO timestamp of creation */
  createdAt: string;
  /** ISO timestamp of last update */
  updatedAt: string;
}

/** Encrypted credential blob stored on disk or in backend */
export interface EncryptedBlob {
  /** XSalsa20-Poly1305 ciphertext (base64) */
  ciphertext: string;
  /** 24-byte nonce (base64) */
  nonce: string;
  /** Encryption algorithm identifier */
  algorithm: 'xsalsa20-poly1305';
  /** Credential version (incremented on rotation) */
  version: number;
  /** ISO timestamp of encryption */
  encryptedAt: string;
}

/** On-disk vault file structure */
export interface VaultFile {
  /** Format version for forward compatibility */
  formatVersion: 1;
  /** Agent ID that owns this vault */
  agentId: string;
  /** Ephemeral X25519 public key used to derive vault key (base64) */
  ephemeralPublicKey: string;
  /** Per-namespace encrypted credential blobs */
  credentials: Record<string, EncryptedBlob>;
  /** ISO timestamp of vault creation */
  createdAt: string;
  /** ISO timestamp of last modification */
  updatedAt: string;
}

/** Request to resolve a credential from the vault */
export interface VaultResolutionRequest {
  /** Namespace to resolve */
  namespace: string;
  /** Requested operation */
  operation: VaultOperation;
  /** Ed25519 signature over `namespace|operation|nonce` (base64) */
  signature: string;
  /** Unique nonce to prevent replay (ISO timestamp + random) */
  nonce: string;
  /** Agent ID making the request */
  agentId: string;
}

/** Result of a credential resolution */
export interface VaultResolutionResult {
  /** Whether resolution succeeded */
  success: boolean;
  /** Decrypted credential value (only present on success, must be zeroized after use) */
  credential?: Uint8Array;
  /** Error message on failure */
  error?: string;
  /** Namespace that was resolved */
  namespace: string;
  /** Credential version that was resolved */
  version?: number;
}

/** Vault-specific audit event */
export interface VaultAuditEvent {
  /** ISO timestamp */
  timestamp: string;
  /** Agent ID that triggered the event */
  agentId: string;
  /** Namespace involved (if applicable) */
  namespace?: string;
  /** Operation type */
  operation: VaultAuditOperation;
  /** Whether the operation succeeded */
  result: 'granted' | 'denied' | 'error';
  /** Reason for denial (if denied) */
  denyReason?: string;
  /** Additional context */
  metadata?: Record<string, unknown>;
}

/** Vault audit operation types */
export type VaultAuditOperation =
  | 'resolve'
  | 'store'
  | 'rotate'
  | 'delete'
  | 'revoke'
  | 'namespace:create'
  | 'namespace:update'
  | 'namespace:revoke'
  | 'vault:init'
  | 'vault:destroy';

/** Input for logging a vault audit event (timestamp added automatically) */
export type VaultAuditEventInput = Omit<VaultAuditEvent, 'timestamp'>;

/** Options for reading vault audit events */
export interface VaultAuditReadOptions {
  /** Maximum number of events to return */
  limit?: number;
  /** Only return events after this ISO timestamp */
  since?: string;
  /** Filter by namespace */
  namespace?: string;
}
