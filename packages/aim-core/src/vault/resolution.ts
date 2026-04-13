/**
 * Vault credential resolution with policy enforcement.
 *
 * Implements the local vault resolution flow (simplified 8-step from the spec):
 * 1. Verify Ed25519 signature
 * 2. (ATC check — skipped in local-only mode)
 * 3. Load namespace, verify status + operation
 * 4. Check capability (vault:resolve:<namespace>)
 * 5. Retrieve encrypted blob from VaultStore
 * 6. Decrypt with vault key
 * 7. (Zeroize — caller responsibility)
 * 8. Write audit entry
 *
 * CR-001: credential never in agent context
 * CR-002: Ed25519 signature required
 * CR-003: capability check before release
 * CR-006: fail closed
 */

import * as nacl from 'tweetnacl';
import * as crypto from 'crypto';
import type {
  VaultResolutionRequest,
  VaultResolutionResult,
  VaultOperation,
} from './types';
import { VaultStore } from './store';
import { getNamespace } from './namespaces';
import { logVaultEvent } from './audit';

/** Maximum age of a nonce before it's considered stale (30 seconds) */
const NONCE_MAX_AGE_MS = 30_000;

/**
 * Create a signed resolution request.
 *
 * The agent signs `namespace|operation|nonce` with its Ed25519 secret key.
 * This proves the resolution request came from the agent that owns the vault.
 */
export function createResolutionRequest(
  namespace: string,
  operation: VaultOperation,
  agentId: string,
  edSecretKey: Uint8Array
): VaultResolutionRequest {
  const nonce = new Date().toISOString() + '.' + crypto.randomBytes(8).toString('hex');
  const message = `${namespace}|${operation}|${nonce}`;
  const messageBytes = new TextEncoder().encode(message);
  const signature = nacl.sign.detached(messageBytes, edSecretKey);

  return {
    namespace,
    operation,
    signature: Buffer.from(signature).toString('base64'),
    nonce,
    agentId,
  };
}

export interface ResolutionContext {
  /** Vault directory path */
  vaultDir: string;
  /** Unlocked VaultStore instance */
  store: VaultStore;
  /** Agent's Ed25519 public key (32 bytes) */
  edPublicKey: Uint8Array;
  /** Capability checker: returns true if the agent has the required capability */
  checkCapability?: (capability: string) => boolean;
}

/**
 * Resolve a credential with full policy enforcement.
 *
 * Performs the local vault resolution flow:
 * 1. Verify Ed25519 signature over request payload
 * 2. Check nonce freshness (replay protection)
 * 3. Load namespace, verify active + operation allowed
 * 4. Check capability if checker provided
 * 5. Decrypt credential from vault
 * 6. Log audit event (always — success or failure)
 *
 * @returns VaultResolutionResult with decrypted credential on success.
 *          Caller MUST zeroize the credential after use.
 */
export function resolveWithPolicy(
  request: VaultResolutionRequest,
  context: ResolutionContext
): VaultResolutionResult {
  const { vaultDir, store, edPublicKey, checkCapability } = context;

  // Step 1: Verify Ed25519 signature (CR-002)
  const message = `${request.namespace}|${request.operation}|${request.nonce}`;
  const messageBytes = new TextEncoder().encode(message);
  const signatureBytes = new Uint8Array(Buffer.from(request.signature, 'base64'));

  const signatureValid = nacl.sign.detached.verify(messageBytes, signatureBytes, edPublicKey);
  if (!signatureValid) {
    logVaultEvent(vaultDir, {
      agentId: request.agentId,
      namespace: request.namespace,
      operation: 'resolve',
      result: 'denied',
      denyReason: 'invalid Ed25519 signature',
    });
    return {
      success: false,
      error: 'Invalid signature',
      namespace: request.namespace,
    };
  }

  // Step 2: Nonce freshness check (replay protection)
  const nonceParts = request.nonce.split('.');
  const nonceTimestamp = nonceParts.slice(0, -1).join('.');
  const nonceAge = Date.now() - new Date(nonceTimestamp).getTime();
  if (nonceAge > NONCE_MAX_AGE_MS || nonceAge < -NONCE_MAX_AGE_MS) {
    logVaultEvent(vaultDir, {
      agentId: request.agentId,
      namespace: request.namespace,
      operation: 'resolve',
      result: 'denied',
      denyReason: 'stale nonce (replay protection)',
    });
    return {
      success: false,
      error: 'Stale nonce — request expired or replayed',
      namespace: request.namespace,
    };
  }

  // Step 3: Load namespace, verify status + operation
  const ns = getNamespace(vaultDir, request.namespace);
  if (!ns) {
    logVaultEvent(vaultDir, {
      agentId: request.agentId,
      namespace: request.namespace,
      operation: 'resolve',
      result: 'denied',
      denyReason: 'namespace not found',
    });
    return {
      success: false,
      error: `Namespace "${request.namespace}" not found`,
      namespace: request.namespace,
    };
  }

  if (ns.status === 'revoked') {
    logVaultEvent(vaultDir, {
      agentId: request.agentId,
      namespace: request.namespace,
      operation: 'resolve',
      result: 'denied',
      denyReason: 'namespace revoked',
    });
    return {
      success: false,
      error: `Namespace "${request.namespace}" is revoked`,
      namespace: request.namespace,
    };
  }

  if (!ns.operations.includes(request.operation)) {
    logVaultEvent(vaultDir, {
      agentId: request.agentId,
      namespace: request.namespace,
      operation: 'resolve',
      result: 'denied',
      denyReason: `operation "${request.operation}" not allowed`,
    });
    return {
      success: false,
      error: `Operation "${request.operation}" not allowed for namespace "${request.namespace}"`,
      namespace: request.namespace,
    };
  }

  // Step 4: Capability check (CR-003)
  if (checkCapability) {
    const requiredCapability = `vault:resolve:${request.namespace}`;
    if (!checkCapability(requiredCapability)) {
      logVaultEvent(vaultDir, {
        agentId: request.agentId,
        namespace: request.namespace,
        operation: 'resolve',
        result: 'denied',
        denyReason: `missing capability "${requiredCapability}"`,
      });
      return {
        success: false,
        error: `Missing capability: ${requiredCapability}`,
        namespace: request.namespace,
      };
    }
  }

  // Step 5 + 6: Decrypt credential (CR-006: fail closed)
  let credential: Uint8Array;
  try {
    credential = store.resolveCredential(request.namespace);
  } catch (err) {
    logVaultEvent(vaultDir, {
      agentId: request.agentId,
      namespace: request.namespace,
      operation: 'resolve',
      result: 'error',
      denyReason: err instanceof Error ? err.message : 'unknown decryption error',
    });
    return {
      success: false,
      error: 'Failed to decrypt credential',
      namespace: request.namespace,
    };
  }

  // Step 8: Audit (success)
  const list = store.listCredentials();
  const credMeta = list.find((c) => c.namespace === request.namespace);

  logVaultEvent(vaultDir, {
    agentId: request.agentId,
    namespace: request.namespace,
    operation: 'resolve',
    result: 'granted',
    metadata: { version: credMeta?.version },
  });

  return {
    success: true,
    credential,
    namespace: request.namespace,
    version: credMeta?.version,
  };
}
