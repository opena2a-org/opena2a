export const VERSION = '0.2.0';

// Re-export all types
export type {
  AIMCoreOptions,
  AIMIdentity,
  StoredIdentity,
  AuditEvent,
  AuditEventInput,
  AuditReadOptions,
  CapabilityPolicy,
  CapabilityRule,
  TrustScore,
  TrustFactors,
  TrustHints,
} from './types';

// Re-export module functions for advanced usage
export { sign, verify } from './crypto';
export { createIdentity, loadIdentity, getOrCreateIdentity } from './identity';
export { logEvent, readAuditLog, hasAuditLog } from './audit';
export { loadPolicy, savePolicy, checkCapability, hasPolicy } from './policy';
export { calculateTrust } from './trust';

// DLP module
export {
  scanText,
  maskMetadata,
  ALL_PATTERNS,
  PII_PATTERNS,
  SECRET_PATTERNS,
  mask,
  maskAll,
  getDLPAction,
  defaultDLPPolicy,
  type DLPPattern,
  type DLPMatch,
  type DLPScanResult,
  type DLPPolicy,
} from './dlp';

// Server reporter
export { AIMServerReporter, type ReporterOptions } from './reporter';

// Event aggregation
export { EventAggregator } from './aggregator';

// Vault module — identity-native encrypted credential storage
export * as vault from './vault';

// --- Imports for AIMCore ---
import type {
  AIMCoreOptions,
  AIMIdentity,
  AuditEvent,
  AuditEventInput,
  AuditReadOptions,
  CapabilityPolicy,
  TrustScore,
  TrustHints,
} from './types';

import * as identity from './identity';
import * as audit from './audit';
import * as policy from './policy';
import * as trust from './trust';
import * as crypto from './crypto';
import { AIMServerReporter } from './reporter';
import { EventAggregator } from './aggregator';
import { VaultStore } from './vault/store';

/**
 * Main entry point for aim-core.
 *
 * Provides Ed25519 identity, local audit logging, capability policy enforcement,
 * trust scoring, and cryptographic signing — all without a server or database.
 */
export class AIMCore {
  private readonly agentName: string;
  private readonly dataDir: string;
  private readonly serverUrl: string;
  private cachedPolicy: CapabilityPolicy | null = null;
  private trustHints: TrustHints = {};
  private reporter: AIMServerReporter | null = null;
  private aggregator: EventAggregator | null = null;

  constructor(options: AIMCoreOptions) {
    this.agentName = options.agentName;
    this.dataDir = options.dataDir ?? this.defaultDataDir();
    this.serverUrl = options.serverUrl ?? '';
  }

  /** Get or create the agent's Ed25519 identity */
  getIdentity(): AIMIdentity {
    return identity.getOrCreateIdentity(this.dataDir, this.agentName);
  }

  /** Alias for getIdentity() — matches documented API */
  getOrCreateIdentity(): AIMIdentity {
    return this.getIdentity();
  }

  /** Check if a capability is allowed by the current policy */
  checkCapability(capability: string, plugin?: string): boolean {
    if (!this.cachedPolicy) {
      this.cachedPolicy = policy.loadPolicy(this.dataDir);
    }
    return policy.checkCapability(this.cachedPolicy, capability, plugin);
  }

  /** Load capability policy from YAML file or inline shorthand */
  loadPolicy(inline?: { allow?: string[]; deny?: string[]; default?: 'allow' | 'deny' }): CapabilityPolicy {
    if (inline) {
      const rules: import('./types').CapabilityRule[] = [];
      if (inline.allow) {
        for (const cap of inline.allow) {
          rules.push({ capability: cap, action: 'allow' });
        }
      }
      if (inline.deny) {
        for (const cap of inline.deny) {
          rules.push({ capability: cap, action: 'deny' });
        }
      }
      this.cachedPolicy = {
        version: '1',
        defaultAction: inline.default ?? 'deny',
        rules,
      };
    } else {
      this.cachedPolicy = policy.loadPolicy(this.dataDir);
    }
    return this.cachedPolicy;
  }

  /** Save a capability policy to YAML file */
  savePolicy(p: CapabilityPolicy): void {
    policy.savePolicy(this.dataDir, p);
    this.cachedPolicy = p;
  }

  /** Log an audit event to the local JSON-lines file and route to reporter */
  logEvent(event: AuditEventInput & { outcome?: 'allowed' | 'denied' | 'error' }): AuditEvent {
    // Accept 'outcome' as alias for 'result'
    if (!event.result && event.outcome) {
      event.result = event.outcome;
    }
    // Default plugin to 'unknown' if omitted
    if (!event.plugin) {
      (event as AuditEventInput).plugin = 'unknown';
    }
    const logged = audit.logEvent(this.dataDir, event);

    // Route to aggregator → reporter pipeline if enabled
    if (this.aggregator) {
      this.aggregator.add(event);
    } else if (this.reporter) {
      this.reporter.enqueue(logged);
    }

    return logged;
  }

  /** Read audit events from local log */
  readAuditLog(options?: AuditReadOptions): AuditEvent[] {
    return audit.readAuditLog(this.dataDir, options);
  }

  /** Calculate the agent's trust score based on current state */
  calculateTrust(): TrustScore {
    const hasId = identity.loadIdentity(this.dataDir) !== null;
    return trust.calculateTrust(this.dataDir, hasId, this.trustHints);
  }

  /** Provide hints from plugins to improve trust score accuracy */
  setTrustHints(hints: TrustHints): void {
    this.trustHints = { ...this.trustHints, ...hints };
  }

  /** Sign data with the agent's Ed25519 private key */
  sign(data: Uint8Array): Uint8Array {
    const secretKey = identity.getSecretKey(this.dataDir);
    if (!secretKey) {
      throw new Error('No identity found. Call getIdentity() first to generate a keypair.');
    }
    return crypto.sign(data, secretKey);
  }

  /** Verify an Ed25519 signature against a public key (accepts base64 string or Uint8Array) */
  verify(data: Uint8Array, signature: Uint8Array, publicKey: Uint8Array | string): boolean {
    return crypto.verify(data, signature, publicKey);
  }

  /** Enable server reporting — batch POST audit events to AIM server */
  enableReporting(options?: { apiToken?: string; flushIntervalMs?: number }): void {
    if (!this.serverUrl) {
      throw new Error('Cannot enable reporting without serverUrl in AIMCoreOptions');
    }

    const id = this.getIdentity();
    this.reporter = new AIMServerReporter({
      serverUrl: this.serverUrl,
      agentId: id.agentId,
      dataDir: this.dataDir,
      apiToken: options?.apiToken,
      flushIntervalMs: options?.flushIntervalMs,
    });
    this.reporter.start();
  }

  /** Enable event aggregation — summarize repeated events before reporting */
  enableAggregation(windowMs?: number): void {
    this.aggregator = new EventAggregator(windowMs);
    this.aggregator.setFlushHandler((events) => {
      for (const event of events) {
        this.reporter?.enqueue(event);
      }
    });
    this.aggregator.start();
  }

  /** Stop reporter and aggregator, flush remaining events */
  async shutdown(): Promise<void> {
    if (this.aggregator) {
      this.aggregator.stop();
      this.aggregator = null;
    }
    if (this.reporter) {
      await this.reporter.stop();
      this.reporter = null;
    }
  }

  /** Get the data directory path */
  getDataDir(): string {
    return this.dataDir;
  }

  /**
   * Get a VaultStore instance for this agent's vault.
   * The vault directory is at ~/.aim/vault/ (separate from the data dir).
   */
  getVault(): VaultStore {
    const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
    return new VaultStore(`${home}/.aim/vault`);
  }

  private defaultDataDir(): string {
    const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
    return `${home}/.opena2a/aim-core`;
  }
}
