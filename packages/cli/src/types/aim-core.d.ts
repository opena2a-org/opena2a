/** Type declarations for optional dependency: @opena2a/aim-core */
declare module '@opena2a/aim-core' {
  interface AIMCoreOptions {
    agentName: string;
    dataDir?: string;
    serverUrl?: string;
  }

  interface AIMIdentity {
    agentId: string;
    publicKey: string;
    agentName: string;
    createdAt: string;
  }

  interface AuditEvent {
    timestamp: string;
    plugin: string;
    action: string;
    target: string;
    result: 'allowed' | 'denied' | 'error';
    metadata?: Record<string, unknown>;
  }

  interface AuditReadOptions {
    limit?: number;
    since?: string;
  }

  interface TrustScore {
    overall: number;
    score: number;
    grade: string;
    factors: Record<string, number>;
    calculatedAt: string;
  }

  export class AIMCore {
    constructor(options: AIMCoreOptions);
    getIdentity(): AIMIdentity;
    getOrCreateIdentity(): AIMIdentity;
    loadPolicy(inline?: { allow?: string[]; deny?: string[]; default?: 'allow' | 'deny' }): unknown;
    checkCapability(capability: string, plugin?: string): boolean;
    logEvent(event: Record<string, unknown>): AuditEvent;
    readAuditLog(options?: AuditReadOptions): AuditEvent[];
    calculateTrust(): TrustScore;
    sign(data: Uint8Array): Uint8Array;
    verify(data: Uint8Array, signature: Uint8Array, publicKey: Uint8Array | string): boolean;
    getDataDir(): string;
  }

  export function getOrCreateIdentity(dataDirOrOptions: string | { agentName: string; dataDir?: string }, agentName?: string): AIMIdentity;
  export function createIdentity(dataDirOrName: string, agentName?: string): AIMIdentity;
  export function logEvent(dataDirOrEvent: string | Record<string, unknown>, event?: Record<string, unknown>): AuditEvent;
}
