/** Type declarations for optional dependency: @opena2a/aim-core */
declare module '@opena2a/aim-core' {
  interface IdentityOptions {
    agentName: string;
    dataDir?: string;
  }
  interface Identity {
    publicKey: string;
    agentId: string;
  }
  interface EventOptions {
    type: string;
    agent: string;
    detail?: Record<string, unknown>;
  }
  export function getOrCreateIdentity(options: IdentityOptions): Identity;
  export function createIdentity(agentName: string): Identity;
  export function logEvent(options: EventOptions): void;
}
