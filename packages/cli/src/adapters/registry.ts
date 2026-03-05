import type { AdapterConfig, AdapterMethod } from './types.js';

export const ADAPTER_REGISTRY: Record<string, AdapterConfig> = {
  scan: {
    name: 'scan',
    method: 'import',
    packageName: 'hackmyagent',
    description: 'Scan AI agent for security vulnerabilities (HackMyAgent)',
  },
  secrets: {
    name: 'secrets',
    method: 'import',
    packageName: 'secretless-ai',
    description: 'Manage credentials for AI coding tools (Secretless)',
  },
  // runtime is now handled directly by packages/cli/src/commands/runtime.ts
  // benchmark is now handled directly by packages/cli/src/commands/benchmark.ts (programmatic API)
  // scan-soul and harden-soul are handled directly in commands/soul.ts (programmatic API)
  registry: {
    name: 'registry',
    method: 'spawn',
    command: 'ai-trust',
    packageName: 'ai-trust',
    subcommand: 'check',
    description: 'Query OpenA2A Trust Registry for package security data',
  },
  train: {
    name: 'train',
    method: 'docker',
    image: 'opena2a/dvaa',
    description: 'Launch vulnerable AI agent for training (DVAA)',
  },
  crypto: {
    name: 'crypto',
    method: 'python',
    pythonModule: 'cryptoserve',
    description: 'Cryptographic inventory and PQC readiness (CryptoServe)',
  },
  // identity is now handled directly by packages/cli/src/commands/identity.ts
  // guard is now handled directly by packages/cli/src/commands/guard.ts (ConfigGuard)
  broker: {
    name: 'broker',
    method: 'import',
    packageName: 'secretless-ai',
    subcommand: 'broker',
    description: 'Identity-aware credential broker daemon',
  },
  // dlp is not yet implemented in secretless-ai; removed to avoid confusing errors
};

export function getAdapter(name: string): AdapterConfig | undefined {
  return ADAPTER_REGISTRY[name];
}

export function listAdapters(): AdapterConfig[] {
  return Object.values(ADAPTER_REGISTRY);
}

export function getAdaptersByMethod(method: AdapterMethod): AdapterConfig[] {
  return Object.values(ADAPTER_REGISTRY).filter(a => a.method === method);
}
