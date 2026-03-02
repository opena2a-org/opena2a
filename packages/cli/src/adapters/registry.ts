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
  benchmark: {
    name: 'benchmark',
    method: 'import',
    packageName: 'hackmyagent',
    description: 'Run security benchmark against AI agent (OASB)',
  },
  registry: {
    name: 'registry',
    method: 'import',
    packageName: 'ai-trust',
    description: 'Query OpenA2A Trust Registry for package security data',
  },
  research: {
    name: 'research',
    method: 'spawn',
    command: 'hma-researcher',
    description: 'Autonomous security research agent (HMA Researcher)',
  },
  hunt: {
    name: 'hunt',
    method: 'spawn',
    command: 'hma-hunter',
    description: 'Autonomous vulnerability hunter (HMA Hunter)',
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
  identity: {
    name: 'identity',
    method: 'spawn',
    command: 'aim',
    description: 'Agent identity management (AIM SDK)',
  },
  // guard is now handled directly by packages/cli/src/commands/guard.ts (ConfigGuard)
  broker: {
    name: 'broker',
    method: 'import',
    packageName: 'secretless-ai',
    description: 'Identity-aware credential broker daemon',
  },
  dlp: {
    name: 'dlp',
    method: 'import',
    packageName: 'secretless-ai',
    description: 'Data loss prevention for AI tool transcripts',
  },
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
