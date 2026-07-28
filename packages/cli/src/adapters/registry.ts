import type { AdapterConfig, AdapterMethod } from './types.js';

/**
 * Environment contracts (#228) — what each delegated tool actually reads.
 *
 * Derived by scanning each installed package for its environment reads, not
 * guessed. `scan`/`secrets` are declared here even though they are `import`
 * adapters, because both fall through to the SpawnAdapter path (see
 * adapters/import.ts) and would otherwise run with the base allowlist alone.
 *
 * Credential names appear deliberately. Handing one credential to the one
 * child whose job requires it IS least privilege; the alternative is a
 * scanner that silently stops escalating and a broker that silently cannot
 * reach its vault.
 */

/** hackmyagent: classifier routing, analyst escalation, registry publish. */
const HACKMYAGENT_ENV = {
  envAllow: [
    'NANOMIND_URL', 'NANOMIND_GUARD_SOCK',
    'ANTHROPIC_API_KEY',
    'REGISTRY_URL', 'REGISTRY_API_KEY',
    'ATC_TOKEN', 'INTERNAL_API_KEY', 'CI_SCAN_HMAC_SECRET',
    'HMA_COMMUNITY_SECRET', 'HACKMYAGENT_LLM_BUDGET',
    'HMA_EXPORT_TRAINING', 'HMA_INTEGRITY_DEBUG',
    'ARP_TELEMETRY_DISABLED',
    'AWS_REGION', 'AWS_ACCOUNT_ID', 'NODE_ENV',
  ],
  envAllowPrefixes: ['HMA_'],
} as const;

/** secretless-ai: it is a credential broker; these ARE its inputs. */
const SECRETLESS_ENV = {
  envAllow: [
    'VAULT_ADDR', 'VAULT_TOKEN',
    'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
    'AWS_REGION', 'AWS_DEFAULT_REGION',
    'GOOGLE_APPLICATION_CREDENTIALS',
    'AIM_API_KEY',
  ],
} as const;

/** Node toolchain, for tools resolved through `npx`. */
const NODE_TOOL_ENV_PREFIXES = [
  'npm_config_', 'NPM_CONFIG_', 'NODE_',
  'NVM_', 'COREPACK_', 'YARN_', 'PNPM_', 'VOLTA_', 'FNM_',
] as const;

export const ADAPTER_REGISTRY: Record<string, AdapterConfig> = {
  scan: {
    name: 'scan',
    method: 'import',
    packageName: 'hackmyagent',
    subcommand: 'secure',
    description: 'Scan AI agent for security vulnerabilities (HackMyAgent)',
    // `secure` resolves the dead-end command HMA emits via HMA_CLI_PREFIX
    // substitution in scan output Next Steps (closes #135).
    aliases: ['secure'],
    ...HACKMYAGENT_ENV,
    envAllowPrefixes: [...HACKMYAGENT_ENV.envAllowPrefixes, ...NODE_TOOL_ENV_PREFIXES],
  },
  secrets: {
    name: 'secrets',
    method: 'import',
    packageName: 'secretless-ai',
    description: 'Manage credentials for AI coding tools (Secretless)',
    ...SECRETLESS_ENV,
    envAllowPrefixes: [...NODE_TOOL_ENV_PREFIXES],
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
    // `ai-trust check` emits JSON via a bare `--json` (not `--format json`),
    // so the router injects `--json` for `opena2a registry <pkg> --json` and
    // skips `--format` injection (which would crash with "unknown option
    // '--format'"). sarif is unsupported and surfaces a one-line note (#191).
    jsonOutputFlag: '--json',
    // ai-trust reads only OPENA2A_HOME, covered by the OPENA2A_ base prefix.
    envAllowPrefixes: [...NODE_TOOL_ENV_PREFIXES],
  },
  train: {
    name: 'train',
    method: 'docker',
    image: 'opena2a/dvaa',
    ports: ['3001-3008:3001-3008', '3010-3013:3010-3013', '3020-3021:3020-3021', '9000:9000'],
    description: 'Launch vulnerable AI agent for training (DVAA)',
    // Docker CLIENT configuration only. `docker run` here passes no -e/--env-file,
    // so the container never receives the parent environment either way.
    envAllow: ['DOCKER_HOST', 'DOCKER_CONFIG', 'DOCKER_CONTEXT', 'DOCKER_CERT_PATH',
      'DOCKER_TLS_VERIFY', 'DOCKER_API_VERSION', 'CONTAINER_HOST', 'CONTAINER_SSHKEY',
      'COLIMA_HOME', 'SSH_AUTH_SOCK'],
    envAllowPrefixes: ['DOCKER_', 'BUILDKIT_', 'COMPOSE_', 'PODMAN_'],
  },
  crypto: {
    name: 'crypto',
    method: 'python',
    pythonModule: 'cryptoserve',
    description: 'Cryptographic inventory and PQC readiness (CryptoServe)',
    envAllow: ['VIRTUAL_ENV'],
    envAllowPrefixes: ['PYTHON', 'PIP_', 'PIPX_', 'PYENV_', 'CONDA_', 'POETRY_', 'UV_'],
  },
  // identity is now handled directly by packages/cli/src/commands/identity.ts
  // guard is now handled directly by packages/cli/src/commands/guard.ts (ConfigGuard)
  broker: {
    name: 'broker',
    method: 'import',
    packageName: 'secretless-ai',
    subcommand: 'broker',
    description: 'Identity-aware credential broker daemon',
    ...SECRETLESS_ENV,
    envAllowPrefixes: [...NODE_TOOL_ENV_PREFIXES],
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
