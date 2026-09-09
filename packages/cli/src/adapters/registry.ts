import type { AdapterConfig, AdapterMethod } from './types.js';
import { buildChildEnv } from '../util/child-env.js';

/**
 * Environment contracts (#228, #246) — what each delegated tool actually reads.
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
 *
 * ---------------------------------------------------------------------------
 * ONE DECLARATION POINT, ONE RESOLVER (#246)
 * ---------------------------------------------------------------------------
 *
 * `CHILD_ENV_CONTRACTS` is keyed by the BINARY a child start runs, not by the
 * opena2a command that starts it, because the same binary is reached by
 * several routes: `hackmyagent` is started by the `scan` adapter, by the
 * direct `check` delegation in index.ts and router.ts, and by `review`'s
 * `npx hackmyagent secure`. Four routes, one contract — so every route hands
 * the scanner the same environment, and a name added for one route cannot be
 * missing from another.
 *
 * Every child start under src/ obtains its environment through one of three
 * resolvers, and nothing else:
 *
 *   childEnv(binary, { set })  the binary's declared contract over the base
 *                              allowlist, via buildChildEnv. Throws for a
 *                              binary with no contract — an undeclared child
 *                              is a declaration to write, not a default to
 *                              fall back on.
 *   inheritEnv()               the parent environment verbatim, minus the
 *                              `OPENA2A_CHILD_ENV_ALLOW` hatch, for the
 *                              `envInherit` exemption only.
 *   probeEnv(prefixes)         util/child-env.ts — availability probes, no
 *                              exact entries, hatch ignored.
 *
 * `__tests__/adapters/child-env-sites.test.ts` walks every child start under
 * src/ and fails on one whose `env:` is not a resolver call, unless the site
 * is on its implicit-inherit roster — which can only shrink.
 */

type EnvContract = Pick<AdapterConfig, 'envAllow' | 'envAllowPrefixes' | 'envInherit'>;

/** hackmyagent: classifier routing, analyst escalation, registry publish. */
const HACKMYAGENT_ENV = {
  envAllow: [
    'NANOMIND_URL', 'NANOMIND_GUARD_SOCK',
    'ANTHROPIC_API_KEY',
    'REGISTRY_URL', 'REGISTRY_API_KEY',
    'ATC_TOKEN', 'INTERNAL_API_KEY', 'CI_SCAN_HMAC_SECRET',
    // Read at narrative/publish-narrative.js:32. Matches the OPENA2A_ base
    // prefix but the guard blocks it on "token", so it needs an exact entry.
    // Without it the narrative POST goes out unauthenticated, gets 401, and
    // the publish still exits 0 — silent degradation.
    'OPENA2A_REGISTRY_TOKEN',
    'HMA_COMMUNITY_SECRET', 'HACKMYAGENT_LLM_BUDGET',
    'HMA_EXPORT_TRAINING', 'HMA_INTEGRITY_DEBUG',
    'ARP_TELEMETRY_DISABLED',
    'AWS_REGION', 'AWS_ACCOUNT_ID', 'NODE_ENV',
  ],
  envAllowPrefixes: ['HMA_'],
} as const satisfies EnvContract;

/**
 * secretless-ai: EXEMPT — the environment is this tool's input, and it reads
 * names it discovers at runtime, so no static list can express the contract.
 *
 *   verify.js:78          `envVars[envVar] = !!process.env[envVar]` over all
 *                         45 names in CREDENTIAL_PATTERNS
 *   init.js:360           builds the "Available API keys" table from whatever
 *                         is actually set
 *   broker/resolver.js:41 `process.env[credentialName]` — the broker's own
 *                         environment fallback
 *   phantom/resolver.js   `env:` references resolve via `process.env[path]`
 *   run.js:31             `opena2a secrets run -- <cmd>` spawns the USER's
 *                         command and is expected to pass their environment
 *
 * Allowlisting it makes `opena2a secrets verify` report a different machine
 * than `secretless-ai verify` — both exit 0, both print PASS, and they
 * disagree. That is the same cross-surface divergence this work exists to
 * prevent, so the honest answer is to declare the exemption rather than ship
 * a quietly wrong answer. Narrowing it means routing the env-enumerating
 * subcommands separately from the rest; tracked in #246.
 */
const SECRETLESS_ENV = { envInherit: true } as const satisfies EnvContract;

/** Node toolchain, for tools resolved through `npx`. */
const NODE_TOOL_ENV_EXACT = [
  // npm client-certificate auth is a trio; `npm_config_cert` and
  // `npm_config_cafile` clear the guard but `npm_config_key` does not, and
  // forwarding two of three fails the TLS handshake on an mTLS registry.
  'npm_config_key',
] as const;

const NODE_TOOL_ENV_PREFIXES = [
  'npm_config_', 'NPM_CONFIG_', 'NODE_',
  'NVM_', 'COREPACK_', 'YARN_', 'PNPM_', 'VOLTA_', 'FNM_',
] as const;

/**
 * claude (the Claude Code CLI, started by shield/llm-backend.ts for the
 * optional semantic pass): model credentials and endpoint selection.
 *
 * Exact entries are the credential names the guard would otherwise block on
 * a prefix match (`api_key`, `auth`, `token`, `bearer`). The prefixes carry
 * the non-credential configuration — model choice, endpoint, provider
 * switches such as `CLAUDE_CODE_USE_BEDROCK`, `AWS_REGION`/`AWS_PROFILE` —
 * and every prefix match still passes through the credential-name guard, so
 * an `AWS_SECRET_ACCESS_KEY` under `AWS_` reaches the child only if it is
 * added here as an exact entry, deliberately.
 */
const CLAUDE_ENV = {
  envAllow: [
    'ANTHROPIC_API_KEY',
    'ANTHROPIC_AUTH_TOKEN',
    'ANTHROPIC_BASE_URL',
    'AWS_BEARER_TOKEN_BEDROCK',
  ],
  envAllowPrefixes: ['ANTHROPIC_', 'CLAUDE_', 'CLAUDE_CODE_', 'AWS_'],
} as const satisfies EnvContract;

/**
 * docker: CLIENT configuration. `docker run` here passes no -e/--env-file, so
 * the container never receives the parent environment either way.
 * SSH_AUTH_SOCK is agent access, not client config — it is here only because
 * `DOCKER_HOST=ssh://user@host` is a documented remote-engine setup that
 * cannot authenticate without it.
 */
const DOCKER_ENV = {
  envAllow: ['DOCKER_HOST', 'DOCKER_CONFIG', 'DOCKER_CONTEXT', 'DOCKER_CERT_PATH',
    'DOCKER_TLS_VERIFY', 'DOCKER_API_VERSION', 'CONTAINER_HOST', 'CONTAINER_SSHKEY',
    'COLIMA_HOME', 'SSH_AUTH_SOCK'],
  envAllowPrefixes: ['DOCKER_', 'BUILDKIT_', 'COMPOSE_', 'PODMAN_'],
} as const satisfies EnvContract;

/** cryptoserve, run as `python3 -m cryptoserve`: interpreter and env discovery. */
const CRYPTOSERVE_ENV = {
  envAllow: ['VIRTUAL_ENV'],
  envAllowPrefixes: ['PYTHON', 'PIP_', 'PIPX_', 'PYENV_', 'CONDA_', 'POETRY_', 'UV_'],
} as const satisfies EnvContract;

/** ai-trust reads only OPENA2A_HOME, covered by the OPENA2A_ base prefix. */
const AI_TRUST_ENV = {
  envAllow: [...NODE_TOOL_ENV_EXACT],
  envAllowPrefixes: [...NODE_TOOL_ENV_PREFIXES],
} as const satisfies EnvContract;

/**
 * The single declaration point: one environment contract per binary opena2a
 * starts. Keyed by the binary name (what goes on the command line, or the
 * `npx <name>` it resolves), not by the opena2a command.
 */
export const CHILD_ENV_CONTRACTS: Readonly<Record<string, EnvContract>> = {
  // hackmyagent is resolved through `npx` on every route (the scan adapter's
  // fallback, `review`, and the direct spawns' not-installed fallback), so
  // the node toolchain entries are part of its contract rather than an
  // addition the scan adapter makes on its own.
  hackmyagent: {
    envAllow: [...HACKMYAGENT_ENV.envAllow, ...NODE_TOOL_ENV_EXACT],
    envAllowPrefixes: [...HACKMYAGENT_ENV.envAllowPrefixes, ...NODE_TOOL_ENV_PREFIXES],
  },
  claude: CLAUDE_ENV,
  'secretless-ai': SECRETLESS_ENV,
  'ai-trust': AI_TRUST_ENV,
  docker: DOCKER_ENV,
  cryptoserve: CRYPTOSERVE_ENV,
};

export interface ChildEnvOptions {
  /**
   * Values to set on the child, applied after the contract so they are
   * authoritative. `undefined` removes a name. The hatch variable can never
   * be reinstated this way (buildChildEnv strips it last).
   */
  set?: Readonly<Record<string, string | undefined>>;
}

function reportNotice(message: string): void {
  process.stderr.write(`${message}\n`);
}

/** Case-insensitive removal of the hatch, so it never reaches a grandchild. */
function stripHatch(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  for (const name of Object.keys(env)) {
    if (name.toLowerCase() === 'opena2a_child_env_allow') delete env[name];
  }
  return env;
}

/**
 * The parent environment, verbatim, minus `OPENA2A_CHILD_ENV_ALLOW`.
 *
 * This is the ONLY place under src/ that spreads `process.env` into a child,
 * and it exists for the `envInherit` exemption alone (`secretless-ai`, whose
 * input is the environment). The hatch is stripped for the same reason
 * buildChildEnv strips it: a widened child must not silently widen its own
 * children.
 */
export function inheritEnv(): NodeJS.ProcessEnv {
  return stripHatch({ ...process.env });
}

/**
 * The environment for a child running `binary`, from its declared contract.
 *
 * Throws for a binary with no entry in CHILD_ENV_CONTRACTS. Neither fallback
 * is acceptable: an empty environment breaks the child, a full one is the
 * leak this module exists to close, and both fail silently — so the missing
 * declaration fails loudly instead.
 */
export function childEnv(binary: string, options: ChildEnvOptions = {}): NodeJS.ProcessEnv {
  if (!Object.prototype.hasOwnProperty.call(CHILD_ENV_CONTRACTS, binary)) {
    throw new Error(
      `No child-environment contract is declared for "${binary}". ` +
      'Add an entry to CHILD_ENV_CONTRACTS in adapters/registry.ts.',
    );
  }
  const contract = CHILD_ENV_CONTRACTS[binary];

  if (contract.envInherit) {
    const out = inheritEnv();
    for (const [name, value] of Object.entries(options.set ?? {})) {
      if (value === undefined) delete out[name];
      else out[name] = value;
    }
    return stripHatch(out);
  }

  return buildChildEnv(
    { allow: contract.envAllow, allowPrefixes: contract.envAllowPrefixes, set: options.set },
    process.env,
    reportNotice,
  );
}

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
    ...CHILD_ENV_CONTRACTS.hackmyagent,
  },
  secrets: {
    name: 'secrets',
    method: 'import',
    packageName: 'secretless-ai',
    description: 'Manage credentials for AI coding tools (Secretless)',
    ...CHILD_ENV_CONTRACTS['secretless-ai'],
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
    ...CHILD_ENV_CONTRACTS['ai-trust'],
  },
  train: {
    name: 'train',
    method: 'docker',
    image: 'opena2a/dvaa',
    ports: ['3001-3008:3001-3008', '3010-3013:3010-3013', '3020-3021:3020-3021', '9000:9000'],
    description: 'Launch vulnerable AI agent for training (DVAA)',
    ...CHILD_ENV_CONTRACTS.docker,
  },
  crypto: {
    name: 'crypto',
    method: 'python',
    pythonModule: 'cryptoserve',
    description: 'Cryptographic inventory and PQC readiness (CryptoServe)',
    ...CHILD_ENV_CONTRACTS.cryptoserve,
  },
  // identity is now handled directly by packages/cli/src/commands/identity.ts
  // guard is now handled directly by packages/cli/src/commands/guard.ts (ConfigGuard)
  broker: {
    name: 'broker',
    method: 'import',
    packageName: 'secretless-ai',
    subcommand: 'broker',
    description: 'Identity-aware credential broker daemon',
    ...CHILD_ENV_CONTRACTS['secretless-ai'],
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
