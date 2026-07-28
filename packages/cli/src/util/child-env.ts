/**
 * Least-privilege environment for spawned child processes (issue #228).
 *
 * The adapters spawn third-party tools (`docker run`, `python3 -m <module>`,
 * `npx <tool>`). Handing those children `{ ...process.env }` gives every one
 * of them the operator's entire environment: cloud credentials, registry
 * tokens, database URLs, model API keys. None of that is part of any
 * adapter's contract.
 *
 * This module builds the child environment from an allowlist instead:
 *
 *   base allowlist          what any process needs to run (PATH, HOME, locale,
 *                           proxy + CA-bundle settings, TTY/color hints) plus
 *                           the opena2a family vars our own delegated tools
 *                           read.
 *   per-call `allow`        exact names the caller needs. Always included —
 *                           an exact name is an explicit decision, so it wins
 *                           over the secret-name guard below.
 *   per-call `allowPrefixes` name prefixes (e.g. `DOCKER_`). Convenient, but
 *                           a prefix cannot know what it will match, so
 *                           prefix matches pass through the secret-name guard.
 *
 * Name matching is case-insensitive: Windows environment lookups are, and a
 * lowercase spelling of a base name (`path`) is not a credential.
 *
 * Escape hatch: `OPENA2A_CHILD_ENV_ALLOW` takes a comma-separated list of
 * exact names and `PREFIX*` patterns for operators whose tooling needs a var
 * we did not anticipate. A bare `*` is rejected — restoring blanket
 * inheritance is the thing this module exists to prevent.
 */

/**
 * Substrings that mark a name as credential-bearing. Applied to prefix
 * matches only (see module docs). Deliberately broad: a false drop is
 * recoverable via an exact `allow` entry or `OPENA2A_CHILD_ENV_ALLOW`, a
 * false pass leaks a secret.
 */
const SECRET_NAME_SUBSTRINGS = [
  'token', 'secret', 'password', 'passwd', 'passphrase',
  'credential', 'apikey', 'api_key', 'privatekey', 'private_key',
  'accesskey', 'access_key', 'signingkey', 'signing_key',
  'bearer', 'cookie', 'session_key',
];

/**
 * Connection-string names that carry embedded credentials without matching
 * any of the substrings above.
 */
const SECRET_NAME_EXACT = [
  'database_url', 'database_uri', 'db_url', 'db_uri',
  'postgres_url', 'postgresql_url', 'mysql_url', 'mongo_url', 'mongodb_uri',
  'redis_url', 'amqp_url', 'clickhouse_url',
];

/** Names every child needs to run, plus the opena2a-family vars. */
const BASE_ALLOW = [
  // Process basics
  'PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'TZ',
  'TMPDIR', 'TMP', 'TEMP',
  // Locale
  'LANG', 'LANGUAGE',
  // Terminal / color / CI hints
  'TERM', 'COLORTERM', 'TERM_PROGRAM', 'TERM_PROGRAM_VERSION',
  'NO_COLOR', 'FORCE_COLOR', 'CLICOLOR', 'CLICOLOR_FORCE', 'CI',
  // Corporate proxy + custom CA roots. Dropping these breaks `npx`, `pip`,
  // and `docker` on any network that MITMs TLS.
  'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
  'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
  'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
  // Telemetry opt-out. If these do not reach the child, a user who opted out
  // silently starts emitting telemetry from the delegated tool.
  'DO_NOT_TRACK',
  // Command-citation rebranding (issues #135/#190/#191). index.ts sets these
  // so delegated tools print `opena2a <verb>` instead of their own binary
  // name; without them every citation in child output is a dead end.
  // SECRETLESS_CLI_PREFIX contains "secret" and is only here — as an exact
  // entry — that it survives the secret-name guard.
  'HMA_CLI_PREFIX', 'HMA_CLI_PATH', 'SECRETLESS_CLI_PREFIX',
  'CRYPTOSERVE_CLI_PREFIX', 'AI_TRUST_CLI_PREFIX',
  // Windows
  'SystemRoot', 'SystemDrive', 'windir', 'COMSPEC', 'PATHEXT',
  'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH',
  'APPDATA', 'LOCALAPPDATA', 'ProgramData',
  'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432',
  'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'OS',
];

/**
 * Prefixes every child gets. `OPENA2A_` carries registry URL, corpus path,
 * telemetry mode and similar; the secret-name guard keeps
 * `OPENA2A_INTERNAL_API_KEY` out of it.
 */
const BASE_ALLOW_PREFIXES = ['LC_', 'OPENA2A_'];

/** Docker client configuration — daemon socket, contexts, TLS material. */
export const DOCKER_ENV: ChildEnvSpec = {
  allow: [
    'DOCKER_HOST', 'DOCKER_CONFIG', 'DOCKER_CONTEXT',
    'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY', 'DOCKER_API_VERSION',
  ],
  allowPrefixes: ['DOCKER_', 'BUILDKIT_', 'COMPOSE_'],
};

/** Interpreter discovery, virtualenvs, and package-manager configuration. */
export const PYTHON_ENV: ChildEnvSpec = {
  allow: ['VIRTUAL_ENV'],
  allowPrefixes: ['PYTHON', 'PIP_', 'PIPX_', 'PYENV_', 'CONDA_', 'POETRY_', 'UV_'],
};

/**
 * Node/npx toolchain configuration. `npm_config_*` is allowed by prefix so
 * private-registry settings survive; the guard drops the `_authToken` entries
 * npm exports alongside them.
 */
export const NODE_TOOL_ENV: ChildEnvSpec = {
  allowPrefixes: [
    'npm_config_', 'NPM_CONFIG_', 'NODE_',
    'NVM_', 'COREPACK_', 'YARN_', 'PNPM_', 'VOLTA_', 'FNM_',
  ],
};

export interface ChildEnvSpec {
  /** Exact names to include. Bypasses the secret-name guard. */
  allow?: readonly string[];
  /** Name prefixes to include. Matches are subject to the secret-name guard. */
  allowPrefixes?: readonly string[];
  /** Values to set on the child. `undefined` removes an inherited name. */
  set?: Readonly<Record<string, string | undefined>>;
}

function looksSecret(name: string): boolean {
  const lower = name.toLowerCase();
  if (SECRET_NAME_EXACT.includes(lower)) return true;
  return SECRET_NAME_SUBSTRINGS.some(s => lower.includes(s));
}

/**
 * Parse `OPENA2A_CHILD_ENV_ALLOW`. Entries ending in `*` are prefixes;
 * everything else is an exact name. A bare `*` is ignored.
 */
export function parseEnvAllowOverride(
  raw: string | undefined,
): { allow: string[]; allowPrefixes: string[] } {
  const allow: string[] = [];
  const allowPrefixes: string[] = [];
  if (!raw) return { allow, allowPrefixes };

  for (const entry of raw.split(',')) {
    const trimmed = entry.trim();
    if (trimmed.length === 0) continue;
    // A bare `*` (or `**`, `  *  `) would restore blanket inheritance.
    if (/^\*+$/.test(trimmed)) continue;
    if (trimmed.endsWith('*')) {
      allowPrefixes.push(trimmed.slice(0, -1));
    } else {
      allow.push(trimmed);
    }
  }
  return { allow, allowPrefixes };
}

/**
 * Build a child-process environment from the base allowlist plus `spec`.
 *
 * @param spec    Per-call additions. See {@link ChildEnvSpec}.
 * @param source  Environment to draw from. Defaults to `process.env`.
 */
export function buildChildEnv(
  spec: ChildEnvSpec = {},
  source: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  const override = parseEnvAllowOverride(source.OPENA2A_CHILD_ENV_ALLOW);

  const exact = new Set(
    [...BASE_ALLOW, ...(spec.allow ?? []), ...override.allow].map(n => n.toLowerCase()),
  );
  const prefixes = [
    ...BASE_ALLOW_PREFIXES,
    ...(spec.allowPrefixes ?? []),
    ...override.allowPrefixes,
  ].map(p => p.toLowerCase());

  const out: NodeJS.ProcessEnv = {};

  for (const [name, value] of Object.entries(source)) {
    if (value === undefined) continue;
    const lower = name.toLowerCase();

    if (exact.has(lower)) {
      out[name] = value;
      continue;
    }
    if (prefixes.some(p => lower.startsWith(p)) && !looksSecret(name)) {
      out[name] = value;
    }
  }

  for (const [name, value] of Object.entries(spec.set ?? {})) {
    if (value === undefined) delete out[name];
    else out[name] = value;
  }

  return out;
}
