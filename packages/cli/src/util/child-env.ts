/**
 * Least-privilege environment for spawned child processes (issue #228).
 *
 * The adapters spawn delegated tools (`docker run`, `python3 -m <module>`,
 * `npx <tool>`). Handing those children the operator's entire environment
 * gives every one of them cloud credentials, registry tokens, database URLs
 * and model API keys that are no part of any adapter's contract.
 *
 * ---------------------------------------------------------------------------
 * WHY THE CONTRACT LIVES IN THE ADAPTER REGISTRY
 * ---------------------------------------------------------------------------
 *
 * A single generic allowlist is wrong here, and wrong in the dangerous
 * direction. These adapters do not run arbitrary third-party code — they run
 * first-party tools, several of which read credentials *as their purpose*:
 *
 *   secretless-ai   VAULT_ADDR / VAULT_TOKEN / AWS_* / GOOGLE_APPLICATION_-
 *                   CREDENTIALS — it is a credential broker. Strip those and
 *                   `opena2a secrets` cannot reach its backend.
 *   hackmyagent     NANOMIND_URL / NANOMIND_GUARD_SOCK route the classifier
 *                   daemon; ANTHROPIC_API_KEY drives analyst escalation;
 *                   REGISTRY_URL / REGISTRY_API_KEY / ATC_TOKEN drive publish.
 *                   Strip those and `opena2a scan` returns DIFFERENT FINDINGS
 *                   from `hackmyagent secure` on the same tree, with a zero
 *                   exit code and no warning.
 *
 * Both reach `SpawnAdapter` through the import-adapter fallback (see
 * adapters/import.ts and the note at router.ts), so "it is only the spawn
 * adapter" is not a containment argument. A silent capability loss in a
 * security scanner is worse than the leak it was meant to prevent.
 *
 * So each entry in ADAPTER_REGISTRY declares the environment its tool reads
 * (`envAllow` / `envAllowPrefixes`), and the adapter passes that declaration
 * here. Adding a tool means writing down its contract, which is the point.
 *
 * ---------------------------------------------------------------------------
 * HOW A NAME GETS THROUGH
 * ---------------------------------------------------------------------------
 *
 *   base allowlist     what any process needs: PATH/HOME/locale/TMPDIR,
 *                      terminal and CI hints, proxy and custom-CA settings.
 *   `allow`            exact names. ALWAYS included — an exact name is an
 *                      explicit decision, and it is how a tool declares the
 *                      credential it genuinely needs.
 *   `allowPrefixes`    name prefixes. Convenient, but a prefix cannot know
 *                      what it will match, so prefix matches must clear the
 *                      credential-name guard below.
 *
 * Matching is case-insensitive: Windows environment lookups are, and a
 * lowercase spelling of a base name (`path`) is not a credential.
 *
 * Escape hatch: `OPENA2A_CHILD_ENV_ALLOW` takes a comma-separated list of
 * exact names and `PREFIX*` patterns. It is deliberately awkward to abuse —
 * see parseEnvAllowOverride.
 *
 * KNOWN RESIDUAL: the guard reads names, never values. `PIP_INDEX_URL`,
 * `UV_INDEX_URL` and similar legitimately carry inline `user:password` for
 * private indexes, and the tools need them, so they pass. Likewise
 * `NODE_OPTIONS` and `PYTHONSTARTUP` are code-injection channels that we
 * forward because real users configure them — they are already applied to
 * this process, so forwarding is not an escalation, but it is not nothing.
 */

/**
 * CI vendor markers, mirrored from `@opena2a/telemetry`'s
 * `CI_VENDOR_ENV_VARS` (packages/telemetry/src/config.ts).
 *
 * Mirrored rather than imported: telemetry is ESM and this package emits
 * CommonJS, and the list is not exported from the package root. A test
 * asserts the two stay identical, so drift fails CI rather than silently
 * re-enabling telemetry in a delegated tool.
 */
export const CI_VENDOR_ENV_VARS = [
  'GITHUB_ACTIONS', 'GITLAB_CI', 'CIRCLECI', 'TRAVIS', 'JENKINS_URL',
  'BUILDKITE', 'DRONE', 'TEAMCITY_VERSION', 'TF_BUILD', 'CODEBUILD_BUILD_ID',
  'APPVEYOR', 'BITBUCKET_BUILD_NUMBER', 'HEROKU_TEST_RUN_ID', 'SEMAPHORE',
  'WOODPECKER_CI', 'NETLIFY', 'VERCEL', 'CF_PAGES',
];

/**
 * Substrings that mark a name as credential-bearing. Long enough to be
 * unambiguous; matched anywhere in the name.
 *
 * Applied to prefix matches only. Deliberately broad — a false drop is
 * recoverable via an exact `allow` entry, a false pass leaks a secret.
 */
const SECRET_NAME_SUBSTRINGS = [
  'token', 'secret', 'password', 'passwd', 'passphrase',
  'credential', 'apikey', 'api_key',
  'privatekey', 'private_key', 'privkey',
  'accesskey', 'access_key', 'signingkey', 'signing_key',
  'signature', 'bearer', 'cookie', 'auth',
  'kubeconfig', 'id_rsa', 'id_ed25519', 'id_ecdsa',
  'session_key', 'session_id', 'sessionid', 'totp',
  // Jenkins `credentials()` emits NAME_USR / NAME_PSW pairs, and Jenkins is
  // one of the CI vendors this module deliberately forwards.
  'mnemonic', 'keyfile', 'keystore', 'keyring',
  '.pem', '_pem', 'partykey', 'signingkey',
  // Connection strings carry embedded credentials. These are substrings, not
  // whole names: OPENA2A_DATABASE_URL must be caught, and an equality test
  // against `database_url` can never fire on a prefix match (every shipped
  // prefix is non-empty, so a matched name is strictly longer).
  'database_url', 'database_uri', 'db_url', 'db_uri',
  'postgres', 'postgresql', 'mysql', 'mongodb', 'mongo_url',
  'redis_url', 'amqp_url', 'clickhouse', 'connection_string',
  'sk_live', 'sk_test', 'client_secret',
];

/**
 * Short credential words that would over-match as bare substrings — `pat`
 * appears in `PATH`, `key` in `MONKEYPATCH`. Matched only as a whole
 * underscore-delimited token.
 */
const SECRET_NAME_TOKENS = [
  'pat', 'pwd', 'pw', 'psw', 'psk', 'jwt', 'dsn', 'sig', 'otp',
  'key', 'keys', 'creds', 'seed', 'salt', 'hmac', 'cipher', 'pem', 'private',
  'pass', 'usr',
];

const SECRET_TOKEN_RE = new RegExp(`(^|_)(${SECRET_NAME_TOKENS.join('|')})(_|$)`, 'i');

/** Names every child needs to run. */
const BASE_ALLOW = [
  // Process basics
  'PATH', 'HOME', 'USER', 'USERNAME', 'LOGNAME', 'SHELL', 'TZ',
  'TMPDIR', 'TMP', 'TEMP',
  // Locale
  'LANG', 'LANGUAGE',
  // Terminal / color hints
  'TERM', 'COLORTERM', 'TERM_PROGRAM', 'TERM_PROGRAM_VERSION',
  'NO_COLOR', 'FORCE_COLOR', 'CLICOLOR', 'CLICOLOR_FORCE',
  // CI detection. Delegated tools run the same CI check we do
  // (@opena2a/telemetry isCI), and it keys on all of these — drop the vendor
  // markers and a Jenkins/TeamCity/Azure runner that does not export `CI`
  // looks like a workstation to the child, which silently re-enables the
  // telemetry the runner meant to suppress.
  'CI', 'CONTINUOUS_INTEGRATION', ...CI_VENDOR_ENV_VARS,
  // Corporate proxy + custom CA roots. Dropping these breaks `npx`, `pip`
  // and `docker` on any network that intercepts TLS.
  'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
  'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
  'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
  // Telemetry opt-out. If these do not reach the child, a user who opted out
  // silently starts emitting from the delegated tool.
  'DO_NOT_TRACK',
  // XDG base directories. A non-default location that does not reach the
  // child means the tool reads the wrong config and says nothing.
  'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_RUNTIME_DIR',
  // Command-citation rebranding (issues #135/#190/#191). index.ts sets these
  // so delegated tools cite `opena2a <verb>` instead of their own binary
  // name; without them every citation in child output is a dead end.
  // SECRETLESS_CLI_PREFIX contains "secret" and survives only because exact
  // entries bypass the credential-name guard.
  'HMA_CLI_PREFIX', 'HMA_CHECK_COMMAND', 'HMA_FULL_SCAN_HINT', 'HMA_CLI_PATH',
  'SECRETLESS_CLI_PREFIX', 'CRYPTOSERVE_CLI_PREFIX', 'AI_TRUST_CLI_PREFIX',
  // Windows
  'SystemRoot', 'SystemDrive', 'windir', 'COMSPEC', 'PATHEXT',
  'USERPROFILE', 'USERDOMAIN', 'HOMEDRIVE', 'HOMEPATH',
  'APPDATA', 'LOCALAPPDATA', 'ProgramData', 'ALLUSERSPROFILE',
  'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432', 'CommonProgramFiles',
  'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'OS', 'PSModulePath',
];

/**
 * Prefixes every child gets. `OPENA2A_` carries registry URL, corpus path,
 * telemetry mode and similar; the credential-name guard keeps
 * `OPENA2A_INTERNAL_API_KEY` and `OPENA2A_FIRST_PARTY_KEY` out of it.
 */
const BASE_ALLOW_PREFIXES = ['LC_', 'OPENA2A_'];

/** Longest prefix pattern the escape hatch will accept below this length. */
const MIN_OVERRIDE_PREFIX_LENGTH = 3;

/** Cap on escape-hatch entries, so it cannot be used to enumerate the env. */
const MAX_OVERRIDE_ENTRIES = 32;

export interface ChildEnvSpec {
  /** Exact names to include. Bypasses the credential-name guard. */
  allow?: readonly string[];
  /** Name prefixes to include. Matches must clear the credential-name guard. */
  allowPrefixes?: readonly string[];
  /** Values to set on the child. `undefined` removes an inherited name. */
  set?: Readonly<Record<string, string | undefined>>;
  /**
   * Ignore `OPENA2A_CHILD_ENV_ALLOW` for this call. Set by probeEnv: the
   * narrowest environment must not be the one an operator can widen, and a
   * probe never needs a variable we did not anticipate.
   */
  ignoreOverride?: boolean;
}

/**
 * Render an operator-supplied pattern for a terminal notice.
 *
 * The hatch's own string is untrusted input (anything that can set an
 * environment variable for this process can set it), and it is echoed back.
 * Unsanitized, `\r` + `\u001b[2K` lets it erase the line and forge our own
 * success output on every delegated spawn.
 */
function renderPattern(raw: string): string {
  // eslint-disable-next-line no-control-regex
  const stripped = raw.replace(/[\u0000-\u001f\u007f-\u009f]/g, '?');
  return stripped.length > 64 ? `${stripped.slice(0, 64)}...` : stripped;
}

/** True if a name looks like it carries a credential. */
export function looksLikeCredentialName(name: string): boolean {
  const lower = name.toLowerCase();
  if (SECRET_NAME_SUBSTRINGS.some(s => lower.includes(s))) return true;
  return SECRET_TOKEN_RE.test(lower);
}

/**
 * Parse `OPENA2A_CHILD_ENV_ALLOW` into exact names and prefixes.
 *
 * The hatch exists for tooling we did not anticipate, not as a way to turn
 * the control off. It is read from the same environment being filtered, so
 * anything that can set a variable for this process (direnv, a CI job config,
 * an npm lifecycle script) can widen it — the constraints below keep that
 * widening narrow and visible rather than total and silent:
 *
 *   - a bare `*`, or any pattern whose prefix is shorter than three
 *     characters, is refused. This is what stops `a*,b*,c*,...` from
 *     reassembling blanket inheritance one letter at a time.
 *   - at most MAX_OVERRIDE_ENTRIES entries are honoured.
 *   - the variable itself is never forwarded to the child, so a widened
 *     environment does not propagate to grandchildren.
 *
 * @returns the parsed patterns plus anything rejected, for reporting.
 */
export function parseEnvAllowOverride(
  raw: string | undefined,
): { allow: string[]; allowPrefixes: string[]; rejected: string[] } {
  const allow: string[] = [];
  const allowPrefixes: string[] = [];
  const rejected: string[] = [];
  if (typeof raw !== 'string' || raw.length === 0) return { allow, allowPrefixes, rejected };

  let honoured = 0;
  for (const entry of raw.split(',')) {
    const trimmed = entry.trim();
    if (trimmed.length === 0) continue;

    if (honoured >= MAX_OVERRIDE_ENTRIES) {
      rejected.push(trimmed);
      continue;
    }

    if (trimmed.endsWith('*')) {
      const prefix = trimmed.replace(/\*+$/, '');
      if (prefix.length < MIN_OVERRIDE_PREFIX_LENGTH) {
        rejected.push(trimmed);
        continue;
      }
      allowPrefixes.push(prefix);
    } else {
      allow.push(trimmed);
    }
    honoured += 1;
  }
  return { allow, allowPrefixes, rejected };
}

/**
 * Build a child-process environment from the base allowlist plus `spec`.
 *
 * @param spec    Per-call additions. See {@link ChildEnvSpec}.
 * @param source  Environment to draw from. Defaults to `process.env`.
 * @param onNotice Called once with a human-readable line when the escape
 *                 hatch widens the environment or rejects a pattern, so the
 *                 widening is never silent. Names only, never values.
 */
export function buildChildEnv(
  spec: ChildEnvSpec = {},
  source: NodeJS.ProcessEnv = process.env,
  onNotice?: (message: string) => void,
): NodeJS.ProcessEnv {
  const override = spec.ignoreOverride
    ? { allow: [], allowPrefixes: [], rejected: [] }
    : parseEnvAllowOverride(source.OPENA2A_CHILD_ENV_ALLOW);

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
    if (prefixes.some(p => lower.startsWith(p)) && !looksLikeCredentialName(name)) {
      out[name] = value;
    }
  }

  // `set` is applied before the hatch strip below, so that `set` cannot
  // reinstate the hatch variable and defeat the non-propagation guarantee.
  // It remains authoritative over the guard:
  // it is how a caller deliberately hands one credential to one child.
  for (const [name, value] of Object.entries(spec.set ?? {})) {
    if (value === undefined) {
      // Case-insensitive removal, to match how names were selected above.
      for (const existing of Object.keys(out)) {
        if (existing.toLowerCase() === name.toLowerCase()) delete out[existing];
      }
    } else {
      out[name] = value;
    }
  }

  // Never propagate the hatch itself — a widened child must not silently
  // widen its own children. Applied last so nothing can put it back.
  for (const name of Object.keys(out)) {
    if (name.toLowerCase() === 'opena2a_child_env_allow') delete out[name];
  }

  if (onNotice) {
    if (override.allow.length > 0 || override.allowPrefixes.length > 0) {
      const widened = [
        ...override.allow.map(renderPattern),
        ...override.allowPrefixes.map(p => `${renderPattern(p)}*`),
      ];
      onNotice(`OPENA2A_CHILD_ENV_ALLOW widened the child environment: ${widened.join(', ')}`);
    }
    if (override.rejected.length > 0) {
      onNotice(
        `OPENA2A_CHILD_ENV_ALLOW ignored ${override.rejected.length} entry/entries ` +
        `(a bare "*", a prefix shorter than ${MIN_OVERRIDE_PREFIX_LENGTH} characters, ` +
        `or beyond the ${MAX_OVERRIDE_ENTRIES}-entry limit): ` +
        override.rejected.map(renderPattern).join(', '),
      );
    }
  }

  return out;
}

/**
 * Environment for a short-lived availability probe (`which x`, `x --version`,
 * `python -c "import m"`). These run on the hot path before nearly every
 * delegated command.
 *
 * A probe gets the adapter's declared PREFIXES — which carry the discovery
 * configuration it genuinely needs, and stay subject to the credential guard
 * — but never its `envAllow` exact entries, which are precisely the
 * credentials a tool declared for its real work. `docker info` must see
 * `DOCKER_HOST` or rootless/colima/remote engines are misreported as "not
 * installed"; it must not see `ANTHROPIC_API_KEY`.
 *
 * The escape hatch is ignored here: the narrowest environment must not be the
 * one an operator can silently widen, and `python -c "import <module>"`
 * executes a third-party package's `__init__`.
 */
export function probeEnv(
  allowPrefixes: readonly string[] = [],
  source: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  return buildChildEnv(
    {
      allowPrefixes: [
        ...allowPrefixes,
        'PYTHON', 'PYENV_', 'CONDA_', 'NVM_', 'VOLTA_', 'FNM_',
      ],
      ignoreOverride: true,
    },
    source,
  );
}
