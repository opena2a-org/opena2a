/**
 * Issue #228 — spawned children must receive an allowlisted environment,
 * not `{ ...process.env }`.
 *
 * These tests pin the allowlist CONTRACT, not just the leak fix: the three
 * things that break if the allowlist is wrong are (a) secrets get through,
 * (b) a tool the adapter needs stops working, (c) a user's telemetry opt-out
 * or a command-citation prefix silently stops propagating.
 */
import { describe, it, expect } from 'vitest';

import {
  buildChildEnv,
  parseEnvAllowOverride,
  DOCKER_ENV,
  PYTHON_ENV,
  NODE_TOOL_ENV,
} from '../../src/util/child-env.js';

/** A source environment shaped like a real developer machine. */
const SOURCE: NodeJS.ProcessEnv = {
  // Base needs
  PATH: '/usr/bin:/bin',
  HOME: '/home/dev',
  SHELL: '/bin/zsh',
  LANG: 'en_US.UTF-8',
  LC_ALL: 'en_US.UTF-8',
  TMPDIR: '/tmp',
  TERM: 'xterm-256color',
  NO_COLOR: '1',
  CI: 'true',
  HTTPS_PROXY: 'http://corp-proxy:3128',
  NODE_EXTRA_CA_CERTS: '/etc/ssl/corp.pem',
  DO_NOT_TRACK: '1',
  // opena2a family
  OPENA2A_REGISTRY_URL: 'https://registry.opena2a.org',
  OPENA2A_TELEMETRY: 'off',
  OPENA2A_CORPUS_PATH: '/home/dev/.opena2a/corpus',
  HMA_CLI_PREFIX: 'opena2a',
  SECRETLESS_CLI_PREFIX: 'opena2a secrets',
  CRYPTOSERVE_CLI_PREFIX: 'opena2a crypto',
  AI_TRUST_CLI_PREFIX: 'opena2a registry',
  // Toolchain
  DOCKER_HOST: 'unix:///var/run/docker.sock',
  DOCKER_CONFIG: '/home/dev/.docker',
  VIRTUAL_ENV: '/home/dev/venv',
  PYTHONPATH: '/home/dev/lib',
  npm_config_registry: 'https://npm.corp.internal',
  NODE_OPTIONS: '--max-old-space-size=4096',
  // Secrets — none of these belong in any child
  ANTHROPIC_API_KEY: 'sk-ant-REDACTED',
  OPENAI_API_KEY: 'sk-REDACTED',
  GITHUB_TOKEN: 'gho_REDACTED',
  NPM_TOKEN: 'npm_REDACTED',
  AWS_ACCESS_KEY_ID: 'AKIAREDACTED',
  AWS_SECRET_ACCESS_KEY: 'REDACTED',
  VAULT_TOKEN: 'hvs.REDACTED',
  DATABASE_URL: 'postgres://user:pw@host/db',
  GOOGLE_APPLICATION_CREDENTIALS: '/home/dev/gcp.json',
  OPENA2A_INTERNAL_API_KEY: 'REDACTED',
  INTERNAL_API_KEY: 'REDACTED',
  ADMIN_TOKEN: 'REDACTED',
  'npm_config_//registry.npmjs.org/:_authToken': 'npm_REDACTED',
};

const SECRET_NAMES = [
  'ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GITHUB_TOKEN', 'NPM_TOKEN',
  'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'VAULT_TOKEN',
  'DATABASE_URL', 'GOOGLE_APPLICATION_CREDENTIALS',
  'OPENA2A_INTERNAL_API_KEY', 'INTERNAL_API_KEY', 'ADMIN_TOKEN',
  'npm_config_//registry.npmjs.org/:_authToken',
];

const SPECS = [
  ['docker', DOCKER_ENV],
  ['python', PYTHON_ENV],
  ['node tool', NODE_TOOL_ENV],
] as const;

describe('buildChildEnv — secrets', () => {
  for (const [label, spec] of SPECS) {
    it(`${label}: passes no known credential variable`, () => {
      const env = buildChildEnv(spec, SOURCE);
      for (const name of SECRET_NAMES) {
        expect(env[name], `${name} must not reach the ${label} child`).toBeUndefined();
      }
    });

    it(`${label}: passes no value that appears only in a credential`, () => {
      const env = buildChildEnv(spec, SOURCE);
      const values = Object.values(env).join('\n');
      for (const marker of ['sk-ant-', 'gho_', 'npm_REDACTED', 'AKIA', 'hvs.', 'postgres://']) {
        expect(values, `${marker} leaked into the ${label} child`).not.toContain(marker);
      }
    });
  }

  it('the whole-environment spread this replaces would have leaked them', () => {
    // Guards the guard: if SOURCE ever stops containing secrets, the
    // assertions above pass vacuously.
    for (const name of SECRET_NAMES) {
      expect({ ...SOURCE }[name]).toBeDefined();
    }
  });

  it('an OPENA2A_ prefix match is still dropped when the name is credential-bearing', () => {
    const env = buildChildEnv({}, SOURCE);
    expect(env.OPENA2A_REGISTRY_URL).toBe('https://registry.opena2a.org');
    expect(env.OPENA2A_INTERNAL_API_KEY).toBeUndefined();
  });
});

describe('buildChildEnv — what children still need', () => {
  it('every spec keeps the process basics', () => {
    for (const [label, spec] of SPECS) {
      const env = buildChildEnv(spec, SOURCE);
      for (const name of ['PATH', 'HOME', 'SHELL', 'LANG', 'TMPDIR', 'TERM']) {
        expect(env[name], `${label} lost ${name}`).toBe(SOURCE[name]);
      }
    }
  });

  it('keeps proxy and custom-CA settings (corporate TLS interception)', () => {
    const env = buildChildEnv(NODE_TOOL_ENV, SOURCE);
    expect(env.HTTPS_PROXY).toBe('http://corp-proxy:3128');
    expect(env.NODE_EXTRA_CA_CERTS).toBe('/etc/ssl/corp.pem');
  });

  it('keeps the telemetry opt-out signals', () => {
    // A dropped opt-out means a user who said no starts emitting from the
    // delegated tool — a privacy regression the leak fix must not cause.
    for (const [, spec] of SPECS) {
      const env = buildChildEnv(spec, SOURCE);
      expect(env.DO_NOT_TRACK).toBe('1');
      expect(env.OPENA2A_TELEMETRY).toBe('off');
    }
  });

  it('keeps the *_CLI_PREFIX citation-rebranding vars', () => {
    // index.ts sets these so delegated tools cite `opena2a <verb>`. Dropping
    // them turns every command citation in child output into a dead end
    // (issues #135/#190/#191).
    for (const [, spec] of SPECS) {
      const env = buildChildEnv(spec, SOURCE);
      expect(env.HMA_CLI_PREFIX).toBe('opena2a');
      expect(env.CRYPTOSERVE_CLI_PREFIX).toBe('opena2a crypto');
      expect(env.AI_TRUST_CLI_PREFIX).toBe('opena2a registry');
    }
  });

  it('keeps SECRETLESS_CLI_PREFIX even though the name contains "secret"', () => {
    // The exact-allow path must win over the secret-name heuristic.
    const env = buildChildEnv(NODE_TOOL_ENV, SOURCE);
    expect(env.SECRETLESS_CLI_PREFIX).toBe('opena2a secrets');
  });

  it('docker keeps daemon/client configuration', () => {
    const env = buildChildEnv(DOCKER_ENV, SOURCE);
    expect(env.DOCKER_HOST).toBe('unix:///var/run/docker.sock');
    expect(env.DOCKER_CONFIG).toBe('/home/dev/.docker');
  });

  it('python keeps interpreter and virtualenv configuration', () => {
    const env = buildChildEnv(PYTHON_ENV, SOURCE);
    expect(env.VIRTUAL_ENV).toBe('/home/dev/venv');
    expect(env.PYTHONPATH).toBe('/home/dev/lib');
  });

  it('node tools keep npm/node configuration but not the npm auth token', () => {
    const env = buildChildEnv(NODE_TOOL_ENV, SOURCE);
    expect(env.npm_config_registry).toBe('https://npm.corp.internal');
    expect(env.NODE_OPTIONS).toBe('--max-old-space-size=4096');
    expect(env['npm_config_//registry.npmjs.org/:_authToken']).toBeUndefined();
  });

  it('specs do not leak into each other', () => {
    expect(buildChildEnv(PYTHON_ENV, SOURCE).DOCKER_HOST).toBeUndefined();
    expect(buildChildEnv(DOCKER_ENV, SOURCE).VIRTUAL_ENV).toBeUndefined();
    expect(buildChildEnv(DOCKER_ENV, SOURCE).npm_config_registry).toBeUndefined();
  });
});

describe('buildChildEnv — set', () => {
  it('applies overrides after the allowlist', () => {
    const env = buildChildEnv(
      { ...NODE_TOOL_ENV, set: { OPENA2A_TELEMETRY: 'off' } },
      { ...SOURCE, OPENA2A_TELEMETRY: 'on' },
    );
    expect(env.OPENA2A_TELEMETRY).toBe('off');
  });

  it('undefined removes an inherited name', () => {
    const env = buildChildEnv({ set: { HOME: undefined } }, SOURCE);
    expect(env.HOME).toBeUndefined();
    expect(env.PATH).toBe('/usr/bin:/bin');
  });

  it('set can pass a value the allowlist would have dropped', () => {
    // Explicit is explicit: a caller that deliberately hands a credential to
    // one child may do so, and only that child sees it.
    const env = buildChildEnv({ set: { ANTHROPIC_API_KEY: 'sk-ant-explicit' } }, SOURCE);
    expect(env.ANTHROPIC_API_KEY).toBe('sk-ant-explicit');
    expect(env.OPENAI_API_KEY).toBeUndefined();
  });
});

describe('OPENA2A_CHILD_ENV_ALLOW escape hatch', () => {
  it('parses exact names and prefix patterns', () => {
    expect(parseEnvAllowOverride('FOO, BAR_*, BAZ')).toEqual({
      allow: ['FOO', 'BAZ'],
      allowPrefixes: ['BAR_'],
    });
  });

  it('ignores empty input and blank entries', () => {
    expect(parseEnvAllowOverride(undefined)).toEqual({ allow: [], allowPrefixes: [] });
    expect(parseEnvAllowOverride(' , ,')).toEqual({ allow: [], allowPrefixes: [] });
  });

  it('refuses a bare wildcard so blanket inheritance cannot be restored', () => {
    expect(parseEnvAllowOverride('*')).toEqual({ allow: [], allowPrefixes: [] });
    expect(parseEnvAllowOverride('**')).toEqual({ allow: [], allowPrefixes: [] });
    expect(parseEnvAllowOverride('  *  ')).toEqual({ allow: [], allowPrefixes: [] });

    const env = buildChildEnv(NODE_TOOL_ENV, { ...SOURCE, OPENA2A_CHILD_ENV_ALLOW: '*' });
    for (const name of SECRET_NAMES) {
      expect(env[name]).toBeUndefined();
    }
  });

  it('an exact override passes a variable the base allowlist omits', () => {
    const source = { ...SOURCE, CORP_TOOL_MODE: 'strict', OPENA2A_CHILD_ENV_ALLOW: 'CORP_TOOL_MODE' };
    expect(buildChildEnv(NODE_TOOL_ENV, source).CORP_TOOL_MODE).toBe('strict');
    expect(buildChildEnv(NODE_TOOL_ENV, SOURCE).CORP_TOOL_MODE).toBeUndefined();
  });

  it('a prefix override is still subject to the secret-name guard', () => {
    const source = {
      ...SOURCE,
      CORP_TOOL_MODE: 'strict',
      CORP_TOOL_TOKEN: 'REDACTED',
      OPENA2A_CHILD_ENV_ALLOW: 'CORP_*',
    };
    const env = buildChildEnv(NODE_TOOL_ENV, source);
    expect(env.CORP_TOOL_MODE).toBe('strict');
    expect(env.CORP_TOOL_TOKEN).toBeUndefined();
  });

  it('an exact override wins over the secret-name guard', () => {
    const source = { ...SOURCE, OPENA2A_CHILD_ENV_ALLOW: 'CORP_TOOL_TOKEN', CORP_TOOL_TOKEN: 'x' };
    expect(buildChildEnv(NODE_TOOL_ENV, source).CORP_TOOL_TOKEN).toBe('x');
  });
});

describe('buildChildEnv — matching', () => {
  it('matches names case-insensitively (Windows spellings)', () => {
    const env = buildChildEnv({}, { Path: 'C:\\Windows', SystemRoot: 'C:\\Windows' });
    expect(env.Path).toBe('C:\\Windows');
    expect(env.SystemRoot).toBe('C:\\Windows');
  });

  it('drops undefined values rather than materializing them', () => {
    const env = buildChildEnv({}, { PATH: '/bin', HOME: undefined });
    expect('HOME' in env).toBe(false);
  });

  it('returns a fresh object that does not alias the source', () => {
    const source = { PATH: '/bin' };
    const env = buildChildEnv({}, source);
    env.PATH = '/tampered';
    expect(source.PATH).toBe('/bin');
  });
});
