/**
 * Issue #228 — spawned children get an allowlisted environment, not the
 * operator's whole one.
 *
 * These tests pin the CONTRACT, not just the leak fix. Three things break if
 * the allowlist is wrong, and all three are silent:
 *   (a) a credential gets through,
 *   (b) a delegated tool loses an input it needs and changes behaviour with a
 *       zero exit code,
 *   (c) a telemetry opt-out or a command-citation prefix stops propagating.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  buildChildEnv,
  parseEnvAllowOverride,
  looksLikeCredentialName,
  probeEnv,
  CI_VENDOR_ENV_VARS,
} from '../../src/util/child-env.js';
import { ADAPTER_REGISTRY } from '../../src/adapters/registry.js';

/** Turn a registry entry into the spec its adapter passes to buildChildEnv. */
function specFor(name: string) {
  const c = ADAPTER_REGISTRY[name];
  return { allow: c.envAllow, allowPrefixes: c.envAllowPrefixes };
}

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
  HTTPS_PROXY: 'http://corp-proxy:3128',
  NODE_EXTRA_CA_CERTS: '/etc/ssl/corp.pem',
  DO_NOT_TRACK: '1',
  XDG_CONFIG_HOME: '/home/dev/.config',
  // opena2a family
  OPENA2A_REGISTRY_URL: 'https://registry.opena2a.org',
  OPENA2A_TELEMETRY: 'off',
  OPENA2A_HOME: '/home/dev/.opena2a',
  HMA_CLI_PREFIX: 'opena2a',
  HMA_CHECK_COMMAND: 'opena2a check',
  HMA_FULL_SCAN_HINT: 'opena2a review',
  SECRETLESS_CLI_PREFIX: 'opena2a secrets',
  CRYPTOSERVE_CLI_PREFIX: 'opena2a crypto',
  AI_TRUST_CLI_PREFIX: 'opena2a registry',
  // Tool inputs
  DOCKER_HOST: 'unix:///var/run/docker.sock',
  DOCKER_CONFIG: '/home/dev/.docker',
  VIRTUAL_ENV: '/home/dev/venv',
  PYTHONPATH: '/home/dev/lib',
  npm_config_registry: 'https://npm.corp.internal',
  NODE_OPTIONS: '--max-old-space-size=4096',
  NANOMIND_URL: 'http://127.0.0.1:871',
  NANOMIND_GUARD_SOCK: '/tmp/nanomind.sock',
  REGISTRY_URL: 'https://registry.opena2a.org',
  VAULT_ADDR: 'https://vault.corp:8200',
  // Credentials that belong to no adapter
  OPENAI_API_KEY: 'REDACTED',
  GITHUB_TOKEN: 'REDACTED',
  NPM_TOKEN: 'REDACTED',
  VAULT_TOKEN: 'REDACTED',
  DATABASE_URL: 'postgres://user:pw@host/db',
  OPENA2A_INTERNAL_API_KEY: 'REDACTED',
  OPENA2A_FIRST_PARTY_KEY: 'REDACTED',
  OPENA2A_DATABASE_URL: 'postgres://user:pw@host/db',
  OPENA2A_PAT: 'REDACTED',
  OPENA2A_JWT: 'REDACTED',
  OPENA2A_SIGNATURE: 'REDACTED',
  npm_config__auth: 'REDACTED',
  NPM_CONFIG__AUTH: 'REDACTED',
  npm_config_otp: 'REDACTED',
  YARN_NPM_AUTH_IDENT: 'REDACTED',
  DOCKER_AUTH_CONFIG: 'REDACTED',
  DOCKER_PAT: 'REDACTED',
  AWS_SECRET_ACCESS_KEY: 'REDACTED',
  ANTHROPIC_API_KEY: 'REDACTED',
  GOOGLE_APPLICATION_CREDENTIALS: '/home/dev/gcp.json',
  AIM_API_KEY: 'REDACTED',
};

/** Credentials that must never reach ANY child. */
const UNIVERSALLY_FORBIDDEN = [
  'OPENAI_API_KEY', 'GITHUB_TOKEN', 'NPM_TOKEN', 'DATABASE_URL',
  'OPENA2A_INTERNAL_API_KEY', 'OPENA2A_FIRST_PARTY_KEY', 'OPENA2A_DATABASE_URL',
  'OPENA2A_PAT', 'OPENA2A_JWT', 'OPENA2A_SIGNATURE',
  'npm_config__auth', 'NPM_CONFIG__AUTH', 'npm_config_otp',
  'YARN_NPM_AUTH_IDENT', 'DOCKER_AUTH_CONFIG', 'DOCKER_PAT',
];

const ADAPTERS = ['scan', 'secrets', 'registry', 'train', 'crypto', 'broker'] as const;

describe('credential-name guard', () => {
  it('catches every credential shape the adversarial pass found', () => {
    for (const name of [
      'OPENA2A_FIRST_PARTY_KEY', 'OPENA2A_DATABASE_URL', 'OPENA2A_MONGODB_URI',
      'OPENA2A_REDIS_URL', 'OPENA2A_PAT', 'OPENA2A_JWT', 'OPENA2A_SIGNATURE',
      'OPENA2A_PRIVKEY', 'OPENA2A_DSN', 'OPENA2A_SESSIONID', 'OPENA2A_PASS',
      'OPENA2A_PWD', 'OPENA2A_PSK', 'OPENA2A_OTP', 'OPENA2A_KUBECONFIG',
      'npm_config__auth', 'NPM_CONFIG__AUTH', 'npm_config_otp',
      'npm_config_//registry.npmjs.org/:_authToken',
      'YARN_NPM_AUTH_IDENT', 'DOCKER_AUTH_CONFIG', 'DOCKER_PAT',
      'GITHUB_TOKEN', 'AWS_SECRET_ACCESS_KEY', 'ANTHROPIC_API_KEY',
      'STRIPE_SK_LIVE', 'CLIENT_SECRET', 'MY_ID_RSA',
    ]) {
      expect(looksLikeCredentialName(name), `${name} should be flagged`).toBe(true);
    }
  });

  it('does not flag the configuration names the tools need', () => {
    for (const name of [
      'PATH', 'PATHEXT', 'PYTHONPATH', 'HOME', 'DOCKER_HOST', 'DOCKER_CONFIG',
      'VIRTUAL_ENV', 'npm_config_registry', 'NODE_OPTIONS', 'NANOMIND_URL',
      'REGISTRY_URL', 'VAULT_ADDR', 'OPENA2A_REGISTRY_URL', 'OPENA2A_HOME',
      'HMA_CLI_PREFIX', 'CI', 'GITHUB_ACTIONS',
    ]) {
      expect(looksLikeCredentialName(name), `${name} should not be flagged`).toBe(false);
    }
  });

  it('flags connection strings under an allowed prefix, not just bare ones', () => {
    // Regression: an equality-only check can never fire on a prefix match,
    // because a name that matched a non-empty prefix is strictly longer.
    const env = buildChildEnv({}, {
      OPENA2A_DATABASE_URL: 'postgres://u:p@h/db',
      OPENA2A_REDIS_URL: 'redis://:pw@h',
      OPENA2A_MONGODB_URI: 'mongodb://u:p@h',
      OPENA2A_REGISTRY_URL: 'https://registry.opena2a.org',
    });
    expect(env.OPENA2A_DATABASE_URL).toBeUndefined();
    expect(env.OPENA2A_REDIS_URL).toBeUndefined();
    expect(env.OPENA2A_MONGODB_URI).toBeUndefined();
    expect(env.OPENA2A_REGISTRY_URL).toBe('https://registry.opena2a.org');
  });
});

describe('every adapter environment', () => {
  it('the fixture really contains the credentials (guards the guard)', () => {
    for (const name of UNIVERSALLY_FORBIDDEN) {
      expect(SOURCE[name], `${name} missing from fixture`).toBeDefined();
    }
  });

  for (const name of ADAPTERS) {
    it(`${name}: passes no credential outside its declared contract`, () => {
      const env = buildChildEnv(specFor(name), SOURCE);
      for (const forbidden of UNIVERSALLY_FORBIDDEN) {
        expect(env[forbidden], `${name} leaked ${forbidden}`).toBeUndefined();
      }
    });

    it(`${name}: keeps the process basics`, () => {
      const env = buildChildEnv(specFor(name), SOURCE);
      for (const base of ['PATH', 'HOME', 'SHELL', 'LANG', 'TMPDIR', 'TERM']) {
        expect(env[base], `${name} lost ${base}`).toBe(SOURCE[base]);
      }
    });

    it(`${name}: keeps the telemetry opt-out`, () => {
      const env = buildChildEnv(specFor(name), SOURCE);
      expect(env.DO_NOT_TRACK).toBe('1');
      expect(env.OPENA2A_TELEMETRY).toBe('off');
    });

    it(`${name}: keeps every *_CLI_PREFIX citation var`, () => {
      const env = buildChildEnv(specFor(name), SOURCE);
      expect(env.HMA_CLI_PREFIX).toBe('opena2a');
      expect(env.HMA_CHECK_COMMAND).toBe('opena2a check');
      expect(env.HMA_FULL_SCAN_HINT).toBe('opena2a review');
      expect(env.CRYPTOSERVE_CLI_PREFIX).toBe('opena2a crypto');
      expect(env.AI_TRUST_CLI_PREFIX).toBe('opena2a registry');
      // Contains "secret" — survives only because exact entries bypass the guard.
      expect(env.SECRETLESS_CLI_PREFIX).toBe('opena2a secrets');
    });
  }
});

describe('declared tool contracts are honoured', () => {
  it('scan (hackmyagent) keeps the inputs that change its findings', () => {
    const env = buildChildEnv(specFor('scan'), SOURCE);
    // Dropping these does not crash — it silently returns different findings.
    expect(env.NANOMIND_URL).toBe('http://127.0.0.1:871');
    expect(env.NANOMIND_GUARD_SOCK).toBe('/tmp/nanomind.sock');
    expect(env.REGISTRY_URL).toBe('https://registry.opena2a.org');
    expect(env.ANTHROPIC_API_KEY).toBe('REDACTED');
    // ...but not credentials outside its contract.
    expect(env.VAULT_TOKEN).toBeUndefined();
    expect(env.GITHUB_TOKEN).toBeUndefined();
  });

  it('secrets/broker (secretless-ai) keep the vault and cloud inputs they broker', () => {
    for (const name of ['secrets', 'broker'] as const) {
      const env = buildChildEnv(specFor(name), SOURCE);
      expect(env.VAULT_ADDR, `${name} lost VAULT_ADDR`).toBe('https://vault.corp:8200');
      expect(env.VAULT_TOKEN, `${name} lost VAULT_TOKEN`).toBe('REDACTED');
      expect(env.AWS_SECRET_ACCESS_KEY).toBe('REDACTED');
      expect(env.GOOGLE_APPLICATION_CREDENTIALS).toBe('/home/dev/gcp.json');
      expect(env.AIM_API_KEY).toBe('REDACTED');
      // Not the scanner's credentials.
      expect(env.ANTHROPIC_API_KEY).toBeUndefined();
    }
  });

  it('train (docker) keeps client configuration, crypto keeps interpreter config', () => {
    const docker = buildChildEnv(specFor('train'), SOURCE);
    expect(docker.DOCKER_HOST).toBe('unix:///var/run/docker.sock');
    expect(docker.DOCKER_CONFIG).toBe('/home/dev/.docker');
    const python = buildChildEnv(specFor('crypto'), SOURCE);
    expect(python.VIRTUAL_ENV).toBe('/home/dev/venv');
    expect(python.PYTHONPATH).toBe('/home/dev/lib');
  });

  it('contracts do not leak between adapters', () => {
    expect(buildChildEnv(specFor('crypto'), SOURCE).DOCKER_HOST).toBeUndefined();
    expect(buildChildEnv(specFor('train'), SOURCE).VIRTUAL_ENV).toBeUndefined();
    expect(buildChildEnv(specFor('crypto'), SOURCE).VAULT_TOKEN).toBeUndefined();
    expect(buildChildEnv(specFor('registry'), SOURCE).ANTHROPIC_API_KEY).toBeUndefined();
  });

  it('every adapter that spawns declares a contract', () => {
    for (const name of ADAPTERS) {
      const c = ADAPTER_REGISTRY[name];
      expect(
        (c.envAllow?.length ?? 0) + (c.envAllowPrefixes?.length ?? 0),
        `${name} declares no environment contract`,
      ).toBeGreaterThan(0);
    }
  });
});

describe('CI detection', () => {
  it('mirrors the telemetry package vendor list exactly', () => {
    // Drift here silently re-enables telemetry in delegated tools on any
    // runner that does not export a bare CI=1.
    const src = readFileSync(
      join(__dirname, '../../../telemetry/src/config.ts'),
      'utf-8',
    );
    const block = src.match(/CI_VENDOR_ENV_VARS = \[([\s\S]*?)\]/);
    expect(block, 'could not locate CI_VENDOR_ENV_VARS in the telemetry package').toBeTruthy();
    const upstream = [...block![1].matchAll(/"([A-Z0-9_]+)"/g)].map(m => m[1]);
    expect([...CI_VENDOR_ENV_VARS].sort()).toEqual([...upstream].sort());
  });

  it('forwards CI markers so a runner still looks like a runner', () => {
    const env = buildChildEnv(specFor('scan'), {
      PATH: '/bin', JENKINS_URL: 'https://ci.corp', CONTINUOUS_INTEGRATION: 'true',
    });
    expect(env.JENKINS_URL).toBe('https://ci.corp');
    expect(env.CONTINUOUS_INTEGRATION).toBe('true');
  });
});

describe('probeEnv', () => {
  it('carries discovery basics but none of the tool credentials', () => {
    const env = probeEnv(SOURCE);
    expect(env.PATH).toBe('/usr/bin:/bin');
    expect(env.PYTHONPATH).toBe('/home/dev/lib');
    for (const name of [...UNIVERSALLY_FORBIDDEN, 'ANTHROPIC_API_KEY', 'VAULT_TOKEN']) {
      expect(env[name], `probe leaked ${name}`).toBeUndefined();
    }
  });
});

describe('set', () => {
  it('applies after the allowlist and can pass a guarded name deliberately', () => {
    const env = buildChildEnv({ set: { ANTHROPIC_API_KEY: 'explicit' } }, SOURCE);
    expect(env.ANTHROPIC_API_KEY).toBe('explicit');
    expect(env.OPENAI_API_KEY).toBeUndefined();
  });

  it('undefined removes a name, case-insensitively', () => {
    expect(buildChildEnv({ set: { HOME: undefined } }, SOURCE).HOME).toBeUndefined();
    // Matching selected names case-insensitively, so removal must too.
    const env = buildChildEnv({ set: { PATH: undefined } }, { Path: 'C:\\Windows' });
    expect(Object.keys(env)).toHaveLength(0);
  });
});

describe('OPENA2A_CHILD_ENV_ALLOW escape hatch', () => {
  it('parses exact names and prefix patterns', () => {
    expect(parseEnvAllowOverride('FOO, BAR_*, BAZ')).toEqual({
      allow: ['FOO', 'BAZ'], allowPrefixes: ['BAR_'], rejected: [],
    });
  });

  it('refuses a bare wildcard', () => {
    for (const raw of ['*', '**', '  *  ']) {
      expect(parseEnvAllowOverride(raw).allowPrefixes).toEqual([]);
    }
  });

  it('refuses the single-letter alphabet bypass', () => {
    // `a*,b*,c*,...` reassembles blanket inheritance one letter at a time.
    const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789_'
      .split('').map(c => `${c}*`).join(',');
    const parsed = parseEnvAllowOverride(alphabet);
    expect(parsed.allowPrefixes).toEqual([]);
    expect(parsed.rejected.length).toBeGreaterThan(30);

    const env = buildChildEnv(specFor('registry'), { ...SOURCE, OPENA2A_CHILD_ENV_ALLOW: alphabet });
    for (const name of UNIVERSALLY_FORBIDDEN) {
      expect(env[name], `alphabet bypass leaked ${name}`).toBeUndefined();
    }
  });

  it('caps the number of honoured entries', () => {
    const many = Array.from({ length: 50 }, (_, i) => `VAR_${i}`).join(',');
    const parsed = parseEnvAllowOverride(many);
    expect(parsed.allow).toHaveLength(32);
    expect(parsed.rejected).toHaveLength(18);
  });

  it('never forwards itself, so a widened child cannot widen its own children', () => {
    const env = buildChildEnv({}, { PATH: '/bin', OPENA2A_CHILD_ENV_ALLOW: 'CORP_TOOL_MODE' });
    expect(env.OPENA2A_CHILD_ENV_ALLOW).toBeUndefined();
    expect(env.PATH).toBe('/bin');
  });

  it('reports what it widened and what it refused, by name', () => {
    const notices: string[] = [];
    buildChildEnv(
      specFor('registry'),
      { ...SOURCE, OPENA2A_CHILD_ENV_ALLOW: 'CORP_TOOL_MODE,CORP_*,x*,*' },
      m => notices.push(m),
    );
    expect(notices.join('\n')).toContain('CORP_TOOL_MODE');
    expect(notices.join('\n')).toContain('ignored');
    // Names only — a notice must never echo a value.
    expect(notices.join('\n')).not.toContain('REDACTED');
  });

  it('an exact override passes a variable the base allowlist omits', () => {
    const src = { ...SOURCE, CORP_TOOL_MODE: 'strict', OPENA2A_CHILD_ENV_ALLOW: 'CORP_TOOL_MODE' };
    expect(buildChildEnv(specFor('registry'), src).CORP_TOOL_MODE).toBe('strict');
    expect(buildChildEnv(specFor('registry'), SOURCE).CORP_TOOL_MODE).toBeUndefined();
  });

  it('a prefix override is still subject to the guard', () => {
    const src = {
      ...SOURCE, CORP_TOOL_MODE: 'strict', CORP_TOOL_TOKEN: 'REDACTED',
      OPENA2A_CHILD_ENV_ALLOW: 'CORP_*',
    };
    const env = buildChildEnv(specFor('registry'), src);
    expect(env.CORP_TOOL_MODE).toBe('strict');
    expect(env.CORP_TOOL_TOKEN).toBeUndefined();
  });
});

describe('matching', () => {
  it('matches names case-insensitively (Windows spellings)', () => {
    const env = buildChildEnv({}, { Path: 'C:\\Windows', SystemRoot: 'C:\\Windows' });
    expect(env.Path).toBe('C:\\Windows');
    expect(env.SystemRoot).toBe('C:\\Windows');
  });

  it('drops undefined values and never aliases the source', () => {
    const source: NodeJS.ProcessEnv = { PATH: '/bin', HOME: undefined };
    const env = buildChildEnv({}, source);
    expect('HOME' in env).toBe(false);
    env.PATH = '/tampered';
    expect(source.PATH).toBe('/bin');
  });
});
