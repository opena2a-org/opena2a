/**
 * The lock-trace loop hands each vitest run an allowlisted environment, not
 * the operator's whole one (#397). The run and the tsx writers it spawns read
 * no credential, so none may reach them; what the suite does read (the Node
 * toolchain's settings, its two concurrency knobs, the trace path) must.
 */
import { describe, it, expect } from 'vitest';
import { lockTraceSuiteEnv } from '../../scripts/shield-lock-trace-env.js';
import { LOCK_TRACE_ENV } from '../../src/shield/lock.js';

const TRACE = '/traces/round-001/lock-trace.jsonl';

/** Names the suite has no use for. Every one reached it through the old spread. */
const UNNEEDED = ['ANTHROPIC_API_KEY', 'GITHUB_TOKEN', 'NODE_AUTH_TOKEN', 'DATABASE_URL', 'UNRELATED_SETTING'];

function operatorEnv(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: '/usr/local/bin:/usr/bin:/bin',
    HOME: '/home/dev',
    TMPDIR: '/tmp/dev',
    LANG: 'en_US.UTF-8',
    NODE_OPTIONS: '--max-old-space-size=4096',
    npm_config_cache: '/home/dev/.npm',
    SHIELD_CONCURRENT_WRITERS: '12',
    OPENA2A_REGISTRY_URL: 'https://registry.example.test',
    ...extra,
  };
  for (const name of UNNEEDED) env[name] = 'not-forwarded';
  return env;
}

describe('shield-lock-trace-loop child environment (#397)', () => {
  it('drops every name outside the allowlist', () => {
    const env = lockTraceSuiteEnv(TRACE, operatorEnv());
    for (const name of UNNEEDED) {
      expect(env[name], name).toBeUndefined();
    }
  });

  it('keeps the base names, the Node toolchain settings and the writer count', () => {
    const source = operatorEnv();
    const env = lockTraceSuiteEnv(TRACE, source);
    for (const name of [
      'PATH', 'HOME', 'TMPDIR', 'LANG', 'NODE_OPTIONS', 'npm_config_cache',
      'SHIELD_CONCURRENT_WRITERS', 'OPENA2A_REGISTRY_URL',
    ]) {
      expect(env[name], name).toBe(source[name]);
    }
  });

  it('points the lock trace at this round\'s file, over any inherited value', () => {
    const env = lockTraceSuiteEnv(TRACE, operatorEnv({ [LOCK_TRACE_ENV]: '/elsewhere.jsonl' }));
    expect(env[LOCK_TRACE_ENV]).toBe(TRACE);
  });

  it('runs one suite round per loop round unless the operator sets the count', () => {
    expect(lockTraceSuiteEnv(TRACE, operatorEnv()).SHIELD_CONCURRENT_ROUNDS).toBe('1');
    expect(
      lockTraceSuiteEnv(TRACE, operatorEnv({ SHIELD_CONCURRENT_ROUNDS: '3' })).SHIELD_CONCURRENT_ROUNDS,
    ).toBe('3');
  });

  it('widens only by an exact OPENA2A_CHILD_ENV_ALLOW name, says so, and does not forward the hatch', () => {
    const notices: string[] = [];
    const env = lockTraceSuiteEnv(
      TRACE,
      operatorEnv({ OPENA2A_CHILD_ENV_ALLOW: 'UNRELATED_SETTING' }),
      n => notices.push(n),
    );
    expect(env.UNRELATED_SETTING).toBe('not-forwarded');
    expect(env.GITHUB_TOKEN).toBeUndefined();
    expect(env.OPENA2A_CHILD_ENV_ALLOW).toBeUndefined();
    expect(notices.join('\n')).toContain('UNRELATED_SETTING');
  });
});
