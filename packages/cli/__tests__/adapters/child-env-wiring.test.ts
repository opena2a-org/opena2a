/**
 * Issue #228 — the adapters must actually USE the allowlist.
 *
 * child-env.test.ts pins the helper's behaviour; these tests pin the wiring.
 * Without them, reverting any adapter to `env: { ...process.env }` leaves the
 * whole suite green.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const spawnCalls: Array<{ bin: string; args: string[]; opts: Record<string, unknown> }> = [];

vi.mock('node:child_process', () => ({
  spawn: vi.fn((bin: string, args: string[], opts: Record<string, unknown>) => {
    spawnCalls.push({ bin, args, opts });
    const noop = { on: vi.fn() };
    return {
      stdout: noop,
      stderr: noop,
      on: vi.fn((event: string, handler: (code: number) => void) => {
        if (event === 'close') setTimeout(() => handler(0), 0);
      }),
    };
  }),
}));

const { DockerAdapter } = await import('../../src/adapters/docker.js');
const { PythonAdapter } = await import('../../src/adapters/python.js');
const { SpawnAdapter } = await import('../../src/adapters/spawn.js');

/** Secrets planted in process.env for the duration of each test. */
const PLANTED = {
  ANTHROPIC_API_KEY: 'sk-ant-PLANTED',
  GITHUB_TOKEN: 'gho_PLANTED',
  AWS_SECRET_ACCESS_KEY: 'PLANTED-aws',
  NPM_TOKEN: 'npm_PLANTED',
  DATABASE_URL: 'postgres://user:PLANTED@host/db',
  OPENA2A_INTERNAL_API_KEY: 'PLANTED-internal',
};

beforeEach(() => {
  spawnCalls.length = 0;
  for (const [k, v] of Object.entries(PLANTED)) vi.stubEnv(k, v);
  vi.stubEnv('HMA_CLI_PREFIX', 'opena2a');
});

afterEach(() => {
  vi.unstubAllEnvs();
});

/** The options of the spawn call that carries an env (the tool invocation). */
function runEnv(): NodeJS.ProcessEnv {
  const call = spawnCalls.find(c => c.opts && 'env' in c.opts);
  expect(call, 'no spawn call carried an env option').toBeDefined();
  return call!.opts.env as NodeJS.ProcessEnv;
}

function expectNoPlantedSecrets(env: NodeJS.ProcessEnv, label: string): void {
  for (const name of Object.keys(PLANTED)) {
    expect(env[name], `${label} leaked ${name}`).toBeUndefined();
  }
  expect(Object.values(env).join('\n'), `${label} leaked a planted value`)
    .not.toContain('PLANTED');
}

describe('adapter env wiring (#228)', () => {
  it('planted secrets are really in process.env', () => {
    // Guards the guard — a stubEnv that silently no-ops would make every
    // assertion below vacuous.
    for (const [k, v] of Object.entries(PLANTED)) {
      expect(process.env[k]).toBe(v);
    }
  });

  it('DockerAdapter passes an allowlisted env', async () => {
    const adapter = new DockerAdapter({
      name: 'train', method: 'docker', image: 'opena2a/dvaa', description: 'test',
    });
    await adapter.run({ args: [], quiet: true });

    const env = runEnv();
    expectNoPlantedSecrets(env, 'docker');
    expect(env.PATH).toBe(process.env.PATH);
    expect(env.HMA_CLI_PREFIX).toBe('opena2a');
  });

  it('PythonAdapter passes an allowlisted env', async () => {
    const adapter = new PythonAdapter({
      name: 'crypto', method: 'python', pythonModule: 'cryptoserve', description: 'test',
    });
    await adapter.run({ args: [], quiet: true });

    const env = runEnv();
    expectNoPlantedSecrets(env, 'python');
    expect(env.PATH).toBe(process.env.PATH);
  });

  it('SpawnAdapter passes an allowlisted env', async () => {
    const adapter = new SpawnAdapter({
      name: 'registry', method: 'spawn', command: 'ai-trust', description: 'test',
    });
    await adapter.run({ args: [], quiet: true });

    const env = runEnv();
    expectNoPlantedSecrets(env, 'spawn');
    expect(env.PATH).toBe(process.env.PATH);
    expect(env.HMA_CLI_PREFIX).toBe('opena2a');
  });
});
