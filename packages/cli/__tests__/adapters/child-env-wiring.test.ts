/**
 * Issue #228 — the adapters must actually USE the allowlist, on EVERY spawn.
 *
 * child-env.test.ts pins the helper; this pins the wiring. The first version
 * of this file selected the spawn call that carried an `env` option, which
 * silently excused every call that had none — precisely the unfixed ones
 * (the `which` / `--version` / `import <module>` availability probes that run
 * on the hot path before nearly every delegated command). It now asserts
 * across ALL spawn calls, so a probe with no environment fails the suite.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const spawnCalls: Array<{ bin: string; args: string[]; opts: Record<string, unknown> }> = [];

vi.mock('node:child_process', () => ({
  spawn: vi.fn((bin: string, args: string[], opts: Record<string, unknown>) => {
    spawnCalls.push({ bin, args, opts: opts ?? {} });
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
const { ADAPTER_REGISTRY } = await import('../../src/adapters/registry.js');

/** Credentials planted in process.env for the duration of each test. */
const PLANTED = {
  OPENAI_API_KEY: 'PLANTED-openai',
  GITHUB_TOKEN: 'PLANTED-gh',
  NPM_TOKEN: 'PLANTED-npm',
  DATABASE_URL: 'postgres://user:PLANTED@host/db',
  OPENA2A_INTERNAL_API_KEY: 'PLANTED-internal',
  OPENA2A_FIRST_PARTY_KEY: 'PLANTED-signing',
  OPENA2A_DATABASE_URL: 'postgres://user:PLANTED@host/db',
  NPM_CONFIG__AUTH: 'PLANTED-basic',
  DOCKER_AUTH_CONFIG: 'PLANTED-dockerauth',
};

beforeEach(() => {
  spawnCalls.length = 0;
  for (const [k, v] of Object.entries(PLANTED)) vi.stubEnv(k, v);
  vi.stubEnv('HMA_CLI_PREFIX', 'opena2a');
});

afterEach(() => {
  vi.unstubAllEnvs();
});

/**
 * Assert every spawn the adapter made carries an explicit, clean environment.
 * A call with no `env` inherits the parent's — that is the bug, not an excuse.
 */
function expectAllSpawnsClean(label: string): void {
  expect(spawnCalls.length, `${label} made no spawn calls`).toBeGreaterThan(0);
  for (const call of spawnCalls) {
    const env = call.opts.env as NodeJS.ProcessEnv | undefined;
    expect(env, `${label}: spawn(${call.bin}) passed no env — inherits everything`).toBeDefined();
    for (const name of Object.keys(PLANTED)) {
      expect(env![name], `${label}: spawn(${call.bin}) leaked ${name}`).toBeUndefined();
    }
    expect(
      Object.values(env!).join('\n'),
      `${label}: spawn(${call.bin}) leaked a planted value`,
    ).not.toContain('PLANTED-');
  }
}

describe('adapter env wiring (#228)', () => {
  it('planted credentials are really in process.env (guards the guard)', () => {
    for (const [k, v] of Object.entries(PLANTED)) expect(process.env[k]).toBe(v);
  });

  it('DockerAdapter: run and the availability probe are both allowlisted', async () => {
    const adapter = new DockerAdapter(ADAPTER_REGISTRY.train);
    await adapter.run({ args: [], quiet: true });
    await adapter.isAvailable();
    expectAllSpawnsClean('docker');
    const runEnv = spawnCalls[0].opts.env as NodeJS.ProcessEnv;
    expect(runEnv.PATH).toBe(process.env.PATH);
    expect(runEnv.HMA_CLI_PREFIX).toBe('opena2a');
  });

  it('PythonAdapter: run and the import probe are both allowlisted', async () => {
    const adapter = new PythonAdapter(ADAPTER_REGISTRY.crypto);
    await adapter.run({ args: [], quiet: true });
    await adapter.isAvailable();
    // `python -c "import cryptoserve"` executes third-party __init__ code.
    expectAllSpawnsClean('python');
  });

  it('SpawnAdapter: run and the which probe are both allowlisted', async () => {
    const adapter = new SpawnAdapter(ADAPTER_REGISTRY.registry);
    await adapter.run({ args: [], quiet: true });
    await adapter.isAvailable();
    expectAllSpawnsClean('spawn');
    const runEnv = spawnCalls.find(c => c.bin !== 'which')!.opts.env as NodeJS.ProcessEnv;
    expect(runEnv.PATH).toBe(process.env.PATH);
  });

  it('SpawnAdapter honours the declared contract of whichever tool it runs', async () => {
    // hackmyagent and secretless-ai both reach SpawnAdapter via the import
    // fallback, and their contracts differ — the adapter must not apply one
    // generic allowlist to both.
    vi.stubEnv('NANOMIND_URL', 'http://127.0.0.1:871');
    vi.stubEnv('VAULT_ADDR', 'https://vault.corp:8200');

    spawnCalls.length = 0;
    await new SpawnAdapter({ ...ADAPTER_REGISTRY.scan, method: 'spawn', command: 'hackmyagent' })
      .run({ args: [], quiet: true });
    const scanEnv = spawnCalls.find(c => c.bin !== 'which')!.opts.env as NodeJS.ProcessEnv;

    spawnCalls.length = 0;
    await new SpawnAdapter({ ...ADAPTER_REGISTRY.secrets, method: 'spawn', command: 'secretless-ai' })
      .run({ args: [], quiet: true });
    const secretsEnv = spawnCalls.find(c => c.bin !== 'which')!.opts.env as NodeJS.ProcessEnv;

    expect(scanEnv.NANOMIND_URL).toBe('http://127.0.0.1:871');
    expect(scanEnv.VAULT_ADDR).toBeUndefined();
    expect(secretsEnv.VAULT_ADDR).toBe('https://vault.corp:8200');
    expect(secretsEnv.NANOMIND_URL).toBeUndefined();
  });
});
