/**
 * One resolver, one contract per binary, every route to a child hands it the
 * same environment (#246).
 *
 * child-env.test.ts pins buildChildEnv; child-env-wiring.test.ts pins the
 * adapters. This file pins the layer between them: `CHILD_ENV_CONTRACTS` as
 * the single declaration point, `childEnv` / `inheritEnv` as the only
 * resolvers, and — the part no earlier test could reach — the direct spawns in
 * index.ts, router.ts, commands/review.ts and shield/llm-backend.ts, run for
 * real under a mocked `node:child_process` so the assertion is on the code
 * each site calls, not on a copy of its environment construction.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

interface Captured { bin: string; args: string[]; opts: Record<string, unknown> }
const spawnCalls: Captured[] = [];
const execFileSyncCalls: Captured[] = [];

vi.mock('node:child_process', () => ({
  spawn: vi.fn((bin: string, args: string[], opts: Record<string, unknown>) => {
    spawnCalls.push({ bin, args, opts: opts ?? {} });
    const noop = { on: vi.fn() };
    return {
      stdout: noop,
      stderr: noop,
      unref: vi.fn(),
      on: vi.fn((event: string, handler: (code: number) => void) => {
        if (event === 'close') setTimeout(() => handler(0), 0);
      }),
    };
  }),
  execFileSync: vi.fn((bin: string, args: string[], opts: Record<string, unknown>) => {
    execFileSyncCalls.push({ bin, args, opts: opts ?? {} });
    if (bin === 'claude') return JSON.stringify({ result: 'stubbed' });
    if (bin === 'which') return '/stub/bin/claude\n';
    throw new Error(`${bin}: not found`);
  }),
}));

const { CHILD_ENV_CONTRACTS, childEnv, inheritEnv, ADAPTER_REGISTRY } =
  await import('../../src/adapters/registry.js');
const { buildChildEnv, probeEnv } = await import('../../src/util/child-env.js');
const { SpawnAdapter } = await import('../../src/adapters/spawn.js');
const { PythonAdapter } = await import('../../src/adapters/python.js');
const { DockerAdapter } = await import('../../src/adapters/docker.js');
const { callClaudeCode, isClaudeCodeAvailable } = await import('../../src/shield/llm-backend.js');
const { spawnHmaCheckFromRouter } = await import('../../src/router.js');
const { runHmaPhase } = await import('../../src/commands/review.js');
// index.ts is the CLI entry point; it starts the CLI only when it is
// `require.main`, so importing it here runs nothing.
const { spawnHmaCheck, spawnHackmyagent } = await import('../../src/index.js');

/** The hackmyagent contract as declared at base (registry.ts:20-37 and :63-73). */
const HACKMYAGENT_EXACT = [
  'NANOMIND_URL', 'NANOMIND_GUARD_SOCK',
  'ANTHROPIC_API_KEY',
  'REGISTRY_URL', 'REGISTRY_API_KEY',
  'ATC_TOKEN', 'INTERNAL_API_KEY', 'CI_SCAN_HMAC_SECRET',
  'OPENA2A_REGISTRY_TOKEN',
  'HMA_COMMUNITY_SECRET', 'HACKMYAGENT_LLM_BUDGET',
  'HMA_EXPORT_TRAINING', 'HMA_INTEGRITY_DEBUG',
  'ARP_TELEMETRY_DISABLED',
  'AWS_REGION', 'AWS_ACCOUNT_ID', 'NODE_ENV',
  // node toolchain, for the `npx` resolution every route can take
  'npm_config_key',
];
const HACKMYAGENT_PREFIXES = [
  'HMA_',
  'npm_config_', 'NPM_CONFIG_', 'NODE_', 'NVM_', 'COREPACK_', 'YARN_', 'PNPM_', 'VOLTA_', 'FNM_',
];

const CITATION_NAMES = ['HMA_CLI_PREFIX', 'HMA_CHECK_COMMAND', 'HMA_FULL_SCAN_HINT'];

function keysWithout(env: NodeJS.ProcessEnv, drop: readonly string[]): string[] {
  return Object.keys(env).filter(k => !drop.includes(k)).sort();
}

function lastSpawn(pred: (c: Captured) => boolean): NodeJS.ProcessEnv {
  const hit = [...spawnCalls].reverse().find(pred);
  if (!hit) throw new Error(`no spawn matched: ${spawnCalls.map(c => `${c.bin} ${c.args.join(' ')}`).join(' | ')}`);
  return hit.opts.env as NodeJS.ProcessEnv;
}

const isHmaRun = (c: Captured): boolean =>
  (c.bin === 'hackmyagent' && c.args[0] !== '--version') ||
  (c.bin === 'npx' && c.args[0] === 'hackmyagent' && c.args[1] !== '--version');

let stderrLines: string[] = [];
let stderrSpy: ReturnType<typeof vi.spyOn> | undefined;

beforeEach(() => {
  spawnCalls.length = 0;
  execFileSyncCalls.length = 0;
  stderrLines = [];
  stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: unknown) => {
    stderrLines.push(String(chunk));
    return true;
  }) as never);
  vi.stubEnv('GITHUB_TOKEN', 'PLANTED-gh');
  vi.stubEnv('NANOMIND_URL', 'http://127.0.0.1:871');
  vi.stubEnv('ANTHROPIC_API_KEY', 'PLANTED-anthropic');
  vi.stubEnv('OPENAI_API_KEY', 'PLANTED-openai');
  vi.stubEnv('DOCKER_HOST', 'unix:///run/user/1000/docker.sock');
  vi.stubEnv('VIRTUAL_ENV', '/opt/venv');
  vi.stubEnv('HMA_CLI_PREFIX', 'opena2a');
  vi.stubEnv('CLAUDECODE', '');
  delete process.env.CLAUDECODE;
  delete process.env.OPENA2A_CHILD_ENV_ALLOW;
});

afterEach(() => {
  stderrSpy?.mockRestore();
  vi.unstubAllEnvs();
});

// ---------------------------------------------------------------------------
// AC1 — one declaration point, one resolver
// ---------------------------------------------------------------------------

describe('CHILD_ENV_CONTRACTS, childEnv and inheritEnv (#246)', () => {
  it('OPA-14.AC1 CHILD_ENV_CONTRACTS is keyed by binary and carries the AdapterConfig env shape', () => {
    for (const binary of ['hackmyagent', 'claude', 'secretless-ai']) {
      expect(CHILD_ENV_CONTRACTS, `contract for ${binary}`).toHaveProperty(binary);
    }
    for (const [binary, contract] of Object.entries(CHILD_ENV_CONTRACTS)) {
      const keys = Object.keys(contract).sort();
      expect(keys.every(k => ['envAllow', 'envAllowPrefixes', 'envInherit'].includes(k)), binary).toBe(true);
      if (contract.envInherit) {
        expect(contract.envAllow, `${binary}: envInherit declares no allowlist`).toBeUndefined();
      } else {
        expect(Array.isArray(contract.envAllow) || Array.isArray(contract.envAllowPrefixes), binary).toBe(true);
      }
    }
    expect(CHILD_ENV_CONTRACTS['secretless-ai']).toEqual({ envInherit: true });
  });

  it('OPA-14.AC1 childEnv("hackmyagent") is buildChildEnv over the base contract plus the node toolchain', () => {
    const contract = CHILD_ENV_CONTRACTS.hackmyagent;
    expect([...contract.envAllow!].sort()).toEqual([...HACKMYAGENT_EXACT].sort());
    expect([...contract.envAllowPrefixes!].sort()).toEqual([...HACKMYAGENT_PREFIXES].sort());

    vi.stubEnv('HMA_INTEGRITY_DEBUG', '1');
    vi.stubEnv('NVM_DIR', '/opt/nvm');
    const expected = buildChildEnv(
      { allow: contract.envAllow, allowPrefixes: contract.envAllowPrefixes },
      process.env,
    );
    expect(childEnv('hackmyagent')).toEqual(expected);
    expect(childEnv('hackmyagent').NANOMIND_URL).toBe('http://127.0.0.1:871');
    expect(childEnv('hackmyagent').NVM_DIR).toBe('/opt/nvm');
    expect(childEnv('hackmyagent').GITHUB_TOKEN).toBeUndefined();
  });

  it('OPA-14.AC1 `set` entries are applied last and win over the contract', () => {
    const env = childEnv('hackmyagent', {
      set: { HMA_CHECK_COMMAND: 'opena2a check', NANOMIND_URL: 'http://override:1' },
    });
    expect(env.HMA_CHECK_COMMAND).toBe('opena2a check');
    expect(env.NANOMIND_URL).toBe('http://override:1');
    // A `set` cannot reinstate the hatch.
    expect(childEnv('hackmyagent', { set: { OPENA2A_CHILD_ENV_ALLOW: 'GITHUB_TOKEN' } }))
      .not.toHaveProperty('OPENA2A_CHILD_ENV_ALLOW');
  });

  it('OPA-14.AC1 childEnv of a binary with no contract throws rather than returning an environment', () => {
    expect(() => childEnv('no-such-binary')).toThrow(/No child-environment contract.*no-such-binary/);
    // Prototype keys are not contracts either.
    expect(() => childEnv('constructor')).toThrow();
    expect(() => childEnv('toString')).toThrow();
  });

  it('OPA-14.AC1 inheritEnv() is the parent environment verbatim minus OPENA2A_CHILD_ENV_ALLOW', () => {
    vi.stubEnv('OPENA2A_CHILD_ENV_ALLOW', 'GITHUB_TOKEN');
    const env = inheritEnv();
    expect(env).not.toHaveProperty('OPENA2A_CHILD_ENV_ALLOW');
    const parent = { ...process.env };
    delete parent.OPENA2A_CHILD_ENV_ALLOW;
    expect(env).toEqual(parent);
    expect(env.GITHUB_TOKEN).toBe('PLANTED-gh');
    expect(env.OPENAI_API_KEY).toBe('PLANTED-openai');
  });

  it('OPA-14.AC1 probeEnv stays the version-probe environment and ignores the hatch', () => {
    vi.stubEnv('OPENA2A_CHILD_ENV_ALLOW', 'GITHUB_TOKEN');
    const probe = probeEnv(CHILD_ENV_CONTRACTS.hackmyagent.envAllowPrefixes);
    expect(probe.GITHUB_TOKEN).toBeUndefined();
    expect(probe.NANOMIND_URL).toBeUndefined();
    expect(probe.ANTHROPIC_API_KEY).toBeUndefined();
    expect(probe.PATH).toBe(process.env.PATH);
    expect(probe).not.toHaveProperty('OPENA2A_CHILD_ENV_ALLOW');
  });

  it('OPA-14.AC1 ADAPTER_REGISTRY entries obtain their environment through the contracts', async () => {
    expect(ADAPTER_REGISTRY.scan.envAllow).toEqual(CHILD_ENV_CONTRACTS.hackmyagent.envAllow);
    expect(ADAPTER_REGISTRY.scan.envAllowPrefixes).toEqual(CHILD_ENV_CONTRACTS.hackmyagent.envAllowPrefixes);
    expect(ADAPTER_REGISTRY.secrets.envInherit).toBe(true);
    expect(ADAPTER_REGISTRY.broker.envInherit).toBe(true);
    expect(ADAPTER_REGISTRY.registry.envAllowPrefixes).toEqual(CHILD_ENV_CONTRACTS['ai-trust'].envAllowPrefixes);
    expect(ADAPTER_REGISTRY.train.envAllow).toEqual(CHILD_ENV_CONTRACTS.docker.envAllow);
    expect(ADAPTER_REGISTRY.crypto.envAllow).toEqual(CHILD_ENV_CONTRACTS.cryptoserve.envAllow);

    await new SpawnAdapter({ ...ADAPTER_REGISTRY.scan, method: 'spawn', command: 'hackmyagent' })
      .run({ args: [], quiet: true });
    const scanEnv = lastSpawn(isHmaRun);
    expect(Object.keys(scanEnv).sort()).toEqual(Object.keys(childEnv('hackmyagent')).sort());
  });
});

// ---------------------------------------------------------------------------
// AC4 — every route to the delegated scanner hands it the same environment
// ---------------------------------------------------------------------------

describe('every route to hackmyagent (#246)', () => {
  async function captureRoutes(): Promise<Record<string, NodeJS.ProcessEnv>> {
    const routes: Record<string, NodeJS.ProcessEnv> = {};

    spawnCalls.length = 0;
    await spawnHmaCheck('express', [], {});
    routes.spawnHmaCheck = lastSpawn(isHmaRun);

    spawnCalls.length = 0;
    await spawnHackmyagent(['scan-soul', '--explain']);
    routes.spawnHackmyagent = lastSpawn(isHmaRun);

    spawnCalls.length = 0;
    await spawnHmaCheckFromRouter('express', [], {});
    routes.spawnHmaCheckFromRouter = lastSpawn(isHmaRun);

    spawnCalls.length = 0;
    await runHmaPhase('.');
    routes.reviewSecure = lastSpawn(c => c.bin === 'npx' && c.args.includes('secure'));

    spawnCalls.length = 0;
    await new SpawnAdapter({ ...ADAPTER_REGISTRY.scan, method: 'spawn', command: 'hackmyagent' })
      .run({ args: [], quiet: true });
    routes.scanAdapter = lastSpawn(isHmaRun);

    return routes;
  }

  it('OPA-14.AC4 the five routes hand the scanner byte-identical key sets once the citation names are removed', async () => {
    const routes = await captureRoutes();
    expect(Object.keys(routes)).toHaveLength(5);

    const keySets = Object.fromEntries(
      Object.entries(routes).map(([name, env]) => [name, keysWithout(env, CITATION_NAMES)]),
    );
    const reference = keySets.scanAdapter;
    for (const [name, keys] of Object.entries(keySets)) {
      expect(keys, `${name} key set differs from the scan adapter's`).toEqual(reference);
    }
    // The direct sites still set the three citation names they set at base.
    for (const site of ['spawnHmaCheck', 'spawnHackmyagent', 'spawnHmaCheckFromRouter']) {
      expect(routes[site].HMA_CLI_PREFIX).toBe('opena2a');
      expect(routes[site].HMA_CHECK_COMMAND).toBe('opena2a check');
      expect(routes[site].HMA_FULL_SCAN_HINT).toBe('opena2a review');
    }
  });

  it('OPA-14.AC4 every route forwards NANOMIND_URL and none forwards GITHUB_TOKEN', async () => {
    const routes = await captureRoutes();
    for (const [name, env] of Object.entries(routes)) {
      expect(env.NANOMIND_URL, `${name} forwards NANOMIND_URL`).toBe('http://127.0.0.1:871');
      expect(env.GITHUB_TOKEN, `${name} must not forward GITHUB_TOKEN`).toBeUndefined();
      // ANTHROPIC_API_KEY is declared by the hackmyagent contract (analyst
      // escalation) and is forwarded on purpose; the undeclared plants are not.
      const values = Object.values(env).join('\n');
      expect(values, `${name} leaked GITHUB_TOKEN's value`).not.toContain('PLANTED-gh');
      expect(values, `${name} leaked OPENAI_API_KEY's value`).not.toContain('PLANTED-openai');
    }
  });

  it('OPA-14.AC4 the not-installed npx fallback of each direct site is on the same contract', () => {
    // Both spawns of each direct site resolve through childEnv; the fallback
    // is the one that runs on a machine without a PATH hackmyagent, which is
    // exactly where `npx` needs the node-toolchain prefixes.
    const fallback = childEnv('hackmyagent', { set: { HMA_CLI_PREFIX: 'opena2a' } });
    expect(fallback.NANOMIND_URL).toBe('http://127.0.0.1:871');
    expect(fallback.GITHUB_TOKEN).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// AC6 — a credential-shaped name no contract declares reaches no fixed site
// ---------------------------------------------------------------------------

describe('the seven fixed sites (#246)', () => {
  interface Site {
    name: string;
    declared: string;
    declaredValue: string;
    capture: () => Promise<NodeJS.ProcessEnv>;
  }

  const sites: Site[] = [
    {
      name: 'index.ts spawnHmaCheck',
      declared: 'NANOMIND_URL', declaredValue: 'http://127.0.0.1:871',
      capture: async () => { await spawnHmaCheck('express', [], {}); return lastSpawn(isHmaRun); },
    },
    {
      name: 'index.ts spawnHackmyagent',
      declared: 'NANOMIND_URL', declaredValue: 'http://127.0.0.1:871',
      capture: async () => { await spawnHackmyagent(['scan-soul', '--explain']); return lastSpawn(isHmaRun); },
    },
    {
      name: 'router.ts spawnHmaCheckFromRouter',
      declared: 'NANOMIND_URL', declaredValue: 'http://127.0.0.1:871',
      capture: async () => { await spawnHmaCheckFromRouter('express', [], {}); return lastSpawn(isHmaRun); },
    },
    {
      name: 'shield/llm-backend.ts callClaudeCode',
      declared: 'ANTHROPIC_API_KEY', declaredValue: 'PLANTED-anthropic',
      capture: async () => {
        expect(callClaudeCode('system', 'user', 100)?.text).toBe('stubbed');
        const call = execFileSyncCalls.find(c => c.bin === 'claude')!;
        return call.opts.env as NodeJS.ProcessEnv;
      },
    },
    {
      name: 'adapters/spawn.ts toolEnv',
      declared: 'NANOMIND_URL', declaredValue: 'http://127.0.0.1:871',
      capture: async () => {
        await new SpawnAdapter({ ...ADAPTER_REGISTRY.scan, method: 'spawn', command: 'hackmyagent' })
          .run({ args: [], quiet: true });
        return lastSpawn(isHmaRun);
      },
    },
    {
      name: 'adapters/python.ts toolEnv',
      declared: 'VIRTUAL_ENV', declaredValue: '/opt/venv',
      capture: async () => {
        await new PythonAdapter(ADAPTER_REGISTRY.crypto).run({ args: [], quiet: true });
        return lastSpawn(c => c.args[0] === '-m');
      },
    },
    {
      name: 'adapters/docker.ts toolEnv',
      declared: 'DOCKER_HOST', declaredValue: 'unix:///run/user/1000/docker.sock',
      capture: async () => {
        await new DockerAdapter(ADAPTER_REGISTRY.train).run({ args: [], quiet: true });
        return lastSpawn(c => c.bin === 'docker' && c.args[0] === 'run');
      },
    },
  ];

  for (const site of sites) {
    it(`OPA-14.AC6 ${site.name}: lacks GITHUB_TOKEN and carries ${site.declared}`, async () => {
      const env = await site.capture();
      expect(env, `${site.name} passed an env`).toBeDefined();
      expect(env.GITHUB_TOKEN).toBeUndefined();
      expect(env[site.declared]).toBe(site.declaredValue);
      expect(env).not.toHaveProperty('OPENA2A_CHILD_ENV_ALLOW');
    });
  }

  it('OPA-14.AC6 the ANTHROPIC_API_KEY the claude contract declares does not reach the hackmyagent-free sites', async () => {
    // A name declared by one contract is not thereby declared by another:
    // docker and python never see the model credential.
    await new DockerAdapter(ADAPTER_REGISTRY.train).run({ args: [], quiet: true });
    expect(lastSpawn(c => c.bin === 'docker' && c.args[0] === 'run').ANTHROPIC_API_KEY).toBeUndefined();
    await new PythonAdapter(ADAPTER_REGISTRY.crypto).run({ args: [], quiet: true });
    expect(lastSpawn(c => c.args[0] === '-m').ANTHROPIC_API_KEY).toBeUndefined();
  });

  it('OPA-14.AC6 the which-claude probe sees neither the model credential nor GITHUB_TOKEN', () => {
    expect(isClaudeCodeAvailable()).toBe(true);
    const probe = execFileSyncCalls.find(c => c.bin === 'which')!.opts.env as NodeJS.ProcessEnv;
    expect(probe).toBeDefined();
    expect(probe.ANTHROPIC_API_KEY).toBeUndefined();
    expect(probe.GITHUB_TOKEN).toBeUndefined();
    expect(probe.PATH).toBe(process.env.PATH);
  });

  it('OPA-14.AC6 with OPENA2A_CHILD_ENV_ALLOW=GITHUB_TOKEN a childEnv route forwards it, reports it, and still drops the hatch', async () => {
    vi.stubEnv('OPENA2A_CHILD_ENV_ALLOW', 'GITHUB_TOKEN');
    await spawnHmaCheck('express', [], {});
    const env = lastSpawn(isHmaRun);
    expect(env.GITHUB_TOKEN).toBe('PLANTED-gh');
    expect(env).not.toHaveProperty('OPENA2A_CHILD_ENV_ALLOW');
    expect(env.NANOMIND_URL).toBe('http://127.0.0.1:871');
    expect(stderrLines.join('')).toMatch(/OPENA2A_CHILD_ENV_ALLOW widened the child environment: GITHUB_TOKEN/);

    // The model CLI route widens the same way.
    callClaudeCode('system', 'user', 100);
    const claude = execFileSyncCalls.find(c => c.bin === 'claude')!.opts.env as NodeJS.ProcessEnv;
    expect(claude.GITHUB_TOKEN).toBe('PLANTED-gh');
    expect(claude).not.toHaveProperty('OPENA2A_CHILD_ENV_ALLOW');
  });

  it('OPA-14.AC6 the envInherit route forwards GITHUB_TOKEN and OPENAI_API_KEY as before and lacks the hatch', async () => {
    vi.stubEnv('OPENA2A_CHILD_ENV_ALLOW', 'GITHUB_TOKEN');
    await new SpawnAdapter({ ...ADAPTER_REGISTRY.secrets, method: 'spawn', command: 'secretless-ai' })
      .run({ args: [], quiet: true });
    const env = lastSpawn(c => c.bin !== 'which');
    expect(env.GITHUB_TOKEN).toBe('PLANTED-gh');
    expect(env.OPENAI_API_KEY).toBe('PLANTED-openai');
    // At base adapters/spawn.ts:14 forwarded the hatch to the child.
    expect(env).not.toHaveProperty('OPENA2A_CHILD_ENV_ALLOW');
  });

  it('OPA-14.AC6 the envInherit entries remain exactly broker and secrets', () => {
    const exempt = Object.keys(ADAPTER_REGISTRY).filter(n => ADAPTER_REGISTRY[n].envInherit);
    expect(exempt.sort()).toEqual(['broker', 'secrets']);
    const inheriting = Object.entries(CHILD_ENV_CONTRACTS).filter(([, c]) => c.envInherit).map(([b]) => b);
    expect(inheriting).toEqual(['secretless-ai']);
  });
});
