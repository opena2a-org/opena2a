// Regression: the CLI never points a user at `registry.opena2a.org`.
//
// That host deliberately has NO DNS — it names the unreleased Registry
// FRONTEND, not the API. Do not "fix" a failure against it by creating the
// record (memory: reference_registry_opena2a_org_dns_is_deliberate).
//
// On a fresh install `opena2a config show` reported it as the registry URL and
// `opena2a trust <pkg>` failed with "fetch failed", while `scan --help`
// advertised `https://api.oa2a.org` — two conflicting defaults in one CLI. The
// cause was a stale PIN: `packages/cli/package.json` pinned `@opena2a/shared`
// at 0.1.0, whose DEFAULT_CONFIG shipped the dead host and which carried no
// migration at all. `trust` and `claim` then read `config.registry.url`
// directly and returned it because it was truthy.
//
// The pin is bumped, but the pin is not what this test guards — a pin can go
// stale again. What is guarded is the resolver: unset, blank and every known
// stale host must all resolve to the canonical API host, and no caller may
// carry its own fallback that could reintroduce a different answer.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const CANONICAL = 'https://api.oa2a.org';
const DEAD_FRONTEND = 'https://registry.opena2a.org';

/** Swap the shared package's config loader for one returning a chosen url. */
function mockSharedConfig(url: string | undefined) {
  vi.doMock('@opena2a/shared', () => ({
    loadUserConfig: () => ({
      version: 1,
      contribute: { enabled: false, consentedAt: null, consentVersion: '1.0' },
      registry: { url },
      llm: { enabled: false, consentedAt: null, consentVersion: '1.0' },
      preferences: { rememberedChoices: {} },
      telemetry: { scanCount: 0, contributePromptDismissedAt: null },
    }),
    isContributeEnabled: () => false,
    incrementScanCount: () => 1,
    shouldPromptContribute: () => false,
    dismissContributePrompt: () => undefined,
  }));
}

async function resolve(configUrl: string | undefined): Promise<string> {
  vi.resetModules();
  mockSharedConfig(configUrl);
  const { getRegistryUrl } = await import('../../src/util/report-submission.js');
  return getRegistryUrl();
}

describe('registry URL resolution', () => {
  beforeEach(() => {
    vi.resetModules();
    delete process.env.OPENA2A_REGISTRY_URL;
  });
  afterEach(() => {
    vi.doUnmock('@opena2a/shared');
    vi.resetModules();
  });

  it('a fresh install resolves to the canonical API host, not the frontend', async () => {
    // The exact shape a fresh install had under the stale pin.
    expect(await resolve(DEAD_FRONTEND)).toBe(CANONICAL);
  });

  it('an unset or blank config url resolves to the canonical API host', async () => {
    // The shape a fresh install has under the CURRENT pin. Both must land in
    // the same place, or the answer depends on which pin happens to be
    // installed — which is the whole defect.
    expect(await resolve(undefined)).toBe(CANONICAL);
    expect(await resolve('')).toBe(CANONICAL);
    expect(await resolve('   ')).toBe(CANONICAL);
  });

  it.each([
    'https://registry.opena2a.org',
    'http://registry.opena2a.org',
    'https://registry.opena2a.org/',
    'https://registry.opena2a.org/v1/trust',
    'https://api.opena2a.org',
    'http://api.opena2a.org',
  ])('rewrites the stale host %s', async (stale) => {
    expect(await resolve(stale)).toBe(CANONICAL);
  });

  it('a deliberately configured registry is left alone', async () => {
    // The rewrite must not become "always ignore the user's config" — a
    // self-hosted registry is a supported setup.
    expect(await resolve('https://registry.internal.example.com')).toBe(
      'https://registry.internal.example.com',
    );
  });

  it('a lookalike host is not rewritten', async () => {
    // `startsWith` on a bare host would swallow this one.
    expect(await resolve('https://not-registry.opena2a.org')).toBe(
      'https://not-registry.opena2a.org',
    );
  });

  it('concurrent callers all get the same answer', async () => {
    // The resolver does `await import('@opena2a/shared')` and the shared
    // `loadUserConfig()` REWRITES config.json when it migrates a stale host, so
    // several commands resolving at once are concurrent readers of a file one
    // of them may be writing. The contract callers depend on is that they all
    // agree — a run where one command talks to a different registry than
    // another is the defect this whole change exists to remove.
    vi.resetModules();
    mockSharedConfig(DEAD_FRONTEND);
    const { getRegistryUrl } = await import('../../src/util/report-submission.js');

    const answers = await Promise.all(Array.from({ length: 12 }, () => getRegistryUrl()));
    expect(new Set(answers).size, `divergent answers: ${[...new Set(answers)].join(', ')}`).toBe(1);
    expect(answers[0]).toBe(CANONICAL);
  });

  it('no command carries its own registry fallback constant', async () => {
    // The two conflicting defaults existed because each command declared its
    // own. `admin` is the documented exception: it transmits the internal admin
    // key and deliberately refuses to follow ambient config.
    const { readdirSync, readFileSync } = await import('node:fs');
    const { join } = await import('node:path');
    const dir = join(__dirname, '..', '..', 'src', 'commands');
    const offenders = readdirSync(dir)
      .filter(f => f.endsWith('.ts') && f !== 'admin.ts')
      .filter(f => /const\s+DEFAULT_REGISTRY_(URL|BASE)\s*=/.test(readFileSync(join(dir, f), 'utf-8')));
    expect(offenders).toEqual([]);
  });
});
