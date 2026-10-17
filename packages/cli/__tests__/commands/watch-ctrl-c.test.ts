import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// `opena2a watch` prints `Polling every 3s (Ctrl+C to stop)` on its banner,
// and its --help says Ctrl+C exits 0. The command installed its SIGINT and
// SIGTERM handlers after printing the banner, so an interrupt that arrived
// between the two, as a script that waits for that line sends, ended the
// process by the signal's default action instead of exit 0. The handlers
// must be in place by the time the banner says Ctrl+C stops the watch.

const getAgentActivity = vi.hoisted(() => vi.fn());

vi.mock('../../src/util/auth.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/util/auth.js')>();
  return {
    ...actual,
    loadAuth: () => ({
      serverUrl: 'http://127.0.0.1:9',
      accessToken: 'test-access-token',
      refreshToken: 'test-refresh-token',
      expiresAt: '2999-01-01T00:00:00.000Z',
      tokenType: 'Bearer',
      authenticatedAt: '2026-01-01T00:00:00.000Z',
    }),
    isAuthValid: () => true,
  };
});

vi.mock('../../src/util/aim-client.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/util/aim-client.js')>();
  return {
    ...actual,
    AimClient: class {
      getAgentActivity = getAgentActivity;
    },
    loadServerConfig: () => ({
      serverUrl: 'http://127.0.0.1:9',
      accessToken: 'test-access-token',
      agentId: 'agent-1',
    }),
  };
});

const { watch } = await import('../../src/commands/watch.js');

const SIGNALS = ['SIGINT', 'SIGTERM'] as const;

let stdout: string;

beforeEach(() => {
  stdout = '';
  getAgentActivity.mockReset();
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('opena2a watch', () => {
  it('handles Ctrl+C from the moment its banner says Ctrl+C stops it, and exits 0', async () => {
    const before = new Map(SIGNALS.map((signal) => [signal, new Set(process.listeners(signal))]));
    /** The listeners `watch` has added for `signal` so far. */
    const added = (signal: (typeof SIGNALS)[number]): NodeJS.SignalsListener[] =>
      process.listeners(signal).filter((listener) => !before.get(signal)!.has(listener));
    /** The number of handlers in place when the banner line was written. */
    let atBanner: Record<string, number> | undefined;

    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      const text = String(chunk);
      stdout += text;
      if (atBanner === undefined && text.includes('Ctrl+C to stop')) {
        atBanner = Object.fromEntries(SIGNALS.map((signal) => [signal, added(signal).length]));
        // Ctrl+C the instant the line is visible.
        for (const listener of added('SIGINT')) listener('SIGINT');
      }
      return true;
    });
    // A poll that runs anyway, because no handler was in place at the banner,
    // stops the watch here, so the case fails on its assertions, not its timeout.
    getAgentActivity.mockImplementation(async () => {
      for (const listener of added('SIGINT')) listener('SIGINT');
      return { events: [] };
    });

    const code = await watch({ interval: 1 });

    expect(atBanner, 'the banner line was printed').toBeDefined();
    expect(atBanner, 'handlers in place when the banner was written').toEqual({ SIGINT: 1, SIGTERM: 1 });
    expect(code).toBe(0);
    expect(stdout).toContain('Stopped watching.');
    for (const signal of SIGNALS) {
      expect(added(signal), `${signal} handler removed once the watch ended`).toEqual([]);
    }
  });
});
