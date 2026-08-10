import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  admin,
  resolveApiKey,
  _internals,
  type AdminOptions,
  type PendingEnrollment,
} from '../../src/commands/admin.js';

function captureStdout(fn: () => Promise<number>): Promise<{ exitCode: number; out: string; err: string }> {
  const outChunks: string[] = [];
  const errChunks: string[] = [];
  const origOut = process.stdout.write;
  const origErr = process.stderr.write;
  process.stdout.write = ((chunk: any) => { outChunks.push(String(chunk)); return true; }) as any;
  process.stderr.write = ((chunk: any) => { errChunks.push(String(chunk)); return true; }) as any;
  const restore = () => { process.stdout.write = origOut; process.stderr.write = origErr; };
  return fn().then(exitCode => { restore(); return { exitCode, out: outChunks.join(''), err: errChunks.join('') }; })
    .catch(err => { restore(); throw err; });
}

const SAMPLE_ID = '11111111-2222-3333-4444-555555555555';

function pending(): PendingEnrollment[] {
  return [{ sensorId: SAMPLE_ID, publicKey: 'abcd1234', createdAt: '2026-06-26T00:00:00Z' }];
}

const ORIG_ENV = { ...process.env };

beforeEach(() => {
  // Isolate from any ambient admin key / registry override.
  delete process.env.OPENA2A_INTERNAL_API_KEY;
  delete process.env.INTERNAL_API_KEY;
  delete process.env.OPENA2A_REGISTRY_URL;
});

afterEach(() => {
  vi.restoreAllMocks();
  process.env = { ...ORIG_ENV };
});

describe('resolveApiKey', () => {
  it('prefers the explicit flag, then namespaced env, then INTERNAL_API_KEY', () => {
    expect(resolveApiKey('flag-key')).toBe('flag-key');
    process.env.INTERNAL_API_KEY = 'legacy';
    expect(resolveApiKey()).toBe('legacy');
    process.env.OPENA2A_INTERNAL_API_KEY = 'namespaced';
    expect(resolveApiKey()).toBe('namespaced');
  });

  it('returns null when no key is present or only whitespace', () => {
    expect(resolveApiKey()).toBeNull();
    process.env.INTERNAL_API_KEY = '   ';
    expect(resolveApiKey()).toBeNull();
  });
});

describe('admin sensors -- auth gating', () => {
  it('refuses every subcommand without a key and never calls the API', async () => {
    const spy = vi.spyOn(_internals, 'listPending');
    const { exitCode, err } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['list-pending'] }));
    expect(exitCode).toBe(1);
    expect(err).toMatch(/admin key/i);
    expect(spy).not.toHaveBeenCalled();
  });

  it('emits the missing-key error as JSON in --json mode', async () => {
    const { exitCode, out } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['list-pending'], json: true }));
    expect(exitCode).toBe(1);
    expect(JSON.parse(out).error).toMatch(/admin key/i);
  });
});

describe('admin sensors list-pending', () => {
  it('renders pending enrollments with an approve next-step (no dead end)', async () => {
    vi.spyOn(_internals, 'listPending').mockResolvedValue({ ok: true, status: 200, data: { pending: pending(), count: 1 } });
    const { exitCode, out } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['list-pending'], apiKey: 'k' }));
    expect(exitCode).toBe(0);
    expect(out).toContain(SAMPLE_ID);
    expect(out).toContain(`approve ${SAMPLE_ID}`);
  });

  it('shows an inbox-clear message on an empty list', async () => {
    vi.spyOn(_internals, 'listPending').mockResolvedValue({ ok: true, status: 200, data: { pending: [], count: 0 } });
    const { exitCode, out } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['pending'], apiKey: 'k' }));
    expect(exitCode).toBe(0);
    expect(out).toMatch(/Inbox clear/i);
  });

  it('emits machine-readable JSON with --json', async () => {
    vi.spyOn(_internals, 'listPending').mockResolvedValue({ ok: true, status: 200, data: { pending: pending(), count: 1 } });
    const { exitCode, out } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['ls'], apiKey: 'k', json: true }));
    expect(exitCode).toBe(0);
    const parsed = JSON.parse(out);
    expect(parsed.count).toBe(1);
    expect(parsed.pending[0].sensorId).toBe(SAMPLE_ID);
  });

  it('maps a 401 to an actionable scope/key message', async () => {
    vi.spyOn(_internals, 'listPending').mockResolvedValue({ ok: false, status: 401 });
    const { exitCode, err } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['list-pending'], apiKey: 'bad' }));
    expect(exitCode).toBe(1);
    expect(err).toMatch(/invalid|scope|401/i);
  });

  it('reports a network failure without throwing', async () => {
    vi.spyOn(_internals, 'listPending').mockRejectedValue(new Error('ECONNREFUSED'));
    const { exitCode, err } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['list-pending'], apiKey: 'k', registryUrl: 'https://example.test' }));
    expect(exitCode).toBe(1);
    expect(err).toMatch(/Could not reach the registry/i);
  });
});

describe('admin sensors approve', () => {
  it('validates the sensor id is a UUID before any call', async () => {
    const spy = vi.spyOn(_internals, 'approve');
    const { exitCode, err } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['approve', 'not-a-uuid'], apiKey: 'k', yes: true }));
    expect(exitCode).toBe(1);
    expect(err).toMatch(/not a valid sensor id/i);
    expect(spy).not.toHaveBeenCalled();
  });

  it('requires a sensor id', async () => {
    const { exitCode, err } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['approve'], apiKey: 'k', yes: true }));
    expect(exitCode).toBe(1);
    expect(err).toMatch(/sensor id is required/i);
  });

  it('approves with --yes and reports the verified state', async () => {
    const spy = vi.spyOn(_internals, 'approve').mockResolvedValue({ ok: true, status: 200, data: { sensorId: SAMPLE_ID, state: 'verified' } });
    const { exitCode, out } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['approve', SAMPLE_ID], apiKey: 'k', yes: true }));
    expect(exitCode).toBe(0);
    expect(spy).toHaveBeenCalledWith(expect.any(String), 'k', SAMPLE_ID);
    expect(out).toMatch(/verified/i);
  });

  it('refuses to approve non-interactively without --yes and does not call the API', async () => {
    const spy = vi.spyOn(_internals, 'approve');
    const { exitCode, out } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['approve', SAMPLE_ID], apiKey: 'k', json: true }));
    expect(exitCode).toBe(1);
    expect(JSON.parse(out).error).toMatch(/--yes/);
    expect(spy).not.toHaveBeenCalled();
  });

  it('maps a 404 (not pending) to a clear message', async () => {
    vi.spyOn(_internals, 'approve').mockResolvedValue({ ok: false, status: 404, error: 'enrollment is not pending' });
    const { exitCode, err } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['approve', SAMPLE_ID], apiKey: 'k', yes: true }));
    expect(exitCode).toBe(1);
    expect(err).toMatch(/not pending|404/i);
  });

  it('a global --ci does NOT consent to the mint without --yes', async () => {
    const spy = vi.spyOn(_internals, 'approve');
    const { exitCode, err } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['approve', SAMPLE_ID], apiKey: 'k', ci: true }));
    expect(exitCode).toBe(1);
    expect(err).toMatch(/--yes/);
    expect(spy).not.toHaveBeenCalled();
  });
});

describe('admin sensors reject', () => {
  it('rejects a pending id with --yes and hits the DELETE service-account path', async () => {
    vi.spyOn(_internals, 'listPending').mockResolvedValue({ ok: true, status: 200, data: { pending: pending(), count: 1 } });
    const spy = vi.spyOn(_internals, 'reject').mockResolvedValue({ ok: true, status: 200, data: {} });
    const { exitCode, out } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['reject', SAMPLE_ID], apiKey: 'k', yes: true }));
    expect(exitCode).toBe(0);
    expect(spy).toHaveBeenCalledWith(expect.any(String), 'k', SAMPLE_ID);
    expect(out).toMatch(/revoked/i);
  });

  it('refuses to revoke an id that is NOT in the pending inbox (footgun guard)', async () => {
    vi.spyOn(_internals, 'listPending').mockResolvedValue({ ok: true, status: 200, data: { pending: [], count: 0 } });
    const spy = vi.spyOn(_internals, 'reject');
    const { exitCode, err } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['reject', SAMPLE_ID], apiKey: 'k', yes: true }));
    expect(exitCode).toBe(1);
    expect(err).toMatch(/not a pending enrollment/i);
    expect(spy).not.toHaveBeenCalled();
  });

  it('refuses to reject non-interactively without --yes', async () => {
    vi.spyOn(_internals, 'listPending').mockResolvedValue({ ok: true, status: 200, data: { pending: pending(), count: 1 } });
    const spy = vi.spyOn(_internals, 'reject');
    const { exitCode, out } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['reject', SAMPLE_ID], apiKey: 'k', json: true }));
    expect(exitCode).toBe(1);
    expect(JSON.parse(out).error).toMatch(/--yes/);
    expect(spy).not.toHaveBeenCalled();
  });
});

describe('admin -- usage', () => {
  it('prints usage for an unknown subcommand', async () => {
    const { out } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['frobnicate'], apiKey: 'k' }));
    expect(out).toMatch(/Usage: opena2a admin sensors/);
  });

  it('accepts the bare `admin <verb>` shorthand (no `sensors` group word)', async () => {
    vi.spyOn(_internals, 'listPending').mockResolvedValue({ ok: true, status: 200, data: { pending: [], count: 0 } });
    const { exitCode, out } = await captureStdout(() =>
      admin({ subcommand: 'list-pending', args: [], apiKey: 'k' }));
    expect(exitCode).toBe(0);
    expect(out).toMatch(/Inbox clear/i);
  });
});

describe('admin -- key safety & host pinning', () => {
  it('never prints the admin key to stdout or stderr', async () => {
    const KEY = 'super-secret-admin-key-9f3a';
    vi.spyOn(_internals, 'approve').mockResolvedValue({ ok: true, status: 200, data: { sensorId: SAMPLE_ID, state: 'verified' } });
    const { out, err } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['approve', SAMPLE_ID], apiKey: KEY, yes: true }));
    expect(out).not.toContain(KEY);
    expect(err).not.toContain(KEY);
  });

  it('does NOT inherit an ambient OPENA2A_REGISTRY_URL (key stays host-pinned)', async () => {
    process.env.OPENA2A_REGISTRY_URL = 'https://evil.example.com';
    const spy = vi.spyOn(_internals, 'listPending').mockResolvedValue({ ok: true, status: 200, data: { pending: [], count: 0 } });
    const { exitCode } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['list-pending'], apiKey: 'k' }));
    expect(exitCode).toBe(0);
    // Default registry, NOT the poisoned env value.
    expect(spy).toHaveBeenCalledWith('https://api.oa2a.org', 'k');
  });

  it('warns when an explicit --registry points at a non-default host', async () => {
    vi.spyOn(_internals, 'listPending').mockResolvedValue({ ok: true, status: 200, data: { pending: [], count: 0 } });
    const { err } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['list-pending'], apiKey: 'k', registryUrl: 'https://my-registry.example.com' }));
    expect(err).toMatch(/Warning/);
    expect(err).toMatch(/trust this host/i);
  });

  it('does not warn for the default registry', async () => {
    vi.spyOn(_internals, 'listPending').mockResolvedValue({ ok: true, status: 200, data: { pending: [], count: 0 } });
    const { err } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['list-pending'], apiKey: 'k', registryUrl: 'https://api.oa2a.org' }));
    expect(err).not.toMatch(/Warning/);
  });

  it('emits a JSON error for an invalid --registry in --json mode', async () => {
    const spy = vi.spyOn(_internals, 'listPending');
    const { exitCode, out } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['list-pending'], apiKey: 'k', registryUrl: 'not a url', json: true }));
    expect(exitCode).toBe(1);
    expect(JSON.parse(out).error).toMatch(/Invalid registry URL/i);
    expect(spy).not.toHaveBeenCalled();
  });

  it('a non-interactive refusal prints one message (no duplicate Aborted)', async () => {
    const { err, out } = await captureStdout(() =>
      admin({ subcommand: 'sensors', args: ['approve', SAMPLE_ID], apiKey: 'k' }));
    expect(err).toMatch(/Refusing to approve/);
    expect(out).not.toMatch(/Aborted/);
  });
});

describe('_internals.request -- wire shape', () => {
  it('sends a Bearer auth header and parses JSON', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ pending: [], count: 0 }),
    });
    vi.stubGlobal('fetch', fetchMock);
    const res = await _internals.request('GET', 'https://api.oa2a.org/internal/telemetry/sensors/pending', 'secret-key');
    expect(res.ok).toBe(true);
    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe('GET');
    expect(init.headers.Authorization).toBe('Bearer secret-key');
    vi.unstubAllGlobals();
  });

  it('returns the server error string on a non-2xx response', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 409,
      json: async () => ({ error: 'key already enrolled' }),
    });
    vi.stubGlobal('fetch', fetchMock);
    const res = await _internals.request('POST', 'https://api.oa2a.org/x', 'k');
    expect(res.ok).toBe(false);
    expect(res.status).toBe(409);
    expect(res.error).toBe('key already enrolled');
    vi.unstubAllGlobals();
  });
});
