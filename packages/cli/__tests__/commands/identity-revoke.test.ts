import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// `identity revoke` must not state a retention period or a deletion the CLI
// cannot observe. The CLI used to print a fixed 30-day window and a
// permanent deletion after it, and put `retentionDays: 30` in its --json
// object, none of which came from the server. Any time value in --json must
// be the server's own, passed through unchanged.

const revokeAgent = vi.hoisted(() => vi.fn());

vi.mock('../../src/util/auth.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/util/auth.js')>();
  return { ...actual, loadAuth: () => null, saveAuth: vi.fn() };
});

vi.mock('../../src/util/aim-client.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/util/aim-client.js')>();
  return {
    ...actual,
    AimClient: class {
      revokeAgent = revokeAgent;
    },
    loadServerConfig: () => ({
      serverUrl: 'https://aim.example.test',
      accessToken: 'test-access-token',
      agentId: 'agent-123',
    }),
  };
});

const { identity } = await import('../../src/commands/identity.js');

const RETENTION_OR_DELETION = /30 days|retain|permanently|all data|delete/i;

let stdout: string;
let stderr: string;

beforeEach(() => {
  stdout = '';
  stderr = '';
  revokeAgent.mockReset();
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
    stdout += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
    stderr += String(chunk);
    return true;
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('identity revoke', () => {
  it('asks for confirmation without stating a retention period or a deletion', async () => {
    const code = await identity({ subcommand: 'revoke' });

    expect(code).toBe(1);
    expect(revokeAgent).not.toHaveBeenCalled();
    expect(stderr).toContain('This will revoke the agent on the server.');
    expect(stderr).toContain('To confirm, run: opena2a identity revoke --server cloud --ci');
    expect(stderr).toContain('To temporarily disable instead: opena2a identity suspend --server cloud');
    expect(stderr).not.toMatch(RETENTION_OR_DELETION);
  });

  it('reports the revoke without stating a retention period or a deletion', async () => {
    revokeAgent.mockResolvedValue({ message: 'Agent revoked' });

    const code = await identity({ subcommand: 'revoke', ci: true });

    expect(code).toBe(0);
    expect(revokeAgent).toHaveBeenCalledWith('agent-123');
    expect(stdout).toContain('Agent agent-123 revoked.');
    expect(stdout).toContain('To reactivate: opena2a identity reactivate --server cloud');
    expect(stdout).not.toMatch(RETENTION_OR_DELETION);
  });

  it('--json carries no retentionDays and no time value the server did not send', async () => {
    revokeAgent.mockResolvedValue({ message: 'Agent revoked' });

    const code = await identity({ subcommand: 'revoke', json: true });

    expect(code).toBe(0);
    const out = JSON.parse(stdout);
    expect(out).toEqual({ action: 'revoked', agentId: 'agent-123', message: 'Agent revoked' });
    expect(Object.keys(out)).not.toContain('retentionDays');
    expect(Object.keys(out)).not.toContain('retentionUntil');
  });

  it('--json passes the server retentionUntil through unchanged', async () => {
    revokeAgent.mockResolvedValue({ message: 'Agent revoked', retentionUntil: '2031-02-03T04:05:06Z' });

    const code = await identity({ subcommand: 'revoke', json: true });

    expect(code).toBe(0);
    const out = JSON.parse(stdout);
    expect(out.retentionUntil).toBe('2031-02-03T04:05:06Z');
    expect(Object.keys(out)).not.toContain('retentionDays');
  });

  it('--json is the CLI object alone when the server answers with no body', async () => {
    revokeAgent.mockResolvedValue(undefined);

    const code = await identity({ subcommand: 'revoke', json: true });

    expect(code).toBe(0);
    expect(JSON.parse(stdout)).toEqual({ action: 'revoked', agentId: 'agent-123' });
  });

  it('usage does not describe revoke as deleting the agent', async () => {
    await identity({ subcommand: 'no-such-subcommand' });

    const revokeLine = stderr.split('\n').find((line) => /^\s+revoke\s/.test(line));
    expect(revokeLine).toBeDefined();
    expect(revokeLine).not.toMatch(RETENTION_OR_DELETION);
    expect(revokeLine).not.toMatch(/irreversible/i);
  });
});
