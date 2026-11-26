import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// `identity suspend` and `identity reactivate` --json put the server's
// response first and the CLI's own action and agentId last, so a server
// member of the same name cannot replace them. A body that is not an object
// (a string, an array, no body) adds nothing, as with revoke.

const suspendAgent = vi.hoisted(() => vi.fn());
const reactivateAgent = vi.hoisted(() => vi.fn());

vi.mock('../../src/util/auth.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/util/auth.js')>();
  return { ...actual, loadAuth: () => null, saveAuth: vi.fn() };
});

vi.mock('../../src/util/aim-client.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/util/aim-client.js')>();
  return {
    ...actual,
    AimClient: class {
      suspendAgent = suspendAgent;
      reactivateAgent = reactivateAgent;
    },
    loadServerConfig: () => ({
      serverUrl: 'https://aim.example.test',
      accessToken: 'test-access-token',
      agentId: 'agent-123',
    }),
  };
});

const { identity } = await import('../../src/commands/identity.js');

let stdout: string;

beforeEach(() => {
  stdout = '';
  suspendAgent.mockReset();
  reactivateAgent.mockReset();
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
    stdout += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
});

const CASES = [
  { subcommand: 'suspend', action: 'suspended', mock: suspendAgent },
  { subcommand: 'reactivate', action: 'reactivated', mock: reactivateAgent },
] as const;

for (const { subcommand, action, mock } of CASES) {
  describe(`identity ${subcommand} --json`, () => {
    it('passes server members through alongside the CLI keys', async () => {
      mock.mockResolvedValue({ message: 'ok', status: action });

      const code = await identity({ subcommand, json: true });

      expect(code).toBe(0);
      expect(mock).toHaveBeenCalledWith('agent-123');
      expect(JSON.parse(stdout)).toEqual({ message: 'ok', status: action, action, agentId: 'agent-123' });
    });

    it('keeps the CLI action and agentId when the server sends members of the same name', async () => {
      mock.mockResolvedValue({ action: 'deleted', agentId: 'agent-999', message: 'ok' });

      const code = await identity({ subcommand, json: true });

      expect(code).toBe(0);
      expect(JSON.parse(stdout)).toEqual({ action, agentId: 'agent-123', message: 'ok' });
    });

    it('adds no index keys when the server answers with a string', async () => {
      mock.mockResolvedValue('ok');

      const code = await identity({ subcommand, json: true });

      expect(code).toBe(0);
      expect(JSON.parse(stdout)).toEqual({ action, agentId: 'agent-123' });
    });

    it('is the CLI object alone when the server answers with an array', async () => {
      mock.mockResolvedValue(['ok']);

      const code = await identity({ subcommand, json: true });

      expect(code).toBe(0);
      expect(JSON.parse(stdout)).toEqual({ action, agentId: 'agent-123' });
    });

    it('is the CLI object alone when the server answers with no body', async () => {
      mock.mockResolvedValue(undefined);

      const code = await identity({ subcommand, json: true });

      expect(code).toBe(0);
      expect(JSON.parse(stdout)).toEqual({ action, agentId: 'agent-123' });
    });
  });
}
