/**
 * A confirmed natural-language match to whoami, login, logout, config or
 * shield runs the same handler as typing the command.
 *
 * Those commands are registered only in Commander (index.ts); dispatchCommand
 * had no entry for them and fell through to createAdapter, which printed
 * "Unknown command" and exited 1.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const login = vi.fn(async () => 0);
const logout = vi.fn(async () => 0);
const whoami = vi.fn(async () => 0);
const runConfig = vi.fn(async () => 0);
const shield = vi.fn(async () => 0);

vi.mock('../../src/commands/login.js', () => ({ login, logout, whoami }));
vi.mock('../../src/commands/config.js', () => ({ runConfig }));
vi.mock('../../src/commands/shield.js', () => ({ shield }));

const { dispatchCommand } = await import('../../src/router.js');

describe('dispatchCommand for Commander-only commands', () => {
  let stderr: string;

  beforeEach(() => {
    vi.clearAllMocks();
    stderr = '';
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      stderr += String(chunk);
      return true;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('runs whoami', async () => {
    expect(await dispatchCommand('whoami', [])).toBe(0);
    expect(whoami).toHaveBeenCalledWith({ format: 'text', json: false });
    expect(stderr).not.toContain('Unknown command');
  });

  it('runs config show', async () => {
    expect(await dispatchCommand('config', ['show'])).toBe(0);
    expect(runConfig).toHaveBeenCalledWith('show', undefined, undefined, { enable: false, disable: false });
    expect(stderr).not.toContain('Unknown command');
  });

  it('passes config set and --enable through', async () => {
    await dispatchCommand('config', ['set', 'llm', 'on']);
    expect(runConfig).toHaveBeenLastCalledWith('set', 'llm', 'on', { enable: false, disable: false });
    await dispatchCommand('config', ['contribute', '--enable']);
    expect(runConfig).toHaveBeenLastCalledWith('contribute', undefined, undefined, { enable: true, disable: false });
  });

  it('runs login with --server', async () => {
    expect(await dispatchCommand('login', ['--server', 'localhost:8080'])).toBe(0);
    expect(login).toHaveBeenCalledWith({ server: 'localhost:8080', ci: false, format: 'text', json: false });
  });

  it('runs logout', async () => {
    expect(await dispatchCommand('logout', [], { format: 'json' })).toBe(0);
    expect(logout).toHaveBeenCalledWith({ format: 'json', json: false });
  });

  it('runs shield init with its flags', async () => {
    expect(await dispatchCommand('shield', ['init', '--dir', '/tmp/x', '--shell-hook'])).toBe(0);
    expect(shield).toHaveBeenCalledWith(expect.objectContaining({
      subcommand: 'init',
      args: [],
      dir: '/tmp/x',
      shellHook: true,
    }));
  });

  it('shield with no subcommand prints usage and exits 1', async () => {
    expect(await dispatchCommand('shield', [])).toBe(1);
    expect(shield).not.toHaveBeenCalled();
    expect(stderr).toContain('Usage: opena2a shield');
  });

  it('a confirmed match keeps its exit code', async () => {
    whoami.mockResolvedValueOnce(3 as never);
    expect(await dispatchCommand('whoami', ['--json'])).toBe(3);
    expect(whoami).toHaveBeenCalledWith({ format: 'text', json: true });
  });
});
