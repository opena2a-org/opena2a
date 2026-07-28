/**
 * Issue #228 item 3 — `shield recover --verify` must verify BEFORE it leaves
 * lockdown, not after.
 *
 * `--verify` is documented as "Verify before recovering". The original
 * implementation called `exitLockdown()` first and only re-entered lockdown if
 * the checks came back compromised, because `runIntegrityChecks` short-circuits
 * to `status: 'lockdown'` while the marker is present. That leaves a window in
 * which a compromised machine is out of lockdown, and anything that ends the
 * process during the window (a throwing check, SIGINT, a kill) leaves it out of
 * lockdown permanently — a fail-open on the one command whose whole job is to
 * decide whether it is safe to unlock.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => _mockHomeDir };
});

const integrity = await import('../../src/shield/integrity.js');
const { shield } = await import('../../src/commands/shield.js');

let tempHome: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-recover-verify-'));
  _mockHomeDir = tempHome;
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tempHome, { recursive: true, force: true });
});

function captureStdout(): { restore: () => void } {
  const spy = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
  const errSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  return { restore: () => { spy.mockRestore(); errSpy.mockRestore(); } };
}

describe('shield recover --verify', () => {
  it('does not leave lockdown when the integrity checks report compromised', async () => {
    integrity.enterLockdown('tamper detected');
    expect(integrity.isLockdown()).toBe(true);

    vi.spyOn(integrity, 'runIntegrityChecks').mockReturnValue({
      status: 'compromised',
      checks: [{ name: 'policy', status: 'fail', detail: 'tampered', checkedAt: '' }],
      lastVerified: '',
      chainHash: '',
    });

    const io = captureStdout();
    const code = await shield({ subcommand: 'recover', verify: true, format: 'json' });
    io.restore();

    expect(code).toBe(1);
    expect(integrity.isLockdown()).toBe(true);
    // The reason survives here, but note it survived pre-fix too: the old code
    // read it before unlocking and passed it back to enterLockdown. This
    // assertion is therefore NOT what distinguishes the fix — the ordering
    // test below is. Kept because the end state still has to be right.
    expect(integrity.getLockdownReason()).toBe('tamper detected');
  });

  it('leaves lockdown only after the checks pass', async () => {
    integrity.enterLockdown('tamper detected');

    vi.spyOn(integrity, 'runIntegrityChecks').mockReturnValue({
      status: 'healthy',
      checks: [],
      lastVerified: '',
      chainHash: '',
    });

    const io = captureStdout();
    const code = await shield({ subcommand: 'recover', verify: true, format: 'json' });
    io.restore();

    expect(code).toBe(0);
    expect(integrity.isLockdown()).toBe(false);
  });

  it('runs the checks while the lockdown marker is still present', async () => {
    integrity.enterLockdown('tamper detected');

    let lockedDuringCheck: boolean | null = null;
    vi.spyOn(integrity, 'runIntegrityChecks').mockImplementation(() => {
      lockedDuringCheck = integrity.isLockdown();
      return { status: 'healthy', checks: [], lastVerified: '', chainHash: '' };
    });

    const io = captureStdout();
    await shield({ subcommand: 'recover', verify: true, format: 'json' });
    io.restore();

    expect(lockedDuringCheck).toBe(true);
  });

  it('reports a throwing check without crashing, and stays in lockdown', async () => {
    // The sharp edge: with exit-then-verify, an exception (or a SIGINT, or a
    // kill) between the two steps leaves the machine unlocked for good.
    integrity.enterLockdown('tamper detected');

    vi.spyOn(integrity, 'runIntegrityChecks').mockImplementation(() => {
      throw new Error('artifact store unreadable');
    });

    const io = captureStdout();
    // `shield status` tells a locked-out user exactly one thing: run
    // `opena2a shield recover --verify`. If that command answers with a raw
    // stack trace, the only cited way out is a dead end.
    const code = await shield({ subcommand: 'recover', verify: true, format: 'json' });
    io.restore();

    expect(code).toBe(1);
    expect(integrity.isLockdown()).toBe(true);
  });

  it('runIntegrityChecks still short-circuits in lockdown by default', async () => {
    // The ignoreLockdown escape hatch must not change what every other caller
    // (selfcheck, review) sees.
    integrity.enterLockdown('tamper detected');
    expect(integrity.runIntegrityChecks({}).status).toBe('lockdown');
    expect(integrity.runIntegrityChecks({ ignoreLockdown: true }).status).not.toBe('lockdown');
  });
});
