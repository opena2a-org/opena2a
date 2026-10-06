/**
 * `shield status` and review's Integrity card print an integrity state that
 * was measured, never a default.
 *
 * The status line used to start at 'healthy' and only ever changed it when the
 * lockdown marker existed, so on a tampered policy `shield selfcheck` exited 1
 * COMPROMISED while `shield status` printed "Integrity: HEALTHY", and its
 * "Integrity issues detected" recommendation could never fire. Status now
 * reads the verdict selfcheck computes, from the same function and the same
 * shell, and its exit code stays what it was: 1 on lockdown only.
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

const { writeEvent, getShieldDir } = await import('../../src/shield/events.js');
const { runIntegrityChecks, recordPolicyHash, enterLockdown } =
  await import('../../src/shield/integrity.js');
const { getShieldStatus, formatStatus } = await import('../../src/shield/status.js');
const { shield } = await import('../../src/commands/shield.js');

let tempHome: string;
let savedShell: string | undefined;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-status-integrity-'));
  _mockHomeDir = tempHome;
  savedShell = process.env.SHELL;
  process.env.SHELL = '/bin/zsh';
});

afterEach(() => {
  vi.restoreAllMocks();
  if (savedShell === undefined) delete process.env.SHELL;
  else process.env.SHELL = savedShell;
  fs.rmSync(tempHome, { recursive: true, force: true });
});

/** The verdict `shield selfcheck` prints for this HOME. */
function selfcheckVerdict(): string {
  return runIntegrityChecks({ shell: 'zsh' }).status;
}

function writeRcFile(): void {
  fs.writeFileSync(path.join(tempHome, '.zshrc'), '# rc\n');
}

function writePolicy(): string {
  const shieldDir = getShieldDir();
  fs.mkdirSync(shieldDir, { recursive: true });
  const policyPath = path.join(shieldDir, 'policy.yaml');
  fs.writeFileSync(policyPath, 'mode: adaptive\n');
  recordPolicyHash(policyPath);
  return policyPath;
}

function writeChainedEvents(count: number): string {
  for (let i = 0; i < count; i++) {
    writeEvent({
      source: 'shield',
      category: 'test',
      severity: 'info',
      agent: null,
      sessionId: null,
      action: `event-${i}`,
      target: '/tmp/target',
      outcome: 'allowed',
      detail: {},
      orgId: null,
      managed: false,
      agentId: null,
    });
  }
  return path.join(getShieldDir(), 'events.jsonl');
}

async function runStatusCommand(): Promise<{ code: number; out: string }> {
  let out = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
    out += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  const code = await shield({ subcommand: 'status', format: 'text' });
  vi.mocked(process.stdout.write).mockRestore();
  vi.mocked(process.stderr.write).mockRestore();
  return { code, out };
}

describe('shield status integrity', () => {
  it('prints COMPROMISED, not HEALTHY, on a tampered policy that selfcheck fails', async () => {
    writeRcFile();
    const policyPath = writePolicy();
    fs.appendFileSync(policyPath, 'tampered: true\n');
    expect(selfcheckVerdict()).toBe('compromised');

    const status = getShieldStatus();
    expect(status.integrityStatus).toBe('compromised');

    const { code, out } = await runStatusCommand();
    expect(out).toContain('Integrity: COMPROMISED');
    expect(out).not.toContain('Integrity: HEALTHY');
    // The recommendation that was unreachable while the state was hardcoded.
    expect(out).toContain('Integrity issues detected. Run: opena2a shield selfcheck');
    // Status is informational: its exit code does not follow the measured verdict.
    expect(code).toBe(0);
  });

  it('agrees with selfcheck on a log whose hash chain is broken', async () => {
    writeRcFile();
    const eventsPath = writeChainedEvents(3);
    const raw = fs.readFileSync(eventsPath, 'utf-8');
    fs.writeFileSync(eventsPath, raw.replace('"event-1"', '"event-X"'));

    const verdict = selfcheckVerdict();
    expect(verdict).not.toBe('healthy');

    const status = getShieldStatus();
    expect(status.integrityStatus).toBe(verdict);

    const text = formatStatus(status, 'text');
    expect(text).toContain(`Integrity: ${verdict.toUpperCase()}`);
    expect(text).toContain('Run: opena2a shield selfcheck');
  });

  it('prints HEALTHY only where selfcheck computes healthy', () => {
    writeRcFile();
    writePolicy();
    writeChainedEvents(2);
    expect(selfcheckVerdict()).toBe('healthy');
    expect(getShieldStatus().integrityStatus).toBe('healthy');
  });

  it('prints the verdict selfcheck computes on an intact HOME that has no rc file', () => {
    // selfcheck warns that the rc file is missing; status must not print
    // HEALTHY over that warning.
    const verdict = selfcheckVerdict();
    expect(verdict).toBe('degraded');
    expect(getShieldStatus().integrityStatus).toBe(verdict);
  });

  it('keeps reporting LOCKDOWN and exiting 1 while the lockdown marker exists', async () => {
    writeRcFile();
    enterLockdown('tamper detected');

    expect(getShieldStatus().integrityStatus).toBe('lockdown');
    const { code, out } = await runStatusCommand();
    expect(out).toContain('Integrity: LOCKDOWN');
    expect(out).toContain('LOCKDOWN active. Run: opena2a shield recover --verify');
    expect(code).toBe(1);
  });

  it('prints NOT CHECKED with the selfcheck command when a check cannot run', async () => {
    // An rc path that cannot be read as a file makes the shell-hook check
    // throw. Status must neither crash nor fall back to HEALTHY.
    fs.mkdirSync(path.join(tempHome, '.zshrc'));
    expect(() => runIntegrityChecks({ shell: 'zsh' })).toThrow();

    const status = getShieldStatus();
    expect(status.integrityStatus).toBe('not-checked');

    const { code, out } = await runStatusCommand();
    expect(out).toContain('Integrity: NOT CHECKED');
    expect(out).toContain('Integrity was not checked. Run: opena2a shield selfcheck');
    expect(code).toBe(0);
  });
});
