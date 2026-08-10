/**
 * opena2a#255 — `shield evaluate` produced zero bytes in its default text mode.
 *
 * Reporting a verdict is the command's whole purpose, and the human-readable
 * path printed nothing for an `allowed` outcome, so a user could not tell
 * 'allowed' from 'crashed'.
 *
 * The silence was deliberate for the shell preexec hook, which runs `evaluate`
 * on EVERY command. That constraint is preserved here: the hook always passes
 * the command as a positional argument (see `getExpectedHookContent` —
 * `opena2a shield evaluate "$1"`), so a bare invocation with NO positional args
 * is the only case that starts reporting. The hook-quiet contract is asserted
 * directly below, not assumed.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => _mockHomeDir,
  };
});

const { shield } = await import('../../src/commands/shield.js');
const { savePolicy, createDefaultPolicy } = await import('../../src/shield/policy.js');
// Take the location from the same constants loadPolicy uses, so a path change
// cannot silently turn these into no-policy tests.
const { SHIELD_DIR, SHIELD_POLICY_FILE } = await import('../../src/shield/types.js');

let tempDir: string;
let stdout: string;
let stderr: string;
let stdoutSpy: ReturnType<typeof vi.spyOn>;
let stderrSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-evaluate-text-'));
  _mockHomeDir = tempDir;
  stdout = '';
  stderr = '';
  stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
    stdout += String(chunk);
    return true;
  });
  stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
    stderr += String(chunk);
    return true;
  });
});

afterEach(() => {
  stdoutSpy.mockRestore();
  stderrSpy.mockRestore();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

/** Write a policy where loadPolicy(dir) will find it. */
function writePolicy(dir: string, mode: 'adaptive' | 'strict' = 'adaptive'): void {
  const policy = createDefaultPolicy(mode);
  const policyPath = path.join(dir, SHIELD_DIR, SHIELD_POLICY_FILE);
  savePolicy(policy, policyPath);
  // Guard the fixture itself: a broken path here would make every assertion
  // below pass or fail for the wrong reason.
  if (!fs.existsSync(policyPath)) {
    throw new Error(`fixture not written: ${policyPath}`);
  }
}

describe('shield evaluate: default text mode reports a verdict (#255)', () => {
  it('writes a non-empty verdict for an allowed outcome', async () => {
    writePolicy(tempDir);

    const code = await shield({ subcommand: 'evaluate', dir: tempDir, args: [] });

    expect(code).toBe(0);
    // The defect: this was 0 bytes.
    expect(stdout.length).toBeGreaterThan(0);
  });

  it('names the outcome and the deciding rule, not just any bytes', async () => {
    writePolicy(tempDir);

    await shield({ subcommand: 'evaluate', dir: tempDir, args: [] });

    // A length assertion alone would pass on a blank line. Assert the three
    // facts the --json path already returned: outcome, rule, agent.
    expect(stdout).toMatch(/allowed/i);
    expect(stdout).toContain('processes:no-match');
    expect(stdout.toLowerCase()).toContain('agent');
  });

  it('states that a default-allow happened because no rule matched', async () => {
    writePolicy(tempDir);

    await shield({ subcommand: 'evaluate', dir: tempDir, args: [] });

    // A default-allow is the state an operator most needs to see explicitly:
    // 'no policy matched, allowing by default' rather than silence.
    expect(stdout).toMatch(/no (policy )?rule matched|default/i);
  });

  it('reports which category and target were actually evaluated', async () => {
    // `shield evaluate --action X --target Y` is printed as remediation by
    // src/shield/findings.ts, but neither flag is registered on the command,
    // so the target evaluated is the empty string. Showing the evaluated
    // subject means a user can SEE that, instead of reading a confident
    // verdict about nothing. Tracked separately from #255.
    writePolicy(tempDir);

    await shield({ subcommand: 'evaluate', dir: tempDir, args: [] });

    expect(stdout).toContain('processes');
  });

  it('still emits exactly the JSON document in --json mode', async () => {
    writePolicy(tempDir);

    await shield({ subcommand: 'evaluate', dir: tempDir, args: [], format: 'json' });

    // --json is a machine contract: the text verdict must not leak into it.
    const parsed = JSON.parse(stdout);
    expect(parsed).toMatchObject({
      allowed: true,
      outcome: 'allowed',
      rule: 'processes:no-match',
    });
  });
});

describe('shield evaluate: the preexec hook stays silent (#255 guard)', () => {
  it('prints nothing on stdout for an allowed command passed as an argument', async () => {
    // This is the hook shape: `opena2a shield evaluate "$1"`. It runs on every
    // interactive command, so an allowed verdict must remain silent. If this
    // fails, the #255 fix has made every shell prompt noisy.
    writePolicy(tempDir);

    const code = await shield({ subcommand: 'evaluate', dir: tempDir, args: ['ls -la'] });

    expect(code).toBe(0);
    expect(stdout).toBe('');
  });

  it('stays silent when the hook passes an absolute-path command', async () => {
    // The positional filter drops args starting with '/', so this reaches the
    // same internal state as a bare invocation. Gating the verdict on the
    // FILTERED command string (rather than on whether any arg was supplied)
    // would make `/usr/bin/ls` print on every hook run.
    writePolicy(tempDir);

    await shield({ subcommand: 'evaluate', dir: tempDir, args: ['/usr/bin/ls -la'] });

    expect(stdout).toBe('');
  });
});
