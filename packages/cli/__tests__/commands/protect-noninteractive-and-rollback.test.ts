/**
 * opena2a#256 — a non-interactive `protect` run exited 0 having changed nothing.
 * opena2a#257 — the only offered rollback was `git checkout`, in directories
 *               that need not be git repositories.
 *
 * Both are pre-existing (protect.ts was byte-identical across
 * v0.10.11..cli-v0.10.12) and both are dead ends in the CISO Rule 11 sense:
 * an exit code that makes an affirmative claim about work that never ran, and
 * a recovery instruction that cannot execute where it is printed.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';

// Reproduce `opena2a protect < /dev/null` faithfully. With stdin at EOF the
// inquirer prompt REJECTS -- it does not hang and it does not resolve false.
// Without this mock the prompt waits forever under vitest and the test would
// fail by timeout, which would not evidence the defect (an exit code of 0).
const promptRejection = new Error('User force closed the prompt with 0 null');
vi.mock('@inquirer/prompts', () => ({
  confirm: vi.fn(() => Promise.reject(promptRejection)),
  select: vi.fn(() => Promise.reject(promptRejection)),
  input: vi.fn(() => Promise.reject(promptRejection)),
}));

import { protect, _protectInternals } from '../../src/commands/protect.js';

function captureStdio(fn: () => Promise<number>): Promise<{ exitCode: number; out: string; err: string }> {
  const outChunks: string[] = [];
  const errChunks: string[] = [];
  const origOut = process.stdout.write;
  const origErr = process.stderr.write;
  process.stdout.write = ((chunk: unknown) => { outChunks.push(String(chunk)); return true; }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: unknown) => { errChunks.push(String(chunk)); return true; }) as typeof process.stderr.write;
  const restore = () => { process.stdout.write = origOut; process.stderr.write = origErr; };
  return fn()
    .then(exitCode => { restore(); return { exitCode, out: outChunks.join(''), err: errChunks.join('') }; })
    .catch(err => { restore(); throw err; });
}

// A synthetic Anthropic-shaped key, assembled at runtime so no real-looking
// credential literal is committed (GitHub push protection).
const FAKE_KEY = 'sk-ant-api03-' + 'A'.repeat(95);

let workDir: string;

beforeEach(() => {
  workDir = fs.mkdtempSync(path.join(tmpdir(), 'protect-noninteractive-'));
  fs.writeFileSync(
    path.join(workDir, 'app.js'),
    `const config = {\n  apiKey: '${FAKE_KEY}',\n};\nmodule.exports = config;\n`,
    'utf-8',
  );
});

afterEach(() => {
  fs.rmSync(workDir, { recursive: true, force: true });
});

describe('protect: a non-interactive run must not claim success (#256)', () => {
  it('does not exit 0 when it cannot prompt and no --ci was given', async () => {
    // vitest runs with a non-TTY stdin, which is the same condition as
    // `opena2a protect < /dev/null` in a CI pipeline.
    expect(process.stdin.isTTY).toBeFalsy();

    const { exitCode } = await captureStdio(() =>
      protect({ targetDir: workDir }),
    );

    // Exit 0 here is an affirmative claim that credentials were migrated.
    expect(exitCode).not.toBe(0);
  });

  it('names --ci so the user has a runnable next step', async () => {
    const { out, err } = await captureStdio(() => protect({ targetDir: workDir }));
    const combined = out + err;

    expect(combined).toContain('--ci');
  });

  it('leaves the credential in source when it refuses', async () => {
    // The refusal must be a genuine no-op on disk, not a partial migration.
    await captureStdio(() => protect({ targetDir: workDir }));

    const after = fs.readFileSync(path.join(workDir, 'app.js'), 'utf-8');
    expect(after).toContain(FAKE_KEY);
  });

  it('still exits 0 when there is nothing to do', async () => {
    // Control: the non-TTY guard must fire only when work was actually
    // skipped. A clean directory has no pending migration to refuse.
    const cleanDir = fs.mkdtempSync(path.join(tmpdir(), 'protect-clean-'));
    fs.writeFileSync(path.join(cleanDir, 'app.js'), 'module.exports = {};\n', 'utf-8');
    try {
      const { exitCode } = await captureStdio(() => protect({ targetDir: cleanDir }));
      expect(exitCode).toBe(0);
    } finally {
      fs.rmSync(cleanDir, { recursive: true, force: true });
    }
  });

  it('refuses in --format json too, so a format flag is not a consent bypass', async () => {
    // `--format json` is an output-format flag. It previously skipped the
    // confirmation entirely, so `opena2a --format json protect` with stdin
    // closed rewrote source files and migrated secrets without ever asking,
    // while text mode asked. `--ci` declares that intent; a format flag does not.
    const { exitCode, out } = await captureStdio(() =>
      protect({ targetDir: workDir, format: 'json' }),
    );

    expect(exitCode).toBe(2);
    const parsed = JSON.parse(out);
    expect(parsed.code).toBe('CONFIRMATION_REQUIRED');
    expect(parsed.migrated).toBe(0);
    expect(parsed.remediation.join(' ')).toContain('--ci');

    // And it really did nothing.
    expect(fs.readFileSync(path.join(workDir, 'app.js'), 'utf-8')).toContain(FAKE_KEY);
  });

  it('still exits 0 for --dry-run, which is a preview and changes nothing', async () => {
    // Control: --dry-run legitimately makes no changes non-interactively.
    const { exitCode } = await captureStdio(() =>
      protect({ targetDir: workDir, dryRun: true }),
    );
    expect(exitCode).toBe(0);
  });
});

describe('protect: rollback guidance must be runnable where it is printed (#257)', () => {
  // Resolved per-call rather than destructured at module scope: an absent
  // export would otherwise abort the whole file and hide the #256 results.
  const renderRollbackLines = (
    dir: string,
    report: { migrated: number },
    af?: { configsSigned?: number; gitignoreFixed?: boolean } | null,
  ): string[] => _protectInternals.renderRollbackLines(dir, report, af);

  it('does not offer git checkout in a directory that is not a git repo', () => {
    // Precondition: the temp dir really is not a work tree.
    let isRepo = true;
    try {
      execFileSync('git', ['rev-parse', '--is-inside-work-tree'], {
        cwd: workDir, stdio: 'pipe',
      });
    } catch {
      isRepo = false;
    }
    expect(isRepo).toBe(false);

    const lines = renderRollbackLines(workDir, { migrated: 1 }).join('\n');
    expect(lines).not.toContain('git checkout');
  });

  it('names a recovery command that exists when there is no git repo', () => {
    const lines = renderRollbackLines(workDir, { migrated: 1 }).join('\n');

    // `secretless-ai secret get <NAME>` is a real subcommand of the vault CLI
    // protect stores into. Without it the user is told only that the edit is
    // irreversible, which is a dead end.
    expect(lines).toMatch(/secret get/);
  });

  it('states plainly that the source edit is not reversible from disk', () => {
    const lines = renderRollbackLines(workDir, { migrated: 1 }).join('\n');
    expect(lines).toMatch(/not reversible|cannot be restored|no backup/i);
  });

  it('DOES offer git checkout inside a real git work tree', () => {
    // Negative control: the fix must not remove working guidance from the
    // case where it works. Without this, deleting the line entirely passes.
    execFileSync('git', ['init', '-q'], { cwd: workDir, stdio: 'pipe' });

    const lines = renderRollbackLines(workDir, { migrated: 1 }).join('\n');
    expect(lines).toContain('git checkout');
  });

  it('offers BOTH options when the git state cannot be determined', () => {
    // git exits non-zero for reasons other than "not a repository": it is not
    // installed, the directory is unreadable, spawn fails, or it refuses with
    // "detected dubious ownership" (routine in containers and CI runners).
    // Asserting "not reversible" to someone who IS in a repo is the worse
    // error, so an indeterminate result must offer both paths.
    const missing = path.join(workDir, 'does-not-exist');
    const state = _protectInternals.isInsideGitWorkTree(missing);
    expect(state).toBe('unknown');

    const lines = renderRollbackLines(missing, { migrated: 1 }).join('\n');
    expect(lines).toContain('git checkout');
    expect(lines).toMatch(/secret get/);
    expect(lines).toMatch(/could not determine/i);
    // It must NOT assert the negative it never verified.
    expect(lines).not.toMatch(/is not a git\s+repository/i);
  });

  it('classifies a genuine non-repo as "no", not "unknown"', () => {
    // Control for the test above: if everything became 'unknown', the honest
    // non-git message from #257 would never be shown again.
    expect(_protectInternals.isInsideGitWorkTree(workDir)).toBe('no');
  });

  it('reports a modified .gitignore even outside a git repo', () => {
    // protect edits .gitignore with no repo check. Printing the rollback line
    // only inside a repo meant a file it had just modified went unmentioned.
    const lines = renderRollbackLines(workDir, { migrated: 0 }, { gitignoreFixed: true }).join('\n');
    expect(lines).toMatch(/\.gitignore was modified/i);
    expect(lines).not.toContain('git checkout');
  });

  it('detects a git work tree from a SUBDIRECTORY of the repo', () => {
    // `existsSync('.git')` would be wrong: protect can be pointed at a
    // subdirectory of a repo, where rollback via git is still available.
    execFileSync('git', ['init', '-q'], { cwd: workDir, stdio: 'pipe' });
    const sub = path.join(workDir, 'packages', 'app');
    fs.mkdirSync(sub, { recursive: true });

    const lines = renderRollbackLines(sub, { migrated: 1 }).join('\n');
    expect(lines).toContain('git checkout');
  });
});
