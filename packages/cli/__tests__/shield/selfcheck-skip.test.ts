/**
 * `shield selfcheck` prints SKIP, not PASS, for a check that had nothing to
 * verify.
 *
 * With no policy.yaml the policy row printed "PASS  No policy file found;
 * nothing to verify.", and with no signature store the artifact-signatures
 * row printed PASS the same way. A check that verified nothing now reports
 * `skip`: printed as SKIP, left out of the pass count, and leaving the
 * overall verdict as the other checks set it. Once a policy and signatures
 * exist, both rows verify them and print PASS.
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

const { recordPolicyHash, runIntegrityChecks } =
  await import('../../src/shield/integrity.js');
const { signAllArtifacts } = await import('../../src/shield/signing.js');
const { createDefaultPolicy, savePolicy } = await import('../../src/shield/policy.js');
const { shield } = await import('../../src/commands/shield.js');

const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

let home: string;
let shieldDir: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(tmpdir(), 'shield-selfcheck-skip-'));
  _mockHomeDir = home;
  shieldDir = path.join(home, '.opena2a', 'shield');
  fs.mkdirSync(shieldDir, { recursive: true });
  // An rc file without the hook: the shell-hook row passes, so the verdict
  // depends on the policy and artifact rows alone.
  fs.writeFileSync(path.join(home, '.zshrc'), '# rc\n');
  vi.stubEnv('SHELL', '/bin/zsh');
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  fs.rmSync(home, { recursive: true, force: true });
});

/** A policy written, recorded and signed as init leaves it. */
function recordPolicy(): void {
  const policyPath = path.join(shieldDir, 'policy.yaml');
  savePolicy(createDefaultPolicy('enforce'), policyPath);
  recordPolicyHash(policyPath);
  signAllArtifacts();
}

async function selfcheck(format?: string): Promise<{ rc: number; out: string }> {
  let out = '';
  vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: unknown) => {
    out += String(chunk);
    return true;
  }) as never);
  vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  try {
    const rc = await shield({ subcommand: 'selfcheck', format });
    return { rc, out: out.replace(STRIP_ANSI, '') };
  } finally {
    vi.mocked(process.stdout.write).mockRestore();
    vi.mocked(process.stderr.write).mockRestore();
  }
}

function rowLine(out: string, name: string): string {
  const line = out.split('\n').find((l) => l.trim().split(/\s+/)[1] === name);
  expect(line, `no ${name} row in:\n${out}`).toBeDefined();
  return line!;
}

function check(name: string) {
  return runIntegrityChecks({ shell: 'zsh' }).checks.find((c) => c.name === name)!;
}

describe('selfcheck with nothing to verify', () => {
  it('reports skip for policy and artifact-signatures, not pass', () => {
    expect(check('policy').status).toBe('skip');
    expect(check('artifact-signatures').status).toBe('skip');
  });

  it('prints SKIP on both rows, leaves them out of the pass count, and keeps the verdict', async () => {
    const { rc, out } = await selfcheck();
    expect(rowLine(out, 'policy')).toMatch(/^\s*SKIP\s/);
    expect(rowLine(out, 'artifact-signatures')).toMatch(/^\s*SKIP\s/);
    expect(out).not.toMatch(/PASS\s+policy\s/);
    expect(out).not.toMatch(/PASS\s+artifact-signatures\s/);
    expect(out).toContain('  Passed: 3 of 3 checks (2 skipped: nothing to verify)\n');
    expect(out).toContain('Overall: HEALTHY');
    expect(rc).toBe(0);
  });

  it('reports skip in the JSON state, with the same overall status', async () => {
    const { rc, out } = await selfcheck('json');
    const state = JSON.parse(out) as { status: string; checks: Array<{ name: string; status: string }> };
    const statusOf = (name: string) => state.checks.find((c) => c.name === name)?.status;
    expect(statusOf('policy')).toBe('skip');
    expect(statusOf('artifact-signatures')).toBe('skip');
    expect(state.status).toBe('healthy');
    expect(rc).toBe(0);
  });

  it('still reports degraded when another check warns', async () => {
    fs.rmSync(path.join(home, '.zshrc'));
    const { rc, out } = await selfcheck();
    expect(rowLine(out, 'policy')).toMatch(/^\s*SKIP\s/);
    expect(rowLine(out, 'shell-hook')).toMatch(/^\s*WARN\s/);
    expect(out).toContain('  Passed: 2 of 3 checks (2 skipped: nothing to verify)\n');
    expect(out).toContain('Overall: DEGRADED');
    expect(rc).toBe(0);
  });
});

describe('selfcheck once a policy and signatures exist', () => {
  it('prints PASS on both rows and counts them', async () => {
    recordPolicy();
    expect(check('policy').status).toBe('pass');
    expect(check('artifact-signatures').status).toBe('pass');

    const { rc, out } = await selfcheck();
    expect(rowLine(out, 'policy')).toMatch(/^\s*PASS\s/);
    expect(rowLine(out, 'artifact-signatures')).toMatch(/^\s*PASS\s/);
    expect(out).not.toContain('SKIP');
    expect(out).toContain('  Passed: 5 of 5 checks\n');
    expect(out).toContain('Overall: HEALTHY');
    expect(rc).toBe(0);
  });
});
