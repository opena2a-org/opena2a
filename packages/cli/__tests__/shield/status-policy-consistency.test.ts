/**
 * `shield status` and `shield policy` give one answer per directory.
 *
 * Status used to read only the user-level policy file and ignore --dir, and
 * it called any file at that path "loaded" even when it did not parse. Policy
 * loads the project's .opena2a/shield/policy.yaml first and treats a file
 * that does not parse as no policy. So for the same directory, status could
 * print "Policy: loaded (adaptive mode)" while policy printed "Mode: enforce",
 * or "No policy loaded". Both now go through loadPolicy and policyModeOf.
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

const { getShieldStatus } = await import('../../src/shield/status.js');
const { createDefaultPolicy, policyModeOf } = await import('../../src/shield/policy.js');
const { shield } = await import('../../src/commands/shield.js');

let tempHome: string;
let projectDir: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-status-policy-home-'));
  projectDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-status-policy-project-'));
  _mockHomeDir = tempHome;
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(projectDir, { recursive: true, force: true });
});

function writePolicyFile(root: string, content: string): void {
  const dir = path.join(root, '.opena2a', 'shield');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'policy.yaml'), content);
}

function policyJson(mode: string | undefined): string {
  const policy: Record<string, unknown> = { ...createDefaultPolicy() };
  if (mode === undefined) delete policy.mode;
  else policy.mode = mode;
  return JSON.stringify(policy, null, 2) + '\n';
}

async function run(subcommand: string, format: 'text' | 'json', dir?: string):
  Promise<{ code: number; out: string; err: string }> {
  let out = '';
  let err = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
    out += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
    err += String(chunk);
    return true;
  });
  try {
    const code = await shield({ subcommand, format, dir });
    return { code, out, err };
  } finally {
    vi.mocked(process.stdout.write).mockRestore();
    vi.mocked(process.stderr.write).mockRestore();
  }
}

/** What each command says about the policy for `dir`: loaded, and in which mode. */
async function answers(dir?: string): Promise<{
  status: { loaded: boolean; mode: string | null };
  policy: { loaded: boolean; mode: string | null };
}> {
  const statusJson = JSON.parse((await run('status', 'json', dir)).out);
  const policyRun = await run('policy', 'json', dir);
  const policyJsonOut = JSON.parse(policyRun.out);
  const policyLoaded = policyRun.code === 0 && policyJsonOut.error === undefined;
  return {
    status: { loaded: statusJson.policyLoaded, mode: statusJson.policyMode },
    policy: {
      loaded: policyLoaded,
      mode: policyLoaded ? policyModeOf(policyJsonOut) : null,
    },
  };
}

describe('shield status and shield policy agree for a directory', () => {
  it('both read the project policy for --dir over the user policy', async () => {
    writePolicyFile(tempHome, policyJson('adaptive'));
    writePolicyFile(projectDir, policyJson('enforce'));

    const { status, policy } = await answers(projectDir);
    expect(status).toEqual({ loaded: true, mode: 'enforce' });
    expect(policy).toEqual(status);

    expect((await run('status', 'text', projectDir)).out).toContain('Policy: loaded (enforce mode)');
    expect((await run('policy', 'text', projectDir)).out).toContain('Mode: enforce');
  });

  it('both fall back to the user policy for a directory without one', async () => {
    writePolicyFile(tempHome, policyJson('monitor'));

    const { status, policy } = await answers(projectDir);
    expect(status).toEqual({ loaded: true, mode: 'monitor' });
    expect(policy).toEqual(status);
  });

  it('both read the user policy without --dir', async () => {
    writePolicyFile(tempHome, policyJson('monitor'));
    writePolicyFile(projectDir, policyJson('enforce'));

    const { status, policy } = await answers();
    expect(status).toEqual({ loaded: true, mode: 'monitor' });
    expect(policy).toEqual(status);
  });

  it('both say no policy is loaded when the policy file does not parse', async () => {
    writePolicyFile(tempHome, 'mode: adaptive\n');

    const { status, policy } = await answers();
    expect(status).toEqual({ loaded: false, mode: null });
    expect(policy).toEqual(status);

    expect(getShieldStatus().policyLoaded).toBe(false);
    expect((await run('status', 'text')).out).toContain('Policy: not loaded');
    const text = await run('policy', 'text');
    expect(text.code).toBe(1);
    expect(text.err).toContain('No policy loaded');
  });

  it('both say no policy is loaded when there is none', async () => {
    const { status, policy } = await answers(projectDir);
    expect(status).toEqual({ loaded: false, mode: null });
    expect(policy).toEqual(status);
  });

  it('both print the same mode for a policy that names none', async () => {
    writePolicyFile(projectDir, policyJson(undefined));

    const { status, policy } = await answers(projectDir);
    expect(status).toEqual({ loaded: true, mode: 'adaptive' });
    expect(policy).toEqual(status);
    expect((await run('policy', 'text', projectDir)).out).toContain('Mode: adaptive');
  });

  it('both print unknown for a mode that is not a mode', async () => {
    writePolicyFile(projectDir, policyJson('enforced'));

    const { status, policy } = await answers(projectDir);
    expect(status).toEqual({ loaded: true, mode: null });
    expect(policy).toEqual(status);
    expect((await run('status', 'text', projectDir)).out).toContain('Policy: loaded (unknown mode)');
    expect((await run('policy', 'text', projectDir)).out).toContain('Mode: unknown');
  });
});
