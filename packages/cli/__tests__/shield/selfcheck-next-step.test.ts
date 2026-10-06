/**
 * Every FAIL `shield selfcheck` prints names one next command.
 *
 * A policy edit printed "FAIL policy" and "FAIL artifact-signatures" with
 * hashes and nothing to run, and lockdown printed "System is in lockdown:
 * <reason>" and "Overall: LOCKDOWN" with exit 1: dead ends. The one command
 * that turns those rows green, `shield init`, re-records the policy hash and
 * re-signs the artifacts, so it erases the evidence instead of explaining it.
 *
 * This walks every failing state the checks can produce and requires, for
 * each FAIL: a next step at the end of the detail; a command that runs as
 * printed (shell steps are run here, `opena2a` steps are parsed against the
 * registered subcommands and flags); and no change to any file under the
 * Shield home while it runs. `shield init` and `--ci` are never the step.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';

import type { IntegrityCheck } from '../../src/shield/types.js';

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => _mockHomeDir };
});

const { runIntegrityChecks } = await import('../../src/shield/integrity.js');
const { shield } = await import('../../src/commands/shield.js');

const INTEGRITY_SRC = path.resolve(__dirname, '../../src/shield/integrity.ts');
const SHIELD_CMD_SRC = path.resolve(__dirname, '../../src/commands/shield.ts');
const INDEX_SRC = path.resolve(__dirname, '../../src/index.ts');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;
const SIGNED_AT = '2026-10-01T00:00:00.000Z';

let tempHome: string;
let shieldDir: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-next-step-'));
  _mockHomeDir = tempHome;
  shieldDir = path.join(tempHome, '.opena2a', 'shield');
  fs.mkdirSync(shieldDir, { recursive: true });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  fs.rmSync(tempHome, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Fixtures: one per failing state
// ---------------------------------------------------------------------------

function sha256(content: string | Buffer): string {
  return createHash('sha256').update(content).digest('hex');
}

/** Record the policy and sign it, as init does, then edit it (cell RB). */
function editRecordedPolicy(): void {
  const policy = 'mode: monitor\nrules: []\n';
  fs.writeFileSync(path.join(shieldDir, 'policy.yaml'), policy);
  fs.writeFileSync(
    path.join(shieldDir, 'policy-hash.json'),
    JSON.stringify({ hash: sha256(policy), recordedAt: SIGNED_AT }),
  );
  fs.writeFileSync(
    path.join(shieldDir, 'signatures.json'),
    JSON.stringify({
      version: 1,
      updatedAt: SIGNED_AT,
      signatures: [{
        filePath: 'policy.yaml',
        hash: `sha256:${sha256(policy)}`,
        signedAt: SIGNED_AT,
        signedBy: 'test',
        fileSize: policy.length,
      }],
    }),
  );
  fs.writeFileSync(path.join(shieldDir, 'policy.yaml'), `${policy}# edited\n`);
}

function enterLockdown(reason: string): void {
  fs.writeFileSync(
    path.join(shieldDir, 'lockdown'),
    JSON.stringify({ reason, timestamp: SIGNED_AT, enteredBy: 'selfcheck' }),
  );
}

interface Scenario {
  state: string;
  /** The checks this state must fail. */
  failing: string[];
  setup: () => void;
}

const SCENARIOS: Scenario[] = [
  {
    state: 'lockdown',
    failing: ['lockdown'],
    setup: () => enterLockdown('policy tampered'),
  },
  {
    state: 'policy edited after it was recorded and signed (cell RB)',
    failing: ['policy', 'artifact-signatures'],
    setup: editRecordedPolicy,
  },
  {
    state: 'recorded policy hash unreadable',
    failing: ['policy'],
    setup: () => {
      fs.writeFileSync(path.join(shieldDir, 'policy.yaml'), 'mode: monitor\n');
      fs.writeFileSync(path.join(shieldDir, 'policy-hash.json'), '{not json');
    },
  },
  {
    state: 'signed artifact missing',
    failing: ['artifact-signatures'],
    setup: () => {
      fs.writeFileSync(
        path.join(shieldDir, 'signatures.json'),
        JSON.stringify({
          version: 1,
          updatedAt: SIGNED_AT,
          signatures: [{
            filePath: 'scan.json',
            hash: `sha256:${sha256('{}')}`,
            signedAt: SIGNED_AT,
            signedBy: 'test',
            fileSize: 2,
          }],
        }),
      );
    },
  },
  {
    state: 'installed shell hook differs from the expected hook',
    failing: ['shell-hook'],
    setup: () => {
      const block = [
        '# >>> opena2a shield hook >>>',
        'opena2a_shield_preexec() { return 0; }',
        '# <<< opena2a shield hook <<<',
      ].join('\n');
      fs.writeFileSync(path.join(tempHome, '.zshrc'), `export A=1\n${block}\n`);
    },
  },
  {
    state: 'events file unreadable',
    failing: ['event-chain'],
    setup: () => fs.mkdirSync(path.join(shieldDir, 'events.jsonl')),
  },
  {
    state: 'node executable gone',
    failing: ['process'],
    setup: () => {
      Object.defineProperty(process, 'execPath', {
        value: path.join(tempHome, 'missing', 'node'),
        configurable: true,
        writable: true,
      });
    },
  },
];

/** Run a scenario with process.execPath restored afterwards. */
function withScenario<T>(scenario: Scenario, fn: () => T): T {
  const realExecPath = process.execPath;
  try {
    scenario.setup();
    return fn();
  } finally {
    Object.defineProperty(process, 'execPath', {
      value: realExecPath,
      configurable: true,
      writable: true,
    });
  }
}

// ---------------------------------------------------------------------------
// How a cited step is checked
// ---------------------------------------------------------------------------

/** Every file under the temporary home, by content. */
function snapshot(dir: string, out: Record<string, string> = {}): Record<string, string> {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out[`${full}/`] = 'dir';
      snapshot(full, out);
    } else {
      out[full] = sha256(fs.readFileSync(full));
    }
  }
  return out;
}

/** `shield` subcommands the dispatcher handles, and the flags `shield` registers. */
function shieldSurface(): { subcommands: Set<string>; flags: Set<string> } {
  const dispatch = fs.readFileSync(SHIELD_CMD_SRC, 'utf-8');
  const subcommands = new Set(
    [...dispatch.matchAll(/^\s*case '([a-z-]+)':/gm)].map((m) => m[1]),
  );
  const index = fs.readFileSync(INDEX_SRC, 'utf-8');
  const start = index.indexOf(".command('shield ");
  const block = index.slice(start, index.indexOf('.action(', start));
  const flags = new Set([...block.matchAll(/\.option\('(--[a-z-]+)/g)].map((m) => m[1]));
  return { subcommands, flags };
}

function expectOpena2aStepParses(step: string): void {
  const [bin, command, subcommand, ...rest] = step.split(/\s+/);
  const { subcommands, flags } = shieldSurface();
  expect(bin).toBe('opena2a');
  expect(command).toBe('shield');
  expect(subcommands.has(subcommand), `unregistered subcommand in "${step}"`).toBe(true);
  for (const token of rest) {
    expect(token.startsWith('--'), `unexpected argument in "${step}"`).toBe(true);
    expect(flags.has(token), `unregistered flag in "${step}"`).toBe(true);
  }
}

function failsOf(checks: IntegrityCheck[]): IntegrityCheck[] {
  return checks.filter((c) => c.status === 'fail');
}

async function captureSelfcheck(): Promise<{ rc: number; out: string }> {
  let out = '';
  const write = (chunk: unknown) => {
    out += String(chunk);
    return true;
  };
  vi.spyOn(process.stdout, 'write').mockImplementation(write as never);
  vi.spyOn(process.stderr, 'write').mockImplementation(write as never);
  const rc = await shield({ subcommand: 'selfcheck' });
  vi.restoreAllMocks();
  return { rc, out: out.replace(STRIP_ANSI, '') };
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

describe('every selfcheck FAIL detail names one next command', () => {
  for (const scenario of SCENARIOS) {
    it(`${scenario.state}: each FAIL carries a step that runs and keeps the evidence`, () => {
      const fails = withScenario(scenario, () =>
        failsOf(runIntegrityChecks({ shell: 'zsh' }).checks),
      );

      expect(fails.map((c) => c.name).sort()).toEqual([...scenario.failing].sort());

      for (const check of fails) {
        const step = check.nextStep;
        expect(step, `${check.name} FAIL has no next step: ${check.detail}`).toBeTruthy();
        expect(check.detail.endsWith(`: ${step}`)).toBe(true);
        expect(step).not.toMatch(/\bshield\s+init\b/);
        expect(step).not.toMatch(/--ci\b/);

        if (step!.startsWith('opena2a ')) {
          expectOpena2aStepParses(step!);
          continue;
        }

        const before = snapshot(tempHome);
        const run = spawnSync('/bin/sh', ['-c', step!], { encoding: 'utf-8' });
        expect(run.status, `"${step}" exited ${run.status}: ${run.stderr}`).toBe(0);
        expect(snapshot(tempHome)).toEqual(before);
      }
    });
  }

  for (const scenario of SCENARIOS) {
    it(`${scenario.state}: the printed FAIL line ends with the step`, async () => {
      const realExecPath = process.execPath;
      let result: { rc: number; out: string };
      let fails: IntegrityCheck[];
      // selfcheck picks the rc file from $SHELL; pin it to the shell used here.
      vi.stubEnv('SHELL', '/bin/zsh');
      try {
        scenario.setup();
        fails = failsOf(runIntegrityChecks({ shell: 'zsh' }).checks);
        result = await captureSelfcheck();
      } finally {
        Object.defineProperty(process, 'execPath', {
          value: realExecPath,
          configurable: true,
          writable: true,
        });
      }

      expect(result.rc).toBe(1);
      const failLines = result.out.split('\n').filter((l) => /^\s*FAIL\s/.test(l));
      expect(failLines.length).toBeGreaterThan(0);
      for (const line of failLines) {
        const name = line.trim().split(/\s+/)[1];
        const check = fails.find((c) => c.name === name);
        expect(check?.nextStep, `no step for printed line: ${line}`).toBeTruthy();
        expect(line.trimEnd().endsWith(check!.nextStep!)).toBe(true);
      }
    });
  }

  it('cell RB: policy and artifact-signatures each carry a next step', () => {
    editRecordedPolicy();
    const fails = failsOf(runIntegrityChecks({ shell: 'zsh' }).checks);
    const policy = fails.find((c) => c.name === 'policy');
    const artifacts = fails.find((c) => c.name === 'artifact-signatures');
    expect(policy?.nextStep).toBe(`cat '${path.join(shieldDir, 'policy.yaml')}'`);
    expect(artifacts?.nextStep).toBe(`ls -l '${shieldDir}'`);
  });

  it('lockdown names opena2a shield recover --verify', () => {
    enterLockdown('policy tampered');
    const [check] = runIntegrityChecks({ shell: 'zsh' }).checks;
    expect(check.name).toBe('lockdown');
    expect(check.detail).toContain('System is in lockdown: policy tampered.');
    expect(check.nextStep).toBe('opena2a shield recover --verify');
  });

  it('the lockdown step, run as printed, keeps a still-failing machine locked and every file unchanged', async () => {
    editRecordedPolicy();
    enterLockdown('policy tampered');
    const before = snapshot(tempHome);

    let err = '';
    vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: unknown) => {
      err += String(chunk);
      return true;
    }) as never);
    const rc = await shield({ subcommand: 'recover', verify: true });
    vi.restoreAllMocks();

    expect(rc).toBe(1);
    expect(snapshot(tempHome)).toEqual(before);
    // The failures it lists carry their own steps.
    expect(err.replace(STRIP_ANSI, '')).toContain(
      `Review the policy as it is now: cat '${path.join(shieldDir, 'policy.yaml')}'`,
    );
  });

  it('a path with a quote in it is still one argument when run as printed', () => {
    const odd = path.join(tempHome, "it's here");
    fs.mkdirSync(odd);
    _mockHomeDir = odd;
    const oddShieldDir = path.join(odd, '.opena2a', 'shield');
    fs.mkdirSync(oddShieldDir, { recursive: true });
    fs.writeFileSync(path.join(oddShieldDir, 'policy.yaml'), 'mode: monitor\n');
    fs.writeFileSync(path.join(oddShieldDir, 'policy-hash.json'), '{not json');

    const policy = failsOf(runIntegrityChecks({ shell: 'zsh' }).checks)
      .find((c) => c.name === 'policy');
    const run = spawnSync('/bin/sh', ['-c', policy!.nextStep!], { encoding: 'utf-8' });
    expect(run.status).toBe(0);
    expect(run.stdout).toBe('{not json');
  });
});

describe('no failing check escapes the walk', () => {
  const src = fs.readFileSync(INTEGRITY_SRC, 'utf-8');

  it('every failing check is built by failCheck, which requires a step', () => {
    expect(src.match(/status:\s*'fail'/g)).toHaveLength(1);
    expect(src).toMatch(/function failCheck\([^)]*step: NextStep/s);
  });

  it('every failCheck call site has a scenario above', () => {
    const callSites = (src.match(/\bfailCheck\(/g) ?? []).length - 1; // minus the definition
    const covered = new Set(SCENARIOS.flatMap((s) => s.failing));
    expect(callSites).toBe(covered.size);
  });
});
