/**
 * shield report lists a deny match recorded under `mode: enforce` as a
 * violation.
 *
 * Under enforce, `shield evaluate` records a deny as `command.monitored` with
 * `verdict: "deny"` at medium severity; by default zsh and bash still run the
 * command. The report's violations list kept only blocked or high/critical
 * events, so that record never reached `topViolations`. It now does, with a
 * recommendation that the shell may have run the command despite the deny
 * rule. A monitored record without the deny verdict (mode: monitor) is still
 * left out.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

// homedir() points at a fresh scratch directory for every test, so the
// policy and the event log a cell reads are never the real ones.
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
const { SHIELD_DIR, SHIELD_POLICY_FILE } = await import('../../src/shield/types.js');

const MAY_HAVE_RUN =
  'The policy denied this under mode enforce, but the shell may have run the command despite the deny rule; check whether it ran.';

interface Violation {
  action: string;
  target: string;
  count: number;
  severity: string;
  recommendation: string;
}

let tempDir: string;
let stdoutSpy: ReturnType<typeof vi.spyOn>;
let stderrSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-report-enforce-deny-'));
  _mockHomeDir = tempDir;
  stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  stdoutSpy.mockRestore();
  stderrSpy.mockRestore();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

function writePolicy(mode: 'enforce' | 'monitor'): void {
  const policyPath = path.join(tempDir, SHIELD_DIR, SHIELD_POLICY_FILE);
  savePolicy(createDefaultPolicy(mode), policyPath);
  if (!fs.existsSync(policyPath)) throw new Error(`fixture not written: ${policyPath}`);
}

/** Write the HTML report and return the topViolations its payload embeds. */
async function topViolations(): Promise<Violation[]> {
  const file = path.join(tempDir, 'report.html');
  const code = await shield({ subcommand: 'report', report: file });
  expect(code).toBe(0);
  const html = fs.readFileSync(file, 'utf-8');
  const marker = html.indexOf('<script id="report-data"');
  expect(marker).toBeGreaterThanOrEqual(0);
  const start = html.indexOf('>', marker) + 1;
  const payload = html.slice(start, html.indexOf('</script>', start));
  return JSON.parse(payload).report.policyEvaluation.topViolations as Violation[];
}

describe('shield report after shield evaluate under mode: enforce', () => {
  it('lists the deny match with the may-have-run recommendation', async () => {
    writePolicy('enforce');
    expect(await shield({ subcommand: 'evaluate', args: ['aws s3 ls'] })).toBe(1);

    const violations = await topViolations();
    const found = violations.filter(v => v.recommendation === MAY_HAVE_RUN);
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({
      action: 'command.monitored',
      target: 'aws s3 ls',
      count: 1,
      severity: 'medium',
    });
  });

  it('counts repeated deny matches of one command in one row', async () => {
    writePolicy('enforce');
    await shield({ subcommand: 'evaluate', args: ['aws s3 ls'] });
    await shield({ subcommand: 'evaluate', args: ['aws s3 ls'] });

    const found = (await topViolations()).filter(v => v.target === 'aws s3 ls');
    expect(found).toHaveLength(1);
    expect(found[0].count).toBe(2);
    expect(found[0].recommendation).toBe(MAY_HAVE_RUN);
  });
});

describe('shield report after shield evaluate under mode: monitor', () => {
  it('does not list the monitored record, which carries no deny verdict', async () => {
    writePolicy('monitor');
    expect(await shield({ subcommand: 'evaluate', args: ['aws s3 ls'] })).toBe(0);

    const violations = await topViolations();
    expect(violations.filter(v => v.target === 'aws s3 ls')).toHaveLength(0);
    expect(violations.filter(v => v.recommendation === MAY_HAVE_RUN)).toHaveLength(0);
  });
});
