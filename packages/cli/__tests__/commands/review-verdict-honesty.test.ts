import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// Hermetic homedir: review reads the Shield event log under ~/.opena2a.
const mockHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => mockHome.dir || actual.homedir() };
});

// The report opener spawns `open` / `xdg-open`. Replace spawn with a spy so a
// regression in the open gate can never launch a real browser from a test.
const spawnSpy = vi.hoisted(() => vi.fn((..._args: unknown[]) => ({ unref: () => {} })));
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  return { ...actual, spawn: spawnSpy };
});

import {
  review,
  aggregateFindings,
  shouldAutoOpenReport,
  type CredentialPhaseData,
  type ShieldPhaseData,
  type DetectFinding,
} from '../../src/commands/review.js';

const CRED_EMPTY: CredentialPhaseData = {
  matches: [], totalFindings: 0, bySeverity: {}, driftFindings: 0,
} as unknown as CredentialPhaseData;
const SHIELD_EMPTY = { classifiedFindings: [] } as unknown as ShieldPhaseData;

async function runReview(
  targetDir: string,
  opts: { format?: 'json'; isTTY?: boolean } = {},
): Promise<{ exitCode: number; output: string }> {
  const chunks: string[] = [];
  const origWrite = process.stdout.write;
  const origErr = process.stderr.write;
  const origTTY = process.stdout.isTTY;
  process.stdout.isTTY = opts.isTTY ?? false;
  process.stdout.write = ((chunk: unknown) => { chunks.push(String(chunk)); return true; }) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    const exitCode = await review({
      targetDir,
      reportPath: path.join(targetDir, 'report.html'),
      skipHma: true,
      format: opts.format,
    });
    return { exitCode, output: chunks.join('') };
  } finally {
    process.stdout.write = origWrite;
    process.stderr.write = origErr;
    process.stdout.isTTY = origTTY;
  }
}

describe('review counts the Shadow AI findings that are about the scanned tree', () => {
  const finding = (id: string, scope: DetectFinding['scope'], severity: string): DetectFinding => ({
    id, scope, severity, title: id, whyItMatters: 'why', remediation: 'fix',
  });

  it('adds project-scoped findings and leaves host-scoped ones in the Shadow AI phase', () => {
    const result = aggregateFindings(CRED_EMPTY, SHIELD_EMPTY, '/tmp/target', null, {
      findings: [
        finding('SHADOW-AI-AGENTS', 'host', 'high'),
        { ...finding('SHADOW-AI-CONFIG', 'project', 'critical'), detail: 'CLAUDE.md' },
        finding('SHADOW-AI-SOUL', 'host', 'medium'),
      ],
    });
    expect(result).toEqual([{
      id: 'SHADOW-AI-CONFIG',
      title: 'SHADOW-AI-CONFIG',
      severity: 'critical',
      source: 'shadow-ai',
      detail: 'CLAUDE.md',
      remediation: 'fix',
    }]);
  });
});

describe('review on a tree whose only finding is a credential in an AI config file', () => {
  let tempDir: string;
  let tempHome: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-verdict-'));
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-verdict-home-'));
    mockHome.dir = tempHome;
    spawnSpy.mockClear();
    // No package.json: the project type is undetected ("Unknown").
    fs.writeFileSync(
      path.join(tempDir, 'CLAUDE.md'),
      '# Project notes\napi_key: FAKEabcdefghijklmnopqrstuvwxyz0123\n',
    );
  });

  afterEach(() => {
    mockHome.dir = '';
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  it('counts the finding and names it in a not-safe verdict', async () => {
    const { exitCode, output } = await runReview(tempDir);

    expect(exitCode).toBe(1);
    expect(output).toMatch(/Score: 0\/100/);
    expect(output).toMatch(/\b1 findings \(1 critical, 0 high, 0 medium\)/);
    const verdictLine = output.split('\n').find(l => /^\s+Verdict\s/.test(l));
    expect(verdictLine).toBeDefined();
    expect(verdictLine).toMatch(/Not safe to ship/);
    expect(verdictLine).toMatch(/AI config files contain credential references/);
    expect(verdictLine).not.toMatch(/No security issues detected/);
    expect(verdictLine).not.toMatch(/looks safe to use/);
    expect(verdictLine).not.toMatch(/Unknown/);
    // The undetected project type is named "project", not "Unknown".
    expect(output).toMatch(/^\s+Surfaces\s+project$/m);
  });

  it('carries the finding in the JSON findings list, matching detectData', async () => {
    const { output } = await runReview(tempDir, { format: 'json' });
    const report = JSON.parse(output);

    expect(report.compositeScore).toBe(0);
    expect(report.detectData.findings.map((f: { id: string }) => f.id)).toContain('SHADOW-AI-CONFIG');
    const counted = report.findings.find((f: { id: string }) => f.id === 'SHADOW-AI-CONFIG');
    expect(counted).toMatchObject({ severity: 'critical', source: 'shadow-ai', detail: 'CLAUDE.md' });
  });

  it('opens no browser when stdout is not a TTY', async () => {
    const { output } = await runReview(tempDir, { isTTY: false });

    expect(spawnSpy).not.toHaveBeenCalled();
    expect(output).not.toMatch(/opened in browser/);
  });

  it('opens the report for a person at a terminal', async () => {
    await runReview(tempDir, { isTTY: true });

    expect(spawnSpy).toHaveBeenCalledTimes(1);
    expect(spawnSpy.mock.calls[0][1]).toEqual([path.join(tempDir, 'report.html')]);
  });
});

describe('shouldAutoOpenReport', () => {
  it('requires auto-open on, --ci off and a TTY on stdout', () => {
    expect(shouldAutoOpenReport({}, true)).toBe(true);
    expect(shouldAutoOpenReport({}, false)).toBe(false);
    expect(shouldAutoOpenReport({ autoOpen: false }, true)).toBe(false);
    expect(shouldAutoOpenReport({ ci: true }, true)).toBe(false);
  });
});
