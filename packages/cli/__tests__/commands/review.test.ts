import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { runInNewContext } from 'node:vm';

// ---------------------------------------------------------------------------
// Hermetic homedir for the review-command tests.
//
// `review` reads (and, since #204, chain-verifies) the global Shield event
// log at ~/.opena2a/shield/events.jsonl. Without this mock the command
// tests below depend on whatever log the developer's machine has
// accumulated — and other test files' writeEvent calls race each other on
// that shared log, forking its hash chain mid-run. When `mockHome.dir` is
// set (only inside the `review` describe block), homedir() points at a
// fresh temp dir; everywhere else the real homedir is used.
// ---------------------------------------------------------------------------

const mockHome = vi.hoisted(() => ({ dir: '' }));

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => mockHome.dir || actual.homedir(),
  };
});

import {
  review,
  aggregateFindings,
  applyDominantAnalyzerFloor,
  buildFloorParticipants,
  targetGovernanceFloorScore,
  shieldCompositeScore,
  shieldRiskFloorScore,
  governanceCompositeScore,
  credentialFloorScore,
  CRITICAL_BAND,
  type CredentialPhaseData,
  type ShieldPhaseData,
  type HmaPhaseData,
  type HmaFinding,
} from '../../src/commands/review.js';
import type { CredentialMatch } from '../../src/util/credential-patterns.js';

function captureStdout(fn: () => Promise<number>): Promise<{ exitCode: number; output: string }> {
  const chunks: string[] = [];
  const origWrite = process.stdout.write;
  process.stdout.write = ((chunk: any) => {
    chunks.push(String(chunk));
    return true;
  }) as any;

  return fn().then(exitCode => {
    process.stdout.write = origWrite;
    return { exitCode, output: chunks.join('') };
  }).catch(err => {
    process.stdout.write = origWrite;
    throw err;
  });
}

/**
 * Render one tab of a generated review report and return its HTML.
 *
 * The report's page renderers are client-side JS embedded in the document, so
 * asserting on the raw file only proves the template contains a string — a
 * renderer can be present and still never run. This executes the real script
 * against a minimal DOM stub, clicks the requested nav tab, and returns what
 * that tab's renderer produced. Everything the script touches at load time is
 * stubbed: the JSON payload element, the nav listener, and the page divs.
 */
function renderReportPage(html: string, page: string): string {
  const script = html.slice(
    html.lastIndexOf('<script>') + '<script>'.length,
    html.lastIndexOf('</script>'),
  );
  const payload = html.slice(
    html.indexOf('>', html.indexOf('<script id="report-data"')) + 1,
    html.indexOf('</script>'),
  );

  const nodes = new Map<string, any>();
  const handlers = new Map<string, (e: any) => void>();
  const node = (id: string) => {
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        innerHTML: '',
        classList: { toggle: () => {}, add: () => {}, remove: () => {} },
        addEventListener: (type: string, fn: (e: any) => void) => handlers.set(`${id}:${type}`, fn),
        querySelectorAll: () => [] as any[],
      });
    }
    return nodes.get(id);
  };
  const documentStub = {
    getElementById: (id: string) => (id === 'report-data' ? { textContent: payload } : node(id)),
    querySelectorAll: () => [] as any[],
    querySelector: () => null,
    createElement: () => ({ style: {}, setAttribute: () => {}, appendChild: () => {} }),
    body: { appendChild: () => {}, removeChild: () => {} },
    execCommand: () => {},
  };

  // The evaluated string is the report our own generator just produced, run
  // against the stub document above. runInNewContext gives it a fresh global
  // scope; it is not a sandbox and is not relied on as one.
  runInNewContext(script, { document: documentStub, window: { addEventListener: () => {} } });

  const onNavClick = handlers.get('main-nav:click');
  if (!onNavClick) throw new Error('report script did not register the nav listener');
  onNavClick({ target: { closest: () => ({ getAttribute: () => page }) } });

  return node(`page-${page}`).innerHTML;
}

describe('review', () => {
  let tempDir: string;
  let tempHome: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-test-'));
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-test-home-'));
    mockHome.dir = tempHome;
  });

  afterEach(() => {
    mockHome.dir = '';
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  it('clean project returns score >= 80', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test-project', version: '1.0.0' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\nnode_modules\n');
    fs.writeFileSync(path.join(tempDir, 'package-lock.json'), '{}');
    fs.mkdirSync(path.join(tempDir, '.git'));

    const reportPath = path.join(tempDir, 'report.html');
    const { exitCode, output } = await captureStdout(() => review({
      targetDir: tempDir,
      format: 'json',
      autoOpen: false,
      skipHma: true,
    }));

    expect(exitCode).toBe(0);
    const report = JSON.parse(output);
    // Adoption-as-recovery (#175 follow-up): a clean project must NOT be scored
    // down for opt-in tooling it hasn't adopted (unsigned configs, no Shield
    // setup, no registered identity). It should clear the "good" band even with
    // none of that set up. Regression guard for the whole adoption-penalty fix.
    expect(report.compositeScore).toBeGreaterThanOrEqual(80);
    expect(['strong', 'good']).toContain(report.grade);
    expect(report.phases).toHaveLength(6);
  });

  it('C1: --skip-hma sets report.provisional=true and emits a stderr notice', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test-project', version: '1.0.0' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\nnode_modules\n');

    const stderrChunks: string[] = [];
    const origStderr = process.stderr.write;
    process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;
    let output = '';
    try {
      ({ output } = await captureStdout(() => review({
        targetDir: tempDir, format: 'json', autoOpen: false, skipHma: true,
      })));
    } finally {
      process.stderr.write = origStderr;
    }

    // The machine path (--json) carries the provisional signal as a field...
    const report = JSON.parse(output);
    expect(report.provisional).toBe(true);
    // ...and a human watching the terminal sees the notice on stderr (not mixed
    // into the JSON on stdout).
    const stderr = stderrChunks.join('');
    expect(stderr).toMatch(/Provisional verdict/);
    expect(stderr).toMatch(/did not run/);
    expect(output).not.toMatch(/Provisional verdict/); // stdout JSON stays clean
  });

  it('C6: a broken event chain marks the Shield phase provisional and says so on stderr', async () => {
    // Before this, the only trace of the exclusion in ANY output was nested
    // inside shieldData.classifiedFindings[0].examples[0].detail in the JSON.
    // A terminal user saw a small "N events, M findings" and a clean-looking
    // phase, with nothing indicating that events had been dropped.
    const { writeEvent, getShieldDir, getEventsPath } = await import('../../src/shield/events.js');
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'chain-test', version: '1.0.0' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\nnode_modules\n');

    const base = {
      source: 'shield' as const, category: 'posture-assessment', severity: 'info' as const,
      agent: null, sessionId: null, outcome: 'allowed' as const, detail: {},
      orgId: null, managed: false, agentId: null,
    };
    getShieldDir();
    writeEvent({ ...base, action: 'genuine-1', target: 'baseline' });
    // One appended event whose hashes do not continue the chain: writeEvent
    // links the next event to it, verification fails at the forged line, and
    // every event after this point is untrusted. This is the whole cost of
    // the attack. (An unparseable line no longer breaks the chain, #244.)
    fs.appendFileSync(getEventsPath(), JSON.stringify({
      id: 'forged', timestamp: new Date().toISOString(), version: 1,
      ...base, action: 'genuine-1', target: 'baseline',
      prevHash: 'f'.repeat(64), eventHash: 'f'.repeat(64),
    }) + '\n', 'utf-8');
    writeEvent({
      ...base, source: 'configguard', outcome: 'blocked', severity: 'critical',
      action: 'tamper-detected', target: path.join(tempDir, 'mcp.json'),
    });
    writeEvent({ ...base, source: 'arp', category: 'process.spawn', action: 'spawn', target: '/usr/bin/curl' });

    const stderrChunks: string[] = [];
    const origStderr = process.stderr.write;
    process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;
    let output = '';
    try {
      ({ output } = await captureStdout(() => review({
        targetDir: tempDir, format: 'json', autoOpen: false, skipHma: true,
      })));
    } finally {
      process.stderr.write = origStderr;
    }

    const report = JSON.parse(output); // stdout JSON stays parseable...
    const shieldPhase = report.phases.find((p: any) => p.name === 'Shield Analysis');
    expect(shieldPhase.provisional).toBe(true);
    expect(shieldPhase.provisionalReason).toMatch(/chain broken/);
    // The detail line carries the excluded count, not just the survivors:
    // the forged line plus the two events chained after it.
    expect(shieldPhase.detail).toMatch(/3 excluded/);
    expect(shieldPhase.detail).toMatch(/chain broken at 1/);
    expect(report.shieldData.chainBroken).toBe(true);
    expect(report.shieldData.untrustedEventsExcluded).toBe(3);
    expect(report.shieldData.brokenAt).toBe(1);

    // ...and a human watching the terminal is told, on stderr, like the HMA notice.
    const stderr = stderrChunks.join('');
    expect(stderr).toMatch(/chain broken/);
    expect(stderr).toMatch(/3 untrusted events/);
    // stdout JSON stays clean: the notice text is on stderr only, and stdout is
    // nothing but the document. (`provisionalReason` legitimately appears IN
    // the JSON — that is the machine-readable half of the same signal.)
    expect(output).not.toMatch(/Shield events partially excluded/);
    expect(output.trimStart().startsWith('{')).toBe(true);

    // The excluded events never become reported findings — only the single
    // chain-break finding does.
    const shieldFindingIds = report.findings
      .filter((f: any) => f.source === 'shield').map((f: any) => f.id);
    expect(shieldFindingIds).toEqual(['SHIELD-INT-002']);
    expect(shieldFindingIds).not.toContain('SHIELD-INT-001');
    expect(shieldFindingIds).not.toContain('SHIELD-PROC-001');
  });

  it('C6: a broken chain is visible in the human summary and on the HTML Shield tab', async () => {
    // The two surfaces a person actually looks at. The JSON fields and the
    // stderr notice are covered above; these are the ones that were silent.
    const { writeEvent, getShieldDir, getEventsPath } = await import('../../src/shield/events.js');
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'chain-html', version: '1.0.0' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\nnode_modules\n');

    const base = {
      source: 'shield' as const, category: 'posture-assessment', severity: 'info' as const,
      agent: null, sessionId: null, outcome: 'allowed' as const, detail: {},
      orgId: null, managed: false, agentId: null,
    };
    getShieldDir();
    writeEvent({ ...base, action: 'genuine-1', target: 'baseline' });
    // A forged event that does not continue the chain (see the C6 test above)
    fs.appendFileSync(getEventsPath(), JSON.stringify({
      id: 'forged', timestamp: new Date().toISOString(), version: 1,
      ...base, action: 'genuine-1', target: 'baseline',
      prevHash: 'f'.repeat(64), eventHash: 'f'.repeat(64),
    }) + '\n', 'utf-8');
    writeEvent({ ...base, source: 'arp', category: 'process.spawn', action: 'spawn', target: '/usr/bin/curl' });

    const reportPath = path.join(tempDir, 'chain-report.html');
    const origStderr = process.stderr.write;
    process.stderr.write = (() => true) as any;
    let output = '';
    try {
      ({ output } = await captureStdout(() => review({
        targetDir: tempDir, reportPath, autoOpen: false, skipHma: true, ci: true,
      })));
    } finally {
      process.stderr.write = origStderr;
    }

    // Terminal summary, on the same screen as the finding count it qualifies.
    expect(output).toMatch(/2 shield events excluded/); // the forged line and the spawn
    expect(output).toMatch(/chain broken at index 1/);

    // HTML Shield tab, actually rendered (not merely present in the template).
    const shieldHtml = renderReportPage(fs.readFileSync(reportPath, 'utf-8'), 'shield');
    expect(shieldHtml).toContain('Excluded (Chain Break)');
    expect(shieldHtml).toContain('Event log hash chain broken');
    expect(shieldHtml).toContain('opena2a shield selfcheck');
  });

  it('C6: an intact event chain leaves the Shield phase non-provisional and silent', async () => {
    // Non-vacuity for the test above: the provisional flag and the notice must
    // be caused by the break, not emitted unconditionally.
    const { writeEvent, getShieldDir } = await import('../../src/shield/events.js');
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'chain-test', version: '1.0.0' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\nnode_modules\n');

    getShieldDir();
    writeEvent({
      source: 'shield', category: 'posture-assessment', severity: 'info',
      agent: null, sessionId: null, action: 'genuine-1', target: 'baseline',
      outcome: 'allowed', detail: {}, orgId: null, managed: false, agentId: null,
    });

    const stderrChunks: string[] = [];
    const origStderr = process.stderr.write;
    process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;
    let output = '';
    try {
      ({ output } = await captureStdout(() => review({
        targetDir: tempDir, format: 'json', autoOpen: false, skipHma: true,
      })));
    } finally {
      process.stderr.write = origStderr;
    }

    const report = JSON.parse(output);
    const shieldPhase = report.phases.find((p: any) => p.name === 'Shield Analysis');
    expect(shieldPhase.provisional).toBeUndefined();
    expect(shieldPhase.detail).not.toMatch(/excluded/);
    expect(report.shieldData.chainBroken).toBe(false);
    expect(stderrChunks.join('')).not.toMatch(/chain broken/);
  });

  it('a full scan (HMA ran) is not marked provisional', async () => {
    // When HMA is available the report must NOT be flagged provisional. We can't
    // guarantee HMA is installed in CI, so assert the contract: provisional
    // mirrors !hmaAvailable.
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test', version: '1.0.0' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    const { output } = await captureStdout(() => review({
      targetDir: tempDir, format: 'json', autoOpen: false, skipHma: true,
    }));
    const report = JSON.parse(output);
    expect(report.provisional).toBe(!(report.hmaData?.available ?? false));
  });

  it('project with credentials returns lower score', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test-project' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), 'node_modules\n');
    const fakeKey = 'sk-ant-api03-' + 'A'.repeat(85);
    fs.writeFileSync(path.join(tempDir, 'config.ts'), `const key = "${fakeKey}";`);

    const { exitCode, output } = await captureStdout(() => review({
      targetDir: tempDir,
      format: 'json',
      autoOpen: false,
      skipHma: true,
    }));

    const report = JSON.parse(output);
    expect(report.compositeScore).toBeLessThan(80);
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.credentialData.totalFindings).toBeGreaterThan(0);
  });

  // #267: review copied every detected credential verbatim into
  // credentialData.matches[].value, so the JSON CI archives and the HTML built
  // to be shared both carried the secret. Two credential shapes on purpose: a
  // single-shape fixture came back clean on a build that leaked.
  it('#267: no output format carries a detected credential value', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test-project' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), 'node_modules\n');
    const anthropicKey = 'sk-ant-api03-' + 'Q7vK2mXp9LrT4wZb'.repeat(5) + 'Hn3c8';
    const githubPat = 'ghp_' + 'R4tY8uIo2pAs6dFg0hJk3lZx7cVb5nMq1wEr';
    fs.writeFileSync(
      path.join(tempDir, 'config.js'),
      `const anthropic = "${anthropicKey}";\nconst github = "${githubPat}";\n`,
    );
    const secrets = [anthropicKey, githubPat];

    const json = await captureStdout(() => review({
      targetDir: tempDir,
      format: 'json',
      autoOpen: false,
      skipHma: true,
    }));
    const report = JSON.parse(json.output);
    // The fixture must actually be detected, or absence proves nothing.
    expect(report.credentialData.totalFindings).toBeGreaterThanOrEqual(2);
    for (const s of secrets) expect(json.output).not.toContain(s);
    for (const m of report.credentialData.matches) {
      expect(m.value).toContain('•');
      expect(m.filePath).toContain('config.js');
      expect(m.line).toBeGreaterThan(0);
    }

    const reportPath = path.join(tempDir, 'shared-report.html');
    const text = await captureStdout(() => review({
      targetDir: tempDir,
      reportPath,
      autoOpen: false,
      skipHma: true,
    }));
    const html = fs.readFileSync(reportPath, 'utf-8');
    for (const s of secrets) {
      expect(text.output).not.toContain(s);
      expect(html).not.toContain(s);
    }
    expect(renderReportPage(html, 'credentials')).toContain('config.js');
    if (process.platform !== 'win32') {
      expect(fs.statSync(reportPath).mode & 0o077).toBe(0);
    }
  });

  it('guard signed files show Active in results', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');

    const { output } = await captureStdout(() => review({
      targetDir: tempDir,
      format: 'json',
      autoOpen: false,
      skipHma: true,
    }));

    const report = JSON.parse(output);
    expect(report.guardData).toBeDefined();
    expect(report.guardData.signatureStatus).toBe('unsigned');
  });

  it('JSON output returns complete ReviewReport', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test', version: '2.0.0' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');

    const { output } = await captureStdout(() => review({
      targetDir: tempDir,
      format: 'json',
      autoOpen: false,
      skipHma: true,
    }));

    const report = JSON.parse(output);
    expect(report).toHaveProperty('timestamp');
    expect(report).toHaveProperty('directory');
    expect(report).toHaveProperty('projectName');
    expect(report).toHaveProperty('projectType');
    expect(report).toHaveProperty('phases');
    expect(report).toHaveProperty('compositeScore');
    expect(report).toHaveProperty('grade');
    expect(report).toHaveProperty('findings');
    expect(report).toHaveProperty('actionItems');
    expect(report).toHaveProperty('initData');
    expect(report).toHaveProperty('credentialData');
    expect(report).toHaveProperty('guardData');
    expect(report).toHaveProperty('shieldData');
  });

  // A credential check that opened no file found nothing because it read
  // nothing. Saying "No hardcoded credentials found. Your project is clean."
  // there answers a question the scan never asked.
  async function reviewBothFormats(dir: string) {
    const reportPath = path.join(tempHome, 'report.html');
    const origStderr = process.stderr.write;
    process.stderr.write = (() => true) as any;
    try {
      const { output } = await captureStdout(() => review({
        targetDir: dir, format: 'json', autoOpen: false, skipHma: true,
      }));
      await captureStdout(() => review({
        targetDir: dir, reportPath, autoOpen: false, skipHma: true, ci: true,
      }));
      const html = fs.readFileSync(reportPath, 'utf-8');
      return {
        report: JSON.parse(output),
        credentialsTab: renderReportPage(html, 'credentials'),
        overviewTab: renderReportPage(html, 'overview'),
      };
    } finally {
      process.stderr.write = origStderr;
    }
  }

  it('a directory in which the credential scan opens no file is not reported as clean', async () => {
    // Every file here is one the credential walk skips: an image, a document
    // and a dotfile that is not an .env file.
    fs.writeFileSync(path.join(tempDir, 'logo.png'), 'PNG');
    fs.writeFileSync(path.join(tempDir, 'guide.pdf'), '%PDF-1.4');
    fs.writeFileSync(path.join(tempDir, '.toolrc'), 'x=1\n');

    const { report, credentialsTab, overviewTab } = await reviewBothFormats(tempDir);

    expect(report.credentialData.filesScanned).toBe(0);
    const credPhase = report.phases.find((p: any) => p.name === 'Credentials');
    expect(credPhase.detail).toBe('No files scanned for credentials');

    expect(credentialsTab).not.toContain('No hardcoded credentials found');
    expect(credentialsTab).not.toContain('Your project is clean');
    expect(credentialsTab).toContain('No files were scanned for credentials');
    expect(credentialsTab).toContain('opena2a review');
    expect(overviewTab).toContain('No files scanned for credentials');
    expect(overviewTab).not.toContain('No hardcoded credentials');
  });

  it('a directory with a readable source file and no credential keeps the clean wording', async () => {
    fs.writeFileSync(path.join(tempDir, 'index.js'), 'console.log("hello");\n');

    const { report, credentialsTab } = await reviewBothFormats(tempDir);

    expect(report.credentialData.filesScanned).toBeGreaterThanOrEqual(1);
    const credPhase = report.phases.find((p: any) => p.name === 'Credentials');
    expect(credPhase.detail).toBe('No hardcoded credentials');
    expect(credentialsTab).toContain('No hardcoded credentials found. Your project is clean.');
  });

  it('HMA unavailable gracefully skips', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');

    const { output } = await captureStdout(() => review({
      targetDir: tempDir,
      format: 'json',
      autoOpen: false,
      skipHma: true,
    }));

    const report = JSON.parse(output);
    const hmaPhase = report.phases.find((p: any) => p.name === 'HMA Scan');
    expect(hmaPhase).toBeDefined();
    expect(hmaPhase.status).toBe('skip');
  });

  it('nonexistent directory returns exit code 1', async () => {
    const stderrChunks: string[] = [];
    const origStderr = process.stderr.write;
    process.stderr.write = ((chunk: any) => {
      stderrChunks.push(String(chunk));
      return true;
    }) as any;

    const exitCode = await review({ targetDir: '/nonexistent/path/xyz', autoOpen: false });
    process.stderr.write = origStderr;

    expect(exitCode).toBe(1);
  });

  it('report writes to custom path', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');

    const reportPath = path.join(tempDir, 'custom-report.html');
    const { exitCode } = await captureStdout(() => review({
      targetDir: tempDir,
      reportPath,
      autoOpen: false,
      skipHma: true,
    }));

    expect(exitCode).toBe(0);
    expect(fs.existsSync(reportPath)).toBe(true);
    const html = fs.readFileSync(reportPath, 'utf-8');
    expect(html).toContain('OpenA2A Security Review');
    expect(html).toContain('report-data');
  });

  it('--format json with --report writes the HTML report and keeps stdout pure JSON', async () => {
    // `--report <path>` used to be dropped silently under `--format json`:
    // the JSON branch returned before the report was written, so the path the
    // user named stayed empty and nothing said so.
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'json-report' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');

    const reportPath = path.join(tempDir, 'json-report.html');
    const stderrChunks: string[] = [];
    const origStderr = process.stderr.write;
    process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;
    let result: { exitCode: number; output: string };
    try {
      result = await captureStdout(() => review({
        targetDir: tempDir,
        reportPath,
        format: 'json',
        autoOpen: false,
        skipHma: true,
      }));
    } finally {
      process.stderr.write = origStderr;
    }

    expect(result.exitCode).toBe(0);
    const report = JSON.parse(result.output);
    expect(report.phases).toHaveLength(6);
    expect(fs.existsSync(reportPath)).toBe(true);
    const html = fs.readFileSync(reportPath, 'utf-8');
    expect(html).toContain('OpenA2A Security Review');
    expect(html).toContain('report-data');
    if (process.platform !== 'win32') {
      expect(fs.statSync(reportPath).mode & 0o077).toBe(0);
    }
    expect(stderrChunks.join('')).toContain(reportPath);
  });

  it('--format json with a --report path that cannot be written still prints the JSON, and exits 2', async () => {
    // Writing the report before the JSON lost the document on stdout when the
    // path was unwritable, and the thrown error surfaced as exit 1 — the code a
    // json run uses for a score below 50, so a gate could not tell them apart.
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'json-report-unwritable' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');

    const reportPath = path.join(tempDir, 'no-such-dir', 'out.html');
    const stderrChunks: string[] = [];
    const origStderr = process.stderr.write;
    process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;
    let result: { exitCode: number; output: string };
    try {
      result = await captureStdout(() => review({
        targetDir: tempDir,
        reportPath,
        format: 'json',
        autoOpen: false,
        skipHma: true,
      }));
    } finally {
      process.stderr.write = origStderr;
    }

    expect(result.exitCode).toBe(2);
    const report = JSON.parse(result.output);
    expect(report.phases).toHaveLength(6);
    expect(fs.existsSync(reportPath)).toBe(false);
    const stderr = stderrChunks.join('');
    expect(stderr).toContain('Report not written');
    expect(stderr).toContain(reportPath);
    expect(stderr).not.toContain('  Report: ');
  });

  it('--format sarif is refused with a message and exit 2, and writes no report', async () => {
    // `--format sarif` used to fall through to text output and write the HTML
    // report, with exit 0 — a SARIF consumer received neither SARIF nor an error.
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'sarif-refused' }));

    const reportPath = path.join(tempDir, 'review.sarif');
    const stderrChunks: string[] = [];
    const origStderr = process.stderr.write;
    process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;
    let result: { exitCode: number; output: string };
    try {
      result = await captureStdout(() => review({
        targetDir: tempDir,
        reportPath,
        format: 'sarif',
        autoOpen: false,
        skipHma: true,
      }));
    } finally {
      process.stderr.write = origStderr;
    }

    expect(result.exitCode).toBe(2);
    expect(result.output).toBe('');
    expect(fs.existsSync(reportPath)).toBe(false);
    const stderr = stderrChunks.join('');
    expect(stderr).toContain('--format sarif');
    expect(stderr).toContain('text');
    expect(stderr).toContain('json');
  });

  it('--quiet prints the score, finding counts and report path only, and keeps the verdict notices', async () => {
    // The global `--quiet` used to be dropped silently: review printed the
    // banner, six progress lines and the Observations block exactly as without it.
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'quiet-text' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');

    const reportPath = path.join(tempDir, 'quiet.html');
    const stderrChunks: string[] = [];
    const origStderr = process.stderr.write;
    process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;
    let result: { exitCode: number; output: string };
    try {
      result = await captureStdout(() => review({
        targetDir: tempDir,
        reportPath,
        autoOpen: false,
        skipHma: true,
        quiet: true,
      }));
    } finally {
      process.stderr.write = origStderr;
    }

    expect(result.exitCode).toBe(0);
    const lines = result.output.replace(/\x1b\[\d+m/g, '').split('\n').filter(l => l.trim() !== '');
    expect(lines).toHaveLength(3);
    expect(lines[0]).toMatch(/^ {2}Score: \d+\/100/);
    expect(lines[1]).toMatch(/^ {2}\d+ findings \(\d+ critical, \d+ high, \d+ medium\)$/);
    expect(lines[2]).toBe(`  Report: ${reportPath}`);
    expect(result.output).not.toContain('OpenA2A Security Review');
    expect(result.output).not.toContain('[1/6]');
    expect(result.output).not.toContain('Surfaces');
    expect(fs.existsSync(reportPath)).toBe(true);
    // The provisional-verdict notice qualifies the score, so it is essential.
    expect(stderrChunks.join('')).toMatch(/Provisional verdict/);
  });

  it('--quiet with --format json keeps stdout pure JSON and drops the report confirmation', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'quiet-json' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');

    const reportPath = path.join(tempDir, 'quiet-json.html');
    const stderrChunks: string[] = [];
    const origStderr = process.stderr.write;
    process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;
    let result: { exitCode: number; output: string };
    try {
      result = await captureStdout(() => review({
        targetDir: tempDir,
        reportPath,
        format: 'json',
        autoOpen: false,
        skipHma: true,
        quiet: true,
      }));
    } finally {
      process.stderr.write = origStderr;
    }

    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.output).phases).toHaveLength(6);
    expect(fs.existsSync(reportPath)).toBe(true);
    const stderr = stderrChunks.join('');
    expect(stderr).not.toContain('Report:');
    expect(stderr).toMatch(/Provisional verdict/);
  });

  it('--quiet with --verbose is refused with a message and exit 2, and writes no report', async () => {
    // The two ask for opposite output; honouring either one ignores the other.
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'quiet-verbose' }));

    const reportPath = path.join(tempDir, 'quiet-verbose.html');
    const stderrChunks: string[] = [];
    const origStderr = process.stderr.write;
    process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;
    let result: { exitCode: number; output: string };
    try {
      result = await captureStdout(() => review({
        targetDir: tempDir,
        reportPath,
        autoOpen: false,
        skipHma: true,
        quiet: true,
        verbose: true,
      }));
    } finally {
      process.stderr.write = origStderr;
    }

    expect(result.exitCode).toBe(2);
    expect(result.output).toBe('');
    expect(fs.existsSync(reportPath)).toBe(false);
    const stderr = stderrChunks.join('');
    expect(stderr).toContain('--quiet');
    expect(stderr).toContain('--verbose');
  });

  it('renders the @opena2a/cli-ui Observations block with Surfaces/Checks/Categories/Verdict labels', async () => {
    // Smoke test for the CA-030 cli-ui wire at packages/cli/src/commands/review.ts:430.
    // Asserts the dynamic import of @opena2a/cli-ui succeeded AND the four label
    // strings appear between the Score summary and the Report line. A regression
    // here means either cli-ui is missing from node_modules or the renderer was
    // accidentally deleted from review() — both are blocking.
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'obs-test', version: '1.0.0' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\nnode_modules\n');

    const { exitCode, output } = await captureStdout(() => review({
      targetDir: tempDir,
      autoOpen: false,
      skipHma: true,
      ci: true,
    }));

    expect(exitCode).toBe(0);
    // All four Observations labels must render.
    expect(output).toContain('Surfaces');
    expect(output).toContain('Checks');
    expect(output).toContain('Categories');
    expect(output).toContain('Verdict');
    // Block appears between Score and Report.
    const scoreIdx = output.indexOf('Score:');
    const surfacesIdx = output.indexOf('Surfaces');
    const reportIdx = output.indexOf('Report:');
    expect(scoreIdx).toBeGreaterThanOrEqual(0);
    expect(surfacesIdx).toBeGreaterThan(scoreIdx);
    expect(reportIdx).toBeGreaterThan(surfacesIdx);
    // cli-ui's standard Checks line shape survives the wire.
    expect(output).toMatch(/\d+ static/);
    expect(output).toContain('semantic (NanoMind AST)');
  });

  it('credentials from quickCredentialScan show up in the Categories line', async () => {
    // Regression for the review-HMA-coverage fix. Before, aggregateFindings
    // could produce zero credential findings even when credData had matches
    // because the loop existed but the Observations block downstream only
    // showed "other". This asserts CRED-* findings are classified into the
    // cli-ui "credentials" bucket end-to-end.
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'cred-test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), 'node_modules\n');
    const fakeKey = 'sk-ant-api03-' + 'A'.repeat(85);
    fs.writeFileSync(path.join(tempDir, 'config.ts'), `const key = "${fakeKey}";`);

    const { exitCode, output } = await captureStdout(() => review({
      targetDir: tempDir,
      autoOpen: false,
      skipHma: true,
      ci: true,
    }));

    // A confirmed critical credential drives the dominant-analyzer floor, so the
    // verdict is "needs attention" (composite < 50 → exit 1). The credential must
    // not be diluted to a passing verdict by the neutralized adoption dimensions.
    expect(exitCode).toBe(1);
    expect(output).toContain('Categories');
    // The cli-ui classifier maps CRED-* into the "credentials" bucket.
    const categoriesLine = output.split('\n').find(l => l.includes('Categories')) ?? '';
    expect(categoriesLine).toContain('credentials');
  });
});

describe('aggregateFindings', () => {
  const SHIELD_EMPTY: ShieldPhaseData = {
    eventCount: 0,
    classifiedFindings: [],
    arpStats: {} as any,
    chainBroken: false,
    untrustedEventsExcluded: 0,
    brokenAt: null,
    shieldPostureScore: 100,
    policyLoaded: false,
    policyMode: null,
    integrityStatus: 'ok',
  };

  const makeCredMatch = (overrides: Partial<CredentialMatch> = {}): CredentialMatch => ({
    findingId: 'CRED-001',
    title: 'Hardcoded API Key',
    severity: 'critical',
    filePath: '/tmp/target/config.ts',
    line: 10,
    value: 'sk-xxx',
    envVar: 'API_KEY',
    ...overrides,
  });

  const makeHmaFinding = (overrides: Partial<HmaFinding> = {}): HmaFinding => ({
    checkId: 'CRED-HMA-001',
    name: 'Hardcoded credential detected',
    description: '',
    category: 'credentials',
    severity: 'critical',
    passed: false,
    message: '',
    file: 'config.ts',
    line: 10,
    fixable: true,
    fix: 'opena2a protect',
    guidance: '',
    count: 1,
    sampleFiles: [],
    ...overrides,
  });

  const makeHmaData = (findings: HmaFinding[]): HmaPhaseData => ({
    available: true,
    score: 50,
    maxScore: 100,
    totalChecks: findings.length,
    passed: 0,
    failed: findings.length,
    bySeverity: {},
    byCategory: {},
    topFindings: findings,
    allFailedFindings: findings,
  });

  it('prefers HMA over quickCredentialScan when both fire at the same file:line', () => {
    const credData: CredentialPhaseData = {
      matches: [makeCredMatch({ filePath: '/tmp/target/config.ts', line: 10 })],
      totalFindings: 1,
      bySeverity: { critical: 1 },
      driftFindings: [],
      envVarSuggestions: [],
    };
    const hmaData = makeHmaData([
      makeHmaFinding({ checkId: 'CRED-HMA-001', file: 'config.ts', line: 10 }),
    ]);

    const result = aggregateFindings(credData, SHIELD_EMPTY, '/tmp/target', hmaData);

    expect(result).toHaveLength(1);
    expect(result[0].source).toBe('hma');
    expect(result[0].id).toBe('CRED-HMA-001');
  });

  it('keeps both when HMA and credData fire at different locations', () => {
    const credData: CredentialPhaseData = {
      matches: [
        makeCredMatch({ filePath: '/tmp/target/a.ts', line: 5 }),
        makeCredMatch({ filePath: '/tmp/target/b.ts', line: 20 }),
      ],
      totalFindings: 2,
      bySeverity: { critical: 2 },
      driftFindings: [],
      envVarSuggestions: [],
    };
    const hmaData = makeHmaData([
      makeHmaFinding({ checkId: 'MCP-001', file: 'mcp.json', line: 1, severity: 'high' }),
      makeHmaFinding({ checkId: 'CRED-HMA-002', file: 'c.ts', line: 30 }),
    ]);

    const result = aggregateFindings(credData, SHIELD_EMPTY, '/tmp/target', hmaData);

    // 2 cred + 2 hma, no overlap
    expect(result).toHaveLength(4);
    const sources = result.map(r => r.source).sort();
    expect(sources).toEqual(['credential-scan', 'credential-scan', 'hma', 'hma']);
  });

  it('null hmaData leaves credData and shield untouched (backward compat)', () => {
    const credData: CredentialPhaseData = {
      matches: [makeCredMatch()],
      totalFindings: 1,
      bySeverity: { critical: 1 },
      driftFindings: [],
      envVarSuggestions: [],
    };

    const result = aggregateFindings(credData, SHIELD_EMPTY, '/tmp/target', null);

    expect(result).toHaveLength(1);
    expect(result[0].source).toBe('credential-scan');
  });

  it('prefers HMA over credData when HMA credential finding has file but no line', () => {
    // Real HMA output often omits line numbers for credential findings (e.g.
    // AST-CRED-001 on config.ts has file but line=null). The dedupe must
    // fall back to file-only comparison for credential-category HMA checks
    // so we don't double-count the same credential.
    const credData: CredentialPhaseData = {
      matches: [makeCredMatch({ filePath: '/tmp/target/config.ts', line: 10 })],
      totalFindings: 1,
      bySeverity: { critical: 1 },
      driftFindings: [],
      envVarSuggestions: [],
    };
    const hmaData = makeHmaData([
      makeHmaFinding({
        checkId: 'AST-CRED-001',
        file: 'config.ts',
        line: undefined,
        severity: 'high',
      }),
    ]);

    const result = aggregateFindings(credData, SHIELD_EMPTY, '/tmp/target', hmaData);

    // Only 1 finding: HMA wins, credData is dropped.
    expect(result).toHaveLength(1);
    expect(result[0].source).toBe('hma');
    // Severity upgraded from HMA's "high" to credData's "critical".
    expect(result[0].severity).toBe('critical');
  });

  it('non-credential HMA finding on a file does NOT mask a credential in that file', () => {
    // A HIGH GIT-002 on .gitignore must not suppress a CRITICAL CRED-001
    // that quickCredentialScan found in the same file — the dedupe is
    // scoped to credential-category HMA checks only.
    const credData: CredentialPhaseData = {
      matches: [makeCredMatch({
        findingId: 'CRED-001',
        filePath: '/tmp/target/.gitignore',
        line: 3,
      })],
      totalFindings: 1,
      bySeverity: { critical: 1 },
      driftFindings: [],
      envVarSuggestions: [],
    };
    const hmaData = makeHmaData([
      makeHmaFinding({
        checkId: 'GIT-002',
        file: '.gitignore',
        line: undefined,
        severity: 'high',
      }),
    ]);

    const result = aggregateFindings(credData, SHIELD_EMPTY, '/tmp/target', hmaData);

    // 2 findings: HMA's GIT-002 and credData's CRED-001 both kept.
    expect(result).toHaveLength(2);
    const sources = result.map(r => r.source).sort();
    expect(sources).toEqual(['credential-scan', 'hma']);
  });

  it('drops credData matches whose path escapes targetDir (defense in depth)', () => {
    const credData: CredentialPhaseData = {
      matches: [
        makeCredMatch({ filePath: '/etc/passwd', line: 1 }),
        makeCredMatch({ filePath: '/tmp/target/../outside.ts', line: 1 }),
        makeCredMatch({ filePath: '/tmp/target/config.ts', line: 10 }),
      ],
      totalFindings: 3,
      bySeverity: { critical: 3 },
      driftFindings: [],
      envVarSuggestions: [],
    };

    const result = aggregateFindings(credData, SHIELD_EMPTY, '/tmp/target', null);

    // Only the in-scope match should survive.
    expect(result).toHaveLength(1);
    expect(result[0].detail).toBe('config.ts:10');
  });

  it('upgrades HMA severity to max(hma, cred) when dedupe fires', () => {
    // credData sees CRITICAL (sk-ant-*), HMA returns HIGH. Dedupe must
    // preserve the higher severity so the Observations block and verdict
    // reflect the worst case, not HMA's narrower classification.
    const credData: CredentialPhaseData = {
      matches: [makeCredMatch({
        filePath: '/tmp/target/config.ts',
        line: 10,
        severity: 'critical',
      })],
      totalFindings: 1,
      bySeverity: { critical: 1 },
      driftFindings: [],
      envVarSuggestions: [],
    };
    const hmaData = makeHmaData([
      makeHmaFinding({
        checkId: 'SEM-CRED-002',
        file: 'config.ts',
        line: 10,
        severity: 'high',
      }),
    ]);

    const result = aggregateFindings(credData, SHIELD_EMPTY, '/tmp/target', hmaData);

    expect(result).toHaveLength(1);
    expect(result[0].source).toBe('hma');
    expect(result[0].severity).toBe('critical');
  });
});

describe('applyDominantAnalyzerFloor (#175 dominant-analyzer floor)', () => {
  // Mirrors the kitchen-sink repro: HMA `secure` and Shadow AI both report
  // 0/100 (critical band) while the weighted composite floats to 67
  // ("improving"). The floor must clamp the composite down to the harshest
  // analyzer so the verdict cannot disagree in direction with `opena2a check`.
  it('clamps composite to the lowest critical-band analyzer (kitchen-sink)', () => {
    const weighted = 67;
    const floored = applyDominantAnalyzerFloor(weighted, [
      { name: 'Project Scan', score: 100, ran: true },
      { name: 'Credentials', score: 100, ran: true },
      { name: 'Config Integrity', score: 100, ran: true },
      { name: 'HMA Scan', score: 0, ran: true },
      { name: 'Shadow AI', score: 0, ran: true },
    ]);
    expect(floored).toBe(0);
  });

  it('fires even without HMA when Shadow AI is in the critical band', () => {
    const floored = applyDominantAnalyzerFloor(76, [
      { name: 'Project Scan', score: 100, ran: true },
      { name: 'Credentials', score: 100, ran: true },
      { name: 'Config Integrity', score: 100, ran: true },
      { name: 'HMA Scan', score: 0, ran: false }, // skipped -> excluded
      { name: 'Shadow AI', score: 0, ran: true },
    ]);
    expect(floored).toBe(0);
  });

  it('ignores skipped analyzers (skip score of 0 must not floor a clean project)', () => {
    // Clean project, HMA skipped. Skipped HMA carries score 0 but ran:false,
    // so it must NOT clamp the composite.
    const floored = applyDominantAnalyzerFloor(72, [
      { name: 'Project Scan', score: 85, ran: true },
      { name: 'Credentials', score: 100, ran: true },
      { name: 'Config Integrity', score: 50, ran: true },
      { name: 'HMA Scan', score: 0, ran: false },
      { name: 'Shadow AI', score: 100, ran: true },
    ]);
    expect(floored).toBe(72);
  });

  it('does NOT downgrade a borderline-but-recoverable project (all analyzers >= 30)', () => {
    // Adversarial check: a project with real-but-recoverable issues sits in
    // the 30-70 band on every analyzer. The floor must leave it untouched so
    // the recovery-framed verdict survives.
    const floored = applyDominantAnalyzerFloor(58, [
      { name: 'Project Scan', score: 70, ran: true },
      { name: 'Credentials', score: 50, ran: true },
      { name: 'Config Integrity', score: 50, ran: true },
      { name: 'HMA Scan', score: 60, ran: true },
      { name: 'Shadow AI', score: 65, ran: true },
    ]);
    expect(floored).toBe(58);
  });

  it('Shield baseline-25 is excluded as a participant (no false downgrade)', () => {
    // Shield Analysis is never passed as a participant by review(). A clean
    // project on a Shield-less machine has Shield posture 25 but must keep its
    // composite. This asserts the documented contract: a 25-scoring Shield is
    // simply absent from the participant list.
    const floored = applyDominantAnalyzerFloor(70, [
      { name: 'Project Scan', score: 85, ran: true },
      { name: 'Credentials', score: 100, ran: true },
      { name: 'Config Integrity', score: 50, ran: true },
      { name: 'Shadow AI', score: 100, ran: true },
      // Shield (25) intentionally NOT here — see applyDominantAnalyzerFloor docs
    ]);
    expect(floored).toBe(70);
  });

  it('clamps down but never raises the composite', () => {
    // If the weighted composite is already below the min analyzer, keep it.
    const floored = applyDominantAnalyzerFloor(10, [
      { name: 'Credentials', score: 25, ran: true },
      { name: 'Shadow AI', score: 100, ran: true },
    ]);
    expect(floored).toBe(10);
  });

  it('a single critical credential leak (score 75) does not floor; three (score 25) do', () => {
    // 1 critical cred => credScore 75, above CRITICAL_BAND, no floor.
    expect(applyDominantAnalyzerFloor(88, [
      { name: 'Credentials', score: 75, ran: true },
      { name: 'Shadow AI', score: 100, ran: true },
    ])).toBe(88);
    // 3 critical creds => credScore 25, below CRITICAL_BAND, floor fires.
    expect(applyDominantAnalyzerFloor(70, [
      { name: 'Credentials', score: 25, ran: true },
      { name: 'Shadow AI', score: 100, ran: true },
    ])).toBe(25);
  });

  it('CRITICAL_BAND boundary: exactly 30 does not floor, 29 does', () => {
    expect(applyDominantAnalyzerFloor(80, [{ name: 'X', score: CRITICAL_BAND, ran: true }])).toBe(80);
    expect(applyDominantAnalyzerFloor(80, [{ name: 'X', score: CRITICAL_BAND - 1, ran: true }])).toBe(CRITICAL_BAND - 1);
  });

  // M1 regression: a malformed analyzer payload (NaN score) must not silently
  // disable the floor (NaN < 30 is false). Non-finite scores are filtered out.
  it('ignores non-finite scores instead of disabling the floor', () => {
    // NaN HMA score is dropped; the real critical Credentials score still floors.
    expect(applyDominantAnalyzerFloor(70, [
      { name: 'HMA Scan', score: NaN, ran: true },
      { name: 'Credentials', score: 0, ran: true },
    ])).toBe(0);
    // If the ONLY participant is non-finite, the composite is left untouched
    // (no clamp) rather than producing NaN.
    expect(applyDominantAnalyzerFloor(70, [
      { name: 'HMA Scan', score: NaN, ran: true },
    ])).toBe(70);
    expect(applyDominantAnalyzerFloor(70, [
      { name: 'HMA Scan', score: Infinity, ran: true },
    ])).toBe(70);
  });
});

describe('buildFloorParticipants (#175 — target-malice scoping)', () => {
  const base = {
    trustScore: 90, credScore: 90, guardScore: 90, hmaScore: 90, hmaAvailable: true,
    projectGovernanceScore: 100, projectGovernanceRan: false,
    shieldRiskScore: 100, shieldRiskRan: false,
  };

  it('includes only target-scoped analyzers, never the host-polluted Shadow AI or adoption baselines', () => {
    const names = buildFloorParticipants(base).map(p => p.name);
    expect(names).toEqual(['Project Scan', 'Credentials', 'Config Integrity', 'HMA Scan', 'Project Governance', 'Shield Runtime Risk']);
    // H1 regression: the raw "Shadow AI" governanceScore is host-polluted (ps aux)
    // and must NOT be a floor participant. Only the target-local slice
    // ("Project Governance") and genuine runtime risk ("Shield Runtime Risk")
    // participate — never the adoption baseline posture.
    expect(names).not.toContain('Shadow AI');
    expect(names).not.toContain('Shield Analysis');
  });

  it('H1: a host-driven low governance score cannot clamp a clean project', () => {
    // Clean repo (trust/cred/config/HMA healthy) on a machine whose RAW
    // governance tanked from ambient host agents. The raw governanceScore is
    // never passed in; projectGovernanceRan is false (no in-repo critical
    // signal), so the floor leaves the composite alone.
    const participants = buildFloorParticipants({ ...base, trustScore: 88, credScore: 92, guardScore: 90, hmaScore: 85 });
    expect(applyDominantAnalyzerFloor(82, participants)).toBe(82);
  });

  it('H1-collateral: a target-local critical governance signal STILL floors (no detection narrowing)', () => {
    // A repo whose only critical signal is an in-repo malicious MCP server:
    // trust/cred/config/HMA all clean, but projectGovernance fires.
    const participants = buildFloorParticipants({
      trustScore: 100, credScore: 100, guardScore: 100, hmaScore: 90, hmaAvailable: true,
      projectGovernanceScore: 0, projectGovernanceRan: true,
      shieldRiskScore: 100, shieldRiskRan: false,
    });
    expect(applyDominantAnalyzerFloor(72, participants)).toBe(0);
  });

  it('HMA participates only when it ran; its score is coerced finite', () => {
    expect(buildFloorParticipants({ ...base, hmaAvailable: false }).find(p => p.name === 'HMA Scan')!.ran).toBe(false);
    expect(buildFloorParticipants({ ...base, hmaAvailable: true }).find(p => p.name === 'HMA Scan')!.ran).toBe(true);
    // NaN HMA score is coerced to 0 at construction so it never reaches the floor as NaN.
    expect(buildFloorParticipants({ ...base, hmaScore: NaN }).find(p => p.name === 'HMA Scan')!.score).toBe(0);
  });

  it('Project Governance participates only when a target-local critical signal exists', () => {
    expect(buildFloorParticipants(base).find(p => p.name === 'Project Governance')!.ran).toBe(false);
    expect(buildFloorParticipants({ ...base, projectGovernanceRan: true, projectGovernanceScore: 0 })
      .find(p => p.name === 'Project Governance')!.ran).toBe(true);
  });

  it('kitchen-sink shape: HMA 0 floors the composite to 0 when HMA ran', () => {
    // trust/cred/config clean, HMA critical — the real kitchen-sink profile.
    const participants = buildFloorParticipants({ ...base, trustScore: 100, credScore: 100, guardScore: 100, hmaScore: 0, hmaAvailable: true });
    expect(applyDominantAnalyzerFloor(67, participants)).toBe(0);
  });

  it('C1: without HMA (and no target-local gov signal), kitchen-sink shape is NOT floored (verdict provisional)', () => {
    // Documents degraded mode: HMA is the only critical signal for this shape,
    // so when it does not run the floor cannot fire. review() emits the
    // provisional notice + sets report.provisional=true.
    const participants = buildFloorParticipants({ ...base, trustScore: 100, credScore: 100, guardScore: 100, hmaScore: 0, hmaAvailable: false });
    expect(applyDominantAnalyzerFloor(67, participants)).toBe(67);
  });
});

describe('targetGovernanceFloorScore (#175 — target-local governance only)', () => {
  it('does not fire for a clean repo (no in-repo critical MCP/config)', () => {
    expect(targetGovernanceFloorScore({ mcpServers: [], aiConfigs: [] })).toEqual({ score: 100, ran: false });
    // a verified / non-critical / non-project MCP server does not fire
    expect(targetGovernanceFloorScore({
      mcpServers: [{ risk: 'critical', source: 'host (system)', verified: false }],
      aiConfigs: [{ risk: 'low' }],
    })).toEqual({ score: 100, ran: false });
    expect(targetGovernanceFloorScore({
      mcpServers: [{ risk: 'critical', source: 'mcp.json (project)', verified: true }],
      aiConfigs: [],
    })).toEqual({ score: 100, ran: false });
  });

  it('fires (score 0) on an in-repo unverified critical MCP server', () => {
    expect(targetGovernanceFloorScore({
      mcpServers: [{ risk: 'critical', source: 'mcp.json (project)', verified: false }],
      aiConfigs: [],
    })).toEqual({ score: 0, ran: true });
  });

  it('fires (score 0) on a critical AI config (credential references)', () => {
    expect(targetGovernanceFloorScore({
      mcpServers: [],
      aiConfigs: [{ risk: 'critical' }],
    })).toEqual({ score: 0, ran: true });
  });
});

describe('adoption-as-recovery composite scoring (#175 follow-up)', () => {
  const sev = (severity: string) => ({ finding: { severity } });

  describe('shieldCompositeScore (weighted-average input)', () => {
    it('is neutral (90) when Shield is unconfigured / has no findings — posture is ignored', () => {
      // baseline posture on a Shield-less machine must NOT drag the composite, and
      // a well-set-up Shield must NOT inflate the TARGET-risk score either.
      expect(shieldCompositeScore({ classifiedFindings: [] })).toBe(90);
    });
    it('is reduced by genuine runtime findings at their severity (incl. medium)', () => {
      expect(shieldCompositeScore({ classifiedFindings: [sev('critical')] })).toBe(60); // 90-30
      expect(shieldCompositeScore({ classifiedFindings: [sev('high')] })).toBe(75);     // 90-15
      expect(shieldCompositeScore({ classifiedFindings: [sev('medium')] })).toBe(84);   // 90-6 (not neutralized)
      expect(shieldCompositeScore({ classifiedFindings: [sev('critical'), sev('critical'), sev('critical')] })).toBe(0); // clamped
    });
    it('C1: takes the harsher of reported and intact-chain counts when the chain broke', () => {
      // The reported findings are only what survived chain verification. When
      // the exclusion dropped genuine findings, scoring the survivors alone
      // rewards the break. `preExclusionCounts` is what an intact chain would
      // have classified; the harsher of the two wins.
      expect(shieldCompositeScore({
        classifiedFindings: [sev('critical')],                         // 90-30 = 60
        preExclusionCounts: { critical: 1, high: 1, medium: 2 },        // 90-30-15-12 = 33
      })).toBe(33);
      // Never the other direction: the counterfactual can lower a score, never raise one.
      expect(shieldCompositeScore({
        classifiedFindings: [sev('critical'), sev('high')],             // 45
        preExclusionCounts: { critical: 0, high: 0, medium: 0 },        // 90
      })).toBe(45);
    });
  });

  describe('shieldRiskFloorScore (floor participant — real runtime risk only)', () => {
    it('does NOT participate for an unconfigured Shield or medium/low-only findings', () => {
      expect(shieldRiskFloorScore({ classifiedFindings: [] })).toEqual({ score: 100, ran: false });
      expect(shieldRiskFloorScore({ classifiedFindings: [sev('medium')] })).toEqual({ score: 100, ran: false });
      expect(shieldRiskFloorScore({ classifiedFindings: [sev('low')] })).toEqual({ score: 100, ran: false });
    });
    it('participates in the critical band on a genuine critical/high runtime finding', () => {
      const crit = shieldRiskFloorScore({ classifiedFindings: [sev('critical')] });
      expect(crit.ran).toBe(true);
      expect(crit.score).toBeLessThan(CRITICAL_BAND);
      const high = shieldRiskFloorScore({ classifiedFindings: [sev('high')] });
      expect(high.ran).toBe(true);
      expect(high.score).toBeLessThan(CRITICAL_BAND);
    });
    it('C1: an excluded critical still floors, even when the survivors would not', () => {
      // Currently defence-in-depth rather than a live path: runShieldPhase
      // always injects a critical chain-break finding, so the reported side is
      // already at the harshest band whenever preExclusionCounts exists. The
      // invariant is pinned here so it survives a change to that synthetic
      // finding's severity — a break must not be able to relax the floor.
      expect(shieldRiskFloorScore({
        classifiedFindings: [sev('medium')],                     // would not participate
        preExclusionCounts: { critical: 1, high: 0, medium: 0 },
      })).toEqual({ score: CRITICAL_BAND - 10, ran: true });
      expect(shieldRiskFloorScore({
        classifiedFindings: [sev('high')],
        preExclusionCounts: { critical: 1, high: 0, medium: 0 },
      })).toEqual({ score: CRITICAL_BAND - 10, ran: true });
      // ...and never relaxes one: a clean counterfactual cannot lift a real finding.
      expect(shieldRiskFloorScore({
        classifiedFindings: [sev('critical')],
        preExclusionCounts: { critical: 0, high: 0, medium: 0 },
      })).toEqual({ score: CRITICAL_BAND - 10, ran: true });
    });
    it('SECURITY: a real Shield critical floors the composite to "needs attention" (not a false good)', () => {
      const shieldRisk = shieldRiskFloorScore({ classifiedFindings: [sev('critical')] });
      // otherwise-clean project, but a real Shield runtime critical fired
      const participants = buildFloorParticipants({
        trustScore: 95, credScore: 100, guardScore: 90, hmaScore: 90, hmaAvailable: true,
        projectGovernanceScore: 100, projectGovernanceRan: false,
        shieldRiskScore: shieldRisk.score, shieldRiskRan: shieldRisk.ran,
      });
      expect(applyDominantAnalyzerFloor(91, participants)).toBeLessThan(CRITICAL_BAND);
    });
  });

  describe('governanceCompositeScore', () => {
    it('is neutral-high when no target-local critical governance signal fired', () => {
      // no-identity / no-SOUL / ambient host agents must NOT penalize the composite
      expect(governanceCompositeScore({ score: 100, ran: false })).toBe(90);
      expect(governanceCompositeScore({ score: 20, ran: false })).toBe(90);
    });
    it('reflects the target-local critical score when one fired', () => {
      expect(governanceCompositeScore({ score: 0, ran: true })).toBe(0);
    });
  });

  describe('credentialFloorScore', () => {
    it('does not clamp when there are no critical/high credential findings', () => {
      expect(credentialFloorScore(92, {})).toBe(92);
      expect(credentialFloorScore(92, { medium: 2, low: 1 })).toBe(92);
    });
    it('SECURITY: a confirmed critical OR high credential enters the critical band (cannot dilute to good)', () => {
      expect(credentialFloorScore(75, { critical: 1 })).toBeLessThan(CRITICAL_BAND);
      expect(credentialFloorScore(85, { high: 1 })).toBeLessThan(CRITICAL_BAND);
      expect(credentialFloorScore(70, { high: 2 })).toBeLessThan(CRITICAL_BAND);
      // critical is at least as severe as high
      expect(credentialFloorScore(75, { critical: 1 }))
        .toBeLessThanOrEqual(credentialFloorScore(85, { high: 1 }));
    });
    it('never raises the score (only clamps down)', () => {
      expect(credentialFloorScore(10, { critical: 1 })).toBe(10);
    });
  });
});
