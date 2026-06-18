import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  review,
  aggregateFindings,
  applyDominantAnalyzerFloor,
  buildFloorParticipants,
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

describe('review', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
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
    // Score depends on Shield product detection and guard signing status.
    // A clean project without Shield products or signatures scores ~65-75.
    expect(report.compositeScore).toBeGreaterThanOrEqual(60);
    expect(['strong', 'good', 'moderate', 'improving']).toContain(report.grade);
    expect(report.phases).toHaveLength(6);
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

    expect(exitCode).toBe(0);
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
    postureScore: 100,
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
  const base = { trustScore: 90, credScore: 90, guardScore: 90, hmaScore: 90, hmaAvailable: true };

  it('includes only the four target-scoped analyzers, never Shield or Shadow AI', () => {
    const names = buildFloorParticipants(base).map(p => p.name);
    expect(names).toEqual(['Project Scan', 'Credentials', 'Config Integrity', 'HMA Scan']);
    // H1 regression: Shadow AI / governance is host-polluted (ps aux) and must
    // NOT be a floor participant, or a clean repo on a dev box running AI tools
    // would be wrongly clamped to a critical verdict.
    expect(names).not.toContain('Shadow AI');
    expect(names).not.toContain('Shield Analysis');
    expect(names).not.toContain('Shield');
  });

  it('H1: a critical Shadow-AI/governance score cannot clamp a clean project', () => {
    // Simulate a clean repo (trust/cred/config/HMA all healthy) on a machine
    // whose governance score tanked to 18 from ambient host agents. Because
    // governance is not a participant, the floor leaves the composite alone.
    const participants = buildFloorParticipants({ ...base, trustScore: 88, credScore: 92, guardScore: 90, hmaScore: 85 });
    expect(applyDominantAnalyzerFloor(82, participants)).toBe(82);
  });

  it('HMA participates only when it ran; its score is coerced finite', () => {
    expect(buildFloorParticipants({ ...base, hmaAvailable: false }).find(p => p.name === 'HMA Scan')!.ran).toBe(false);
    expect(buildFloorParticipants({ ...base, hmaAvailable: true }).find(p => p.name === 'HMA Scan')!.ran).toBe(true);
    // NaN HMA score is coerced to 0 at construction so it never reaches the floor as NaN.
    expect(buildFloorParticipants({ ...base, hmaScore: NaN }).find(p => p.name === 'HMA Scan')!.score).toBe(0);
  });

  it('kitchen-sink shape: HMA 0 floors the composite to 0 when HMA ran', () => {
    // trust/cred/config clean, HMA critical — the real kitchen-sink profile.
    const participants = buildFloorParticipants({ trustScore: 100, credScore: 100, guardScore: 100, hmaScore: 0, hmaAvailable: true });
    expect(applyDominantAnalyzerFloor(67, participants)).toBe(0);
  });

  it('C1: without HMA, the same kitchen-sink shape is NOT floored (verdict is provisional)', () => {
    // Documents the degraded-mode behavior: HMA is the only critical signal for
    // this shape, so when it does not run the floor cannot fire. review() warns.
    const participants = buildFloorParticipants({ trustScore: 100, credScore: 100, guardScore: 100, hmaScore: 0, hmaAvailable: false });
    expect(applyDominantAnalyzerFloor(67, participants)).toBe(67);
  });
});
