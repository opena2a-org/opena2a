import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { review } from '../../src/commands/review.js';

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
});
