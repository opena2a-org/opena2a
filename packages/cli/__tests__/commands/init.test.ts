import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { init } from '../../src/commands/init.js';

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

describe('init', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-init-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('returns 0 for a clean project', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test-project', version: '1.0.0' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\nnode_modules\n');
    fs.writeFileSync(path.join(tempDir, 'package-lock.json'), '{}');
    fs.mkdirSync(path.join(tempDir, '.git'));

    const { exitCode, output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const report = JSON.parse(output);
    expect(report.projectType).toContain('Node.js');
    expect(report.credentialFindings).toBe(0);
    // Unified score: clean project scores well but environmental factors
    // (running LLM servers, HMA shell findings) may lower it on real machines
    expect(report.securityScore).toBeGreaterThanOrEqual(70);
    expect(['A', 'B', 'C']).toContain(report.securityGrade);
    // Backward compat aliases
    expect(report.trustScore).toBe(report.securityScore);
    expect(report.grade).toBe(report.securityGrade);
    expect(report.postureScore).toBe(report.securityScore);
  });

  it('detects hardcoded credentials', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test-project' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), 'node_modules\n');
    const fakeKey = 'sk-ant-api03-' + 'A'.repeat(85);
    fs.writeFileSync(path.join(tempDir, 'config.ts'), `const key = "${fakeKey}";`);

    const { exitCode, output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(1);
    const report = JSON.parse(output);
    expect(report.credentialFindings).toBeGreaterThan(0);
    expect(report.securityScore).toBeLessThan(90);
    // Findings should be grouped
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.findings[0].severity).toBe('critical');
  });

  it('detects MCP config', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'mcp-server' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(tempDir, 'mcp.json'), '{}');

    const { exitCode, output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const report = JSON.parse(output);
    expect(report.projectType).toContain('MCP');
  });

  it('warns about missing .gitignore', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));

    const { exitCode, output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const report = JSON.parse(output);
    const gitignoreCheck = report.hygieneChecks.find((c: any) => c.label === '.gitignore');
    expect(gitignoreCheck.status).toBe('warn');
    expect(report.securityScore).toBeLessThan(90);
  });

  it('generates JSON output with version 2 format', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test', version: '2.0.0' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    // v2 fields
    expect(report.version).toBe(2);
    expect(report).toHaveProperty('securityScore');
    expect(report).toHaveProperty('securityGrade');
    expect(report).toHaveProperty('scoreBreakdown');
    expect(report).toHaveProperty('findings');
    expect(report).toHaveProperty('actions');
    expect(report).toHaveProperty('hmaAvailable');
    // Backward compat
    expect(report).toHaveProperty('trustScore');
    expect(report).toHaveProperty('grade');
    expect(report).toHaveProperty('postureScore');
    expect(report).toHaveProperty('riskLevel');
    expect(report).toHaveProperty('activeTools');
    expect(report).toHaveProperty('totalTools');
    expect(report).toHaveProperty('projectName');
    expect(report).toHaveProperty('projectType');
    expect(report).toHaveProperty('directory');
    expect(report).toHaveProperty('credentialFindings');
    expect(report).toHaveProperty('hygieneChecks');
    expect(report).toHaveProperty('nextSteps');
  });

  it('includes protect in next steps when credentials found', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    const fakeKey = 'sk-ant-api03-' + 'B'.repeat(85);
    fs.writeFileSync(path.join(tempDir, 'app.js'), `const k = "${fakeKey}";`);

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    const protectStep = report.nextSteps.find((s: any) => s.command === 'opena2a protect');
    expect(protectStep).toBeDefined();
    expect(protectStep.severity).toBe('critical');
    // Actions should also include protect
    const protectAction = report.actions.find((a: any) => a.command === 'opena2a protect');
    expect(protectAction).toBeDefined();
    expect(protectAction.why).toBeTruthy();
  });

  it('calculates correct grade boundaries', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'clean' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\nnode_modules\n');
    fs.writeFileSync(path.join(tempDir, 'package-lock.json'), '{}');

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    expect(report.securityGrade).toMatch(/^[A-F]$/);
    expect(report.securityScore).toBeGreaterThanOrEqual(0);
    expect(report.securityScore).toBeLessThanOrEqual(100);
  });

  it('returns 1 for nonexistent directory', async () => {
    const stderrChunks: string[] = [];
    const origStderr = process.stderr.write;
    process.stderr.write = ((chunk: any) => {
      stderrChunks.push(String(chunk));
      return true;
    }) as any;

    const exitCode = await init({ targetDir: '/nonexistent/path/xyz' });
    process.stderr.write = origStderr;

    expect(exitCode).toBe(1);
  });

  it('uses diminishing returns scoring for multiple credentials', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(tempDir, 'package-lock.json'), '{}');

    // Create multiple critical credentials
    const lines: string[] = [];
    for (let i = 0; i < 5; i++) {
      const key = 'sk-ant-api03-' + String.fromCharCode(65 + i).repeat(85);
      lines.push(`const key${i} = "${key}";`);
    }
    fs.writeFileSync(path.join(tempDir, 'config.ts'), lines.join('\n'));

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    // With diminishing returns and category cap at 60, score should NOT be 0
    // 5 critical: 20 + 4*8 = 52 cred deduction, score should be ~48
    expect(report.securityScore).toBeGreaterThan(0);
    expect(report.securityScore).toBeLessThan(60);
    // Verify score breakdown exists
    expect(report.scoreBreakdown.credentials.deduction).toBeLessThanOrEqual(60);
  });

  it('groups findings by findingId', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');

    // Two files with the same type of key
    const key1 = 'sk-ant-api03-' + 'X'.repeat(85);
    const key2 = 'sk-ant-api03-' + 'Y'.repeat(85);
    fs.writeFileSync(path.join(tempDir, 'a.ts'), `const a = "${key1}";`);
    fs.writeFileSync(path.join(tempDir, 'b.ts'), `const b = "${key2}";`);

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    const anthroFinding = report.findings.find((f: any) => f.findingId === 'CRED-001');
    expect(anthroFinding).toBeDefined();
    expect(anthroFinding.count).toBe(2);
    expect(anthroFinding.locations.length).toBe(2);
  });

  it('shows "Project" instead of "Unknown" for generic projects', async () => {
    // No package.json, go.mod, etc. -- just a bare directory
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(tempDir, 'README.md'), '# Test');

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    expect(report.projectType).toBe('Project');
    expect(report.projectType).not.toContain('Unknown');
  });

  it('includes score breakdown in report', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    // No .gitignore, no lock file -- configuration penalties
    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    expect(report.scoreBreakdown).toBeDefined();
    expect(report.scoreBreakdown.credentials).toHaveProperty('deduction');
    expect(report.scoreBreakdown.credentials).toHaveProperty('detail');
    expect(report.scoreBreakdown.environment).toHaveProperty('deduction');
    expect(report.scoreBreakdown.configuration).toHaveProperty('deduction');
    // Missing .gitignore should cause configuration deduction
    expect(report.scoreBreakdown.configuration.deduction).toBeGreaterThan(0);
  });
});
