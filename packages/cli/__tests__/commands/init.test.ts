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
    // Create a clean Node project
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
    expect(report.trustScore).toBeGreaterThanOrEqual(90);
    expect(report.grade).toBe('A');
  });

  it('detects hardcoded credentials', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test-project' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), 'node_modules\n');
    // Simulate a file with a hardcoded key
    const fakeKey = 'sk-ant-api03-' + 'A'.repeat(85);
    fs.writeFileSync(path.join(tempDir, 'config.ts'), `const key = "${fakeKey}";`);

    const { exitCode, output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const report = JSON.parse(output);
    expect(report.credentialFindings).toBeGreaterThan(0);
    expect(report.trustScore).toBeLessThan(90);
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
    expect(report.trustScore).toBeLessThan(90);
  });

  it('generates JSON output with all expected fields', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test', version: '2.0.0' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    expect(report).toHaveProperty('projectName');
    expect(report).toHaveProperty('projectType');
    expect(report).toHaveProperty('directory');
    expect(report).toHaveProperty('credentialFindings');
    expect(report).toHaveProperty('hygieneChecks');
    expect(report).toHaveProperty('trustScore');
    expect(report).toHaveProperty('grade');
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
  });

  it('calculates correct grade boundaries', async () => {
    // Clean project should get A
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'clean' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\nnode_modules\n');
    fs.writeFileSync(path.join(tempDir, 'package-lock.json'), '{}');

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    expect(report.grade).toMatch(/^[A-F]$/);
    expect(report.trustScore).toBeGreaterThanOrEqual(0);
    expect(report.trustScore).toBeLessThanOrEqual(100);
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
});
