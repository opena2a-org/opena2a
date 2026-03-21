import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { hardenSkill } from '../../src/commands/harden-skill.js';

// --- Test helpers ---

let tmpDir: string;
let origCwd: string;

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

function captureStderr(fn: () => Promise<number>): Promise<{ exitCode: number; stderr: string; stdout: string }> {
  const stderrChunks: string[] = [];
  const stdoutChunks: string[] = [];
  const origStderr = process.stderr.write;
  const origStdout = process.stdout.write;
  process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;
  process.stdout.write = ((chunk: any) => { stdoutChunks.push(String(chunk)); return true; }) as any;

  return fn().then(exitCode => {
    process.stderr.write = origStderr;
    process.stdout.write = origStdout;
    return { exitCode, stderr: stderrChunks.join(''), stdout: stdoutChunks.join('') };
  }).catch(err => {
    process.stderr.write = origStderr;
    process.stdout.write = origStdout;
    throw err;
  });
}

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'harden-skill-test-'));
  origCwd = process.cwd();
  process.chdir(tmpDir);
});

afterEach(() => {
  process.chdir(origCwd);
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe('harden-skill', () => {
  it('errors when file not found', async () => {
    const { exitCode, stderr } = await captureStderr(() =>
      hardenSkill({ file: '/nonexistent/SKILL.md', format: 'text' })
    );
    expect(exitCode).toBe(1);
    expect(stderr).toContain('File not found');
  });

  it('errors when no skill files in directory', async () => {
    const { exitCode, stderr } = await captureStderr(() =>
      hardenSkill({ format: 'text' })
    );
    expect(exitCode).toBe(1);
    expect(stderr).toContain('No skill files found');
  });

  it('hardens a file without frontmatter', async () => {
    const filePath = path.join(tmpDir, 'SKILL.md');
    fs.writeFileSync(filePath, '## My Skill\n\nDoes stuff.\n', 'utf-8');

    const { exitCode, output } = await captureStdout(() =>
      hardenSkill({ file: filePath, format: 'text' })
    );

    expect(exitCode).toBe(0);
    expect(output).toContain('Hardening');
    expect(output).toContain('Added YAML frontmatter');
    expect(output).toContain('SHA-256');

    // Verify the written file has frontmatter
    const hardened = fs.readFileSync(filePath, 'utf-8');
    expect(hardened).toMatch(/^---\n/);
    expect(hardened).toContain('name:');
    expect(hardened).toContain('version: 1.0.0');
    expect(hardened).toContain('capabilities:');
    expect(hardened).toContain('integrity: sha256-');
  });

  it('adds permission boundaries for filesystem:*', async () => {
    const content = `---
name: risky
version: 1.0.0
capabilities:
  - filesystem:*
  - network:outbound
---

## Content`;
    const filePath = path.join(tmpDir, 'SKILL.md');
    fs.writeFileSync(filePath, content, 'utf-8');

    const { exitCode, output } = await captureStdout(() =>
      hardenSkill({ file: filePath, format: 'text' })
    );

    expect(exitCode).toBe(0);
    expect(output).toContain('Replaced filesystem:*');

    const hardened = fs.readFileSync(filePath, 'utf-8');
    expect(hardened).toContain('filesystem:read');
    expect(hardened).toContain('filesystem:write');
    expect(hardened).not.toContain('filesystem:*');
  });

  it('dry-run does not write changes', async () => {
    const original = '## No frontmatter\n\nContent.\n';
    const filePath = path.join(tmpDir, 'SKILL.md');
    fs.writeFileSync(filePath, original, 'utf-8');

    const { exitCode, output } = await captureStdout(() =>
      hardenSkill({ file: filePath, dryRun: true, format: 'text' })
    );

    expect(exitCode).toBe(0);
    expect(output).toContain('dry-run');

    // File should remain unchanged
    const afterContent = fs.readFileSync(filePath, 'utf-8');
    expect(afterContent).toBe(original);
  });

  it('returns JSON output', async () => {
    const content = `---
name: test
version: 1.0.0
capabilities: []
---

## Body`;
    const filePath = path.join(tmpDir, 'SKILL.md');
    fs.writeFileSync(filePath, content, 'utf-8');

    const { exitCode, output } = await captureStdout(() =>
      hardenSkill({ file: filePath, format: 'json' })
    );

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.file).toBe('SKILL.md');
    expect(result.hash).toBeDefined();
    expect(result.written).toBe(true);
    expect(result.changes).toBeInstanceOf(Array);
  });

  it('adds maxIterations for tool:chain', async () => {
    const content = `---
name: chainer
version: 1.0.0
capabilities:
  - tool:chain
---

## Chain skill`;
    const filePath = path.join(tmpDir, 'SKILL.md');
    fs.writeFileSync(filePath, content, 'utf-8');

    const { exitCode } = await captureStdout(() =>
      hardenSkill({ file: filePath, format: 'text' })
    );

    expect(exitCode).toBe(0);
    const hardened = fs.readFileSync(filePath, 'utf-8');
    expect(hardened).toContain('maxIterations: 10');
  });

  it('auto-discovers skill files in current directory', async () => {
    const filePath = path.join(tmpDir, 'deploy.skill.md');
    fs.writeFileSync(filePath, '## Deploy skill\n', 'utf-8');

    const { exitCode, output } = await captureStdout(() =>
      hardenSkill({ ci: true, format: 'text' })
    );

    expect(exitCode).toBe(0);
    expect(output).toContain('deploy.skill.md');
  });
});
