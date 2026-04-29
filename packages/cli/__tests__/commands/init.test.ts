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

function captureStderr(fn: () => Promise<number>): Promise<{ exitCode: number; stderr: string }> {
  const chunks: string[] = [];
  const origWrite = process.stderr.write;
  process.stderr.write = ((chunk: any) => {
    chunks.push(String(chunk));
    return true;
  }) as any;

  return fn().then(exitCode => {
    process.stderr.write = origWrite;
    return { exitCode, stderr: chunks.join('') };
  }).catch(err => {
    process.stderr.write = origWrite;
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
    expect(['strong', 'good', 'moderate']).toContain(report.securityGrade);
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
    expect(['strong', 'good', 'moderate', 'improving', 'needs-attention']).toContain(report.securityGrade);
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

  // --- AI-specific scan integration tests ---

  it('detects MCP high-risk tools in hygiene checks', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify({
      mcpServers: {
        'fs-server': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'] },
      },
    }));

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    const mcpCheck = report.hygieneChecks.find((c: any) => c.label === 'MCP high-risk tools');
    expect(mcpCheck).toBeDefined();
    expect(mcpCheck.status).toBe('warn');
    // Should also appear as a grouped finding
    const mcpFinding = report.findings.find((f: any) => f.findingId === 'MCP-TOOLS');
    expect(mcpFinding).toBeDefined();
    expect(mcpFinding.severity).toBe('high');
  });

  it('detects MCP hardcoded credentials as proper credential findings', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    const fakeKey = 'sk-ant-api03-' + 'M'.repeat(85);
    fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify({
      mcpServers: {
        'api': { command: 'node', args: ['server.js'], env: { KEY: fakeKey } },
      },
    }));

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    // MCP credentials now show up as real CRED-001 findings (critical severity)
    expect(report.credentialFindings).toBeGreaterThan(0);
    const credFinding = report.findings.find((f: any) => f.findingId === 'CRED-001');
    expect(credFinding).toBeDefined();
    expect(credFinding.severity).toBe('critical');
    // MCP-CRED hygiene check should also still appear
    const mcpCredCheck = report.hygieneChecks.find((c: any) => c.label === 'MCP credentials');
    expect(mcpCredCheck).toBeDefined();
  });

  it('detects AI config files not excluded from git', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    fs.mkdirSync(path.join(tempDir, '.git'));
    fs.writeFileSync(path.join(tempDir, 'CLAUDE.md'), '# AI instructions');

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    const aiConfig = report.hygieneChecks.find((c: any) => c.label === 'AI config exposure');
    expect(aiConfig).toBeDefined();
    expect(aiConfig.status).toBe('warn');
    const aiFinding = report.findings.find((f: any) => f.findingId === 'AI-CONFIG');
    expect(aiFinding).toBeDefined();
    expect(aiFinding.severity).toBe('medium');
  });

  it('does not flag AI config files when properly excluded', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\nCLAUDE.md\n');
    fs.mkdirSync(path.join(tempDir, '.git'));
    fs.writeFileSync(path.join(tempDir, 'CLAUDE.md'), '# AI instructions');

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    const aiConfig = report.hygieneChecks.find((c: any) => c.label === 'AI config exposure');
    expect(aiConfig).toBeUndefined();
  });

  it('includes MCP findings in environment score deduction', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(tempDir, 'package-lock.json'), '{}');
    fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify({
      mcpServers: {
        'fs': { command: 'filesystem-server', args: [] },
      },
    }));

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    // Per #116: MCP-TOOLS now scales by server count (-3 per server,
    // sub-cap -15). Single-server fixture deducts 3, not 5.
    expect(report.scoreBreakdown.environment.deduction).toBeGreaterThanOrEqual(3);
    expect(report.scoreBreakdown.environment.detail).toContain('MCP');
  });

  it('uses consulting-style prose in actions (no "recover N points")', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), 'node_modules\n');
    const fakeKey = 'sk-ant-api03-' + 'Z'.repeat(85);
    fs.writeFileSync(path.join(tempDir, 'config.ts'), `const k = "${fakeKey}";`);

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    for (const action of report.actions) {
      expect(action.why).not.toContain('Recover');
      expect(action.why).not.toContain('recover');
      expect(action.why).not.toContain('points');
    }
  });

  it('generates MCP-related actions when MCP findings exist', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    const fakeKey = 'sk-ant-api03-' + 'N'.repeat(85);
    fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify({
      mcpServers: {
        'fs': { command: 'filesystem-server', args: [], env: { KEY: fakeKey } },
      },
    }));

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    const mcpToolAction = report.actions.find((a: any) => a.description.includes('MCP server permissions'));
    expect(mcpToolAction).toBeDefined();
    // MCP credential is now a regular CRED finding, so protect action covers it
    const protectAction = report.actions.find((a: any) => a.command === 'opena2a protect');
    expect(protectAction).toBeDefined();
  });

  it('text output uses -N deduction format (not +N recoverable)', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    // No .gitignore -- triggers configuration deduction
    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
    }));

    expect(output).not.toContain('recoverable');
    // Should contain deduction indicators
    expect(output).toContain('Recommendations');
  });

  // Regression: audit-wave-1 bug B — ENOENT must print Next Steps with
  // discoverable usage. Bare "Directory not found" was a CISO Rule 1 dead
  // end. JSON mode emits a structured error object so CI consumers can
  // distinguish ENOENT from valid-zero-finding states.
  it('text-mode ENOENT prints Next Steps with --help reference (audit B)', async () => {
    const { stderr, exitCode } = await captureStderr(() => init({
      targetDir: '/tmp/opena2a-init-enoent-' + Date.now(),
    }));
    expect(exitCode).toBe(1);
    expect(stderr).toContain('Directory not found');
    expect(stderr).toContain('Next steps');
    expect(stderr).toContain('opena2a init --help');
  });

  it('json-mode ENOENT emits structured error object (audit B)', async () => {
    const missing = '/tmp/opena2a-init-enoent-json-' + Date.now();
    const { output, exitCode } = await captureStdout(() => init({
      targetDir: missing,
      format: 'json',
    }));
    expect(exitCode).toBe(1);
    const parsed = JSON.parse(output);
    expect(parsed.error).toBe('directory-not-found');
    expect(parsed.directory).toBe(missing);
    expect(parsed.message).toContain('Directory not found');
  });

  // Regression: opena2a/issues/116 — `init` was scoring kitchen-sink-class
  // malicious projects at 96/100 because the quick-scan path did not detect
  // private-key files in source. The fix adds .key/.pem detection and
  // surfaces them as CRITICAL credential findings.
  it('detects .key/.pem private-key files as CRITICAL credentials (#116)', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(tempDir, 'fake-private.key'), '-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----');
    fs.writeFileSync(path.join(tempDir, 'fake-cert.pem'), '-----BEGIN CERTIFICATE-----');

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    expect(report.credentialsBySeverity.critical).toBeGreaterThanOrEqual(2);
    const keyFinding = report.findings.find((f: any) => f.findingId === 'CRED-KEYFILE');
    expect(keyFinding).toBeDefined();
    expect(keyFinding.severity).toBe('critical');
    // Score must drop materially below the pre-#116 baseline of 96/100 for
    // a project carrying .key + .pem in its root.
    expect(report.securityScore).toBeLessThan(70);
  });

  it('scales MCP-tools deduction by server count across multiple configs (#116)', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(tempDir, 'package-lock.json'), '{}');
    fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify({
      mcpServers: {
        'a': { command: 'filesystem-server' },
        'b': { command: 'filesystem-server' },
        'c': { command: 'filesystem-server' },
        'd': { command: 'filesystem-server' },
      },
    }));
    fs.mkdirSync(path.join(tempDir, '.cursor'));
    fs.writeFileSync(path.join(tempDir, '.cursor', 'mcp.json'), JSON.stringify({
      mcpServers: {
        'e': { command: 'filesystem-server' },
      },
    }));

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    expect(report.scoreBreakdown.environment.detail).toContain('5 server');
    // 5 servers × -3 = -15 to environment, plus the score must reflect
    // that this is a high-impact MCP surface (well below the
    // single-server baseline).
    expect(report.scoreBreakdown.environment.deduction).toBeGreaterThanOrEqual(15);
  });

  it('surfaces unsigned skill files as a discrete AI-SKILLS finding (#116)', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(tempDir, 'SKILL.md'), '# unsigned skill');
    fs.writeFileSync(path.join(tempDir, 'extra.skill.md'), '# unsigned skill');

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    const skillFinding = report.findings.find((f: any) => f.findingId === 'AI-SKILLS');
    expect(skillFinding).toBeDefined();
    expect(skillFinding.severity).toBe('medium');
    expect(skillFinding.locations.length).toBeGreaterThan(0);
  });

  it('benign + buggy + malicious-shaped fixtures keep monotonic score order (#116)', async () => {
    // Benign: lock file + security config + .gitignore + nothing else
    const benignDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-benign-'));
    try {
      fs.writeFileSync(path.join(benignDir, 'package.json'), JSON.stringify({ name: 'b' }));
      fs.writeFileSync(path.join(benignDir, '.gitignore'), '.env\nnode_modules\n');
      fs.writeFileSync(path.join(benignDir, 'package-lock.json'), '{}');
      fs.mkdirSync(path.join(benignDir, '.opena2a'), { recursive: true });
      fs.mkdirSync(path.join(benignDir, '.opena2a', 'guard'), { recursive: true });
      fs.writeFileSync(path.join(benignDir, '.opena2a', 'guard', 'signatures.json'), '{}');

      const { output: benignOut } = await captureStdout(() => init({ targetDir: benignDir, format: 'json' }));
      const benign = JSON.parse(benignOut);

      // Buggy: 1 hardcoded credential in .env.example
      const buggyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-buggy-'));
      fs.writeFileSync(path.join(buggyDir, 'package.json'), JSON.stringify({ name: 'bg' }));
      fs.writeFileSync(path.join(buggyDir, '.gitignore'), '.env\n');
      const fakeKey = 'sk-ant-api03-' + 'Q'.repeat(85);
      fs.writeFileSync(path.join(buggyDir, '.env.example'), `KEY=${fakeKey}\n`);

      const { output: buggyOut } = await captureStdout(() => init({ targetDir: buggyDir, format: 'json' }));
      const buggy = JSON.parse(buggyOut);

      // Malicious: private key + 4-server MCP + unsigned skill
      const malDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-mal-'));
      fs.writeFileSync(path.join(malDir, 'package.json'), JSON.stringify({ name: 'm' }));
      fs.writeFileSync(path.join(malDir, '.gitignore'), '.env\n');
      fs.writeFileSync(path.join(malDir, 'fake-private.key'), '-----BEGIN PRIVATE KEY-----\nFAKE');
      fs.writeFileSync(path.join(malDir, 'fake-cert.pem'), '-----BEGIN CERTIFICATE-----');
      fs.writeFileSync(path.join(malDir, 'mcp.json'), JSON.stringify({
        mcpServers: {
          'a': { command: 'filesystem-server' },
          'b': { command: 'filesystem-server' },
          'c': { command: 'filesystem-server' },
          'd': { command: 'filesystem-server' },
        },
      }));
      fs.writeFileSync(path.join(malDir, 'SKILL.md'), '# unsigned');

      const { output: malOut } = await captureStdout(() => init({ targetDir: malDir, format: 'json' }));
      const mal = JSON.parse(malOut);

      // Monotonicity: benign > buggy > malicious. With band assertions:
      expect(benign.securityScore).toBeGreaterThan(buggy.securityScore);
      expect(buggy.securityScore).toBeGreaterThan(mal.securityScore);
      expect(benign.securityScore).toBeGreaterThanOrEqual(80);
      expect(buggy.securityScore).toBeGreaterThanOrEqual(50);
      expect(buggy.securityScore).toBeLessThanOrEqual(80);
      // Malicious must drop below 60 (pre-#116 it was 96/100).
      expect(mal.securityScore).toBeLessThan(60);

      fs.rmSync(buggyDir, { recursive: true, force: true });
      fs.rmSync(malDir, { recursive: true, force: true });
    } finally {
      fs.rmSync(benignDir, { recursive: true, force: true });
    }
  });

  // Regression: opena2a/issues/119 — JSON findings must carry the same
  // verify / fix / locations the text view prints. CI gates and IDE
  // plugins parse the JSON; missing fields force them to re-run scanners.
  it('JSON findings populate verify, fix, and locations (#119)', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify({
      mcpServers: {
        'fs': { command: 'filesystem-server', args: [] },
      },
    }));
    const fakeKey = 'sk-ant-api03-' + 'P'.repeat(85);
    fs.writeFileSync(path.join(tempDir, 'config.ts'), `const k = "${fakeKey}";`);
    // Add a key file so we can also assert CRED-KEYFILE carries a non-
    // misleading fix command (Phase 4.5 follow-up: pre-fix this routed
    // to `opena2a protect` which silently no-ops on binary key files).
    fs.writeFileSync(path.join(tempDir, 'leak.key'), '-----BEGIN PRIVATE KEY-----\nFAKE');

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    const textCred = report.findings.find((f: any) => f.findingId === 'CRED-001');
    expect(textCred).toBeDefined();
    expect(typeof textCred.verify).toBe('string');
    expect(textCred.verify.length).toBeGreaterThan(0);
    expect(textCred.fix).toBe('opena2a protect');
    expect(textCred.locations.length).toBeGreaterThan(0);
    expect(textCred.locations[0]).toMatchObject({ file: expect.any(String), line: expect.any(Number) });

    const keyfile = report.findings.find((f: any) => f.findingId === 'CRED-KEYFILE');
    expect(keyfile).toBeDefined();
    // Critical: CRED-KEYFILE must NOT route to plain `opena2a protect`,
    // which silently no-ops on binary key files. The fix command must
    // mention `git rm` so the user has an actionable next step.
    expect(keyfile.fix).not.toBe('opena2a protect');
    expect(keyfile.fix).toContain('git rm');

    const mcpFinding = report.findings.find((f: any) => f.findingId === 'MCP-TOOLS');
    expect(mcpFinding).toBeDefined();
    expect(mcpFinding.verify).toContain('mcp.json');
    expect(mcpFinding.fix).toBe('opena2a shield init');
    expect(mcpFinding.locations.length).toBeGreaterThan(0);
    expect(mcpFinding.locations[0].file.endsWith('mcp.json')).toBe(true);
  });

  // Phase 4.5 follow-up: a single MEDIUM `.crt` finding alone must NOT
  // co-exist with a 100/100 score and a "+5 security config" bonus.
  // Pre-fix `hasHighImpact` only checked critCount/highCount.
  it('MEDIUM CRED-CERTFILE alone suppresses the security-config bonus (#116/Phase4.5)', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(tempDir, 'package-lock.json'), '{}');
    fs.mkdirSync(path.join(tempDir, '.opena2a', 'guard'), { recursive: true });
    fs.writeFileSync(path.join(tempDir, '.opena2a', 'guard', 'signatures.json'), '{}');
    fs.writeFileSync(path.join(tempDir, 'leaf.crt'), '-----BEGIN CERTIFICATE-----');

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    expect(report.securityScore).toBeLessThan(100);
    const certFinding = report.findings.find((f: any) => f.findingId === 'CRED-CERTFILE');
    expect(certFinding).toBeDefined();
    expect(certFinding.severity).toBe('medium');
  });

  // Phase 4.5 follow-up: assert the real corpus is checked when present
  // so monotonicity isn't only validated on synthetic shapes.
  const corpusKitchenSink = path.join(os.homedir(), 'workspace', 'opena2a-org', 'opena2a-corpus', 'repo', 'malicious', 'kitchen-sink');
  const corpusBenign = path.join(os.homedir(), 'workspace', 'opena2a-org', 'opena2a-corpus', 'repo', 'benign', 'tiny-clean-repo');
  const hasCorpus = fs.existsSync(corpusKitchenSink) && fs.existsSync(corpusBenign);
  it.skipIf(!hasCorpus)('real corpus: malicious < buggy ceiling, benign within band (#116)', async () => {
    const { output: malOut } = await captureStdout(() => init({ targetDir: corpusKitchenSink, format: 'json' }));
    const mal = JSON.parse(malOut);
    expect(mal.securityScore).toBeLessThan(60); // pre-#116 was 96
    const { output: benignOut } = await captureStdout(() => init({ targetDir: corpusBenign, format: 'json' }));
    const benign = JSON.parse(benignOut);
    expect(benign.securityScore).toBeGreaterThan(mal.securityScore);
    expect(benign.securityScore).toBeGreaterThanOrEqual(80);
  });

  // Regression: opena2a/issues/117 — Fix commands must point to runnable
  // mutations, never to status/read-only commands. `opena2a shield status`
  // is read-only and creates a dead-end UX (CISO Rule 3 violation).
  it('action commands never point to read-only status commands (#117)', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    fs.writeFileSync(path.join(tempDir, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify({
      mcpServers: {
        'fs': { command: 'filesystem-server', args: [] },
      },
    }));

    const { output } = await captureStdout(() => init({
      targetDir: tempDir,
      format: 'json',
    }));

    const report = JSON.parse(output);
    for (const action of report.actions) {
      expect(action.command).not.toBe('opena2a shield status');
      expect(action.command).not.toMatch(/\bstatus\s*$/);
    }
  });
});
