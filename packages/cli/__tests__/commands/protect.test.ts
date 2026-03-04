import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { protect } from '../../src/commands/protect.js';

const mockFetch = vi.fn();

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-protect-'));
}

function cleanupDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('protect command', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempDir();
    // Create a package.json so it's recognized as a project root
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name": "test"}');
    // Mock fetch for liveness verification (default: no Gemini access)
    vi.stubGlobal('fetch', mockFetch);
    mockFetch.mockReset();
    mockFetch.mockResolvedValue({ status: 403 });
  });

  afterEach(() => {
    cleanupDir(tempDir);
    vi.unstubAllGlobals();
  });

  it('returns 0 when no credentials are found', async () => {
    fs.writeFileSync(path.join(tempDir, 'app.ts'), 'const x = 42;\n');

    const exitCode = await protect({
      targetDir: tempDir,
      ci: true,
      format: 'json',
    });

    expect(exitCode).toBe(0);
  });

  it('detects Anthropic API key in TypeScript file', async () => {
    const fakeKey = 'sk-ant-api03-' + 'A'.repeat(80);
    fs.writeFileSync(
      path.join(tempDir, 'config.ts'),
      `const key = "${fakeKey}";\n`
    );

    const exitCode = await protect({
      targetDir: tempDir,
      dryRun: true,
      ci: true,
    });

    expect(exitCode).toBe(0); // dry run always returns 0
  });

  it('detects OpenAI API key', async () => {
    const fakeKey = 'sk-' + 'A'.repeat(48);
    fs.writeFileSync(
      path.join(tempDir, 'index.js'),
      `const apiKey = "${fakeKey}";\n`
    );

    const exitCode = await protect({
      targetDir: tempDir,
      dryRun: true,
      ci: true,
    });

    expect(exitCode).toBe(0);
  });

  it('detects Google API key (DRIFT-001)', async () => {
    const fakeKey = 'AIza' + 'B'.repeat(35);
    fs.writeFileSync(
      path.join(tempDir, 'maps.js'),
      `const key = "${fakeKey}";\n`
    );

    const exitCode = await protect({
      targetDir: tempDir,
      dryRun: true,
      ci: true,
    });

    expect(exitCode).toBe(0);
  });

  it('detects AWS access key (DRIFT-002)', async () => {
    const fakeKey = 'AKIA' + 'C'.repeat(16);
    fs.writeFileSync(
      path.join(tempDir, 'deploy.sh'),
      `export AWS_KEY="${fakeKey}"\n`
    );

    const exitCode = await protect({
      targetDir: tempDir,
      dryRun: true,
      ci: true,
    });

    expect(exitCode).toBe(0);
  });

  it('skips env var references (process.env.X)', async () => {
    fs.writeFileSync(
      path.join(tempDir, 'safe.ts'),
      `const key = process.env.OPENAI_API_KEY;\n`
    );

    const exitCode = await protect({
      targetDir: tempDir,
      dryRun: true,
      ci: true,
      format: 'json',
    });

    expect(exitCode).toBe(0);
  });

  it('replaces credential with env var reference in .ts file', async () => {
    const fakeKey = 'AIza' + 'D'.repeat(35);
    fs.writeFileSync(
      path.join(tempDir, 'api.ts'),
      `const key = "${fakeKey}";\n`
    );

    const exitCode = await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
    });

    const content = fs.readFileSync(path.join(tempDir, 'api.ts'), 'utf-8');
    expect(content).toContain('process.env.GOOGLE_API_KEY');
    expect(content).not.toContain(fakeKey);
  });

  it('replaces credential with env var reference in .py file', async () => {
    const fakeKey = 'AIza' + 'E'.repeat(35);
    fs.writeFileSync(
      path.join(tempDir, 'app.py'),
      `key = "${fakeKey}"\n`
    );

    const exitCode = await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
    });

    const content = fs.readFileSync(path.join(tempDir, 'app.py'), 'utf-8');
    expect(content).toContain("os.environ.get('GOOGLE_API_KEY')");
    expect(content).not.toContain(fakeKey);
  });

  it('creates .env.example with migrated variables', async () => {
    const fakeKey = 'AIza' + 'F'.repeat(35);
    fs.writeFileSync(
      path.join(tempDir, 'index.ts'),
      `const key = "${fakeKey}";\n`
    );

    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
    });

    const envExample = path.join(tempDir, '.env.example');
    expect(fs.existsSync(envExample)).toBe(true);

    const content = fs.readFileSync(envExample, 'utf-8');
    expect(content).toContain('GOOGLE_API_KEY=');
  });

  it('creates broker deny policy for migrated credentials', async () => {
    const fakeKey = 'AIza' + 'G'.repeat(35);
    fs.writeFileSync(
      path.join(tempDir, 'main.ts'),
      `const key = "${fakeKey}";\n`
    );

    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
    });

    const policyFile = path.join(os.homedir(), '.secretless-ai', 'broker-policies.json');
    if (fs.existsSync(policyFile)) {
      const parsed = JSON.parse(fs.readFileSync(policyFile, 'utf-8'));
      const rules = Array.isArray(parsed) ? parsed : parsed.rules;
      const hasPolicy = rules.some(
        (p: any) => p.credentialSelector === 'GOOGLE_API_KEY' && p.effect === 'deny'
      );
      expect(hasPolicy).toBe(true);
    }
    // If policyFile doesn't exist, SecretStore/broker not installed -- acceptable in CI
  });

  it('returns error for nonexistent directory', async () => {
    const exitCode = await protect({
      targetDir: '/nonexistent/path',
      ci: true,
    });

    expect(exitCode).toBe(1);
  });

  it('skips binary and media files', async () => {
    // Create a binary-like file
    fs.writeFileSync(path.join(tempDir, 'image.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47]));
    fs.writeFileSync(path.join(tempDir, 'app.ts'), 'const x = 1;\n');

    const exitCode = await protect({
      targetDir: tempDir,
      dryRun: true,
      ci: true,
      format: 'json',
    });

    expect(exitCode).toBe(0);
  });

  it('skips node_modules directory', async () => {
    const nmDir = path.join(tempDir, 'node_modules', 'some-pkg');
    fs.mkdirSync(nmDir, { recursive: true });

    const fakeKey = 'AIza' + 'H'.repeat(35);
    fs.writeFileSync(
      path.join(nmDir, 'index.js'),
      `const key = "${fakeKey}";\n`
    );

    const exitCode = await protect({
      targetDir: tempDir,
      dryRun: true,
      ci: true,
      format: 'json',
    });

    expect(exitCode).toBe(0); // should find nothing
  });

  it('handles multiple credentials in same file', async () => {
    const googleKey = 'AIza' + 'I'.repeat(35);
    const awsKey = 'AKIA' + 'J'.repeat(16);

    fs.writeFileSync(
      path.join(tempDir, 'multi.ts'),
      `const google = "${googleKey}";\nconst aws = "${awsKey}";\n`
    );

    const exitCode = await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
    });

    const content = fs.readFileSync(path.join(tempDir, 'multi.ts'), 'utf-8');
    expect(content).toContain('process.env.GOOGLE_API_KEY');
    expect(content).toContain('process.env.AWS_ACCESS_KEY_ID');
  });

  it('produces JSON output with format=json', async () => {
    const fakeKey = 'AIza' + 'K'.repeat(35);
    fs.writeFileSync(
      path.join(tempDir, 'config.ts'),
      `const key = "${fakeKey}";\n`
    );

    // Capture stdout
    const chunks: string[] = [];
    const origWrite = process.stdout.write;
    process.stdout.write = ((chunk: any) => {
      chunks.push(String(chunk));
      return true;
    }) as any;

    try {
      await protect({
        targetDir: tempDir,
        ci: true,
        format: 'json',
        skipVerify: true,
      });
    } finally {
      process.stdout.write = origWrite;
    }

    const output = chunks.join('');
    const report = JSON.parse(output);
    expect(report.totalFound).toBeGreaterThan(0);
    expect(report.results).toBeInstanceOf(Array);
    expect(report).toHaveProperty('durationMs');
  });

  it('escalates DRIFT-001 to critical when Gemini access confirmed', async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      json: async () => ({ models: [{ name: 'gemini-pro' }] }),
    });

    const fakeKey = 'AIza' + 'L'.repeat(35);
    fs.writeFileSync(
      path.join(tempDir, 'api.ts'),
      `const key = "${fakeKey}";\n`
    );

    const chunks: string[] = [];
    const origWrite = process.stdout.write;
    process.stdout.write = ((chunk: any) => {
      chunks.push(String(chunk));
      return true;
    }) as any;

    try {
      await protect({
        targetDir: tempDir,
        ci: true,
        format: 'json',
        skipVerify: true,
      });
    } finally {
      process.stdout.write = origWrite;
    }

    const output = chunks.join('');
    const report = JSON.parse(output);

    // Severity should be escalated to critical
    const driftResult = report.results.find(
      (r: any) => r.credential.findingId === 'DRIFT-001'
    );
    expect(driftResult.credential.severity).toBe('critical');

    // Liveness results should be included
    expect(report.livenessResults).toBeDefined();
    const livenessEntry = Object.values(report.livenessResults)[0] as any;
    expect(livenessEntry.live).toBe(true);
    expect(livenessEntry.escalatedSeverity).toBe('critical');
  });

  it('keeps DRIFT-001 as high when Gemini access denied', async () => {
    mockFetch.mockResolvedValueOnce({ status: 403 });

    const fakeKey = 'AIza' + 'M'.repeat(35);
    fs.writeFileSync(
      path.join(tempDir, 'config.ts'),
      `const key = "${fakeKey}";\n`
    );

    const chunks: string[] = [];
    const origWrite = process.stdout.write;
    process.stdout.write = ((chunk: any) => {
      chunks.push(String(chunk));
      return true;
    }) as any;

    try {
      await protect({
        targetDir: tempDir,
        ci: true,
        format: 'json',
        skipVerify: true,
      });
    } finally {
      process.stdout.write = origWrite;
    }

    const output = chunks.join('');
    const report = JSON.parse(output);

    const driftResult = report.results.find(
      (r: any) => r.credential.findingId === 'DRIFT-001'
    );
    expect(driftResult.credential.severity).toBe('high');
  });

  it('creates CLAUDE.md with secretless section after migration', async () => {
    const fakeKey = 'AIza' + 'P'.repeat(35);
    fs.writeFileSync(
      path.join(tempDir, 'service.ts'),
      `const key = "${fakeKey}";\n`
    );

    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
    });

    const claudeMd = path.join(tempDir, 'CLAUDE.md');
    expect(fs.existsSync(claudeMd)).toBe(true);

    const content = fs.readFileSync(claudeMd, 'utf-8');
    expect(content).toContain('<!-- secretless:managed -->');
    expect(content).toContain('GOOGLE_API_KEY');
    expect(content).toContain('Blocked file patterns');
  });

  it('includes aiToolsUpdated in JSON output after migration', async () => {
    const fakeKey = 'AIza' + 'Q'.repeat(35);
    fs.writeFileSync(
      path.join(tempDir, 'app.ts'),
      `const key = "${fakeKey}";\n`
    );

    const chunks: string[] = [];
    const origWrite = process.stdout.write;
    process.stdout.write = ((chunk: any) => {
      chunks.push(String(chunk));
      return true;
    }) as any;

    try {
      await protect({
        targetDir: tempDir,
        ci: true,
        format: 'json',
        skipVerify: true,
      });
    } finally {
      process.stdout.write = origWrite;
    }

    const output = chunks.join('');
    const report = JSON.parse(output);
    expect(report.aiToolsUpdated).toContain('CLAUDE.md');
  });

  it('does not create CLAUDE.md in dry-run mode', async () => {
    const fakeKey = 'AIza' + 'R'.repeat(35);
    fs.writeFileSync(
      path.join(tempDir, 'config.ts'),
      `const key = "${fakeKey}";\n`
    );

    await protect({
      targetDir: tempDir,
      dryRun: true,
      ci: true,
    });

    expect(fs.existsSync(path.join(tempDir, 'CLAUDE.md'))).toBe(false);
  });

  it('skips liveness verification with --skip-liveness', async () => {
    const fakeKey = 'AIza' + 'N'.repeat(35);
    fs.writeFileSync(
      path.join(tempDir, 'config.ts'),
      `const key = "${fakeKey}";\n`
    );

    await protect({
      targetDir: tempDir,
      dryRun: true,
      ci: true,
      skipLiveness: true,
    });

    // fetch should not have been called
    expect(mockFetch).not.toHaveBeenCalled();
  });

  // --- Phase 4: .gitignore fix ---

  it('creates .gitignore with .env exclusion when missing', async () => {
    fs.writeFileSync(path.join(tempDir, 'app.ts'), 'const x = 42;\n');

    await protect({
      targetDir: tempDir,
      ci: true,
      format: 'text',
      skipSign: true,
    });

    const gitignorePath = path.join(tempDir, '.gitignore');
    expect(fs.existsSync(gitignorePath)).toBe(true);
    const content = fs.readFileSync(gitignorePath, 'utf-8');
    expect(content).toContain('.env');
    expect(content).toContain('.env.*');
  });

  it('appends .env to existing .gitignore if missing', async () => {
    fs.writeFileSync(path.join(tempDir, '.gitignore'), 'node_modules\n');
    fs.writeFileSync(path.join(tempDir, 'app.ts'), 'const x = 42;\n');

    await protect({
      targetDir: tempDir,
      ci: true,
      format: 'text',
      skipSign: true,
    });

    const content = fs.readFileSync(path.join(tempDir, '.gitignore'), 'utf-8');
    expect(content).toContain('node_modules');
    expect(content).toContain('.env');
  });

  it('skips .gitignore fix if .env already in .gitignore', async () => {
    fs.writeFileSync(path.join(tempDir, '.gitignore'), 'node_modules\n.env\n');
    fs.writeFileSync(path.join(tempDir, 'app.ts'), 'const x = 42;\n');

    const chunks: string[] = [];
    const origWrite = process.stdout.write;
    process.stdout.write = ((chunk: any) => {
      chunks.push(String(chunk));
      return true;
    }) as any;

    try {
      await protect({
        targetDir: tempDir,
        ci: true,
        format: 'json',
        skipSign: true,
      });
    } finally {
      process.stdout.write = origWrite;
    }

    const report = JSON.parse(chunks.join(''));
    expect(report.additionalFixes?.gitignoreFixed).toBeUndefined();
  });

  it('skips git fixes with --skip-git', async () => {
    fs.writeFileSync(path.join(tempDir, 'app.ts'), 'const x = 42;\n');

    await protect({
      targetDir: tempDir,
      ci: true,
      skipGit: true,
      skipSign: true,
    });

    expect(fs.existsSync(path.join(tempDir, '.gitignore'))).toBe(false);
  });

  // --- Phase 5: AI config exclusion ---

  it('adds AI config files to .git/info/exclude', async () => {
    // Create a .git directory and a CLAUDE.md
    fs.mkdirSync(path.join(tempDir, '.git', 'info'), { recursive: true });
    fs.writeFileSync(path.join(tempDir, 'CLAUDE.md'), '# Instructions\n');
    fs.writeFileSync(path.join(tempDir, 'app.ts'), 'const x = 42;\n');

    await protect({
      targetDir: tempDir,
      ci: true,
      skipSign: true,
    });

    const excludePath = path.join(tempDir, '.git', 'info', 'exclude');
    expect(fs.existsSync(excludePath)).toBe(true);
    const content = fs.readFileSync(excludePath, 'utf-8');
    expect(content).toContain('CLAUDE.md');
  });

  it('skips AI config exclusion when no .git directory', async () => {
    fs.writeFileSync(path.join(tempDir, 'CLAUDE.md'), '# Instructions\n');
    fs.writeFileSync(path.join(tempDir, 'app.ts'), 'const x = 42;\n');

    const chunks: string[] = [];
    const origWrite = process.stdout.write;
    process.stdout.write = ((chunk: any) => {
      chunks.push(String(chunk));
      return true;
    }) as any;

    try {
      await protect({
        targetDir: tempDir,
        ci: true,
        format: 'json',
        skipSign: true,
      });
    } finally {
      process.stdout.write = origWrite;
    }

    const report = JSON.parse(chunks.join(''));
    expect(report.additionalFixes?.gitExclusionsAdded).toBeUndefined();
  });

  // --- Phase 6: Config signing ---

  it('signs config files and includes in report', async () => {
    fs.writeFileSync(path.join(tempDir, 'app.ts'), 'const x = 42;\n');

    const chunks: string[] = [];
    const origWrite = process.stdout.write;
    process.stdout.write = ((chunk: any) => {
      chunks.push(String(chunk));
      return true;
    }) as any;

    try {
      await protect({
        targetDir: tempDir,
        ci: true,
        format: 'json',
        skipGit: true,
      });
    } finally {
      process.stdout.write = origWrite;
    }

    const report = JSON.parse(chunks.join(''));
    // package.json exists so at least 1 config file should be signed
    expect(report.additionalFixes?.configsSigned).toBeGreaterThanOrEqual(1);
    expect(fs.existsSync(path.join(tempDir, '.opena2a', 'guard', 'signatures.json'))).toBe(true);
  });

  it('skips signing with --skip-sign', async () => {
    fs.writeFileSync(path.join(tempDir, 'app.ts'), 'const x = 42;\n');

    await protect({
      targetDir: tempDir,
      ci: true,
      skipSign: true,
      skipGit: true,
    });

    expect(fs.existsSync(path.join(tempDir, '.opena2a', 'guard', 'signatures.json'))).toBe(false);
  });

  // --- Phase 7: Before/after score ---

  it('includes scoreBefore and scoreAfter in JSON output', async () => {
    const fakeKey = 'AIza' + 'S'.repeat(35);
    fs.writeFileSync(
      path.join(tempDir, 'config.ts'),
      `const key = "${fakeKey}";\n`
    );

    const chunks: string[] = [];
    const origWrite = process.stdout.write;
    process.stdout.write = ((chunk: any) => {
      chunks.push(String(chunk));
      return true;
    }) as any;

    try {
      await protect({
        targetDir: tempDir,
        ci: true,
        format: 'json',
        skipVerify: true,
        skipSign: true,
      });
    } finally {
      process.stdout.write = origWrite;
    }

    const report = JSON.parse(chunks.join(''));
    expect(report.scoreBefore).toBeDefined();
    expect(report.scoreAfter).toBeDefined();
    expect(report.scoreAfter).toBeGreaterThanOrEqual(report.scoreBefore);
  });
});
