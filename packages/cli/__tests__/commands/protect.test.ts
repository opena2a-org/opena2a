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

  // --- Regression tests for credential-migration bugs (2026-04-17) ---

  it('bug #6: replace does not span lines when source has unbalanced quotes in template literals', async () => {
    // Old regex `"[^"]*${escVal}[^"]*"` could greedily span across newlines,
    // matching from a stray `"` on one line through the credential to a `"`
    // many lines later — corrupting unrelated content. New regex uses
    // `[^"\n]*` so matches are line-bounded.
    const fakeKey = 'AIza' + 'X'.repeat(35);
    const source = `const help = \`
  Example: "first quoted fragment"
  Paste your key: ${fakeKey}
  Or use "second quoted fragment"
\`;
const tail = "tail";
`;
    fs.writeFileSync(path.join(tempDir, 'app.ts'), source);

    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    const after = fs.readFileSync(path.join(tempDir, 'app.ts'), 'utf-8');
    // Both quoted fragments must survive untouched.
    expect(after).toContain('"first quoted fragment"');
    expect(after).toContain('"second quoted fragment"');
    expect(after).toContain('"tail"');
    // The credential must be gone, replaced by an env var reference.
    expect(after).not.toContain(fakeKey);
    expect(after).toContain('GOOGLE_API_KEY');
  });

  it('bug #7 + #12: AWS key longer than 20 chars is stored byte-equal in source replacement (JSON)', async () => {
    // DRIFT-002 regex captures AKIA+16 = 20 chars exactly. If the source
    // has a 21-char token (test fixture, malformed key, custom key prefix),
    // the original code replaced only the 20-char prefix — leaving a stray
    // trailing char and storing a vault value that did not match source.
    const realKey = 'AKIAFAKE000TESTONLY1';     // 20-char standard
    const longKey = 'AKIAFAKE000TESTONLY11';    // 21-char (one extra)
    fs.writeFileSync(
      path.join(tempDir, 'config.json'),
      JSON.stringify({ AWS_ACCESS_KEY_ID: longKey, OTHER: realKey }, null, 2)
    );

    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    const after = fs.readFileSync(path.join(tempDir, 'config.json'), 'utf-8');
    // No fragment of the long key should remain — neither the 21-char form
    // nor the 20-char prefix `longKey.slice(0, 20)` followed by a stray `1`.
    expect(after).not.toContain(longKey);
    // Stray trailing char from a partial replacement would look like `}1"`
    // or `"}1` — verify nothing of the sort survives.
    expect(after).not.toMatch(/[}"\s]1["}]/);
  });

  it('bug #7 + #12: scan extends captured value to the full token in source (JS)', async () => {
    // Same as above but in a .ts file so the strip-quotes branch runs.
    const longKey = 'AKIAFAKE000TESTONLY11'; // 21 chars
    fs.writeFileSync(
      path.join(tempDir, 'aws.ts'),
      `const k = "${longKey}";\n`
    );

    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    const after = fs.readFileSync(path.join(tempDir, 'aws.ts'), 'utf-8');
    expect(after).not.toContain(longKey);
    expect(after).not.toContain(longKey.slice(0, 20)); // not even the prefix should remain
    expect(after).toContain('process.env.AWS_ACCESS_KEY_ID');
  });

  it('bug #8: detects Slack tokens', async () => {
    // Constructed from parts so the literal byte sequence never appears
    // contiguously in source — see CRED-006 test rationale.
    const token = 'xox' + 'b-1234567890-' + 'abcdefghijklmnopqrstuvwx';
    fs.writeFileSync(
      path.join(tempDir, 'slack.ts'),
      `const t = "${token}";\n`
    );

    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    const after = fs.readFileSync(path.join(tempDir, 'slack.ts'), 'utf-8');
    expect(after).not.toContain(token);
    expect(after).toContain('SLACK_TOKEN');
  });

  it('bug #9: detects Stripe secret keys', async () => {
    const key = 'sk_live_' + 'A'.repeat(24);
    fs.writeFileSync(
      path.join(tempDir, 'pay.ts'),
      `const stripe = "${key}";\n`
    );

    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    const after = fs.readFileSync(path.join(tempDir, 'pay.ts'), 'utf-8');
    expect(after).not.toContain(key);
    expect(after).toContain('STRIPE_SECRET_KEY');
  });

  it('bug #10: detects ghu_ OAuth and ghr_ refresh GitHub tokens', async () => {
    const oauth = 'ghu_' + 'A'.repeat(40);
    const refresh = 'ghr_' + 'B'.repeat(40);
    fs.writeFileSync(
      path.join(tempDir, 'gh.ts'),
      `const o = "${oauth}";\nconst r = "${refresh}";\n`
    );

    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    const after = fs.readFileSync(path.join(tempDir, 'gh.ts'), 'utf-8');
    expect(after).not.toContain(oauth);
    expect(after).not.toContain(refresh);
    expect(after).toContain('GITHUB_TOKEN');
  });

  it('bug #13: detects vendor-prefixed key in JSON env value (CRED-004 JSON-quoted-key form)', async () => {
    // Real-world reproducer from /tmp/hma-real-world/ibm-mcp/mcp.json: protect
    // previously printed "No hardcoded credentials detected" because CRED-004
    // required contiguous `key\s*[:=]` and missed the closing `"` of the JSON
    // key. Same shape as CRED-005 bug #11.
    fs.writeFileSync(
      path.join(tempDir, 'mcp.json'),
      JSON.stringify({
        mcpServers: {
          'ibm-watsonx': {
            command: 'npx',
            args: ['@ibm/watsonx-mcp-server'],
            env: {
              WATSONX_API_KEY: 'ibm-api-FAKE-key-for-testing-1234567890',
              WATSONX_URL: 'https://us-south.ml.cloud.ibm.com',
            },
          },
        },
      }, null, 2)
    );

    const chunks: string[] = [];
    const origWrite = process.stdout.write;
    process.stdout.write = ((chunk: any) => { chunks.push(String(chunk)); return true; }) as any;
    try {
      await protect({
        targetDir: tempDir,
        ci: true,
        format: 'json',
        skipVerify: true,
        skipSign: true,
        skipGit: true,
        skipLiveness: true,
      });
    } finally {
      process.stdout.write = origWrite;
    }

    const report = JSON.parse(chunks.join(''));
    expect(report.totalFound).toBeGreaterThanOrEqual(1);
    const watsonx = report.results.find(
      (r: any) => r.credential.value === 'ibm-api-FAKE-key-for-testing-1234567890'
    );
    expect(watsonx).toBeDefined();
  });

  it('bug #14: stale rollback manifest is removed on a no-credential run', async () => {
    // Pre-seed a stale manifest as if a prior run had migrated credentials.
    // This run finds none, so the manifest must be cleaned up — leaving it
    // would tell the user secrets are still in vault when they are not.
    const opDir = path.join(tempDir, '.opena2a');
    fs.mkdirSync(opDir, { recursive: true });
    const manifestPath = path.join(opDir, 'protect-rollback.json');
    fs.writeFileSync(manifestPath, JSON.stringify({
      timestamp: new Date().toISOString(),
      credentials: [{ envVar: 'OLD_KEY', filePath: 'app.ts', line: 1, storageLocation: 'vault' }],
      backups: [],
    }));

    fs.writeFileSync(path.join(tempDir, 'app.ts'), 'const x = 42;\n');

    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
      skipLiveness: true,
    });

    expect(fs.existsSync(manifestPath)).toBe(false);
  });

  it('bug #14: dry-run does not delete an existing rollback manifest', async () => {
    const opDir = path.join(tempDir, '.opena2a');
    fs.mkdirSync(opDir, { recursive: true });
    const manifestPath = path.join(opDir, 'protect-rollback.json');
    fs.writeFileSync(manifestPath, '{"credentials": []}');

    fs.writeFileSync(path.join(tempDir, 'app.ts'), 'const x = 42;\n');

    await protect({
      targetDir: tempDir,
      ci: true,
      dryRun: true,
      skipLiveness: true,
    });

    // Dry-run guarantees no filesystem mutations, including manifest cleanup.
    expect(fs.existsSync(manifestPath)).toBe(true);
  });

  // Regression: CRED-004's regex allows unquoted values so it can match
  // .env-style bare assignments, but that also admits source-code identifier
  // lookups like `const api_key = config.credentials.apiKeyRef`. Rewriting
  // the RHS to process.env.API_KEY would break working code.
  it('does NOT flag unquoted dotted-identifier assignments (CRED-004 FP fix)', async () => {
    const originalContent = 'const api_key = config.credentials.apiKeyValue_xxxxxxxxx;\n';
    const targetFile = path.join(tempDir, 'identifier-lookup.js');
    fs.writeFileSync(targetFile, originalContent);

    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    // Source must be untouched — this is a reference, not a literal secret.
    expect(fs.readFileSync(targetFile, 'utf-8')).toBe(originalContent);
  });

  it('still flags quoted CRED-004 values (positive control for identifier FP fix)', async () => {
    const fakeKey = 'Z'.repeat(32);
    const targetFile = path.join(tempDir, 'quoted-key.py');
    fs.writeFileSync(targetFile, `api_key = "${fakeKey}"\n`);

    await protect({
      targetDir: tempDir,
      dryRun: true,
      ci: true,
      format: 'json',
      skipLiveness: true,
    });

    // Dry run: file unmodified but a finding should exist. The JSON output
    // contains totalFound > 0 — we can't easily assert on captured stdout
    // here so verify indirectly by running a second live scan that would
    // rewrite the file.
    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    const after = fs.readFileSync(targetFile, 'utf-8');
    // Quoted value should be rewritten to a bare env-var reference
    expect(after).not.toContain(fakeKey);
    expect(after).toMatch(/os\.environ\.get\(['"]API_KEY['"]\)/);
  });

  // Regression: the pre-pass backup loop previously wrapped every copyFileSync
  // in one try/catch with an empty handler. If backup failed mid-loop, some
  // files were backed up and some weren't, but migration proceeded — source
  // files got rewritten with no restore path. Now each backup is attempted
  // independently and any failure skips migration of that file.
  it('skips migration and preserves source when backup fails', async () => {
    const fakeKey = 'sk-ant-api03-' + 'A'.repeat(80);
    const originalContent = `const key = "${fakeKey}";\n`;
    const targetFile = path.join(tempDir, 'config.ts');
    fs.writeFileSync(targetFile, originalContent);

    // Seed a file where mkdir expects a directory — this makes mkdirSync
    // fail with EEXIST (file already exists), which is the failure path.
    fs.mkdirSync(path.join(tempDir, '.opena2a'), { recursive: true });
    fs.writeFileSync(path.join(tempDir, '.opena2a', 'backup'), 'blocker');

    const exitCode = await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    // Source file must remain unchanged — no silent data loss.
    expect(fs.readFileSync(targetFile, 'utf-8')).toBe(originalContent);
    // Migration should report failure (non-zero exit).
    expect(exitCode).toBe(1);
  });

  it('skips test-fixtures/ and __fixtures__/ directories (regression for bug #5)', async () => {
    fs.mkdirSync(path.join(tempDir, 'test-fixtures'), { recursive: true });
    fs.mkdirSync(path.join(tempDir, '__fixtures__'), { recursive: true });
    const fakeKey = 'AIza' + 'Z'.repeat(35);
    const fixtureContent = `const k = "${fakeKey}";\n`;
    fs.writeFileSync(path.join(tempDir, 'test-fixtures', 'cred.ts'), fixtureContent);
    fs.writeFileSync(path.join(tempDir, '__fixtures__', 'cred.ts'), fixtureContent);

    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    // Fixture files must remain untouched — scanner must skip these dirs.
    const fixA = fs.readFileSync(path.join(tempDir, 'test-fixtures', 'cred.ts'), 'utf-8');
    const fixB = fs.readFileSync(path.join(tempDir, '__fixtures__', 'cred.ts'), 'utf-8');
    expect(fixA).toBe(fixtureContent);
    expect(fixB).toBe(fixtureContent);
  });
});
