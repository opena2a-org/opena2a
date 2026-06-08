import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { quickCredentialScan, SKIP_FILENAME_PATTERNS, TEMPLATE_ENV_FILES } from '../../src/util/credential-patterns.js';

// Real-shaped placeholder credentials. These are the values that triggered
// the 7 false positives surfaced during the 2026-04-29 `opena2a review` audit
// (DLP test fixtures, VHS demo scripts, demo-setup.sh). The scanner must
// silently ignore matches inside the corresponding fixture/demo paths.
const FIXTURE_AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const FIXTURE_GITHUB_TOKEN = 'ghp_' + 'a'.repeat(36);
const FIXTURE_OPENAI_KEY = 'sk-proj-' + 'a'.repeat(40);

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-fixture-skip-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function write(rel: string, body: string): string {
  const abs = path.join(tmpDir, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, body);
  return abs;
}

describe('credential-patterns: SKIP_FILENAME_PATTERNS regex correctness', () => {
  const matches = (name: string) => SKIP_FILENAME_PATTERNS.some(re => re.test(name));

  it('matches *.test.ts / *.test.tsx / *.test.js / *.test.jsx / *.test.mjs / *.test.cjs / *.test.py', () => {
    for (const ext of ['ts', 'tsx', 'js', 'jsx', 'mjs', 'cjs', 'py']) {
      expect(matches(`dlp.test.${ext}`)).toBe(true);
    }
  });

  it('matches *.spec.* equivalents', () => {
    for (const ext of ['ts', 'tsx', 'js', 'jsx', 'mjs', 'cjs', 'py']) {
      expect(matches(`dlp.spec.${ext}`)).toBe(true);
    }
  });

  it('matches Go and Python *_test conventions', () => {
    expect(matches('dlp_test.go')).toBe(true);
    expect(matches('dlp_test.py')).toBe(true);
  });

  it('matches demo-* scripts (sh / ts / js / py)', () => {
    expect(matches('demo-setup.sh')).toBe(true);
    expect(matches('demo_setup.sh')).toBe(true);
    expect(matches('demo-setup.ts')).toBe(true);
    expect(matches('demo-setup.js')).toBe(true);
    expect(matches('demo-setup.py')).toBe(true);
  });

  it('does NOT match production source files', () => {
    expect(matches('dlp.ts')).toBe(false);
    expect(matches('protect.ts')).toBe(false);
    expect(matches('handler.go')).toBe(false);
    expect(matches('main.py')).toBe(false);
    expect(matches('setup.sh')).toBe(false);
  });

  it('does NOT match files that merely contain "test" or "demo" in the middle', () => {
    expect(matches('greatest.ts')).toBe(false);
    expect(matches('contestant.ts')).toBe(false);
    expect(matches('redemo.sh')).toBe(false);
  });
});

describe('quickCredentialScan: fixture/demo files are silently skipped', () => {
  it('skips *.test.ts files alongside source (the dlp.test.ts case)', () => {
    write('packages/aim-core/src/dlp/dlp.ts', 'export const x = 1;');
    write('packages/aim-core/src/dlp/dlp.test.ts',
      `const realShape = "${FIXTURE_OPENAI_KEY}";\n` +
      `const aws = "${FIXTURE_AWS_KEY}";\n` +
      `const gh = "${FIXTURE_GITHUB_TOKEN}";\n`,
    );
    const matches = quickCredentialScan(tmpDir);
    expect(matches).toHaveLength(0);
  });

  it('skips *.spec.ts files alongside source', () => {
    write('src/auth/token.ts', 'export const t = 1;');
    write('src/auth/token.spec.ts', `const k = "${FIXTURE_OPENAI_KEY}";`);
    const matches = quickCredentialScan(tmpDir);
    expect(matches).toHaveLength(0);
  });

  it('skips files in vhs/ directory (terminal-recording demo asset convention)', () => {
    write('docs/vhs/setup-lab.sh',
      `# VHS demo recording — placeholder creds for terminal capture\n` +
      `export OPENAI_API_KEY="${FIXTURE_OPENAI_KEY}"\n` +
      `export AWS_ACCESS_KEY_ID="${FIXTURE_AWS_KEY}"\n`,
    );
    const matches = quickCredentialScan(tmpDir);
    expect(matches).toHaveLength(0);
  });

  it('skips demo-*.sh scripts (the scripts/demo-setup.sh case)', () => {
    write('scripts/demo-setup.sh', `OPENAI_API_KEY="${FIXTURE_OPENAI_KEY}"`);
    const matches = quickCredentialScan(tmpDir);
    expect(matches).toHaveLength(0);
  });

  it('skips Go _test.go files (e.g. handler_test.go)', () => {
    write('cmd/api/handler_test.go', `var key = "${FIXTURE_AWS_KEY}"`);
    const matches = quickCredentialScan(tmpDir);
    expect(matches).toHaveLength(0);
  });

  it('STILL detects credentials in production source files (regression guard)', () => {
    write('src/config.ts',
      `// real production code path — must NOT be skipped\n` +
      `const apiKey = "${FIXTURE_OPENAI_KEY}";\n`,
    );
    const matches = quickCredentialScan(tmpDir);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].findingId).toBe('CRED-002');
  });

  it('STILL detects credentials in non-test shell scripts (regression guard)', () => {
    // setup.sh (no demo- prefix) is production tooling — must keep firing
    write('scripts/setup.sh', `export OPENAI_API_KEY="${FIXTURE_OPENAI_KEY}"`);
    const matches = quickCredentialScan(tmpDir);
    expect(matches.length).toBeGreaterThan(0);
  });

  it('does NOT skip a production file just because a sibling is a test file', () => {
    write('src/auth/token.ts', `const real = "${FIXTURE_OPENAI_KEY}";`);
    write('src/auth/token.test.ts', `const fixture = "${FIXTURE_OPENAI_KEY}";`);
    const matches = quickCredentialScan(tmpDir);
    expect(matches).toHaveLength(1);
    expect(matches[0].filePath).toMatch(/token\.ts$/);
    expect(matches[0].filePath).not.toMatch(/\.test\.ts$/);
  });

  it('reproduces the exact 2026-04-29 audit FP set: 7 fixtures across 3 file paths → 0 findings', () => {
    // Mirrors the user's `opena2a review` self-scan output:
    //   - 3 OpenAI keys (dlp.test.ts, setup-lab.sh, demo-setup.sh)
    //   - 2 AWS keys   (dlp.test.ts, setup-lab.sh)
    //   - 1 GitHub token (dlp.test.ts)
    //   - 1 generic api_key in setup-lab.sh
    write('packages/aim-core/src/dlp/dlp.test.ts',
      `const o = "${FIXTURE_OPENAI_KEY}";\n` +
      `const a = "${FIXTURE_AWS_KEY}";\n` +
      `const g = "${FIXTURE_GITHUB_TOKEN}";\n`,
    );
    write('docs/vhs/setup-lab.sh',
      `export OPENAI_API_KEY="${FIXTURE_OPENAI_KEY}"\n` +
      `export AWS_ACCESS_KEY_ID="${FIXTURE_AWS_KEY}"\n` +
      `export api_key="${'a'.repeat(30)}"\n`,
    );
    write('scripts/demo-setup.sh',
      `export OPENAI_API_KEY="${FIXTURE_OPENAI_KEY}"\n`,
    );
    const matches = quickCredentialScan(tmpDir);
    expect(matches).toHaveLength(0);
  });
});

// Regression: template env files (.env.example / .sample / .template / .dist)
// hold placeholder values by convention and are meant to be committed. Scanning
// them produced CRITICAL false positives (surfaced 2026-06-08 by the
// opena2a-cli 0.10.8 fresh-user release test, where `protect`/`init` flagged
// `.env.example:1` as a CRITICAL OpenAI key). Real env files still scan.
describe('quickCredentialScan: template env files are skipped (placeholders, not secrets)', () => {
  const PLACEHOLDER = `OPENAI_API_KEY=${FIXTURE_OPENAI_KEY}`; // real-shaped placeholder

  for (const tmpl of [...TEMPLATE_ENV_FILES]) {
    it(`skips ${tmpl} (no findings even with a real-shaped placeholder)`, () => {
      write(tmpl, PLACEHOLDER + '\n');
      expect(quickCredentialScan(tmpDir)).toHaveLength(0);
    });
  }

  it('STILL scans a real .env file (regression guard — that is where protect migrates from)', () => {
    write('.env', PLACEHOLDER + '\n');
    const matches = quickCredentialScan(tmpDir);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].findingId).toBe('CRED-002');
  });

  it('STILL scans .env.local and .env.production (live env files, not templates)', () => {
    write('.env.local', PLACEHOLDER + '\n');
    write('.env.production', PLACEHOLDER + '\n');
    expect(quickCredentialScan(tmpDir).length).toBeGreaterThanOrEqual(2);
  });

  it('TEMPLATE_ENV_FILES covers the four conventional template names', () => {
    expect([...TEMPLATE_ENV_FILES].sort()).toEqual(
      ['.env.dist', '.env.example', '.env.sample', '.env.template'],
    );
  });

  it('STILL scans a real .env nested in a normal subdirectory (subtree scanning intact)', () => {
    // Guard against an over-broad skip: only template FILES are excluded, never
    // whole subtrees. A real secret in config/.env must still be found.
    write('config/.env', PLACEHOLDER + '\n');
    expect(quickCredentialScan(tmpDir).length).toBeGreaterThan(0);
  });

  it('a DIRECTORY named .env.example is treated as a normal hidden dir (documents, does not special-case)', () => {
    // Documents the intended behavior: because the exclusion is enforced via
    // SCAN_DOTFILES omission (not a name-keyed skip branch), a dir named like a
    // template is handled by the same rule as any other hidden directory
    // (.git, .vscode) — not recursed. NOTE: this is a documentation test, not a
    // regression guard for the over-broad name-skip an earlier draft had — that
    // draft was behaviorally identical for a template-named entry, so no fixture
    // can distinguish them. The real guards are the subtree-scanning test above
    // and the real-.env tests. Per adversarial-review verifier feedback.
    write('.env.example/.env', PLACEHOLDER + '\n');     // inside a hidden dir → not scanned
    write('visible/.env', PLACEHOLDER + '\n');           // normal dir → scanned
    const matches = quickCredentialScan(tmpDir);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.every(m => !m.filePath.includes('.env.example'))).toBe(true);
  });
});

// Regression: the walker's self-exemption previously used dir.includes(marker)
// on "packages/cli/src" and "packages/cli/dist", which silently skipped ANY
// user project whose path contained those substrings. The anchored fix
// resolves the CLI's own package root at module load and compares with
// path.startsWith, so user directories are scanned even when they share
// the path fragment.
describe('walkFiles self-exemption is anchored, not substring', () => {
  it('scans a user directory whose path contains "packages/cli/src"', async () => {
    const { walkFiles } = await import('../../src/util/credential-patterns.js');
    const userDir = path.join(tmpDir, 'packages', 'cli', 'src');
    fs.mkdirSync(userDir, { recursive: true });
    const file = path.join(userDir, 'app.ts');
    fs.writeFileSync(file, 'const x = 1;', 'utf-8');

    const visited: string[] = [];
    walkFiles(tmpDir, (p: string) => { visited.push(p); });

    expect(visited).toContain(file);
  });

  it('still skips the CLI\'s own source tree', async () => {
    const { walkFiles } = await import('../../src/util/credential-patterns.js');
    let dir = __dirname;
    while (dir !== path.parse(dir).root) {
      const pkgPath = path.join(dir, 'package.json');
      if (fs.existsSync(pkgPath)) {
        try {
          const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
          if (pkg.name === 'opena2a-cli') break;
        } catch {
          // ignore
        }
      }
      dir = path.dirname(dir);
    }
    const cliRoot = dir;
    const srcDir = path.join(cliRoot, 'src');
    // Vitest always runs from the dev tree, where src/ must exist. If it
    // doesn't, the test is running in an unexpected environment and we
    // want a loud failure rather than a silent no-op pass.
    expect(fs.existsSync(srcDir)).toBe(true);

    const visited: string[] = [];
    walkFiles(srcDir, (p: string) => { visited.push(p); });
    expect(visited.length).toBe(0);
  });
});
