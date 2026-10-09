import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execFileSync } from 'node:child_process';
import {
  collectEnvFileFacts, countAssignments, findEnvFiles, symbolicMode,
} from '../../src/commands/review-facts.js';
import { scanCredentialsWithCoverage } from '../../src/util/credential-patterns.js';
import { GUARD_FILES, defaultSigningFiles } from '../../src/commands/guard.js';

const posixOnly = process.platform === 'win32' ? it.skip : it;

function git(dir: string, ...args: string[]): void {
  execFileSync('git', ['-C', dir, ...args], { stdio: 'ignore' });
}

function write(dir: string, rel: string, content: string): void {
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), content);
}

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-facts-'));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('env-file facts in a git repository', () => {
  it('an untracked env file with no matching rule is covered by `git add .`', () => {
    git(dir, 'init', '-q');
    write(dir, '.gitignore', 'node_modules\n');
    write(dir, '.env', 'A=1\nB=two\n');

    expect(collectEnvFileFacts(dir)).toMatchObject([
      { path: '.env', assignments: 2, gitIgnored: false, gitTracked: false, stagedByAddAll: true },
    ]);
  });

  it('an ignored env file is not covered', () => {
    git(dir, 'init', '-q');
    write(dir, '.gitignore', '.env\n');
    write(dir, '.env', 'A=1\n');

    expect(collectEnvFileFacts(dir)).toMatchObject([
      { path: '.env', gitIgnored: true, gitTracked: false, stagedByAddAll: false },
    ]);
  });

  it('a tracked env file stays covered even when a rule names it', () => {
    git(dir, 'init', '-q');
    write(dir, '.env', 'A=1\n');
    git(dir, 'add', '.env');
    write(dir, '.gitignore', '.env\n');

    expect(collectEnvFileFacts(dir)).toMatchObject([
      { path: '.env', gitIgnored: true, gitTracked: true, stagedByAddAll: true },
    ]);
  });

  it('outside a git work tree the git facts are unknown, not false', () => {
    write(dir, '.env', 'A=1\n');

    expect(collectEnvFileFacts(dir)).toMatchObject([
      { path: '.env', assignments: 1, gitIgnored: null, gitTracked: null, stagedByAddAll: null },
    ]);
  });

  posixOnly('a fsmonitor hook named in the repository config is never executed', () => {
    git(dir, 'init', '-q');
    write(dir, '.env', 'A=1\n');
    git(dir, 'add', '.env');
    const marker = path.join(dir, 'hook-ran');
    const hook = path.join(dir, 'hook.sh');
    fs.writeFileSync(hook, `#!/bin/sh\ntouch '${marker}'\nexit 1\n`, { mode: 0o755 });
    git(dir, 'config', 'core.fsmonitor', hook);

    const facts = collectEnvFileFacts(dir);

    expect(facts[0].gitTracked).toBe(true);
    expect(fs.existsSync(marker)).toBe(false);
  });
});

describe('env-file discovery', () => {
  it('finds nested env files and skips templates, dependency and hidden folders, and symlinks', () => {
    write(dir, '.env.local', 'A=1\n');
    write(dir, '.env.example', 'A=your-key\n');
    write(dir, 'packages/api/.env', 'A=1\n');
    write(dir, 'node_modules/pkg/.env', 'A=1\n');
    write(dir, '.hidden/.env', 'A=1\n');
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-facts-outside-'));
    try {
      write(outside, 'secret.env', 'A=1\n');
      fs.symlinkSync(path.join(outside, 'secret.env'), path.join(dir, '.env.prod'));

      expect(findEnvFiles(dir)).toEqual(['.env.local', 'packages/api/.env']);
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  it('counts assignments with a value and nothing else', () => {
    const content = [
      '# comment', 'A=1', 'export B="x"', 'C=', 'D=""', 'E= # note', '', 'not an assignment', 'F.G-h=val',
    ].join('\n');
    expect(countAssignments(content)).toBe(3);
  });

  it('never carries an env-file value into the facts', () => {
    const values = ['s3cr3t-value-one-9f8e7d', 'postgres://app:FAKEpw-4c3b2a@localhost/app'];
    write(dir, '.env', `ONE=${values[0]}\nDATABASE_URL=${values[1]}\n`);

    const json = JSON.stringify(collectEnvFileFacts(dir));

    expect(json).toContain('"assignments":2');
    for (const v of values) expect(json).not.toContain(v);
  });

  posixOnly('reports the mode as ls -l prints it', () => {
    write(dir, '.env', 'A=1\n');
    fs.chmodSync(path.join(dir, '.env'), 0o644);
    expect(collectEnvFileFacts(dir)[0].mode).toBe('-rw-r--r--');
    fs.chmodSync(path.join(dir, '.env'), 0o600);
    expect(collectEnvFileFacts(dir)[0].mode).toBe('-rw-------');
    expect(symbolicMode(0o100755)).toBe('-rwxr-xr-x');
  });
});

describe('credential scan coverage', () => {
  it('counts placeholders it dropped and names the folders it did not enter', async () => {
    const FAKE_AWS_EXAMPLE_KEY = 'AKIAIOSFODNN7EXAMPLE'; // the documented example key, which the scan treats as a placeholder
    write(dir, 'config.yaml', `aws_access_key_id: ${FAKE_AWS_EXAMPLE_KEY}\n`);
    write(dir, 'node_modules/pkg/index.js', 'module.exports = 1;\n');
    write(dir, '.claude/settings.json', '{}\n');
    write(dir, 'test/a.js', 'x\n');

    const scan = await scanCredentialsWithCoverage(dir);

    expect(scan.matches).toHaveLength(0);
    expect(scan.filesScanned).toBe(1);
    expect(scan.placeholdersSkipped).toBe(1);
    expect(scan.skippedDirs).toEqual(['.claude', 'node_modules', 'test']);
  });
});

describe('guard signing candidates', () => {
  it('lists the guarded files present here that git does not ignore', () => {
    git(dir, 'init', '-q');
    write(dir, 'package.json', '{}\n');
    write(dir, 'tsconfig.json', '{}\n');
    write(dir, 'README.md', '# x\n');
    write(dir, '.gitignore', 'tsconfig.json\n');

    const candidates = defaultSigningFiles(dir);

    expect(candidates).toEqual(['package.json']);
    for (const c of candidates) expect(GUARD_FILES).toContain(c);
  });
});
