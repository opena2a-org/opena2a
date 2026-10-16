import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { ignoreCommand, scanCryptoKeyFiles, untrackCommand } from '../../src/util/crypto-key-files.js';

/** git in `dir` with no hook, signing or user config of the machine running the test. */
function git(dir: string, args: string[]): string {
  return execFileSync('git', [
    '-C', dir,
    '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
    '-c', 'user.name=t', '-c', 'user.email=t@t.invalid',
    ...args,
  ], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
}

/** Does git ignore `rel` in `dir`? `git check-ignore -q` exits 0 when it does. */
function ignored(dir: string, rel: string): boolean {
  try {
    git(dir, ['check-ignore', '-q', '--', rel]);
    return true;
  } catch {
    return false;
  }
}

describe('scanCryptoKeyFiles (#116)', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-keyfiles-'));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('flags .key files as CRITICAL CRED-KEYFILE', () => {
    fs.writeFileSync(path.join(dir, 'fake-private.key'), '-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----');
    const matches = scanCryptoKeyFiles(dir);
    expect(matches).toHaveLength(1);
    expect(matches[0].severity).toBe('critical');
    expect(matches[0].findingId).toBe('CRED-KEYFILE');
    expect(matches[0].title).toContain('Private key');
  });

  it('flags .pem files as CRITICAL', () => {
    fs.writeFileSync(path.join(dir, 'fake-cert.pem'), '-----BEGIN CERTIFICATE-----');
    const matches = scanCryptoKeyFiles(dir);
    expect(matches).toHaveLength(1);
    expect(matches[0].severity).toBe('critical');
  });

  it('flags .p12 and .pfx as CRITICAL', () => {
    fs.writeFileSync(path.join(dir, 'store.p12'), '');
    fs.writeFileSync(path.join(dir, 'store.pfx'), '');
    const matches = scanCryptoKeyFiles(dir);
    expect(matches).toHaveLength(2);
    expect(matches.every(m => m.severity === 'critical')).toBe(true);
  });

  it('flags .crt and .cer as MEDIUM CRED-CERTFILE (public certs are not secrets)', () => {
    fs.writeFileSync(path.join(dir, 'public.crt'), '-----BEGIN CERTIFICATE-----');
    fs.writeFileSync(path.join(dir, 'chain.cer'), '-----BEGIN CERTIFICATE-----');
    const matches = scanCryptoKeyFiles(dir);
    expect(matches).toHaveLength(2);
    expect(matches.every(m => m.severity === 'medium')).toBe(true);
    expect(matches.every(m => m.findingId === 'CRED-CERTFILE')).toBe(true);
  });

  it('ignores files without key/cert extensions', () => {
    fs.writeFileSync(path.join(dir, 'README.md'), '# hi');
    fs.writeFileSync(path.join(dir, 'src.ts'), 'export {}');
    const matches = scanCryptoKeyFiles(dir);
    expect(matches).toHaveLength(0);
  });

  it('does not descend into node_modules / dist / .git', () => {
    fs.mkdirSync(path.join(dir, 'node_modules'));
    fs.writeFileSync(path.join(dir, 'node_modules', 'leaked.key'), 'x');
    fs.mkdirSync(path.join(dir, '.git'));
    fs.writeFileSync(path.join(dir, '.git', 'leaked.pem'), 'x');
    const matches = scanCryptoKeyFiles(dir);
    expect(matches).toHaveLength(0);
  });

  it('descends into normal subdirectories', () => {
    fs.mkdirSync(path.join(dir, 'certs'));
    fs.writeFileSync(path.join(dir, 'certs', 'leaf.key'), '');
    const matches = scanCryptoKeyFiles(dir);
    expect(matches).toHaveLength(1);
    expect(matches[0].filePath.endsWith('leaf.key')).toBe(true);
  });

  it('attaches a clear explanation, businessImpact, and line=1', () => {
    fs.writeFileSync(path.join(dir, 'a.key'), 'x');
    const [m] = scanCryptoKeyFiles(dir);
    expect(m.line).toBe(1);
    expect(typeof m.explanation).toBe('string');
    expect(m.explanation!.length).toBeGreaterThan(20);
    expect(typeof m.businessImpact).toBe('string');
    expect(m.businessImpact!.length).toBeGreaterThan(20);
  });
});

// The explanation states what git measured about the file, and every key
// file has a Fix: `git rm --cached` when git tracks it, an anchored
// .gitignore rule when it does not.
describe('key files and git tracking', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-keyfiles-git-'));
    git(dir, ['init', '-q']);
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('reports a key in a repository with no commit as in the working tree, never as checked into source', () => {
    fs.writeFileSync(path.join(dir, 'x.key'), 'FAKE\n');
    const [m] = scanCryptoKeyFiles(dir);
    expect(m.severity).toBe('critical');
    expect(m.title).toBe('Private key file');
    expect(m.explanation).not.toContain('checked into source');
    expect(m.explanation).toContain('in the working tree, not tracked by git');
  });

  it('reports a key git ignores as not tracked', () => {
    fs.writeFileSync(path.join(dir, '.gitignore'), '*.key\n');
    fs.writeFileSync(path.join(dir, 'x.key'), 'FAKE\n');
    const [m] = scanCryptoKeyFiles(dir);
    expect(m.severity).toBe('critical');
    expect(m.explanation).toContain('in the working tree, not tracked by git');
  });

  it('reports a committed key as tracked by git', () => {
    fs.writeFileSync(path.join(dir, 'x.key'), 'FAKE\n');
    git(dir, ['add', '--', 'x.key']);
    git(dir, ['commit', '-qm', 'x']);
    const [m] = scanCryptoKeyFiles(dir);
    expect(m.severity).toBe('critical');
    expect(m.explanation).toContain('tracked by git');
    expect(m.explanation).not.toContain('not tracked');
    expect(m.explanation).not.toContain('checked into source');
  });

  it('names the store key of the hackmyagent credential vault, still a critical CRED-KEYFILE', () => {
    fs.mkdirSync(path.join(dir, '.opena2a', 'credvault'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.opena2a', 'credvault', 'store.key'), 'FAKE\n');
    const [m] = scanCryptoKeyFiles(dir);
    expect(m.findingId).toBe('CRED-KEYFILE');
    expect(m.severity).toBe('critical');
    expect(m.title).toBe('Vault store key');
    expect(m.explanation).toContain('.opena2a/credvault/');
    expect(m.explanation).toContain('secrets.enc');
    expect(m.explanation).toContain('in the working tree, not tracked by git');
  });

  it('ignoreCommand writes one anchored rule per untracked file, runs as printed and leaves the files on disk', () => {
    // No trailing newline: a bare append would turn `.env` into `.env/x.key`.
    fs.writeFileSync(path.join(dir, '.gitignore'), '.env');
    fs.mkdirSync(path.join(dir, '.opena2a', 'credvault'), { recursive: true });
    const untracked = ['x.key', '.opena2a/credvault/store.key', 'a b*.key'];
    for (const f of [...untracked, 'kept.key', 'a bz.key']) {
      fs.writeFileSync(path.join(dir, f), 'FAKE\n');
    }
    git(dir, ['add', '--', 'kept.key']);
    git(dir, ['commit', '-qm', 'x']);

    // Printed for, and run from, the scanned directory.
    const fix = ignoreCommand(dir, [...untracked, 'kept.key'], dir);
    expect(fix).not.toBeNull();
    expect(fix!.paths).toEqual(['.opena2a/credvault/store.key', 'a b*.key', 'x.key']);
    expect(fix!.command).toBe(
      String.raw`printf '%s\n' '' '/.opena2a/credvault/store.key' '/a b\*.key' '/x.key' >> .gitignore`,
    );
    expect(untrackCommand(dir, [...untracked, 'kept.key'])!.paths).toEqual(['kept.key']);

    execFileSync('sh', ['-c', fix!.command], { cwd: dir, stdio: 'ignore' });
    for (const f of untracked) {
      expect(ignored(dir, f), `${f} is ignored`).toBe(true);
      expect(fs.existsSync(path.join(dir, f)), `${f} stays on disk`).toBe(true);
    }
    expect(ignored(dir, '.env'), 'the last rule before the append still matches').toBe(true);
    expect(ignored(dir, 'a bz.key'), 'the * in a name is literal, not a glob').toBe(false);
  });

  it('ignoreCommand is null when git tracks every file', () => {
    fs.writeFileSync(path.join(dir, 'x.key'), 'FAKE\n');
    git(dir, ['add', '--', 'x.key']);
    expect(ignoreCommand(dir, ['x.key'])).toBeNull();
  });
});
