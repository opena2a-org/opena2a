import { describe, it, expect, vi, beforeEach, afterEach, afterAll } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { protect } from '../../src/commands/protect.js';
import { collectPemPrivateKeyMatches, type CredentialMatch } from '../../src/util/credential-patterns.js';

/**
 * PEM private key blocks embedded in source (CRED-PEM).
 *
 * Same sandbox as protect.test.ts: a throwaway HOME and `security` /
 * `secret-tool` stubs that exit 1, so nothing reaches the developer's keychain,
 * vault or shell profile. A PEM finding must not reach them anyway -- protect
 * reports it and leaves the move to the user -- and the tests check that.
 */
const sandbox = await vi.hoisted(async () => {
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-protect-pem-home-'));
  const home = path.join(root, 'home');
  const bin = path.join(root, 'bin');
  fs.mkdirSync(home);
  fs.mkdirSync(bin);
  for (const tool of ['security', 'secret-tool']) {
    fs.writeFileSync(path.join(bin, tool), '#!/bin/sh\nexit 1\n');
    fs.chmodSync(path.join(bin, tool), 0o755);
  }
  const keys = ['HOME', 'USERPROFILE', 'XDG_CONFIG_HOME', 'PATH'] as const;
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  process.env.XDG_CONFIG_HOME = path.join(home, '.config');
  process.env.PATH = `${bin}${path.delimiter}${process.env.PATH ?? ''}`;
  return { root, home, saved };
});

afterAll(() => {
  for (const [key, value] of Object.entries(sandbox.saved)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  fs.rmSync(sandbox.root, { recursive: true, force: true });
});

// Generated at run time so no key material is committed to the repository.
const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
const RSA_PKCS1 = privateKey.export({ type: 'pkcs1', format: 'pem' }).toString().trim();
const PKCS8 = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString().trim();
const BODY = RSA_PKCS1.split('\n').slice(1, -1).join('\n');

function block(label: string, body = BODY): string {
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
}

function scan(content: string, fileName = 'a.js'): CredentialMatch[] {
  const matches: CredentialMatch[] = [];
  collectPemPrivateKeyMatches(content, `/project/${fileName}`, new Set(), matches);
  return matches;
}

describe('collectPemPrivateKeyMatches', () => {
  it('finds an RSA key in a template literal, on the header line', () => {
    const matches = scan(`// config\nconst k = \`${RSA_PKCS1}\`;\n`);
    expect(matches).toHaveLength(1);
    expect(matches[0]).toMatchObject({
      findingId: 'CRED-PEM',
      line: 2,
      severity: 'critical',
      title: 'PEM RSA PRIVATE KEY',
      envVar: 'PRIVATE_KEY',
      value: RSA_PKCS1,
    });
  });

  it('finds a bare PKCS#8 key', () => {
    const matches = scan(`const k = \`${PKCS8}\`;\n`);
    expect(matches.map(m => m.title)).toEqual(['PEM PRIVATE KEY']);
  });

  it.each([
    'EC PRIVATE KEY',
    'OPENSSH PRIVATE KEY',
    'DSA PRIVATE KEY',
    'ENCRYPTED PRIVATE KEY',
    'PGP PRIVATE KEY',
    'PGP PRIVATE KEY BLOCK',
  ])('finds a %s block', (label) => {
    expect(scan(`key = """\n${block(label)}\n"""\n`, 'a.py').map(m => m.title)).toEqual([`PEM ${label}`]);
  });

  it('finds a key written on one line with \\n escapes', () => {
    const oneLine = RSA_PKCS1.split('\n').join('\\n');
    const matches = scan(`{\n  "private_key": "${oneLine}"\n}\n`, 'sa.json');
    expect(matches).toHaveLength(1);
    expect(matches[0].line).toBe(2);
  });

  it('numbers a second key in the same file', () => {
    const matches = scan(`a = \`${RSA_PKCS1}\`;\nb = \`${PKCS8}\`;\n`);
    expect(matches.map(m => m.envVar)).toEqual(['PRIVATE_KEY', 'PRIVATE_KEY_2']);
  });

  it.each([
    ['a truncated body', block('RSA PRIVATE KEY', 'MIIEpAIBAAKCAQEA...')],
    ['a placeholder body', block('PRIVATE KEY', '<your private key here>')],
    ['a low-entropy filler', block('PRIVATE KEY', 'A'.repeat(64) + '\n' + 'B'.repeat(64))],
    ['a public key', block('PUBLIC KEY')],
    ['a certificate', block('CERTIFICATE')],
    ['a header without a footer', `-----BEGIN RSA PRIVATE KEY-----\n${BODY}\n`],
    ['mismatched header and footer', `-----BEGIN RSA PRIVATE KEY-----\n${BODY}\n-----END EC PRIVATE KEY-----`],
  ])('ignores %s', (_name, content) => {
    expect(scan(`const k = \`${content}\`;\n`)).toEqual([]);
  });

  it('leaves .pem and .key files to the key-file scanner', () => {
    expect(scan(RSA_PKCS1 + '\n', 'server.pem')).toEqual([]);
    expect(scan(RSA_PKCS1 + '\n', 'server.key')).toEqual([]);
  });
});

describe('protect with a PEM private key in source', () => {
  let tempDir: string;
  let file: string;
  let source: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-protect-pem-'));
    file = path.join(tempDir, 'a.js');
    source = `const k = \`${RSA_PKCS1}\`;\nmodule.exports = k;\n`;
    fs.writeFileSync(file, source);
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  async function run(opts: { format?: 'json' }): Promise<{ code: number; out: string }> {
    const chunks: string[] = [];
    const origOut = process.stdout.write;
    const origErr = process.stderr.write;
    process.stdout.write = ((chunk: unknown) => { chunks.push(String(chunk)); return true; }) as typeof process.stdout.write;
    process.stderr.write = (() => true) as typeof process.stderr.write;
    try {
      const code = await protect({ targetDir: tempDir, ci: true, skipSign: true, skipGit: true, ...opts });
      return { code, out: chunks.join('') };
    } finally {
      process.stdout.write = origOut;
      process.stderr.write = origErr;
    }
  }

  it('reports the key, leaves it for the user to move, and exits 1 under --ci', async () => {
    const { code, out } = await run({});
    expect(out).toContain('CRED-PEM');
    expect(out).toContain('PEM RSA PRIVATE KEY');
    expect(out).toContain('a.js:1');
    expect(out).toContain('MANUAL');
    expect(out).toContain('PRIVATE_KEY_FILE');
    expect(out).not.toContain('No hardcoded credentials detected');
    expect(code).toBe(1);

    // Not rewritten, not stored anywhere under HOME, no shell-profile export.
    expect(fs.readFileSync(file, 'utf-8')).toBe(source);
    for (const profile of ['.zshrc', '.bashrc']) {
      const p = path.join(sandbox.home, profile);
      if (fs.existsSync(p)) expect(fs.readFileSync(p, 'utf-8')).not.toContain('PRIVATE KEY');
    }
  });

  it('marks the result manual in JSON and still counts the key in the after-score', async () => {
    const { out } = await run({ format: 'json' });
    const report = JSON.parse(out);
    expect(report.totalFound).toBe(1);
    expect(report.migrated).toBe(0);
    expect(report.skipped).toBe(1);
    expect(report.results[0].credential.findingId).toBe('CRED-PEM');
    expect(report.results[0].stored).toBe(false);
    expect(report.results[0].manual).toContain('outside the repository');
    expect(report.scoreAfter).toBeLessThanOrEqual(report.scoreBefore);
  });
});
