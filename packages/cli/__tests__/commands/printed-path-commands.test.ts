import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { init, getVerificationCommand, getToolRecommendation } from '../../src/commands/init.js';
import { keyFileRemediation } from '../../src/util/crypto-key-files.js';
import { shellWord } from '../../src/util/shell-word.js';

// Every command the CLI prints with a scanned path in it (a Fix, a Verify,
// the key-file recommendation) is something the user pastes into a shell,
// and the path is a file name the scanned repository chose. These cells run
// each printed command through `sh -c` exactly as printed, in a scratch
// repository whose tracked file names carry `$(...)`, a quote, a space and a
// leading `-`. A double-quoted or bare path runs the `touch CANARY` inside a
// name; the single-quoted shell word does not.

const KEY_FILES = ['server.key', "a b'c.key", '-n2.key', 'x$(touch CANARY).key'];
const CERT_FILE = 'site.crt';
const TEXT_CRED_FILE = 'cred $(touch CANARY);x.ts';
const TEMPLATE_FILE = 'x$(touch CANARY).env.example';
const ALL_FILES = [...KEY_FILES, CERT_FILE, TEXT_CRED_FILE, TEMPLATE_FILE];
const FAKE_ANTHROPIC_KEY = 'sk-ant-api03-' + 'P'.repeat(85);

function git(dir: string, args: string[]): string {
  return execFileSync('git', ['-C', dir, ...args], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
}

function indexed(dir: string): string[] {
  return git(dir, ['ls-files', '-z']).split('\0').filter(Boolean);
}

/** Run a printed command exactly as printed; throws on a non-zero exit. */
function runPrinted(dir: string, command: string): void {
  execFileSync('sh', ['-c', command], { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
}

function captureStdout(fn: () => Promise<number>): Promise<string> {
  const chunks: string[] = [];
  const origWrite = process.stdout.write;
  process.stdout.write = ((chunk: unknown) => { chunks.push(String(chunk)); return true; }) as typeof process.stdout.write;
  return fn().finally(() => { process.stdout.write = origWrite; }).then(() => chunks.join(''));
}

function finding(findingId: string, dir: string, file: string) {
  return {
    findingId,
    title: findingId,
    severity: 'critical',
    count: 1,
    explanation: '',
    businessImpact: '',
    locations: [{ file: path.join(dir, file), line: 1 }],
  };
}

describe('shellWord', () => {
  it('single-quotes every path, plain names included', () => {
    expect(shellWord('server.key')).toBe(`'server.key'`);
    expect(shellWord('dir/a b.key')).toBe(`'dir/a b.key'`);
  });

  it("writes an embedded ' as '\\''", () => {
    expect(shellWord("a b'c.key")).toBe(`'a b'\\''c.key'`);
  });

  it('prefixes ./ when the path begins with -', () => {
    expect(shellWord('-n2.key')).toBe(`'./-n2.key'`);
  });

  it('keeps $(...), backticks and ; literal', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-shellword-'));
    try {
      for (const name of ['x$(touch CANARY).key', 'x`touch CANARY`.key', 'a.key;touch CANARY']) {
        const out = execFileSync('sh', ['-c', `printf '%s' ${shellWord(name)}`], { cwd: dir, encoding: 'utf-8' });
        expect(out).toBe(name);
      }
      expect(fs.existsSync(path.join(dir, 'CANARY'))).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('printed commands over scanned paths run as printed', () => {
  let repo: string;

  beforeEach(() => {
    repo = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-printed-'));
    git(repo, ['init', '-q']);
    for (const f of KEY_FILES) {
      fs.writeFileSync(path.join(repo, f), '-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n');
    }
    fs.writeFileSync(path.join(repo, CERT_FILE), '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n');
    fs.writeFileSync(path.join(repo, TEXT_CRED_FILE), `const k = "${FAKE_ANTHROPIC_KEY}";\n`);
    fs.writeFileSync(path.join(repo, TEMPLATE_FILE), 'ANTHROPIC_API_KEY=FAKE\n');
    git(repo, ['add', '--', ...ALL_FILES]);
  });

  afterEach(() => {
    fs.rmSync(repo, { recursive: true, force: true });
  });

  it('the double-quoted form this replaces runs the name (the cell can go red)', () => {
    runPrinted(repo, `head -1 "x$(touch CANARY).key" || true`);
    expect(fs.existsSync(path.join(repo, 'CANARY'))).toBe(true);
  });

  it('every printed Fix, Verify and the key-file recommendation runs, untracks only, and runs no name', async () => {
    const report = JSON.parse(await captureStdout(() => init({ targetDir: repo, format: 'json' })));

    const keyfile = report.findings.find((f: { findingId: string }) => f.findingId === 'CRED-KEYFILE');
    const certfile = report.findings.find((f: { findingId: string }) => f.findingId === 'CRED-CERTFILE');
    const textCred = report.findings.find((f: { findingId: string }) => f.findingId === 'CRED-001');
    expect(keyfile).toBeDefined();
    expect(certfile).toBeDefined();
    expect(textCred).toBeDefined();

    // The recommendation names every tracked key file in ascending order,
    // each a single-quoted word: no placeholder, no chain, no .gitignore
    // write, no certificate.
    const keyAction = report.actions.find((a: { command: string }) => a.command.startsWith('git rm --cached'));
    expect(keyAction).toBeDefined();
    expect(keyAction.command).toBe(
      `git rm --cached './-n2.key' 'a b'\\''c.key' 'server.key' 'x$(touch CANARY).key'`,
    );
    expect(keyAction.command).not.toMatch(/&&|\|\||;\s|\.gitignore|<file>/);
    expect(keyAction.command).not.toContain(CERT_FILE);
    expect(keyAction.description).toMatch(/^Revoke 4 tracked private keys /);

    // No key or certificate file is offered `opena2a protect`.
    expect(keyfile.fix).toBe(keyAction.command);
    expect(certfile.fix).toBe(`git rm --cached 'site.crt'`);

    const protectFixes = [...KEY_FILES.map(f => ['CRED-KEYFILE', f]), ['CRED-CERTFILE', CERT_FILE]]
      .map(([id, f]) => ({ command: keyFileRemediation(id, f).remediation, paths: [f] }));

    const fixes: { command: string; paths: string[] }[] = [
      { command: keyAction.command, paths: KEY_FILES },
      { command: keyfile.fix, paths: KEY_FILES },
      { command: certfile.fix, paths: [CERT_FILE] },
      ...protectFixes,
    ];
    for (const fix of fixes) {
      git(repo, ['add', '--', ...ALL_FILES]);
      runPrinted(repo, fix.command);
      const index = indexed(repo);
      for (const p of fix.paths) {
        expect(index, `${fix.command} untracks ${p}`).not.toContain(p);
        expect(fs.existsSync(path.join(repo, p)), `${fix.command} leaves ${p} on disk`).toBe(true);
      }
      for (const p of ALL_FILES.filter(f => !fix.paths.includes(f))) {
        expect(index, `${fix.command} leaves ${p} tracked`).toContain(p);
      }
    }

    // CRED- and DRIFT- share the located Verify branch; both are quoted.
    const verifies = [
      keyfile.verify,
      certfile.verify,
      textCred.verify,
      getVerificationCommand(finding('DRIFT-002', repo, TEXT_CRED_FILE), repo),
      getVerificationCommand(finding('ENV-EXAMPLE-LEAK', repo, TEMPLATE_FILE), repo),
    ];
    for (const verify of verifies) {
      expect(typeof verify).toBe('string');
      runPrinted(repo, verify);
    }

    expect(fs.existsSync(path.join(repo, 'CANARY'))).toBe(false);
  });

  it('protect prints the revoke-first note beside the command, never inside it', () => {
    const key = keyFileRemediation('CRED-KEYFILE', 'leak.key');
    expect(key.remediation).toBe(`git rm --cached 'leak.key'`);
    expect(key.remediationNote).toMatch(/^Run after the key is revoked or replaced with the CA or service that issued it/);
    expect(key.remediationNote).toContain('.gitignore');
    const cert = keyFileRemediation('CRED-CERTFILE', 'site.crt');
    expect(cert.remediation).toBe(`git rm --cached 'site.crt'`);
    for (const r of [key.remediation, cert.remediation]) {
      expect(r).not.toMatch(/&&|\|\||;|\.gitignore|rotate/);
    }
  });

  it('emits no key-file recommendation and no Fix when no key file is tracked', async () => {
    git(repo, ['rm', '-q', '--cached', '--', ...KEY_FILES]);
    const report = JSON.parse(await captureStdout(() => init({ targetDir: repo, format: 'json' })));
    expect(report.actions.some((a: { command: string }) => a.command.startsWith('git rm --cached'))).toBe(false);
    const keyfile = report.findings.find((f: { findingId: string }) => f.findingId === 'CRED-KEYFILE');
    expect(keyfile).toBeDefined();
    expect(keyfile.fix).toBeUndefined();
    expect(getToolRecommendation(keyfile, repo)).toBeNull();
  });
});
