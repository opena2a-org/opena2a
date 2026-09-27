import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { generateKeyPairSync } from 'node:crypto';
import { scanCryptoKeyFiles, scanEmbeddedPrivateKeys } from '../../src/util/crypto-key-files.js';

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

describe('scanEmbeddedPrivateKeys (#270)', () => {
  let dir: string;
  // Real key material, generated per run: the scanner has to recognise an
  // actual key body, and a hard-coded key would be a fixture in its own right.
  const rsaPem = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  }).privateKey;
  const ecPem = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  }).privateKey;
  const bodyOf = (pem: string) => pem.split('\n').filter(l => l && !l.startsWith('-----'));
  // Armor lines are assembled at runtime so this file carries no literal
  // key-block header for secret scanners to trip on.
  const armor = (edge: 'BEGIN' | 'END', label: string) => `-----${edge} ${label}-----`;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-embedded-key-'));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('flags a multi-line RSA key in a template literal, at the BEGIN line', () => {
    fs.writeFileSync(path.join(dir, 'app.js'), `// config\nconst key = \`${rsaPem}\`;\n`);
    const matches = scanEmbeddedPrivateKeys(dir);
    expect(matches).toHaveLength(1);
    expect(matches[0]).toMatchObject({
      findingId: 'CRED-KEYEMBED',
      severity: 'critical',
      line: 2,
      value: 'RSA PRIVATE KEY',
    });
    // No field carries key material.
    const serialised = JSON.stringify(matches);
    for (const bodyLine of bodyOf(rsaPem)) expect(serialised).not.toContain(bodyLine);
  });

  it('flags a key written with escaped newlines in a one-line string', () => {
    const oneLine = JSON.stringify({ privateKey: ecPem });
    fs.writeFileSync(path.join(dir, 'settings.json'), oneLine);
    const matches = scanEmbeddedPrivateKeys(dir);
    expect(matches).toHaveLength(1);
    expect(matches[0].value).toBe('PRIVATE KEY');
    expect(matches[0].line).toBe(1);
  });

  it('flags OpenSSH and PGP armor labels', () => {
    const body = 'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW';
    fs.writeFileSync(path.join(dir, 'deploy.sh'),
      `cat > id <<EOF\n${armor('BEGIN', 'OPENSSH PRIVATE KEY')}\n${body}\n${armor('END', 'OPENSSH PRIVATE KEY')}\nEOF\n`);
    fs.writeFileSync(path.join(dir, 'notes.txt'),
      `${armor('BEGIN', 'PGP PRIVATE KEY BLOCK')}\n\nlQOYBGXk${body}\n${armor('END', 'PGP PRIVATE KEY BLOCK')}\n`);
    const labels = scanEmbeddedPrivateKeys(dir).map(m => m.value).sort();
    expect(labels).toEqual(['OPENSSH PRIVATE KEY', 'PGP PRIVATE KEY BLOCK']);
  });

  it('does not flag armor without key material (docs, placeholders, headers alone)', () => {
    fs.writeFileSync(path.join(dir, 'README.md'),
      `Paste your key between ${armor('BEGIN', 'RSA PRIVATE KEY')} and ${armor('END', 'RSA PRIVATE KEY')} markers.\n`);
    fs.writeFileSync(path.join(dir, 'fixture.ts'),
      `const k = '${armor('BEGIN', 'PRIVATE KEY')}\\nFAKE\\n${armor('END', 'PRIVATE KEY')}';\n` +
      `const p = '${armor('BEGIN', 'EC PRIVATE KEY')}\\nMIIEowIBAAKCAQEA...\\n${armor('END', 'EC PRIVATE KEY')}';\n`);
    fs.writeFileSync(path.join(dir, 'regex.ts'), 'const re = /-----BEGIN (RSA )?PRIVATE KEY-----/;\n');
    expect(scanEmbeddedPrivateKeys(dir)).toEqual([]);
  });

  it('does not flag a BEGIN with no matching END', () => {
    fs.writeFileSync(path.join(dir, 'truncated.js'), rsaPem.split('-----END')[0]);
    expect(scanEmbeddedPrivateKeys(dir)).toEqual([]);
  });

  it('reports two keys in one file separately', () => {
    fs.writeFileSync(path.join(dir, 'keys.py'), `A = """${rsaPem}"""\nB = """${ecPem}"""\n`);
    const matches = scanEmbeddedPrivateKeys(dir);
    expect(matches.map(m => m.value)).toEqual(['RSA PRIVATE KEY', 'PRIVATE KEY']);
    expect(matches[1].line).toBeGreaterThan(matches[0].line);
  });

  it('is included in scanCryptoKeyFiles, and a .pem key file is reported once, by file type', () => {
    fs.writeFileSync(path.join(dir, 'server.pem'), rsaPem);
    fs.writeFileSync(path.join(dir, 'app.ts'), `export const key = \`${ecPem}\`;\n`);
    const ids = scanCryptoKeyFiles(dir).map(m => `${m.findingId}:${path.basename(m.filePath)}`).sort();
    expect(ids).toEqual(['CRED-KEYEMBED:app.ts', 'CRED-KEYFILE:server.pem']);
  });
});
