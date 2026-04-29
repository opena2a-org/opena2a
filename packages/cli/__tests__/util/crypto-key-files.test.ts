import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { scanCryptoKeyFiles } from '../../src/util/crypto-key-files.js';

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
