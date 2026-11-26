/**
 * `signConfigFilesSilent` (used by `protect` and `shield init`) follows the
 * consent rule of `guard sign`: a signed file whose contents changed is not
 * re-signed without consent. These flows do not prompt, so the changed file
 * keeps its stored entry, stays reported as tampered, and is listed with the
 * command that re-signs it. Before this, `protect` or `shield init` replaced
 * the signature of any changed file, so a change nobody confirmed became the
 * new baseline.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => _mockHomeDir };
});

const { signConfigFilesSilent, guard } = await import('../../src/commands/guard.js');

let tempHome: string;
let targetDir: string;
let storePath: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'guard-silent-sign-home-'));
  targetDir = fs.mkdtempSync(path.join(tmpdir(), 'guard-silent-sign-target-'));
  storePath = path.join(targetDir, '.opena2a/guard/signatures.json');
  _mockHomeDir = tempHome;
});

afterEach(() => {
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(targetDir, { recursive: true, force: true });
});

function storedHashes(): Record<string, string> {
  const store = JSON.parse(fs.readFileSync(storePath, 'utf-8')) as { signatures: { filePath: string; hash: string }[] };
  return Object.fromEntries(store.signatures.map(s => [s.filePath, s.hash]));
}

function capture(): { out: string[]; err: string[]; restore: () => void } {
  const out: string[] = [];
  const err: string[] = [];
  const outSpy = vi.spyOn(process.stdout, 'write').mockImplementation((c: any) => { out.push(String(c)); return true; });
  const errSpy = vi.spyOn(process.stderr, 'write').mockImplementation((c: any) => { err.push(String(c)); return true; });
  return { out, err, restore: () => { outSpy.mockRestore(); errSpy.mockRestore(); } };
}

describe('signConfigFilesSilent consent', () => {
  it('signs every file when there is no store yet', async () => {
    fs.writeFileSync(path.join(targetDir, 'package.json'), '{"name":"a"}\n');
    const result = await signConfigFilesSilent(targetDir);
    expect(result.signed).toBe(1);
    expect(result.files).toEqual(['package.json']);
    expect(result.kept).toEqual([]);
  });

  it('keeps the stored signature of a changed signed file and signs the rest', async () => {
    fs.writeFileSync(path.join(targetDir, 'package.json'), '{"name":"a"}\n');
    await signConfigFilesSilent(targetDir);
    const before = storedHashes();

    fs.writeFileSync(path.join(targetDir, 'package.json'), '{"name":"a","scripts":{"postinstall":"x"}}\n');
    fs.writeFileSync(path.join(targetDir, 'tsconfig.json'), '{}\n');
    const result = await signConfigFilesSilent(targetDir);

    expect(result.kept.map(k => k.filePath)).toEqual(['package.json']);
    expect(result.files).toEqual(['tsconfig.json']);
    expect(result.signed).toBe(1);
    const after = storedHashes();
    expect(after['package.json']).toBe(before['package.json']);
    expect(after['tsconfig.json']).toMatch(/^sha256:/);
  });

  it('leaves the change reported as tampered by guard verify', async () => {
    fs.writeFileSync(path.join(targetDir, 'package.json'), '{"name":"a"}\n');
    await signConfigFilesSilent(targetDir);
    fs.writeFileSync(path.join(targetDir, 'package.json'), '{"name":"b"}\n');
    await signConfigFilesSilent(targetDir);

    const io = capture();
    let exitCode: number;
    try { exitCode = await guard({ subcommand: 'verify', targetDir, format: 'json' }); }
    finally { io.restore(); }
    expect(exitCode).not.toBe(0);
    const report = JSON.parse(io.out.join('')) as { results: { filePath: string; status: string }[] };
    expect(report.results.find(r => r.filePath === 'package.json')?.status).toBe('tampered');
  });

  it('does not write the store when every signed file changed', async () => {
    fs.writeFileSync(path.join(targetDir, 'package.json'), '{"name":"a"}\n');
    await signConfigFilesSilent(targetDir);
    const raw = fs.readFileSync(storePath, 'utf-8');
    fs.writeFileSync(path.join(targetDir, 'package.json'), '{"name":"b"}\n');

    const result = await signConfigFilesSilent(targetDir);
    expect(result.signed).toBe(0);
    expect(result.kept.map(k => k.filePath)).toEqual(['package.json']);
    expect(fs.readFileSync(storePath, 'utf-8')).toBe(raw);
  });

  it('reports the kept files on the stream asked for, and is quiet otherwise', async () => {
    fs.writeFileSync(path.join(targetDir, 'package.json'), '{"name":"a"}\n');
    await signConfigFilesSilent(targetDir);
    fs.writeFileSync(path.join(targetDir, 'package.json'), '{"name":"ab"}\n');

    let io = capture();
    try { await signConfigFilesSilent(targetDir); } finally { io.restore(); }
    expect(io.out.join('') + io.err.join('')).toBe('');

    io = capture();
    try { await signConfigFilesSilent(targetDir, { report: 'stderr' }); } finally { io.restore(); }
    expect(io.out.join('')).toBe('');
    const err = io.err.join('');
    expect(err).toContain('Not re-signed');
    expect(err).toContain('CHANGED package.json (+1b)');
    expect(err).toContain('opena2a guard resign');

    io = capture();
    try { await signConfigFilesSilent(targetDir, { report: 'stdout' }); } finally { io.restore(); }
    expect(io.out.join('')).toContain('CHANGED package.json');
    expect(io.err.join('')).toBe('');
  });
});
