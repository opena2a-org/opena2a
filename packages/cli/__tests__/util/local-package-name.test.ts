import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readLocalPackageName } from '../../src/util/local-package-name.js';

const dirs: string[] = [];

function project(packageJson?: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'opena2a-pkgname-'));
  dirs.push(dir);
  if (packageJson !== undefined) writeFileSync(join(dir, 'package.json'), packageJson);
  return dir;
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('readLocalPackageName', () => {
  it('returns the name package.json declares', () => {
    expect(readLocalPackageName(project('{"name":"@scope/my-pkg","version":"1.0.0"}'))).toBe('@scope/my-pkg');
  });

  it('returns null with no package.json', () => {
    expect(readLocalPackageName(project())).toBeNull();
  });

  it('returns null when package.json has no usable name', () => {
    expect(readLocalPackageName(project('{"version":"1.0.0"}'))).toBeNull();
    expect(readLocalPackageName(project('{"name":""}'))).toBeNull();
    expect(readLocalPackageName(project('{"name":42}'))).toBeNull();
    expect(readLocalPackageName(project('[]'))).toBeNull();
  });

  it('returns null when package.json does not parse', () => {
    expect(readLocalPackageName(project('{ not json'))).toBeNull();
  });
});
