/**
 * programOnPath looks a program up in PATH's absolute directories only, and
 * absolutePathDirs drops every empty or relative entry. No child process is
 * started; every file is written at run time into an `mkdtemp` directory.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';

import { absolutePathDirs, programOnPath } from '../../src/util/program-on-path.js';

let root: string;

function executable(dir: string, name: string): string {
  const p = join(dir, name);
  writeFileSync(p, '#!/bin/sh\necho hi\n');
  chmodSync(p, 0o755);
  return p;
}

function pathEnv(value: string): NodeJS.ProcessEnv {
  return { PATH: value };
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'program-on-path-'));
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('programOnPath', () => {
  it('returns the absolute path of an executable regular file in an absolute PATH directory', () => {
    const absoluteDir = join(root, 'absolute');
    mkdirSync(absoluteDir);
    const kubectl = executable(absoluteDir, 'kubectl');
    expect(programOnPath('kubectl', pathEnv(absoluteDir))).toBe(kubectl);
  });

  it('returns the first match in PATH order', () => {
    const first = join(root, 'first');
    const second = join(root, 'second');
    mkdirSync(first);
    mkdirSync(second);
    const inFirst = executable(first, 'gh');
    executable(second, 'gh');
    expect(programOnPath('gh', pathEnv(`${first}${delimiter}${second}`))).toBe(inFirst);
  });

  it('skips a relative PATH entry (`.`, a bare name, node_modules/.bin)', () => {
    for (const relative of ['.', 'bin', join('node_modules', '.bin')]) {
      // Planted under the relative entry, but relative entries are not searched.
      const planted = join(root, relative);
      mkdirSync(planted, { recursive: true });
      executable(planted, 'terraform');
      expect(programOnPath('terraform', pathEnv(relative))).toBeNull();
    }
  });

  it('skips the empty entry a leading, trailing or doubled separator leaves', () => {
    const absoluteDir = join(root, 'absolute');
    mkdirSync(absoluteDir);
    for (const path of [`${delimiter}${absoluteDir}`, `${absoluteDir}${delimiter}`, `${absoluteDir}${delimiter}${delimiter}${absoluteDir}`]) {
      const found = programOnPath('aws', pathEnv(path));
      // No `aws` anywhere, so null — the point is the empty entry does not throw
      // and is not resolved against the working directory.
      expect(found).toBeNull();
    }
  });

  it('returns null when no absolute directory holds the program', () => {
    const absoluteDir = join(root, 'absolute');
    mkdirSync(absoluteDir);
    expect(programOnPath('vercel', pathEnv(absoluteDir))).toBeNull();
  });

  it('ignores a non-executable file and a directory that share the name', () => {
    const notExecutable = join(root, 'not-exec');
    const isDirectory = join(root, 'is-dir');
    mkdirSync(notExecutable);
    mkdirSync(isDirectory);
    writeFileSync(join(notExecutable, 'gcloud'), 'not executable\n'); // mode 0644
    mkdirSync(join(isDirectory, 'gcloud')); // a directory named gcloud
    expect(programOnPath('gcloud', pathEnv(`${notExecutable}${delimiter}${isDirectory}`))).toBeNull();
  });

  it('follows a symlink to an executable regular file', () => {
    const target = join(root, 'target');
    const linkDir = join(root, 'link');
    mkdirSync(target);
    mkdirSync(linkDir);
    const real = executable(target, 'az-real');
    symlinkSync(real, join(linkDir, 'az'));
    expect(programOnPath('az', pathEnv(linkDir))).toBe(join(linkDir, 'az'));
  });

  it('returns null for an empty or unset PATH', () => {
    expect(programOnPath('gh', pathEnv(''))).toBeNull();
    expect(programOnPath('gh', {})).toBeNull();
  });
});

describe('absolutePathDirs', () => {
  it('keeps only the absolute directories, in order, and drops empty and relative entries', () => {
    const a = join(root, 'a');
    const b = join(root, 'b');
    const input = `${a}${delimiter}.${delimiter}bin${delimiter}${delimiter}${b}${delimiter}node_modules/.bin`;
    expect(absolutePathDirs(pathEnv(input))).toBe(`${a}${delimiter}${b}`);
  });

  it('is empty when PATH holds no absolute directory', () => {
    expect(absolutePathDirs(pathEnv(`.${delimiter}bin`))).toBe('');
    expect(absolutePathDirs({})).toBe('');
  });
});
