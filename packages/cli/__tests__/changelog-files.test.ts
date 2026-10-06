/**
 * opena2a-cli keeps one changelog: the repository-root CHANGELOG.md.
 * packages/cli/CHANGELOG.md is retired. It points to the root file and keeps
 * the history up to 0.10.11. Entries written to it after that were missed at
 * the 0.10.12 and 0.10.13 cuts, so it takes no Unreleased section and no
 * newer version.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const CLI_ROOT = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(CLI_ROOT, '..', '..');

const FILES: Record<string, string> = {
  'CHANGELOG.md': path.join(REPO_ROOT, 'CHANGELOG.md'),
  'packages/cli/CHANGELOG.md': path.join(CLI_ROOT, 'CHANGELOG.md'),
};

function read(rel: string): string {
  return fs.readFileSync(FILES[rel], 'utf-8');
}

/** Every `## ` heading, in file order. */
function releaseHeadings(changelog: string): string[] {
  return changelog.split('\n').filter(l => /^## /.test(l));
}

/** `### ` headings that occur more than once under the same `## ` heading. */
function repeatedSubheadings(changelog: string): string[] {
  const repeated: string[] = [];
  let release = '(before the first release heading)';
  let seen = new Set<string>();
  for (const line of changelog.split('\n')) {
    if (/^## /.test(line)) {
      release = line;
      seen = new Set();
    } else if (/^### /.test(line)) {
      const heading = line.trimEnd();
      if (seen.has(heading)) repeated.push(`${release} > ${heading}`);
      seen.add(heading);
    }
  }
  return repeated;
}

describe('packages/cli/CHANGELOG.md is retired to the root CHANGELOG.md', () => {
  const retired = read('packages/cli/CHANGELOG.md');

  it('its first line links to the repository-root CHANGELOG.md', () => {
    const first = retired.split('\n')[0];
    expect(first).toContain('](../../CHANGELOG.md)');
    expect(fs.existsSync(path.resolve(CLI_ROOT, '../../CHANGELOG.md'))).toBe(true);
  });

  it('carries no Unreleased section', () => {
    expect(releaseHeadings(retired).filter(h => /^## \[?Unreleased/i.test(h))).toEqual([]);
  });

  it('ends its history at 0.10.11', () => {
    expect(releaseHeadings(retired)[0]).toBe('## 0.10.11');
  });
});

describe('no release in a CLI changelog repeats a subsection heading', () => {
  for (const rel of Object.keys(FILES)) {
    it(rel, () => {
      expect(repeatedSubheadings(read(rel))).toEqual([]);
    });
  }
});
