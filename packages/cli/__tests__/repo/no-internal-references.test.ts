import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

// Every package compiles without `removeComments`, so each comment under
// `packages/*/src` ships verbatim in the published `dist/` (`.js` and
// `.d.ts`), and each package's README.md ships beside it. Those files, and
// the package changelogs, are read by people outside this project. A
// reference to an internal decision log, an internal role tag or a private
// notes file is a citation they cannot open: name the public issue, or state
// the design rule itself (#381).

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const PACKAGES_DIR = path.join(REPO_ROOT, 'packages');

const INTERNAL_REFERENCES: { name: string; pattern: RegExp }[] = [
  { name: 'internal decision log', pattern: /COUNCIL_LEDGER/ },
  { name: 'internal role tag', pattern: /\bCHIEF-[A-Z]{2,4}\b/ },
  { name: 'internal ruling', pattern: /design-function ruling/ },
  { name: 'private notes file', pattern: /\bfeedback_[a-z0-9_]+\.md\b/ },
];

const SOURCE_EXT = /\.(ts|tsx|js|mjs|cjs)$/;
const TEST_FILE = /\.(test|spec)\.[cm]?[jt]sx?$/;
const SKIP_DIRS = new Set(['__tests__', '__snapshots__', 'node_modules', 'dist']);

function walkSources(dir: string, out: string[]): void {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walkSources(full, out);
    } else if (SOURCE_EXT.test(entry.name) && !TEST_FILE.test(entry.name)) {
      out.push(full);
    }
  }
}

function shippedFiles(): string[] {
  const files: string[] = [];
  for (const pkg of fs.readdirSync(PACKAGES_DIR, { withFileTypes: true })) {
    if (!pkg.isDirectory()) continue;
    const root = path.join(PACKAGES_DIR, pkg.name);
    const src = path.join(root, 'src');
    if (fs.existsSync(src)) walkSources(src, files);
    for (const doc of ['README.md', 'CHANGELOG.md']) {
      const p = path.join(root, doc);
      if (fs.existsSync(p)) files.push(p);
    }
  }
  return files;
}

describe('shipped sources and package docs cite no internal references', () => {
  const files = shippedFiles();

  it('walks every package source tree, README and changelog', () => {
    const rel = files.map((f) => path.relative(REPO_ROOT, f).split(path.sep).join('/'));
    // A walker that silently finds nothing would make the check below pass
    // vacuously; pin a few files that must always be in scope.
    expect(rel).toContain('packages/cli/src/index.ts');
    expect(rel).toContain('packages/cli-ui/src/grammar.ts');
    expect(rel).toContain('packages/check-core/README.md');
    expect(rel).toContain('packages/cli-ui/CHANGELOG.md');
    expect(rel.some((f) => /\.test\.ts$|__tests__\//.test(f))).toBe(false);
  });

  it('no line names an internal decision log, role tag, ruling or notes file', () => {
    const hits: string[] = [];
    for (const file of files) {
      const lines = fs.readFileSync(file, 'utf-8').split('\n');
      lines.forEach((line, i) => {
        for (const { name, pattern } of INTERNAL_REFERENCES) {
          const m = pattern.exec(line);
          if (m) {
            const rel = path.relative(REPO_ROOT, file).split(path.sep).join('/');
            hits.push(`${rel}:${i + 1}: ${name} "${m[0]}"`);
          }
        }
      });
    }
    expect(hits, `replace each with the public issue or the rule itself:\n${hits.join('\n')}`).toEqual([]);
  });
});
