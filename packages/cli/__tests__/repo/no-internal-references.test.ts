import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
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
  // A numbered rule from an internal role's charter, e.g. "Rule 11" cited
  // under a role name. "CISO" as a reader ("the CISO scanning the output")
  // stays allowed; only the rule citation is matched.
  {
    name: 'internal charter rule',
    pattern: /\b(?:CA|CCO|CDE|CDO|CDS|CISO|CPO|CRO|CSR|DPO)[- ][Rr]ule[- ]?\d+\b/,
  },
  { name: 'private notes file', pattern: /\b(?:feedback|project|reference|user)_[a-z0-9_]+\.md\b/ },
];

// A planning file or local checkout path that lives outside this repository,
// e.g. `briefs/<name>.md`, `todo/<date>-<name>.md` or `~/workspace/...`, or
// a checkout's local instruction file cited by path (`<repo>/CLAUDE.md`),
// which is never tracked. A reader cannot open any of them: state the rule
// instead.
const PRIVATE_PATH =
  /(?<![A-Za-z0-9_.-])(?:briefs|todo)\/[A-Za-z0-9._/-]+\.md\b|~\/workspace\/|(?<![A-Za-z0-9_.-])[A-Za-z0-9_-]+\/CLAUDE\.md\b/;

// A decision id cited as `[AB-123]` or "per / after AB-123". Matched by that
// citation shape, not by any `AB-123` token, so public check ids such as
// `NEMO-009` stay allowed.
const DECISION_ID_CITATION = /\[[A-Z]{2,4}-\d{3}\]|(?<![A-Za-z0-9_])(?:per|after) [A-Z]{2,4}-\d{3}(?![A-Za-z0-9])/i;

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

  it('no shipped source, README or changelog cites an internal decision id', () => {
    const hits: string[] = [];
    for (const file of files) {
      const lines = fs.readFileSync(file, 'utf-8').split('\n');
      lines.forEach((line, i) => {
        const m = DECISION_ID_CITATION.exec(line);
        if (m) {
          const rel = path.relative(REPO_ROOT, file).split(path.sep).join('/');
          hits.push(`${rel}:${i + 1}: "${m[0]}"`);
        }
      });
    }
    expect(hits, `drop the id and keep the sentence:\n${hits.join('\n')}`).toEqual([]);
  });

  it('no shipped source, README or changelog points to a private planning file or local path', () => {
    const hits: string[] = [];
    for (const file of files) {
      const lines = fs.readFileSync(file, 'utf-8').split('\n');
      lines.forEach((line, i) => {
        const m = PRIVATE_PATH.exec(line);
        if (m) {
          const rel = path.relative(REPO_ROOT, file).split(path.sep).join('/');
          hits.push(`${rel}:${i + 1}: "${m[0]}"`);
        }
      });
    }
    expect(hits, `replace the path with the rule it points to:\n${hits.join('\n')}`).toEqual([]);
  });
});

// The repository is public as well: test files, release scripts, docs and
// workflows never reach a package but are read by every contributor. Each
// tracked file is held to the same rule. The two guard files below name the
// forbidden tokens in order to reject them and are the only exceptions.
const GUARD_FILES = new Set([
  'packages/cli/__tests__/repo/no-internal-references.test.ts',
  'packages/cli/__tests__/child-env-policy.test.ts',
]);
const BINARY_EXT = /\.(gif|png|jpe?g|ico|woff2?|tgz|gz|zip)$/i;

function trackedFiles(): string[] {
  const out = execFileSync('git', ['ls-files', '-z'], { cwd: REPO_ROOT, encoding: 'utf-8' });
  return out
    .split('\0')
    .filter((f) => f && !BINARY_EXT.test(f) && !GUARD_FILES.has(f))
    .filter((f) => fs.existsSync(path.join(REPO_ROOT, f)));
}

describe('tracked repository files cite no internal references', () => {
  const files = trackedFiles();

  it('lists every tracked file, tests and scripts included', () => {
    expect(files).toContain('README.md');
    expect(files).toContain('packages/cli/scripts/release-smoke-corpus.ts');
    expect(files).toContain('packages/telemetry/src/index.test.ts');
  });

  it('no tracked line names an internal role tag, decision id, decision log, ruling or notes file', () => {
    const hits: string[] = [];
    for (const file of files) {
      const lines = fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8').split('\n');
      lines.forEach((line, i) => {
        for (const { name, pattern } of INTERNAL_REFERENCES) {
          const m = pattern.exec(line);
          if (m) hits.push(`${file}:${i + 1}: ${name} "${m[0]}"`);
        }
        const m = DECISION_ID_CITATION.exec(line);
        if (m) hits.push(`${file}:${i + 1}: decision id "${m[0]}"`);
      });
    }
    expect(hits, `drop the tag or id and keep the sentence:\n${hits.join('\n')}`).toEqual([]);
  });

  it('no tracked line points to a private planning file or local path', () => {
    const hits: string[] = [];
    for (const file of files) {
      const lines = fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8').split('\n');
      lines.forEach((line, i) => {
        const m = PRIVATE_PATH.exec(line);
        if (m) hits.push(`${file}:${i + 1}: "${m[0]}"`);
      });
    }
    expect(hits, `replace the path with the rule it points to:\n${hits.join('\n')}`).toEqual([]);
  });
});
