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

// The id prefixes of the internal roles, used for their decision ids. A
// charter rule is matched by its shape alone, so a role missing here still
// cannot cite its rules.
const INTERNAL_ROLES = ['CA', 'CCO', 'CDE', 'CDO', 'CDS', 'CISO', 'CPO', 'CRO', 'CSR', 'DPO'];
const INTERNAL_ROLE_PREFIX = `(?:${INTERNAL_ROLES.join('|')})`;

const INTERNAL_REFERENCES: { name: string; pattern: RegExp }[] = [
  { name: 'internal decision log', pattern: /COUNCIL_LEDGER/ },
  { name: 'internal role tag', pattern: /\bCHIEF-[A-Z]{2,4}\b/ },
  { name: 'internal ruling', pattern: /design-function ruling/ },
  // A numbered rule from an internal role's charter, e.g. "Rule 11" cited
  // under a role acronym. Any two to four capitals count, so a new role needs
  // no list entry. "CISO" as a reader ("the CISO scanning the output") stays
  // allowed; only the rule citation is matched.
  { name: 'internal charter rule', pattern: /\b[A-Z]{2,4}[- ][Rr]ule[- ]?\d+\b/ },
  { name: 'private notes file', pattern: /\b(?:feedback|project|reference|user)_[a-z0-9_]+\.md\b/ },
  // A section, mockup, baseline or session of a private planning brief. A
  // reader cannot open the brief: state the behaviour the citation stood for.
  {
    name: 'planning brief citation',
    pattern: /\bbrief (?:§|`|mockups?\b|baseline\b|acceptance\b)|\bper brief\b|\bdivergence brief\b/i,
  },
  { name: 'planning mockup number', pattern: /\bmockup \d/i },
  // The name of an internal measurement environment. A reader has no access
  // to it: state its limits instead (process cap, CPU count).
  { name: 'internal environment name', pattern: /\bfleet[- ]lanes?\b/i },
  { name: 'planning session label', pattern: /\bsession \d+[a-z]?\b/i },
  { name: 'review finding label', pattern: /\bPhase \d+(?:\.\d+)? (?:adversarial review )?finding\b/i },
  // The step number of an internal pre-release review checklist. The CLI's
  // own numbered steps ("Phase 3.5: Update AI tool config files") stay allowed.
  { name: 'review phase label', pattern: /\bPhase ?4\.5\b/i },
  // A file in the registry's source tree, which is not public.
  {
    name: 'private registry file',
    pattern:
      /\bopena2a-registry\/(?:(?:tree|blob)\/[\w.-]+\/)?(?:internal|docs|cmd|migrations|pkg)\/|\bmigration \d{3}\b/i,
  },
];

// A finding number from a private planning brief ("F5", "§F3"). Checked under
// packages/ only: the release-check captures and scripts use F1 and F2 as
// their own cell ids.
const PLANNING_FINDING_ID = /(?<![A-Za-z0-9_#\\-])§?F\d{1,2}\b(?![-.]\w)/;

// A planning file or local checkout path that lives outside this repository,
// e.g. `briefs/<name>.md`, `todo/<date>-<name>.md`, `todo/scripts/<name>.mjs`
// or `~/workspace/...`, or a checkout's local instruction file cited by path
// (`<repo>/CLAUDE.md`), which is never tracked. A reader cannot open any of
// them: state the rule instead.
const PRIVATE_PATH =
  /(?<![A-Za-z0-9_.-])(?:briefs|todo)\/[A-Za-z0-9._/-]+\.(?:md|mjs|js|ts|py|sh)\b|~\/workspace\/|(?<![A-Za-z0-9_.-])[A-Za-z0-9_-]+\/CLAUDE\.md\b/;

// A decision id cited as `[AB-123]`, or as "per / after CA-123" with an
// internal role prefix. Matched by that citation shape, not by any `AB-123`
// token. Only "per" and "after" ignore case; the id itself must be uppercase,
// so prose ("hashed per sha-256", "retried after rfc-822") and public check
// ids ("run after NEMO-009 fires") stay allowed.
const DECISION_ID_CITATION = new RegExp(
  `\\[[A-Z]{2,4}-\\d{3}\\]|(?<![A-Za-z0-9_])(?:[Pp][Ee][Rr]|[Aa][Ff][Tt][Ee][Rr]) ${INTERNAL_ROLE_PREFIX}-\\d{3}(?![A-Za-z0-9])`,
);

// An acceptance criterion of a private plan cited by id: a ticket id followed
// by `.AC` and a number. A reader cannot resolve it: name the behaviour it
// stood for (#388).
const CRITERION_ID = /\b[A-Z]{2,4}-\d+\.AC\d+\b/;

// A ticket of the private tracker cited by id, with or without the hyphen and
// in either case (`QGF-305`, `qgf97-`, `OPA-04`). Checked in test files, test
// fixtures, stored snapshots and vitest configs, which a contributor reads and
// cannot resolve such an id from: name the case or behaviour instead (#388).
const TICKET_ID = /(?<![A-Za-z0-9])(?:QGF|OPA)-?\d+/i;
const TEST_SURFACE = /(?:^|\/)(?:__tests__|__snapshots__|__fixtures__|test-fixtures)\/|\.(?:test|spec)\.[cm]?[jt]sx?$|(?:^|\/)vitest\.[\w.]+\.[cm]?[jt]s$/;

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

  it('no line names an internal decision log, role tag, ruling, notes file, planning brief or registry file', () => {
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

  it('every pattern above still matches the citation shape it was written for', () => {
    const named = (name: string) => INTERNAL_REFERENCES.find((r) => r.name === name)!.pattern;
    expect(named('planning brief citation').test('rules per brief §5.1')).toBe(true);
    expect(named('planning brief citation').test('Covers the brief baseline')).toBe(true);
    expect(named('planning mockup number').test('VERIFIED skill (mockup 3.2)')).toBe(true);
    expect(named('planning session label').test('cli-ui 0.4.0 (session 3)')).toBe(true);
    expect(named('review finding label').test('Phase 3 adversarial review finding HIGH-1')).toBe(true);
    expect(named('internal environment name').test(`measured in the ${['fleet', 'lane'].join(' ')}`)).toBe(true);
    expect(named('internal environment name').test(`(${['fleet', 'lane'].join('-')} census)`)).toBe(true);
    expect(named('review phase label').test('is allowlisted (Phase 4.5 fix)')).toBe(true);
    expect(named('review phase label').test('config bonus (#116/Phase4.5)')).toBe(true);
    expect(named('private registry file').test('opena2a-registry/docs/telemetry-spec.md')).toBe(true);
    expect(named('private registry file').test('stored by migration 223')).toBe(true);
    expect(named('private registry file').test('opena2a-registry/pkg/atcverify')).toBe(true);
    expect(
      named('private registry file').test('github.com/opena2a-org/opena2a-registry/tree/main/pkg/atcverify'),
    ).toBe(true);
    expect(PLANNING_FINDING_ID.test('meter gating (F6)')).toBe(true);
    expect(PLANNING_FINDING_ID.test('git-style misses, §F3')).toBe(true);
    expect(PRIVATE_PATH.test('todo/scripts/own-package-census.mjs')).toBe(true);
    // Assembled from parts, so that a search of the tree for the id shapes
    // lists only real citations.
    const decision = ['CA', '034'].join('-');
    expect(DECISION_ID_CITATION.test(`after ${decision}`)).toBe(true);
    expect(DECISION_ID_CITATION.test(`Per ${decision}, each consumer`)).toBe(true);
    expect(DECISION_ID_CITATION.test(`a rule [${decision}]`)).toBe(true);
    expect(named('internal charter rule').test(`${['CISO', 'Rule'].join('-')}-11`)).toBe(true);
    expect(named('internal charter rule').test('// CXO Rule 4')).toBe(true);
    // Ordinary prose and public references stay allowed.
    expect(named('planning brief citation').test('a brief pause before retrying')).toBe(false);
    expect(named('review phase label').test('// Phase 3.5: Update AI tool config files')).toBe(false);
    expect(named('private registry file').test("repositoryUrl: 'https://github.com/opena2a-org/opena2a-registry'")).toBe(false);
    expect(PLANNING_FINDING_ID.test('color #F59E0B, key 0xF1, F1-score')).toBe(false);
    expect(DECISION_ID_CITATION.test('hashed per sha-256')).toBe(false);
    expect(DECISION_ID_CITATION.test('retried after rfc-822')).toBe(false);
    expect(DECISION_ID_CITATION.test('run after NEMO-009 fires')).toBe(false);
    expect(DECISION_ID_CITATION.test(`after ${decision.toLowerCase()}`)).toBe(false);
    expect(named('internal charter rule').test('the CISO scanning the output')).toBe(false);
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

// A source archive (a release tarball, a GitHub "Download ZIP") has no `.git`,
// so `git ls-files` cannot list the tracked files. The checks then walk the
// directory instead, skipping what the repository's .gitignore files exclude.
const HAS_GIT = fs.existsSync(path.join(REPO_ROOT, '.git'));
const IGNORED_DIRS = new Set(['.git', 'node_modules', 'dist', '.turbo', 'coverage']);
const IGNORED_FILE =
  /^(?:\.DS_Store|\.env|\.env\..*|secrets\.json|\.pre-push-review-passed)$|\.(?:tsbuildinfo|log|pem|key|p12|tgz)$/;

function walkRepo(dir: string, out: string[]): void {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!IGNORED_DIRS.has(entry.name)) walkRepo(full, out);
    } else if (entry.isFile() && !IGNORED_FILE.test(entry.name)) {
      out.push(path.relative(REPO_ROOT, full).split(path.sep).join('/'));
    }
  }
}

function walkedFiles(): string[] {
  const out: string[] = [];
  walkRepo(REPO_ROOT, out);
  return out;
}

function gitFiles(): string[] {
  const out = execFileSync('git', ['ls-files', '-z'], { cwd: REPO_ROOT, encoding: 'utf-8' });
  return out.split('\0').filter((f) => f && fs.existsSync(path.join(REPO_ROOT, f)));
}

function trackedFiles(): string[] {
  if (!HAS_GIT) {
    console.warn(
      `no-internal-references: ${REPO_ROOT} has no .git, so the tracked-file checks walk the directory instead of using git ls-files`,
    );
  }
  return (HAS_GIT ? gitFiles() : walkedFiles()).filter((f) => !BINARY_EXT.test(f) && !GUARD_FILES.has(f));
}

describe('tracked repository files cite no internal references', () => {
  const files = trackedFiles();

  it.runIf(HAS_GIT)('the directory walk used without .git covers every tracked file', () => {
    // The fallback must not narrow the checks: every file git tracks is one
    // the walk would read from a source archive.
    const walked = new Set(walkedFiles());
    const missed = gitFiles().filter((f) => !walked.has(f));
    expect(missed, `the walk skips tracked files:\n${missed.join('\n')}`).toEqual([]);
  });

  it('lists every tracked file, tests and scripts included', () => {
    expect(files).toContain('README.md');
    expect(files).toContain('packages/cli/scripts/release-smoke-corpus.ts');
    expect(files).toContain('packages/telemetry/src/index.test.ts');
  });

  it('no tracked line names an internal role tag, decision id, decision log, ruling, notes file, planning brief or registry file', () => {
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

  it('no tracked line under packages/ cites a planning finding number', () => {
    const hits: string[] = [];
    for (const file of files.filter((f) => f.startsWith('packages/'))) {
      const lines = fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8').split('\n');
      lines.forEach((line, i) => {
        const m = PLANNING_FINDING_ID.exec(line);
        if (m) hits.push(`${file}:${i + 1}: "${m[0]}"`);
      });
    }
    expect(hits, `drop the number and state the behaviour it stood for:\n${hits.join('\n')}`).toEqual([]);
  });

  it('no tracked line cites an acceptance-criterion id, stored snapshot keys included', () => {
    const hits: string[] = [];
    for (const file of files) {
      const lines = fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8').split('\n');
      lines.forEach((line, i) => {
        const m = CRITERION_ID.exec(line);
        if (m) hits.push(`${file}:${i + 1}: "${m[0]}"`);
      });
    }
    expect(hits, `drop the id and name the behaviour it stood for:\n${hits.join('\n')}`).toEqual([]);
  });

  it('no test, test fixture, stored snapshot or vitest config cites a ticket id', () => {
    const surface = files.filter((f) => TEST_SURFACE.test(f));
    // A filter that silently matched nothing would make this pass vacuously.
    expect(surface).toContain('packages/cli/vitest.config.ts');
    expect(surface).toContain('packages/cli-ui/src/__snapshots__/grammar.test.ts.snap');
    expect(surface).toContain('packages/cli/__tests__/child-process-audit.ts');
    expect(surface).toContain('scripts/__tests__/fixtures/fake-npm.mjs');
    const hits: string[] = [];
    for (const file of surface) {
      const lines = fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8').split('\n');
      lines.forEach((line, i) => {
        const m = TICKET_ID.exec(line);
        if (m) hits.push(`${file}:${i + 1}: "${m[0]}"`);
      });
    }
    expect(hits, `drop the id and name the case or behaviour it stood for:\n${hits.join('\n')}`).toEqual([]);
  });

  it('the criterion and ticket checks match the id shapes they were written for', () => {
    // Assembled from parts, so that a search of the tree for the id shapes
    // lists only real citations.
    const id = ['ABC', '01.AC1'].join('-');
    expect(CRITERION_ID.test(`pinned by ${id}`)).toBe(true);
    expect(CRITERION_ID.test('NEMO-009, AC1 and 1.AC1')).toBe(false);
    for (const ticket of [['QGF', '305'].join('-'), ['qgf', '97-exec-'].join(''), `(${['OPA', '04'].join('-')})`]) {
      expect(TICKET_ID.test(ticket), ticket).toBe(true);
    }
    for (const allowed of ['opena2a-qgf-clean', '0.0.0-qgf-smokefail', 'SHIELD-INT-002', 'NEMO-009']) {
      expect(TICKET_ID.test(allowed), allowed).toBe(false);
    }
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
