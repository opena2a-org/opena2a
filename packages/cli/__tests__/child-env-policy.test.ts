/**
 * The parts of the #246 ruling that live outside src/: the CHANGELOG entry,
 * the ignore files, and the dev scripts' declared shapes.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const CLI_ROOT = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(CLI_ROOT, '..', '..');

function read(rel: string): string {
  return fs.readFileSync(path.join(REPO_ROOT, rel), 'utf-8');
}

/** `### Security` bullets of the section directly above `## [<prior>]`. For #246, prior is 0.10.13, the last release
 * cut before db035b8c: the section is [Unreleased] before the release cut and that release's own section after it. */
function securityEntriesAbove(changelog: string, prior: string): string[] {
  const lines = changelog.split('\n');
  const end = lines.findIndex(l => l.startsWith(`## [${prior}]`));
  const start = lines.slice(0, Math.max(end, 0)).map(l => /^## /.test(l)).lastIndexOf(true);
  expect(start, `CHANGELOG has a [${prior}] section and a section above it`).toBeGreaterThanOrEqual(0);
  const section = lines.slice(start + 1, end);
  const secStart = section.findIndex(l => /^### Security/.test(l));
  expect(secStart, `the section above [${prior}] has a ### Security subsection`).toBeGreaterThanOrEqual(0);
  let secEnd = section.findIndex((l, i) => i > secStart && /^### /.test(l));
  if (secEnd === -1) secEnd = section.length;
  const entries: string[] = [];
  for (const line of section.slice(secStart + 1, secEnd)) {
    if (/^- /.test(line)) entries.push(line);
    else if (entries.length > 0 && line.trim() !== '') entries[entries.length - 1] += `\n${line}`;
  }
  return entries;
}

describe('CHANGELOG Security entry (#246)', () => {
  const changelog = read('CHANGELOG.md');
  const closing = securityEntriesAbove(changelog, '0.10.13').filter(e => e.includes('Closes #246'));

  it('one Security entry of the first release after 0.10.13 closes #246, and no other line does', () => {
    expect([closing.length, changelog.split('\n').filter(l => l.includes('Closes #246')).length]).toEqual([1, 1]);
  });

  it('the entry names the sites by path and the children as objects', () => {
    const entry = closing[0];
    for (const site of [
      'packages/cli/src/index.ts', 'router.ts', 'shield/llm-backend.ts',
      'adapters/spawn.ts', 'python.ts', 'docker.ts',
    ]) {
      expect(entry, site).toContain(site);
    }
    expect(entry).toMatch(/delegated scanner/);
    expect(entry).toMatch(/model CLI/);
  });

  it('the entry states the exposure window, the declared names, the widening path and the cap', () => {
    const entry = closing[0];
    expect(entry).toMatch(/full environment/);
    expect(entry).toMatch(/every release since/i);
    // The first release carrying each site, named.
    expect(entry).toMatch(/\b0\.\d+\.\d+\b/);
    expect(entry).toContain('NANOMIND_URL');
    expect(entry).toContain('ANTHROPIC_API_KEY');
    expect(entry).toContain('OPENA2A_CHILD_ENV_ALLOW');
    expect(entry).toMatch(/200-file cap/);
    expect(entry).toMatch(/partial/);
    expect(entry).toMatch(/Closes #246/);
  });

  it('the entry carries no internal artifact path or governance tag', () => {
    const entry = closing[0];
    expect(entry).not.toMatch(/\.qgf|qgf\/|COUNCIL_LEDGER|roadmap\/|\[CHIEF-|CISO|OPA-14/);
  });
});

describe('ignore files and dev scripts (#246)', () => {
  it('no root .hmaignore rule names a path under packages/cli/src, and packages/cli/.hmaignore is absent', () => {
    const root = path.join(REPO_ROOT, '.hmaignore');
    if (fs.existsSync(root)) {
      const rules = fs.readFileSync(root, 'utf-8').split('\n')
        .map(l => l.trim())
        .filter(l => l !== '' && !l.startsWith('#'));
      for (const rule of rules) {
        expect(rule, `root .hmaignore rule "${rule}" must not cover shipped source`)
          .not.toMatch(/^!?\/?packages\/cli\/src(\/|$)/);
      }
    }
    expect(fs.existsSync(path.join(CLI_ROOT, '.hmaignore')), 'packages/cli/.hmaignore is retired').toBe(false);
  });

  it('shield-lock-trace-loop.ts hands its vitest run lockTraceSuiteEnv instead of spreading process.env (#397)', () => {
    const text = read('packages/cli/scripts/shield-lock-trace-loop.ts');
    expect(text).not.toContain('...process.env');
    expect(text).toMatch(/env: lockTraceSuiteEnv\(traceFile\b/);
  });

  it('release-smoke-corpus.ts keeps its spread, under a comment stating both sides get the identical environment by design', () => {
    const lines = read('packages/cli/scripts/release-smoke-corpus.ts').split('\n');
    const idx = lines.findIndex(l => /const env = \{ \.\.\.process\.env, OPENA2A_CORPUS_DETERMINISTIC: '1' \};/.test(l));
    expect(idx).toBeGreaterThan(0);
    // The comment block directly above the spread.
    let i = idx - 1;
    const comment: string[] = [];
    while (i >= 0 && /^\s*\/\//.test(lines[i])) { comment.unshift(lines[i]); i--; }
    expect(comment.length).toBeGreaterThan(0);
    expect(comment.join(' ')).toMatch(/both sides of the parity run receive the identical environment by design/i);
  });

  it('the benchmark, comply and init harnesses feed their spread to buildChildEnv', () => {
    for (const [file, line] of [
      ['packages/cli/scripts/release-smoke-benchmark.ts', 69],
      ['packages/cli/scripts/release-smoke-comply.ts', 72],
      ['packages/cli/scripts/release-smoke-init.ts', 82],
    ] as const) {
      const text = read(file).split('\n')[line - 1];
      expect(text, `${file}:${line}`).toMatch(/buildChildEnv\(.*\{ \.\.\.process\.env/);
    }
  });
});
