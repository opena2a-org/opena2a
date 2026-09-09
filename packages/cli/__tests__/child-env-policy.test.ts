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

/** Bullet entries of the `### Security` subsection under `## [Unreleased]`. */
function unreleasedSecurityEntries(changelog: string): string[] {
  const lines = changelog.split('\n');
  const start = lines.findIndex(l => /^## \[Unreleased\]/.test(l));
  expect(start, 'CHANGELOG has an [Unreleased] section').toBeGreaterThanOrEqual(0);
  let end = lines.findIndex((l, i) => i > start && /^## \[/.test(l));
  if (end === -1) end = lines.length;
  const section = lines.slice(start + 1, end);
  const secStart = section.findIndex(l => /^### Security/.test(l));
  expect(secStart, '[Unreleased] has a ### Security subsection').toBeGreaterThanOrEqual(0);
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
  const entries = unreleasedSecurityEntries(read('CHANGELOG.md'));
  const closing = entries.filter(e => e.includes('Closes #246'));

  it('OPA-14.AC8 one Unreleased Security entry closes #246', () => {
    expect(closing).toHaveLength(1);
  });

  it('OPA-14.AC8 the entry names the sites by path and the children as objects', () => {
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

  it('OPA-14.AC8 the entry states the exposure window, the declared names, the widening path and the cap', () => {
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

  it('OPA-14.AC8 the entry carries no internal artifact path or governance tag', () => {
    const entry = closing[0];
    expect(entry).not.toMatch(/\.qgf|qgf\/|COUNCIL_LEDGER|roadmap\/|\[CHIEF-|CISO|OPA-14/);
  });
});

describe('ignore files and dev scripts (#246)', () => {
  it('OPA-14.AC9 no root .hmaignore rule names a path under packages/cli/src, and packages/cli/.hmaignore is absent', () => {
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

  it('OPA-14.AC9 shield-lock-trace-loop.ts keeps its line-63 spread as the declared dev-script site', () => {
    const lines = read('packages/cli/scripts/shield-lock-trace-loop.ts').split('\n');
    expect(lines[62]).toContain('...process.env');
  });

  it('OPA-14.AC9 release-smoke-corpus.ts keeps its spread, under a comment stating both sides get the identical environment by design', () => {
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

  it('OPA-14.AC9 the benchmark, comply and init harnesses feed their spread to buildChildEnv', () => {
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
