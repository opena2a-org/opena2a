#!/usr/bin/env tsx
/**
 * release-smoke-benchmark.ts — `opena2a benchmark` corpus-tier gate.
 *
 * Why this exists:
 *   `benchmark` shipped returning `Rating: Certified` for an EMPTY directory,
 *   and for a project with a hardcoded API key that `init` and `protect` both
 *   called CRITICAL (issue #250). The cause was a fail-open: a control counted
 *   as passing whenever no finding mentioned its check ID, and the only source
 *   consulted evaluated none of the 39 OASB L1 controls. Every `Certified` the
 *   command had ever printed meant "the scanner did not mention these IDs".
 *
 *   The repo rule is that every score-producing command is exercised against
 *   the canonical 3-tier corpus. This is that harness for `benchmark`.
 *
 * What it asserts, and what it deliberately does NOT:
 *
 *   1. No tier is ever `Certified` or `Passing` while coverage is partial.
 *      This is the #250 invariant and the one that must never regress.
 *   2. The malicious tier scores materially worse than the benign tier.
 *   3. An empty directory is never `Certified`.
 *   4. Coverage is disclosed on every run (evaluated / total), so a number is
 *      never presented as a full assessment.
 *   5. A hardcoded credential surfaces as a FAILING control, not a passing one
 *      — the cross-command agreement with `protect` that #250 broke.
 *
 *   It does NOT assert strict benign > buggy > malicious monotonicity, because
 *   that would be false today and forcing it would mean inventing coverage.
 *   Only 3 of the 39 L1 controls are evaluable from this repo's own scanners
 *   (CRED-002/003/004); the buggy tier's defect is a template-env leak, which
 *   has no OASB L1 control, so buggy and benign legitimately tie. Widening
 *   coverage is tracked separately — when it lands, tighten this to full
 *   monotonicity.
 *
 * Exit code 0 = green, 1 = assertion failure, 2 = setup error.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildChildEnv } from '../src/util/child-env.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const CORPUS_ROOT = process.env.OPENA2A_CORPUS_PATH ?? join(homedir(), '.opena2a', 'corpus');
const FALLBACK_CORPUS = join(homedir(), 'workspace', 'opena2a-org', 'opena2a-corpus');
const CLI = resolve(__dirname, '..', 'dist', 'index.js');

const NODE_PREFIXES = ['npm_config_', 'NPM_CONFIG_', 'NODE_', 'NVM_', 'COREPACK_', 'YARN_', 'PNPM_'];

let failures = 0;
function pass(msg: string): void { process.stdout.write(`  ok: ${msg}\n`); }
function fail(msg: string): void { process.stderr.write(`  FAIL: ${msg}\n`); failures++; }

interface BenchmarkResult {
  rating: string;
  compliance: { l1: number | null };
  coverage: { evaluated: number; notEvaluated: number; total: number };
  summary: { failingControls: number; passingControls: number };
  categories: Array<{ id: number; name: string; compliance: number | null; failing: string[] }>;
}

function runBenchmark(targetDir: string): BenchmarkResult | null {
  const r = spawnSync('node', [CLI, 'benchmark', targetDir, '--json'], {
    encoding: 'utf-8',
    env: buildChildEnv({ allowPrefixes: NODE_PREFIXES }, { ...process.env, OPENA2A_TELEMETRY: 'off' }),
  });
  if (r.status !== 0) return null;
  try {
    return JSON.parse(r.stdout) as BenchmarkResult;
  } catch {
    return null;
  }
}

function resolveCorpusRoot(): string | null {
  if (existsSync(CORPUS_ROOT)) return CORPUS_ROOT;
  if (existsSync(FALLBACK_CORPUS)) return FALLBACK_CORPUS;
  return null;
}

/** Ratings that assert the target met the bar. Never legal under partial coverage. */
const AFFIRMATIVE_RATINGS = ['Certified', 'Passing'];

function main(): number {
  if (!existsSync(CLI)) {
    process.stderr.write('[release-smoke-benchmark] dist not built. Run: npm run build\n');
    return 2;
  }
  const corpus = resolveCorpusRoot();
  if (!corpus) {
    process.stderr.write(`[release-smoke-benchmark] corpus not found at ${CORPUS_ROOT} or ${FALLBACK_CORPUS}\n`);
    return 2;
  }

  process.stdout.write('opena2a benchmark — corpus-tier gate\n');
  process.stdout.write(`  corpus: ${corpus}\n\n`);

  const tiers = ['benign/tiny-clean-repo', 'buggy/leaky-env-example', 'malicious/kitchen-sink'];
  const scores: Record<string, BenchmarkResult> = {};

  for (const fixture of tiers) {
    const target = join(corpus, 'repo', fixture);
    if (!existsSync(target)) { fail(`fixture missing: ${target}`); continue; }
    const r = runBenchmark(target);
    if (!r) { fail(`benchmark failed or returned unparseable JSON for ${fixture}`); continue; }
    scores[fixture] = r;
    process.stdout.write(
      `  ${fixture.padEnd(26)} rating=${r.rating.padEnd(15)} l1=${String(r.compliance.l1).padStart(4)}` +
      `  coverage=${r.coverage.evaluated}/${r.coverage.total}  failing=${r.summary.failingControls}\n`,
    );
  }
  process.stdout.write('\n');

  // 1. The #250 invariant: never assert compliance over unevaluated controls.
  for (const [fixture, r] of Object.entries(scores)) {
    if (r.coverage.notEvaluated > 0 && AFFIRMATIVE_RATINGS.includes(r.rating)) {
      fail(`${fixture}: rating "${r.rating}" with ${r.coverage.notEvaluated} controls unevaluated`);
    }
  }
  if (failures === 0) pass('no tier claims an affirmative rating over unevaluated controls');

  // 2. Coverage is always disclosed.
  for (const [fixture, r] of Object.entries(scores)) {
    if (typeof r.coverage.evaluated !== 'number' || typeof r.coverage.total !== 'number') {
      fail(`${fixture}: coverage not disclosed in JSON output`);
    }
  }
  pass('every run discloses evaluated / total coverage');

  // 3. Malicious must be materially worse than benign.
  const benign = scores['benign/tiny-clean-repo'];
  const malicious = scores['malicious/kitchen-sink'];
  if (benign && malicious) {
    const b = benign.compliance.l1;
    const m = malicious.compliance.l1;
    if (b === null || m === null) {
      fail(`benign or malicious returned a null score (benign=${b}, malicious=${m})`);
    } else if (!(m < b)) {
      fail(`malicious (${m}) is not worse than benign (${b})`);
    } else if (b - m < 30) {
      fail(`malicious (${m}) is only ${b - m} points below benign (${b}); expected a clear separation`);
    } else {
      pass(`malicious (${m}) is ${b - m} points below benign (${b})`);
    }
    if (malicious.summary.failingControls === 0) {
      fail('malicious fixture reports zero failing controls');
    } else {
      pass(`malicious fixture reports ${malicious.summary.failingControls} failing control(s)`);
    }
  }

  // 4. An empty directory is never Certified. This is the literal #250 report.
  const empty = mkdtempSync(join(tmpdir(), 'benchmark-smoke-empty-'));
  try {
    const r = runBenchmark(empty);
    if (!r) {
      fail('benchmark failed on an empty directory');
    } else if (AFFIRMATIVE_RATINGS.includes(r.rating)) {
      fail(`empty directory rated "${r.rating}"`);
    } else {
      pass(`empty directory rated "${r.rating}", not Certified`);
    }
  } finally {
    rmSync(empty, { recursive: true, force: true });
  }

  // 5. A hardcoded credential must surface as a FAILING control — the
  //    cross-command agreement with `protect` that #250 broke.
  const credDir = mkdtempSync(join(tmpdir(), 'benchmark-smoke-cred-'));
  try {
    // Built at runtime so no credential-shaped literal is committed.
    const key = 'sk-' + 'FAKEFAKE'.repeat(5);
    writeFileSync(join(credDir, 'package.json'), '{"name":"cred-smoke","version":"1.0.0"}\n');
    writeFileSync(join(credDir, 'index.js'), `const openai = "${key}";\n`);
    const r = runBenchmark(credDir);
    if (!r) {
      fail('benchmark failed on the hardcoded-credential fixture');
    } else {
      const cred = r.categories.find(c => /credential/i.test(c.name));
      if (!cred) {
        fail('no Credential Protection category in output');
      } else if (cred.compliance === 100 || cred.failing.length === 0) {
        fail(`hardcoded credential scored Credential Protection ${cred.compliance}% with ${cred.failing.length} failing — this is the #250 regression`);
      } else {
        pass(`hardcoded credential fails Credential Protection (${cred.failing.join(', ')})`);
      }
      if (AFFIRMATIVE_RATINGS.includes(r.rating)) {
        fail(`hardcoded-credential fixture rated "${r.rating}"`);
      }
    }
  } finally {
    rmSync(credDir, { recursive: true, force: true });
  }

  process.stdout.write('\n');
  if (failures > 0) {
    process.stdout.write(`  RESULT: RED — ${failures} assertion(s) failed. Release-blocking.\n\n`);
    return 1;
  }
  process.stdout.write('  RESULT: GREEN — benchmark scoring is within contract.\n\n');
  return 0;
}

process.exit(main());
