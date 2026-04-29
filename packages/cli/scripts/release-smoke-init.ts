#!/usr/bin/env tsx
/**
 * release-smoke-init.ts — `opena2a init` corpus-tier monotonicity gate.
 *
 * Why this exists:
 *   `opena2a init` produces a single security score that the user reads
 *   first and acts on. Pre-#116 the scoring algorithm was missing surfaces
 *   (private-key files, multi-MCP, unsigned skills) that allowed a
 *   malicious-fixture project to score 96/100 ("strong"), HIGHER than the
 *   benign-fixture project at 93/100. /release-test only exercised init
 *   against a clean tree, so the regression shipped.
 *
 *   This harness exercises `opena2a init` against the canonical 3-tier
 *   corpus (`benign/tiny-clean-repo`, `buggy/leaky-env-example`,
 *   `malicious/kitchen-sink`) and asserts:
 *
 *     1. Score monotonicity: benign > buggy > malicious
 *     2. Per-tier score band:
 *        - benign:    >= 80
 *        - buggy:     50..80 (inclusive)
 *        - malicious: <= 60 (give 30-pt margin above the corpus
 *                            ceiling of 30 — actively-malicious
 *                            scoring will tighten in follow-up waves)
 *
 *   Failures are release-blockers. The init scoring algorithm cannot drift
 *   past these bounds without an audit-doc decision and a band update.
 *
 * Per [CHIEF-CDS-028] OPENA2A_CORPUS_DETERMINISTIC=1.
 *
 * Exit code 0 = green, 1 = score-band failure, 2 = setup error.
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const CORPUS_ROOT =
  process.env.OPENA2A_CORPUS_PATH ?? join(homedir(), '.opena2a', 'corpus');
const FALLBACK_CORPUS = join(homedir(), 'workspace', 'opena2a-org', 'opena2a-corpus');
const OPENA2A_CLI = resolve(__dirname, '..', 'dist', 'index.js');

interface TierExpectation {
  tier: 'benign' | 'buggy' | 'malicious';
  fixture: string;
  scoreFloor: number;
  scoreCeiling: number;
}

const TIERS: TierExpectation[] = [
  { tier: 'benign',    fixture: 'repo/benign/tiny-clean-repo',     scoreFloor: 80, scoreCeiling: 100 },
  { tier: 'buggy',     fixture: 'repo/buggy/leaky-env-example',    scoreFloor: 50, scoreCeiling: 80 },
  { tier: 'malicious', fixture: 'repo/malicious/kitchen-sink',     scoreFloor: 0,  scoreCeiling: 60 },
];

function resolveCorpusRoot(): string | null {
  if (existsSync(CORPUS_ROOT)) return CORPUS_ROOT;
  if (existsSync(FALLBACK_CORPUS)) return FALLBACK_CORPUS;
  return null;
}

function runInit(targetDir: string): { score: number; raw: string } | null {
  const result = spawnSync(
    'node',
    [OPENA2A_CLI, 'init', '--json', '--ci', '--no-contribute', targetDir],
    {
      env: { ...process.env, OPENA2A_CORPUS_DETERMINISTIC: '1' },
      encoding: 'utf-8',
    },
  );
  if (result.status !== 0 && result.status !== 1) return null;
  try {
    const parsed = JSON.parse(result.stdout);
    if (typeof parsed.securityScore !== 'number') return null;
    return { score: parsed.securityScore, raw: result.stdout };
  } catch {
    return null;
  }
}

function main(): number {
  const corpus = resolveCorpusRoot();
  if (!corpus) {
    process.stderr.write(`[release-smoke-init] corpus not found at ${CORPUS_ROOT} or ${FALLBACK_CORPUS}\n`);
    process.stderr.write(`[release-smoke-init] set OPENA2A_CORPUS_PATH or check out opena2a-corpus alongside this repo.\n`);
    return 2;
  }
  if (!existsSync(OPENA2A_CLI)) {
    process.stderr.write(`[release-smoke-init] dist not built. Run: npm run build\n`);
    return 2;
  }

  const results: Array<{ tier: string; score: number; passed: boolean; reason: string }> = [];
  for (const t of TIERS) {
    const target = join(corpus, t.fixture);
    if (!existsSync(target)) {
      results.push({ tier: t.tier, score: -1, passed: false, reason: `fixture missing: ${target}` });
      continue;
    }
    const out = runInit(target);
    if (!out) {
      results.push({ tier: t.tier, score: -1, passed: false, reason: 'init failed or returned non-numeric score' });
      continue;
    }
    const inBand = out.score >= t.scoreFloor && out.score <= t.scoreCeiling;
    results.push({
      tier: t.tier,
      score: out.score,
      passed: inBand,
      reason: inBand ? '' : `score ${out.score} outside band [${t.scoreFloor}, ${t.scoreCeiling}]`,
    });
  }

  const benign = results.find(r => r.tier === 'benign');
  const buggy  = results.find(r => r.tier === 'buggy');
  const mal    = results.find(r => r.tier === 'malicious');

  let monotonicityOk = true;
  let monotonicityReason = '';
  if (benign && buggy && mal && benign.score >= 0 && buggy.score >= 0 && mal.score >= 0) {
    if (!(benign.score > buggy.score && buggy.score > mal.score)) {
      monotonicityOk = false;
      monotonicityReason = `expected benign(${benign.score}) > buggy(${buggy.score}) > malicious(${mal.score})`;
    }
  } else {
    monotonicityOk = false;
    monotonicityReason = 'one or more tier results missing';
  }

  process.stdout.write('opena2a init — corpus-tier monotonicity gate\n');
  process.stdout.write(`  corpus: ${corpus}\n`);
  process.stdout.write('\n');
  for (const r of results) {
    const mark = r.passed ? 'PASS' : 'FAIL';
    process.stdout.write(`  [${mark}] ${r.tier.padEnd(10)} score=${String(r.score).padStart(3)}${r.reason ? `  — ${r.reason}` : ''}\n`);
  }
  process.stdout.write('\n');
  process.stdout.write(`  monotonicity: ${monotonicityOk ? 'PASS' : 'FAIL'}${monotonicityReason ? `  — ${monotonicityReason}` : ''}\n`);
  process.stdout.write('\n');

  const allBandsOk = results.every(r => r.passed);
  if (allBandsOk && monotonicityOk) {
    process.stdout.write('  RESULT: GREEN — init scoring is within contract.\n');
    return 0;
  }
  process.stdout.write('  RESULT: RED — release-blocking. See per-tier failures above.\n');
  return 1;
}

process.exit(main());
