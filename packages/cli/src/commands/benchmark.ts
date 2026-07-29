/**
 * benchmark command.
 *
 * Maps security findings to OASB-1 controls to produce a compliance rating.
 *
 * SCORING CONTRACT (issue #250) — a control is scored only if a source that can
 * evaluate it actually ran. Controls nothing assessed are reported as NOT
 * EVALUATED and never counted as passing.
 *
 * The original model marked a control passing whenever no finding mentioned its
 * check ID. That is a fail-open, and it was total: the only source consulted
 * (`HardeningScanner`) emits GIT-* ids and evaluates none of the 39 OASB L1
 * check IDs, so every L1 control "passed" by never being assessed. An empty
 * directory came back `Certified`, and so did a project with a hardcoded API
 * key that `init` and `protect` both call CRITICAL.
 *
 * A compliance rating is evidence a user hands to a third party. Asserting that
 * a control passed without evaluating it is fabrication, so:
 *
 *   - `evaluated`  a source with that check in its vocabulary ran
 *   - `failing`    evaluated AND found non-compliant
 *   - `passing`    evaluated AND not failing
 *   - anything else is NOT EVALUATED and is excluded from the numerator AND
 *     the denominator, with the count disclosed on the score line
 *
 * `Certified` and `Passing` additionally require COMPLETE coverage of the
 * level. A partially-assessed target can be `Partial` at best, because a
 * rating over unknown controls is not a rating.
 *
 * Coverage today is genuinely thin — `quickCredentialScan` supplies CRED-002/
 * 003/004 and `HardeningScanner` supplies whatever it emits. The remaining
 * OASB controls (SEM-*, PERM-*, PROMPT-*, IO-*, NET-*, …) need HMA's semantic
 * pass wired in, tracked separately. Reporting that honestly is the point: a
 * thin-but-true number beats a complete-looking false one.
 */

import { quickCredentialScan } from '../util/credential-patterns.js';

export interface BenchmarkOptions {
  targetDir?: string;
  level?: string;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
}

interface OASBCategory {
  id: number;
  name: string;
  description: string;
  controls: OASBControl[];
}

interface OASBControl {
  id: string;
  name: string;
  category: string;
  level: string;
  scored: boolean;
  description: string;
  checkIds: string[];
}

/** What a set of sources actually assessed, and what they found wanting. */
interface Assessment {
  evaluated: Set<string>;
  failing: Set<string>;
}

/** Compliance over the evaluated subset of a check-id list. */
interface LevelScore {
  /** null when nothing in the list was evaluated — NOT zero, and NOT 100. */
  compliance: number | null;
  evaluated: string[];
  passing: string[];
  failing: string[];
  notEvaluated: string[];
}

/**
 * OASB L1 controls the bundled credential scan evaluates.
 *
 * Verified against `getCheckIdsForLevel('L1')`; a test asserts the two stay in
 * step, because a silent divergence here under-reports coverage.
 */
const OASB_CREDENTIAL_CONTROLS = ['CRED-002', 'CRED-003', 'CRED-004'] as const;

/**
 * Where a hardcoded-secret finding lands when its own pattern id is not an
 * OASB control.
 *
 * `CREDENTIAL_PATTERNS` emits CRED-001/002/003/004/005 and DRIFT-001/002;
 * OASB L1 defines only CRED-002/003/004. An Anthropic key (CRED-001) or an AWS
 * secret (CRED-005) is still a hardcoded credential in source, which is exactly
 * what CRED-002 covers, so it fails that control rather than vanishing.
 */
const CREDENTIAL_CONTROL_FOR_HARDCODED_SECRET = 'CRED-002';

async function getHMA(): Promise<any> {
  try {
    const hma: any = await import('hackmyagent');
    return hma;
  } catch {
    process.stderr.write('hackmyagent is not installed.\n');
    process.stderr.write('Install: npm install -g hackmyagent\n');
    return null;
  }
}

/**
 * Score a list of check IDs against an assessment.
 *
 * Unevaluated ids leave both the numerator and the denominator — they are not
 * failures (we did not find a problem) and not passes (we did not look).
 */
export function scoreCheckIds(checkIds: string[], assessment: Assessment): LevelScore {
  const unique = [...new Set(checkIds)];
  const evaluated = unique.filter(id => assessment.evaluated.has(id));
  const failing = evaluated.filter(id => assessment.failing.has(id));
  const passing = evaluated.filter(id => !assessment.failing.has(id));
  return {
    compliance: evaluated.length > 0 ? Math.round((passing.length / evaluated.length) * 100) : null,
    evaluated,
    passing,
    failing,
    notEvaluated: unique.filter(id => !assessment.evaluated.has(id)),
  };
}

/**
 * Gate the rating on coverage.
 *
 * A rating asserted over controls nobody assessed is not a rating, so the two
 * affirmative ratings require the level to be fully evaluated.
 */
export function gateRating(
  score: LevelScore,
  baseRating: string,
): { rating: string; reason: string | null } {
  if (score.evaluated.length === 0) {
    return {
      rating: 'Not assessable',
      reason: 'no control in this level was evaluated by the checks this command runs',
    };
  }
  // Coverage gating removes UNEARNED affirmative ratings. It must not remove an
  // EARNED negative one: masking `Not Passing` as `Partial` because coverage is
  // incomplete is the same overclaim pointed the other way, and it made the
  // rating field constant in practice (every real target returned `Partial`).
  if (score.failing.length > 0) {
    return {
      rating: baseRating,
      reason: score.notEvaluated.length > 0
        ? `${score.failing.length} evaluated control(s) failing; ${score.notEvaluated.length} of ${score.evaluated.length + score.notEvaluated.length} not evaluated`
        : null,
    };
  }
  if (score.notEvaluated.length > 0) {
    return {
      rating: 'Partial',
      reason: `${score.notEvaluated.length} of ${score.evaluated.length + score.notEvaluated.length} controls were not evaluated`,
    };
  }
  return { rating: baseRating, reason: null };
}

export async function benchmark(options: BenchmarkOptions): Promise<number> {
  const hma = await getHMA();
  if (!hma) return 1;

  const {
    OASB_1_CATEGORIES,
    OASB_1_VERSION,
    OASB_1_NAME,
    getCheckIdsForLevel,
    calculateRating,
    HardeningScanner,
  } = hma;

  if (!OASB_1_CATEGORIES || !getCheckIdsForLevel || !HardeningScanner) {
    process.stderr.write('hackmyagent does not export OASB benchmark API or HardeningScanner. Update hackmyagent.\n');
    return 1;
  }

  const targetDir = options.targetDir ?? process.cwd();
  const level = (options.level ?? 'L1').toUpperCase();

  if (!['L1', 'L2', 'L3'].includes(level)) {
    process.stderr.write(`Invalid level: ${level}. Use L1, L2, or L3.\n`);
    return 1;
  }

  try {
    const assessment: Assessment = { evaluated: new Set(), failing: new Set() };
    const sources: string[] = [];

    // --- Source 1: HardeningScanner ------------------------------------
    // Every id it reports on was assessed, whether it passed or failed. Ids it
    // never mentions were NOT assessed, which is the whole point of #250.
    const scanner = new HardeningScanner();
    const scanResult = await scanner.scan({ targetDir });
    const hardeningFindings: any[] = scanResult?.findings ?? [];
    for (const f of hardeningFindings) {
      const id = f.checkId ?? f.ruleId ?? f.id;
      if (!id) continue;
      assessment.evaluated.add(id);
      if (f.passed === false) assessment.failing.add(id);
    }
    if (hardeningFindings.length > 0) sources.push('hardening scanner');

    // --- Source 2: credential scan -------------------------------------
    // The same scan `init` and `protect` run. Its vocabulary is enumerable and
    // CRED-002/003/004 are OASB L1 controls, so this is affirmative coverage:
    // running it evaluates those controls whether or not anything matches.
    // Without this, a hardcoded key scored Credential Protection 10/10 while
    // two other commands called the same file CRITICAL.
    let unmappedCredentialFindings: Array<{ id: string; severity: string }> = [];
    try {
      for (const id of OASB_CREDENTIAL_CONTROLS) assessment.evaluated.add(id);
      const matches = await quickCredentialScan(targetDir);
      for (const m of matches) {
        if (!m.findingId) continue;
        if ((OASB_CREDENTIAL_CONTROLS as readonly string[]).includes(m.findingId)) {
          assessment.failing.add(m.findingId);
          continue;
        }
        // A hardcoded credential whose pattern id has no OASB control still
        // fails the thing those controls are ABOUT. Discarding it is how the
        // original defect survived a rewrite: `protect` reported
        // "CRITICAL CRED-001 Anthropic API Key" while this command printed
        // "Credential Protection: 100% [PASS]" for the same directory,
        // byte-identical to an empty one.
        assessment.failing.add(CREDENTIAL_CONTROL_FOR_HARDCODED_SECRET);
        unmappedCredentialFindings.push({ id: m.findingId, severity: m.severity });
      }
      sources.push('credential scan');
    } catch {
      // A credential scan that cannot run leaves those controls unevaluated,
      // which is the correct fail-closed outcome — not a silent pass.
      for (const id of OASB_CREDENTIAL_CONTROLS) assessment.evaluated.delete(id);
      unmappedCredentialFindings = [];
    }

    // --- Score ----------------------------------------------------------
    const levelIds = getCheckIdsForLevel(level) as string[];
    const score = scoreCheckIds(levelIds, assessment);

    const baseRating = score.compliance !== null
      ? calculateRating(score.compliance, 0, 0, level)
      : 'Not Passing';
    const { rating, reason } = gateRating(score, baseRating);

    // --- Per-category breakdown ----------------------------------------
    const categories = (OASB_1_CATEGORIES as OASBCategory[]).map((cat: OASBCategory) => {
      const catControls = cat.controls.filter((c: OASBControl) => {
        if (level === 'L1') return c.level === 'L1';
        if (level === 'L2') return c.level === 'L1' || c.level === 'L2';
        return true;
      });
      const catIds = [...new Set(catControls.flatMap((c: OASBControl) => c.checkIds))];
      // A category with no controls at this level is NOT APPLICABLE. Rendering
      // it as 0% put "NEEDS WORK" next to a 100% headline.
      if (catIds.length === 0) {
        return {
          id: cat.id, name: cat.name, applicable: false,
          compliance: null, evaluated: 0, totalChecks: 0, failing: [] as string[],
        };
      }
      const catScore = scoreCheckIds(catIds, assessment);
      return {
        id: cat.id,
        name: cat.name,
        applicable: true,
        compliance: catScore.compliance,
        evaluated: catScore.evaluated.length,
        totalChecks: catIds.length,
        failing: catScore.failing,
      };
    });

    const result = {
      benchmark: OASB_1_NAME ?? 'OASB-1',
      version: OASB_1_VERSION ?? '1.0',
      level,
      target: targetDir,
      timestamp: new Date().toISOString(),
      rating,
      ratingReason: reason,
      compliance: {
        l1: level === 'L1' ? score.compliance : null,
        scoredOver: 'evaluated controls only',
      },
      coverage: {
        evaluated: score.evaluated.length,
        notEvaluated: score.notEvaluated.length,
        total: score.evaluated.length + score.notEvaluated.length,
        notEvaluatedIds: score.notEvaluated,
        sources,
      },
      summary: {
        failingControls: score.failing.length,
        passingControls: score.passing.length,
        /** Credential findings with no OASB control of their own, folded into CRED-002. */
        unmappedCredentialFindings,
      },
      categories,
    };

    if (options.format === 'json') {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    } else {
      const total = score.evaluated.length + score.notEvaluated.length;
      process.stdout.write(`\n  OASB-1 Security Benchmark\n`);
      process.stdout.write(`  ${'-'.repeat(40)}\n`);
      process.stdout.write(`  Target:     ${targetDir}\n`);
      process.stdout.write(`  Level:      ${level}\n`);
      process.stdout.write(`  Rating:     ${rating}\n`);
      if (reason) process.stdout.write(`              ${reason}\n`);
      const scoreText = score.compliance === null ? 'not assessable' : `${score.compliance}%`;
      process.stdout.write(
        `  ${level}:         ${scoreText} (${score.evaluated.length} of ${total} controls evaluated)\n`,
      );
      if (score.notEvaluated.length > 0) {
        process.stdout.write(`  Not evaluated: ${score.notEvaluated.length} control(s) — these are NOT counted as passing\n`);
      }
      process.stdout.write(`  Failing:    ${score.failing.length}\n`);
      process.stdout.write(`\n`);

      if (options.verbose) {
        process.stdout.write(`  Category Breakdown:\n`);
        for (const cat of categories) {
          if (!cat.applicable) {
            process.stdout.write(`    ${cat.id}. ${cat.name}: n/a (no ${level} controls)\n`);
            continue;
          }
          if (cat.compliance === null) {
            process.stdout.write(`    ${cat.id}. ${cat.name}: not evaluated (0 of ${cat.totalChecks} controls assessed)\n`);
            continue;
          }
          // The badge is qualified by coverage for the same reason the headline
          // rating is: `[PASS]` over 3 of 10 assessed controls is an absolute
          // label on a partial assessment.
          const fullyAssessed = cat.evaluated === cat.totalChecks;
          const bar = cat.compliance === 100
            ? (fullyAssessed ? '[PASS]' : '[PASS, PARTIAL COVERAGE]')
            : cat.compliance >= 70 ? '[PARTIAL]' : '[NEEDS WORK]';
          process.stdout.write(
            `    ${cat.id}. ${cat.name}: ${cat.compliance}% ${bar} (${cat.evaluated} of ${cat.totalChecks} assessed)\n`,
          );
        }
        process.stdout.write('\n');
        if (score.notEvaluated.length > 0) {
          process.stdout.write(`  Controls not evaluated by this command:\n`);
          process.stdout.write(`    ${score.notEvaluated.join(', ')}\n\n`);
        }
      }

      // Path forward, recovery-framed and honest about what is missing.
      const failingCats = categories.filter(c => c.applicable && c.compliance !== null && c.compliance < 100);
      if (failingCats.length > 0) {
        process.stdout.write(`  Failing controls to address:\n`);
        for (const cat of failingCats.slice(0, 3)) {
          process.stdout.write(`    - ${cat.name}: ${cat.failing.join(', ')}\n`);
        }
        process.stdout.write(`\n  Fix credentials:  opena2a protect ${targetDir}\n`);
      }
      if (unmappedCredentialFindings.length > 0) {
        const ids = unmappedCredentialFindings.map(f => `${f.id} (${f.severity})`).join(', ');
        process.stdout.write(`  Counted under CRED-002 (no OASB control of their own): ${ids}\n`);
      }
      if (score.notEvaluated.length > 0) {
        process.stdout.write(`  Deeper analysis (evaluates more controls):  opena2a scan ${targetDir} --deep\n`);
      }
      if (!options.verbose) {
        process.stdout.write(`  Per-category breakdown:  opena2a benchmark ${targetDir} --verbose\n`);
      }
      process.stdout.write('\n');
    }

    return 0;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Benchmark failed: ${message}\n`);
    if (options.verbose && err instanceof Error && err.stack) {
      process.stderr.write(`${err.stack}\n`);
    }
    return 1;
  }
}
