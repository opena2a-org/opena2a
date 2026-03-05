/**
 * benchmark command.
 * Uses hackmyagent's OASB benchmark API and ExternalScanner programmatically.
 * Runs a security scan against the target directory, then maps findings
 * to OASB-1 controls to produce a compliance rating.
 */

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

export async function benchmark(options: BenchmarkOptions): Promise<number> {
  const hma = await getHMA();
  if (!hma) return 1;

  const {
    OASB_1_CATEGORIES,
    OASB_1_VERSION,
    OASB_1_NAME,
    getControlsForLevel,
    getCheckIdsForLevel,
    calculateRating,
    HardeningScanner,
  } = hma;

  if (!OASB_1_CATEGORIES || !getControlsForLevel || !HardeningScanner) {
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
    // Run HMA HardeningScanner to get findings with check IDs
    const scanner = new HardeningScanner();
    const scanResult = await scanner.scan({ targetDir });
    // Only count failing checks (passed === false)
    const findings = (scanResult?.findings ?? []).filter((f: any) => !f.passed);

    // Get check IDs covered by findings
    const foundCheckIds = new Set<string>();
    for (const finding of findings) {
      if (finding.checkId) {
        foundCheckIds.add(finding.checkId);
      }
      // Some findings use ruleId or id
      if (finding.ruleId) {
        foundCheckIds.add(finding.ruleId);
      }
    }

    // Calculate compliance per level
    const l1Controls = getControlsForLevel('L1') as OASBControl[];
    const l2Controls = getControlsForLevel('L2') as OASBControl[];
    const l3Controls = getControlsForLevel('L3') as OASBControl[];

    const l1CheckIds = getCheckIdsForLevel('L1') as string[];
    const l2CheckIds = getCheckIdsForLevel('L2') as string[];
    const l3CheckIds = getCheckIdsForLevel('L3') as string[];

    // A check "passes" if it was NOT flagged as a finding (no vulnerability found)
    // For OASB, findings represent issues, so a check passes when no finding exists
    const l1Passing = l1CheckIds.filter((id: string) => !foundCheckIds.has(id));
    const l2Only = l2CheckIds.filter((id: string) => !l1CheckIds.includes(id));
    const l2Passing = l2Only.filter((id: string) => !foundCheckIds.has(id));
    const l3Only = l3CheckIds.filter((id: string) => !l2CheckIds.includes(id));
    const l3Passing = l3Only.filter((id: string) => !foundCheckIds.has(id));

    const l1Compliance = l1CheckIds.length > 0 ? Math.round((l1Passing.length / l1CheckIds.length) * 100) : 0;
    const l2Compliance = l2Only.length > 0 ? Math.round((l2Passing.length / l2Only.length) * 100) : 0;
    const l3Compliance = l3Only.length > 0 ? Math.round((l3Passing.length / l3Only.length) * 100) : 0;

    const rating = calculateRating(l1Compliance, l2Compliance, l3Compliance, level);

    // Build per-category breakdown
    const categories = (OASB_1_CATEGORIES as OASBCategory[]).map((cat: OASBCategory) => {
      const catControls = cat.controls.filter((c: OASBControl) => {
        if (level === 'L1') return c.level === 'L1';
        if (level === 'L2') return c.level === 'L1' || c.level === 'L2';
        return true;
      });
      const totalChecks = catControls.reduce((sum: number, c: OASBControl) => sum + c.checkIds.length, 0);
      const passingChecks = catControls.reduce((sum: number, c: OASBControl) => {
        return sum + c.checkIds.filter((id: string) => !foundCheckIds.has(id)).length;
      }, 0);
      return {
        id: cat.id,
        name: cat.name,
        totalChecks,
        passingChecks,
        compliance: totalChecks > 0 ? Math.round((passingChecks / totalChecks) * 100) : 0,
      };
    });

    const result = {
      benchmark: OASB_1_NAME ?? 'OASB-1',
      version: OASB_1_VERSION ?? '1.0',
      level,
      target: targetDir,
      timestamp: new Date().toISOString(),
      rating,
      compliance: {
        l1: l1Compliance,
        l2: l2Compliance,
        l3: l3Compliance,
      },
      summary: {
        totalFindings: findings.length,
        totalChecks: l1CheckIds.length + l2Only.length + l3Only.length,
      },
      categories,
    };

    if (options.format === 'json') {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    } else {
      process.stdout.write(`\n  OASB-1 Security Benchmark\n`);
      process.stdout.write(`  ${'-'.repeat(40)}\n`);
      process.stdout.write(`  Target:     ${targetDir}\n`);
      process.stdout.write(`  Level:      ${level}\n`);
      process.stdout.write(`  Rating:     ${rating}\n`);
      process.stdout.write(`  L1:         ${l1Compliance}% (${l1Passing.length}/${l1CheckIds.length} checks)\n`);
      if (level !== 'L1') {
        process.stdout.write(`  L2:         ${l2Compliance}% (${l2Passing.length}/${l2Only.length} checks)\n`);
      }
      if (level === 'L3') {
        process.stdout.write(`  L3:         ${l3Compliance}% (${l3Passing.length}/${l3Only.length} checks)\n`);
      }
      process.stdout.write(`  Findings:   ${findings.length}\n`);
      process.stdout.write(`\n`);

      if (options.verbose) {
        process.stdout.write(`  Category Breakdown:\n`);
        for (const cat of categories) {
          const bar = cat.compliance === 100 ? '[PASS]' : cat.compliance >= 70 ? '[PARTIAL]' : '[NEEDS WORK]';
          process.stdout.write(`    ${cat.id}. ${cat.name}: ${cat.compliance}% ${bar}\n`);
        }
        process.stdout.write('\n');
      }

      // Actionable guidance
      if (rating === 'Certified' || rating === 'Passing') {
        process.stdout.write(`  Status: ${level} compliance is on track.\n`);
      } else {
        const failingCats = categories.filter(c => c.compliance < 70);
        if (failingCats.length > 0) {
          process.stdout.write(`  Focus areas for improvement:\n`);
          for (const cat of failingCats.slice(0, 3)) {
            process.stdout.write(`    - ${cat.name} (${cat.compliance}%)\n`);
          }
        }
        process.stdout.write(`\n  Run \`opena2a scan secure\` for detailed findings.\n`);
        process.stdout.write(`  Run \`opena2a benchmark --verbose\` for per-category breakdown.\n`);
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
