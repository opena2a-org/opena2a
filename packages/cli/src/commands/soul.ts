/**
 * scan-soul and harden-soul commands.
 * Uses hackmyagent's SoulScanner programmatic API directly.
 */

export interface SoulOptions {
  targetDir?: string;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
  profile?: string;
  tier?: string;
  deep?: boolean;
  dryRun?: boolean;
  strict?: boolean;
}

async function getSoulScanner(): Promise<any> {
  try {
    const hma: any = await import('hackmyagent');
    const SoulScanner = hma.SoulScanner ?? hma.default?.SoulScanner;
    if (!SoulScanner) {
      process.stderr.write('hackmyagent does not export SoulScanner. Update hackmyagent.\n');
      return null;
    }
    return new SoulScanner();
  } catch {
    process.stderr.write('hackmyagent is not installed.\n');
    process.stderr.write('Install: npm install -g hackmyagent\n');
    return null;
  }
}

export async function scanSoul(options: SoulOptions): Promise<number> {
  const scanner = await getSoulScanner();
  if (!scanner) return 1;

  const targetDir = options.targetDir ?? process.cwd();

  try {
    const result = await scanner.scanSoul(targetDir, {
      profile: options.profile,
      tier: options.tier,
      deep: options.deep,
      verbose: options.verbose,
    });

    if (options.format === 'json') {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    } else {
      formatScanResult(result, options.verbose ?? false, options.strict ?? false);
    }

    // In strict mode, fail if ANY critical SOUL control is missing
    if (options.strict) {
      const missingCritical = findMissingCriticalControls(result);
      if (missingCritical.length > 0) {
        if (options.format !== 'json') {
          process.stderr.write(`\n[strict] Failed: ${missingCritical.length} critical control(s) missing:\n`);
          for (const id of missingCritical) {
            process.stderr.write(`  - ${id}\n`);
          }
          process.stderr.write('\n');
        }
        return 1;
      }
    }

    // Exit 1 if score is below threshold (no governance or low score)
    return (result.score ?? result.overallScore ?? 0) < 60 ? 1 : 0;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`scan-soul failed: ${message}\n`);
    return 1;
  }
}

export async function hardenSoul(options: SoulOptions): Promise<number> {
  const scanner = await getSoulScanner();
  if (!scanner) return 1;

  const targetDir = options.targetDir ?? process.cwd();

  try {
    const result = await scanner.hardenSoul(targetDir, {
      profile: options.profile,
      tier: options.tier,
      dryRun: options.dryRun,
      verbose: options.verbose,
    });

    if (options.format === 'json') {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    } else {
      formatHardenResult(result, options.verbose ?? false);
    }

    return 0;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`harden-soul failed: ${message}\n`);
    return 1;
  }
}

// Critical SOUL controls that must pass in --strict mode
const CRITICAL_SOUL_CONTROLS = [
  'SOUL-IH-003', // Role-play refusal
  'SOUL-HB-001', // Safety immutables
];

/**
 * Find critical SOUL controls that are missing (not passing) in scan results.
 */
function findMissingCriticalControls(result: any): string[] {
  const missing: string[] = [];
  const domains = result.domains ?? [];

  // Build a set of all passing control IDs
  const passingIds = new Set<string>();
  for (const domain of domains) {
    for (const control of (domain.controls ?? [])) {
      if (control.passed) {
        passingIds.add(control.id ?? control.controlId ?? '');
      }
    }
  }

  for (const criticalId of CRITICAL_SOUL_CONTROLS) {
    if (!passingIds.has(criticalId)) {
      missing.push(criticalId);
    }
  }

  return missing;
}

function formatScanResult(result: any, verbose: boolean, strict = false): void {
  const score = result.score ?? result.overallScore ?? 0;
  const rawLevel = result.level ?? result.grade ?? 'unknown';
  const file = result.file ?? 'not found';
  const tier = result.agentTier ?? 'unknown';
  const profile = result.agentProfile ?? 'unknown';
  const totalControls = result.totalControls ?? 0;
  const passingControls = result.totalPassed ?? result.passingControls ?? 0;
  const profileMismatch = result.profileMismatch;

  // #136: detect partial scope from BOTH sources HMA exposes — the top-level
  // `skippedDomains` array AND the per-domain `skippedByProfile: true` flag.
  // Either alone is sufficient; relying on `skippedDomains` alone leaves a
  // bypass class if HMA changes which field it populates (adversarial review
  // C1, 2026-05-21).
  const domainsArray: any[] = Array.isArray(result.domains) ? result.domains : [];
  const skippedFromTopLevel: string[] = Array.isArray(result.skippedDomains) ? result.skippedDomains : [];
  const skippedFromPerDomain: string[] = domainsArray
    .filter((d: any) => d && d.skippedByProfile === true)
    .map((d: any) => String(d.domain ?? 'unknown'));
  // Union of both sources, dedup, stable order (top-level first).
  const skippedSet = new Set<string>(skippedFromTopLevel);
  for (const d of skippedFromPerDomain) skippedSet.add(d);
  const skippedDomains: string[] = Array.from(skippedSet);

  // Total domain count: prefer the actual domains array length; fall back
  // to a defensive non-zero value so we never emit "N of 0 domains" (which
  // would render as a negative `evaluatedDomains`).
  const totalDomains = domainsArray.length > 0
    ? domainsArray.length
    : Math.max(skippedDomains.length, 9); // 9 is HMA's current full-tier count
  const evaluatedDomains = Math.max(0, totalDomains - skippedDomains.length);
  const hasPartialScope = skippedDomains.length > 0;

  // #136: any non-empty absolute label gets downgraded when scope is
  // partial — `[hardened]`, `[HARDENED]`, `[standard]`, `[developing]`,
  // anything except `[initial]`/`[not-started]` would lie about the
  // analyzer's actual coverage. Case-insensitive match (adversarial review
  // H1) and apply to every level except the explicit "scan didn't run"
  // labels.
  const NON_ASSERTIVE_LEVELS = new Set(['initial', 'not-started', 'unknown']);
  const lowerLevel = String(rawLevel).toLowerCase();
  const displayLevel = hasPartialScope && !NON_ASSERTIVE_LEVELS.has(lowerLevel)
    ? `partial-${lowerLevel}`
    : rawLevel;

  process.stdout.write(`\nGovernance Score: ${score}/100 [${displayLevel}]\n`);
  process.stdout.write(`File: ${file}\n`);
  process.stdout.write(`Tier: ${tier} | Profile: ${profile}\n`);
  process.stdout.write(`Controls: ${passingControls}/${totalControls} passing\n`);
  if (hasPartialScope) {
    // Inline scope disclosure — required regardless of verbose mode so the
    // partial-scope state is visible to CISO-rule-11 readers. Closes #136.
    process.stdout.write(`Scope:    ${evaluatedDomains} of ${totalDomains} domains evaluated; ${skippedDomains.length} skipped: ${skippedDomains.join(', ')}\n`);
  }

  // #136: surface profile-mismatch as a prominent finding with severity +
  // checkId so the wrapper output matches HMA's direct render in signal
  // strength (adversarial review H2). HMA emits this as a HIGH
  // SOUL-PROFILE-MISMATCH finding when the declared profile narrows scope
  // past what the body content suggests. The opena2a wrapper previously
  // dropped it entirely; without the severity + checkId the CISO scanning
  // the output gets a weaker signal than `hackmyagent scan-soul` direct.
  if (profileMismatch && typeof profileMismatch === 'object') {
    const declared = profileMismatch.declaredProfile ?? profile;
    const inferred = profileMismatch.inferredProfile ?? 'unknown';
    const mismatchSkipped: string[] = Array.isArray(profileMismatch.skippedDomains)
      ? profileMismatch.skippedDomains
      : skippedDomains;
    process.stdout.write(`\nHIGH  SOUL-PROFILE-MISMATCH  Profile narrows scope past body content\n`);
    process.stdout.write(`      Declared profile=${declared} skips ${mismatchSkipped.length} domains; body suggests profile=${inferred}\n`);
    const signals: string[] = Array.isArray(profileMismatch.signals) ? profileMismatch.signals : [];
    if (signals.length > 0) {
      process.stdout.write(`      Signals: ${signals.slice(0, 3).join('; ')}${signals.length > 3 ? `; +${signals.length - 3} more` : ''}\n`);
    }
    if (mismatchSkipped.length > 0) {
      process.stdout.write(`      Skipped domains: ${mismatchSkipped.join(', ')}\n`);
    }
    process.stdout.write(`      Fix: remove the <!-- soul:profile=${declared} --> marker, or revise the body to match the declared profile.\n`);
  }

  if (result.domains && verbose) {
    process.stdout.write('\nDomain Breakdown:\n');
    for (const domain of result.domains) {
      const passed = domain.controls?.filter((c: any) => c.passed).length ?? 0;
      const total = domain.controls?.length ?? 0;
      const skippedMark = domain.skippedByProfile ? ' (skipped)' : '';
      process.stdout.write(`  ${domain.domain}: ${passed}/${total}${skippedMark}\n`);
    }
  }

  // Path forward
  if (score < 100 && totalControls > passingControls) {
    const recoverable = Math.min(100 - score, Math.round(((totalControls - passingControls) / totalControls) * 100));
    process.stdout.write(`\nPath forward: +${recoverable} recoverable by addressing ${totalControls - passingControls} controls\n`);
    process.stdout.write(`Run: opena2a harden-soul to auto-generate governance content\n`);
  }

  process.stdout.write('\n');
}

function formatHardenResult(result: any, verbose: boolean): void {
  const file = result.file ?? result.governanceFile ?? 'SOUL.md';
  const sectionsAdded = result.sectionsAdded ?? [];
  const controlsAdded = result.controlsAdded ?? 0;

  if (result.dryRun) {
    process.stdout.write('\n[Dry run] Would write governance to: ' + file + '\n');
  } else {
    process.stdout.write('\nGovernance written to: ' + file + '\n');
  }

  if (sectionsAdded.length > 0) {
    process.stdout.write(`Sections added: ${sectionsAdded.length}\n`);
    if (verbose) {
      for (const s of sectionsAdded) {
        process.stdout.write(`  + ${s}\n`);
      }
    }
  }

  process.stdout.write(`Controls covered: ${controlsAdded}\n`);
  process.stdout.write('\nRun: opena2a scan-soul to verify governance coverage\n\n');
}
