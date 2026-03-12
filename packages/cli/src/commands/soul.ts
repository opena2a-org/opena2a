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
      formatScanResult(result, options.verbose ?? false);
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

function formatScanResult(result: any, verbose: boolean): void {
  const score = result.score ?? result.overallScore ?? 0;
  const level = result.level ?? result.grade ?? 'unknown';
  const file = result.file ?? 'not found';
  const tier = result.agentTier ?? 'unknown';
  const profile = result.agentProfile ?? 'unknown';
  const totalControls = result.totalControls ?? 0;
  const passingControls = result.totalPassed ?? result.passingControls ?? 0;

  process.stdout.write(`\nGovernance Score: ${score}/100 [${level}]\n`);
  process.stdout.write(`File: ${file}\n`);
  process.stdout.write(`Tier: ${tier} | Profile: ${profile}\n`);
  process.stdout.write(`Controls: ${passingControls}/${totalControls} passing\n`);

  if (result.domains && verbose) {
    process.stdout.write('\nDomain Breakdown:\n');
    for (const domain of result.domains) {
      const passed = domain.controls?.filter((c: any) => c.passed).length ?? 0;
      const total = domain.controls?.length ?? 0;
      process.stdout.write(`  ${domain.domain}: ${passed}/${total}\n`);
    }
  }

  if (result.skippedDomains?.length > 0 && verbose) {
    process.stdout.write(`\nSkipped domains (not applicable to ${profile} profile):\n`);
    for (const d of result.skippedDomains) {
      process.stdout.write(`  ${d}\n`);
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
