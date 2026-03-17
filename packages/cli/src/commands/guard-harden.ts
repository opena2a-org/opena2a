/**
 * guard harden -- Scan SKILL.md and HEARTBEAT.md files for security issues
 * using the HackMyAgent HardeningScanner, with optional auto-fix.
 */

import * as path from 'node:path';
import { bold, green, yellow, red, dim, cyan } from '../util/colors.js';

// --- Types ---

export interface HardenOptions {
  skills?: boolean;
  heartbeats?: boolean;
  fix?: boolean;
  dryRun?: boolean;
  verbose?: boolean;
  ci?: boolean;
  format?: string;
}

interface HardenFinding {
  checkId: string;
  severity: string;
  name: string;
  fixable: boolean;
  fixed?: boolean;
  wouldFix?: boolean;
  message: string;
  file?: string;
}

interface HardenSummary {
  fixable: number;
  reviewNeeded: number;
  passed: number;
  fixed: number;
}

interface HardenReport {
  findings: HardenFinding[];
  summary: HardenSummary;
  fixed: boolean;
}

// --- Main ---

export async function guardHarden(targetDir: string, options: HardenOptions): Promise<number> {
  const resolvedDir = path.resolve(targetDir);
  const isJson = options.format === 'json';
  const includeSkills = options.skills !== false;
  const includeHeartbeats = options.heartbeats !== false;

  // Dynamic import of hackmyagent
  let hma: any;
  try {
    hma = await import('hackmyagent');
  } catch {
    const msg = 'HackMyAgent is required for skill hardening.\nInstall: npm install -g hackmyagent\n';
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: msg.trim() }, null, 2) + '\n');
    } else {
      process.stderr.write(red(msg));
    }
    return 1;
  }

  // Build ignore list: exclude everything EXCEPT SKILL-* and HEARTBEAT-* prefixes
  const allowPrefixes: string[] = [];
  if (includeSkills) allowPrefixes.push('SKILL-');
  if (includeHeartbeats) allowPrefixes.push('HEARTBEAT-');

  if (allowPrefixes.length === 0) {
    const msg = 'No check categories selected. Use --skills and/or --heartbeats.\n';
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: msg.trim() }, null, 2) + '\n');
    } else {
      process.stderr.write(yellow(msg));
    }
    return 1;
  }

  // Run the scan
  const scanner = new hma.HardeningScanner();

  // Build ignore list from all known check ID prefixes except the ones we want
  const allPrefixes = [
    'CRED-', 'GIT-', 'NET-', 'MCP-', 'CLAUDE-', 'FILE-', 'PERM-',
    'ENV-', 'LOG-', 'DEP-', 'AUTH-', 'PROC-', 'API-', 'SECRET-', 'IO-',
    'PROMPT-', 'INPUT-', 'RATE-', 'SESSION-', 'ENCRYPT-', 'AUDIT-',
    'SANDBOX-', 'TOOL-', 'CURSOR-', 'VSCODE-', 'GATEWAY-', 'CONFIG-',
    'SUPPLY-', 'CVE-',
  ];
  const ignorePrefixes = allPrefixes.filter(
    p => !allowPrefixes.some(a => p.startsWith(a))
  );

  let scanResult: any;
  try {
    scanResult = await scanner.scan({
      targetDir: resolvedDir,
      autoFix: options.fix || options.dryRun || false,
      dryRun: options.dryRun || false,
      ignore: [],
      cliName: 'opena2a',
    });
  } catch (err: any) {
    const msg = `Scan failed: ${err?.message ?? String(err)}\n`;
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: msg.trim() }, null, 2) + '\n');
    } else {
      process.stderr.write(red(msg));
    }
    return 1;
  }

  // Filter findings to only SKILL-* and HEARTBEAT-* checks
  const allFindings: HardenFinding[] = (scanResult.findings ?? [])
    .filter((f: any) => allowPrefixes.some(p => f.checkId?.startsWith(p)))
    .map((f: any) => ({
      checkId: f.checkId,
      severity: f.severity,
      name: f.name ?? f.description ?? f.checkId,
      fixable: f.fixable ?? false,
      fixed: f.fixed ?? false,
      wouldFix: f.wouldFix ?? false,
      message: f.message ?? f.description ?? '',
      file: f.file,
    }));

  // If no skill/heartbeat files found at all
  if (allFindings.length === 0) {
    // Check if there are passed findings too (from allFindings)
    const passedFindings = (scanResult.allFindings ?? [])
      .filter((f: any) => allowPrefixes.some(p => f.checkId?.startsWith(p)) && f.passed);

    if (passedFindings.length === 0) {
      if (isJson) {
        process.stdout.write(JSON.stringify({
          findings: [],
          summary: { fixable: 0, reviewNeeded: 0, passed: 0, fixed: 0 },
          fixed: false,
          message: 'No SKILL.md or HEARTBEAT.md files found.',
        }, null, 2) + '\n');
      } else {
        process.stdout.write('No SKILL.md or HEARTBEAT.md files found.\n');
      }
      return 0;
    }

    // All checks passed
    const summary: HardenSummary = { fixable: 0, reviewNeeded: 0, passed: passedFindings.length, fixed: 0 };
    if (isJson) {
      process.stdout.write(JSON.stringify({ findings: [], summary, fixed: false }, null, 2) + '\n');
    } else {
      process.stdout.write(bold('Skills Hardening Report') + '\n\n');
      process.stdout.write(green(`  All ${passedFindings.length} checks passed.`) + '\n\n');
    }
    return 0;
  }

  // Categorize findings
  const didFix = options.fix && !options.dryRun;
  const fixedFindings = allFindings.filter(f => f.fixed);
  const wouldFixFindings = allFindings.filter(f => f.wouldFix && !f.fixed);
  const fixableFindings = allFindings.filter(f => f.fixable && !f.fixed && !f.wouldFix);
  const reviewFindings = allFindings.filter(f => !f.fixable && !f.fixed);

  const summary: HardenSummary = {
    fixable: fixableFindings.length + wouldFixFindings.length,
    reviewNeeded: reviewFindings.length,
    passed: 0,
    fixed: fixedFindings.length,
  };

  // Count passed findings from allFindings if available
  const passedCount = (scanResult.allFindings ?? [])
    .filter((f: any) => allowPrefixes.some(p => f.checkId?.startsWith(p)) && f.passed)
    .length;
  summary.passed = passedCount;

  if (isJson) {
    const report: HardenReport = {
      findings: allFindings,
      summary,
      fixed: didFix ?? false,
    };
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    formatTextOutput(allFindings, summary, options);
  }

  // Return non-zero if there are unresolved findings
  const unresolvedCount = allFindings.filter(f => !f.fixed).length;
  return unresolvedCount > 0 ? 1 : 0;
}

// --- Text formatting ---

function formatTextOutput(findings: HardenFinding[], summary: HardenSummary, options: HardenOptions): void {
  process.stdout.write(bold('Skills Hardening Report') + '\n\n');

  // Group findings by file
  const byFile = new Map<string, HardenFinding[]>();
  for (const f of findings) {
    const key = f.file ?? '(unknown)';
    const list = byFile.get(key) ?? [];
    list.push(f);
    byFile.set(key, list);
  }

  for (const [file, fileFindings] of byFile) {
    const fixedAll = fileFindings.every(f => f.fixed);
    const count = fileFindings.length;

    if (fixedAll) {
      process.stdout.write(`  ${file.padEnd(24)} ${green('FIXED')}       ${dim(`[${count} issue${count !== 1 ? 's' : ''} fixed]`)}\n`);
    } else {
      process.stdout.write(`  ${file.padEnd(24)} ${yellow(`${count} finding${count !== 1 ? 's' : ''}`)}\n`);
    }

    for (const f of fileFindings) {
      const sevColor = f.severity === 'critical' ? red : f.severity === 'high' ? yellow : dim;
      const sevLabel = sevColor(f.severity.padEnd(10));

      if (f.fixed) {
        process.stdout.write(`    ${f.checkId}  ${sevLabel} ${green('Fixed:')} ${f.name}\n`);
      } else if (f.wouldFix) {
        process.stdout.write(`    ${f.checkId}  ${sevLabel} ${cyan('[would fix]')} ${f.name}\n`);
      } else if (f.fixable) {
        process.stdout.write(`    ${f.checkId}  ${sevLabel} ${f.name}    ${dim('[fixable]')}\n`);
      } else {
        process.stdout.write(`    ${f.checkId}  ${sevLabel} ${f.name}    ${dim('Review permissions')}\n`);
      }
    }
  }

  process.stdout.write('\n');

  // Summary line
  const parts: string[] = [];
  if (summary.fixed > 0) parts.push(green(`${summary.fixed} fixed`));
  if (summary.fixable > 0) parts.push(yellow(`${summary.fixable} fixable`));
  if (summary.reviewNeeded > 0) parts.push(red(`${summary.reviewNeeded} review-needed`));
  if (summary.passed > 0) parts.push(dim(`${summary.passed} passed`));

  process.stdout.write(`Summary: ${parts.join(' | ')}\n`);

  if (summary.fixable > 0 && !options.fix) {
    process.stdout.write(dim('Run: opena2a guard harden --fix\n'));
  }
  if (options.dryRun) {
    process.stdout.write(dim('(dry-run: no changes were made)\n'));
  }
}
