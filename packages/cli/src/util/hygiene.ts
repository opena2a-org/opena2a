/**
 * Hygiene checks — shared between init and protect.
 *
 * Runs the subset of hygiene checks needed for scoring:
 * .gitignore, .env protection, lock file, security config, MCP, AI config.
 *
 * Does NOT run: LLM server probe (slow), HMA shell checks (optional).
 * Those are only used in init's full assessment.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { scanMcpConfig, scanAiConfigFiles } from './ai-config.js';
import type { HygieneCheck } from './scoring.js';

/**
 * Run hygiene checks needed for security scoring.
 * Fast and synchronous (no network calls).
 */
export function runScoringChecks(dir: string, credCount: number): HygieneCheck[] {
  const checks: HygieneCheck[] = [];

  // Credential scan result
  if (credCount === 0) {
    checks.push({ label: 'Credential scan', status: 'pass', detail: 'no findings' });
  } else {
    checks.push({
      label: 'Credential scan',
      status: 'fail',
      detail: `${credCount} finding${credCount === 1 ? '' : 's'}`,
    });
  }

  // .gitignore
  const gitignorePath = path.join(dir, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    checks.push({ label: '.gitignore', status: 'pass', detail: 'present' });

    // .env protection
    const gitignoreContent = fs.readFileSync(gitignorePath, 'utf-8');
    if (gitignoreContent.includes('.env')) {
      checks.push({ label: '.env protection', status: 'pass', detail: 'in .gitignore' });
    } else {
      checks.push({ label: '.env protection', status: 'warn', detail: 'NOT in .gitignore' });
    }
  } else {
    checks.push({ label: '.gitignore', status: 'warn', detail: 'missing' });
    checks.push({ label: '.env protection', status: 'warn', detail: 'no .gitignore' });
  }

  // Lock file
  const lockFiles = [
    { file: 'package-lock.json', label: 'package-lock.json' },
    { file: 'yarn.lock', label: 'yarn.lock' },
    { file: 'pnpm-lock.yaml', label: 'pnpm-lock.yaml' },
    { file: 'bun.lockb', label: 'bun.lockb' },
    { file: 'go.sum', label: 'go.sum' },
    { file: 'poetry.lock', label: 'poetry.lock' },
    { file: 'Pipfile.lock', label: 'Pipfile.lock' },
  ];
  const foundLock = lockFiles.find(lf => fs.existsSync(path.join(dir, lf.file)));
  if (foundLock) {
    checks.push({ label: 'Lock file', status: 'pass', detail: foundLock.label });
  } else {
    checks.push({ label: 'Lock file', status: 'warn', detail: 'none found' });
  }

  // Security config
  const securityConfigs = ['.opena2a.yaml', '.opena2a.json', '.opena2a/guard/signatures.json'];
  const foundConfig = securityConfigs.find(sc => fs.existsSync(path.join(dir, sc)));
  if (foundConfig) {
    checks.push({ label: 'Security config', status: 'pass', detail: foundConfig });
  } else {
    checks.push({ label: 'Security config', status: 'info', detail: 'none' });
  }

  // MCP config findings
  for (const f of scanMcpConfig(dir)) {
    checks.push({ label: f.label, status: f.status, detail: f.detail });
  }

  // AI config exposure
  const aiCfg = scanAiConfigFiles(dir);
  if (aiCfg) checks.push({ label: aiCfg.label, status: aiCfg.status, detail: aiCfg.detail });

  return checks;
}
