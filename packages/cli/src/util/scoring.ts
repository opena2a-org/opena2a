/**
 * Security score calculation — shared between init and protect.
 *
 * Extracted from init.ts to allow protect to compute before/after scores
 * without duplicating the scoring algorithm.
 */

import type { RiskLevel } from '../shield/types.js';

// --- Types ---

export interface HygieneCheck {
  label: string;
  status: 'pass' | 'warn' | 'fail' | 'info';
  detail: string;
}

export interface ScoreBreakdown {
  credentials: { deduction: number; detail: string };
  environment: { deduction: number; detail: string };
  configuration: { deduction: number; detail: string };
}

// --- Score calculation ---

export function calculateSecurityScore(
  credsBySeverity: Record<string, number>,
  checks: HygieneCheck[],
  hmaBySeverity?: Record<string, number>,
): { score: number; grade: string; breakdown: ScoreBreakdown } {
  // --- Credentials category (cap at -60) ---
  let credDeduction = 0;
  const critCount = (credsBySeverity['critical'] || 0);
  const highCount = (credsBySeverity['high'] || 0);
  const medCount = (credsBySeverity['medium'] || 0);
  const lowCount = (credsBySeverity['low'] || 0);

  // Diminishing returns: first finding costs more, subsequent cost less
  if (critCount > 0) {
    credDeduction += 20; // first critical
    credDeduction += Math.min((critCount - 1) * 8, 24); // subsequent critical, cap additional at 24
  }
  if (highCount > 0) {
    credDeduction += 12; // first high
    credDeduction += Math.min((highCount - 1) * 5, 15); // subsequent high, cap additional at 15
  }
  credDeduction += Math.min(medCount * 4, 20); // medium, cap at 20
  credDeduction += Math.min(lowCount * 2, 8); // low, cap at 8

  credDeduction = Math.min(credDeduction, 60); // category cap

  const credDetail = formatCredCount(critCount, highCount, medCount, lowCount);

  // --- Environment category (cap at -25) ---
  let envDeduction = 0;
  const llmCheck = checks.find(c => c.label === 'LLM server exposure');
  if (llmCheck?.status === 'warn') envDeduction += 10;

  const envProtection = checks.find(c => c.label === '.env protection');
  if (envProtection?.status === 'warn') envDeduction += 8;

  // MCP config findings
  const mcpToolsCheck = checks.find(c => c.label === 'MCP high-risk tools' && c.status === 'warn');
  if (mcpToolsCheck) envDeduction += 5;

  const mcpCredCheck = checks.find(c => c.label === 'MCP credentials' && c.status === 'warn');
  if (mcpCredCheck) envDeduction += 5;

  // AI config exposure
  const aiConfigCheck = checks.find(c => c.label === 'AI config exposure' && c.status === 'warn');
  if (aiConfigCheck) envDeduction += 3;

  // HMA shell findings
  if (hmaBySeverity) {
    envDeduction += Math.min((hmaBySeverity['critical'] || 0) * 10, 10);
    envDeduction += Math.min((hmaBySeverity['high'] || 0) * 6, 12);
    envDeduction += Math.min((hmaBySeverity['medium'] || 0) * 3, 9);
  }

  envDeduction = Math.min(envDeduction, 25); // category cap

  const envDetails: string[] = [];
  if (llmCheck?.status === 'warn') envDetails.push('LLM server exposed');
  if (envProtection?.status === 'warn') envDetails.push('.env unprotected');
  if (mcpToolsCheck) envDetails.push('MCP high-risk tools');
  if (mcpCredCheck) envDetails.push('MCP credentials');
  if (aiConfigCheck) envDetails.push('AI config exposed');
  if (hmaBySeverity && Object.keys(hmaBySeverity).length > 0) envDetails.push('shell findings');
  const envDetail = envDetails.length > 0 ? envDetails.join(', ') : 'clean';

  // --- Configuration category (cap at -15, bonus up to +5) ---
  let configDeduction = 0;
  const gitignoreCheck = checks.find(c => c.label === '.gitignore');
  if (gitignoreCheck?.status !== 'pass') configDeduction += 8;

  const lockCheck = checks.find(c => c.label === 'Lock file');
  if (lockCheck?.status !== 'pass') configDeduction += 4;

  const secConfig = checks.find(c => c.label === 'Security config');
  if (secConfig?.status !== 'pass') configDeduction += 3;

  // Bonus for having security config
  let configBonus = 0;
  if (secConfig?.status === 'pass') configBonus = 5;

  configDeduction = Math.min(configDeduction, 15); // category cap

  const configDetails: string[] = [];
  if (gitignoreCheck?.status !== 'pass') configDetails.push('no .gitignore');
  if (lockCheck?.status !== 'pass') configDetails.push('no lock file');
  if (secConfig?.status !== 'pass') configDetails.push('no security config');
  if (configBonus > 0) configDetails.push('security config present');
  const configDetail = configDetails.length > 0 ? configDetails.join(', ') : 'clean';

  const score = Math.max(0, Math.min(100, 100 - credDeduction - envDeduction - configDeduction + configBonus));

  let grade: string;
  if (score >= 90) grade = 'strong';
  else if (score >= 80) grade = 'good';
  else if (score >= 70) grade = 'moderate';
  else if (score >= 60) grade = 'improving';
  else grade = 'needs-attention';

  return {
    score,
    grade,
    breakdown: {
      credentials: { deduction: credDeduction, detail: credDetail },
      environment: { deduction: envDeduction, detail: envDetail },
      configuration: { deduction: configDeduction - configBonus, detail: configDetail },
    },
  };
}

export function formatCredCount(crit: number, high: number, med: number, low: number): string {
  const parts: string[] = [];
  if (crit > 0) parts.push(`${crit} critical`);
  if (high > 0) parts.push(`${high} high`);
  if (med > 0) parts.push(`${med} medium`);
  if (low > 0) parts.push(`${low} low`);
  return parts.length > 0 ? parts.join(', ') : 'none';
}

export function scoreToRiskLevel(score: number): RiskLevel {
  if (score >= 90) return 'SECURE';
  if (score >= 70) return 'LOW';
  if (score >= 50) return 'MEDIUM';
  if (score >= 30) return 'HIGH';
  return 'CRITICAL';
}
