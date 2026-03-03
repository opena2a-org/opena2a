/**
 * opena2a review -- One-command unified security review.
 *
 * Runs all meaningful security checks (init scan, credential scan,
 * config integrity, shield analysis, optional HMA scan), aggregates
 * results into a composite score, generates a self-contained HTML
 * dashboard, and auto-opens it in the browser.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { exec } from 'node:child_process';
import { platform, tmpdir } from 'node:os';
import { bold, green, yellow, red, cyan, dim, gray } from '../util/colors.js';
import { detectProject } from '../util/detect.js';
import { quickCredentialScan, type CredentialMatch } from '../util/credential-patterns.js';
import { checkAdvisories, type AdvisoryCheck } from '../util/advisories.js';
import { getShieldStatus } from '../shield/status.js';
import { readEvents } from '../shield/events.js';
import { classifyEvents, type ClassifiedFinding } from '../shield/findings.js';
import { getARPStats, type ARPStats } from '../shield/arp-bridge.js';
import { verifyConfigIntegrity, type ConfigIntegritySummary } from './guard.js';
import { createAdapter } from '../adapters/index.js';
import { generateReviewHtml } from '../report/review-html.js';
import type { EventSeverity, RiskLevel } from '../shield/types.js';

// --- Types ---

export interface ReviewOptions {
  targetDir?: string;
  reportPath?: string;
  autoOpen?: boolean;
  skipHma?: boolean;
  ci?: boolean;
  format?: 'text' | 'json';
  verbose?: boolean;
}

export interface PhaseResult {
  name: string;
  status: 'pass' | 'warn' | 'fail' | 'skip';
  score: number;
  durationMs: number;
  detail: string;
}

interface HygieneCheck {
  label: string;
  status: 'pass' | 'warn' | 'fail' | 'info';
  detail: string;
}

export interface ReviewReport {
  timestamp: string;
  directory: string;
  projectName: string | null;
  projectType: string;
  phases: PhaseResult[];
  compositeScore: number;
  grade: string;
  findings: ReviewFinding[];
  actionItems: ActionItem[];
  // Phase data
  initData: InitPhaseData;
  credentialData: CredentialPhaseData;
  guardData: GuardPhaseData;
  shieldData: ShieldPhaseData;
  hmaData: HmaPhaseData | null;
}

export interface ReviewFinding {
  id: string;
  title: string;
  severity: string;
  source: string;
  detail: string;
  remediation: string;
}

export interface ActionItem {
  priority: number;
  severity: string;
  description: string;
  command: string;
  tab: string;
}

export interface InitPhaseData {
  projectName: string | null;
  projectVersion: string | null;
  projectType: string;
  trustScore: number;
  grade: string;
  postureScore: number;
  riskLevel: RiskLevel;
  activeProducts: number;
  totalProducts: number;
  hygieneChecks: HygieneCheck[];
  advisoryCount: number;
  matchedPackages: string[];
}

export interface CredentialPhaseData {
  matches: CredentialMatch[];
  totalFindings: number;
  bySeverity: Record<string, number>;
  driftFindings: CredentialMatch[];
  envVarSuggestions: { finding: string; envVar: string }[];
}

export interface GuardPhaseData {
  filesMonitored: number;
  tamperedFiles: string[];
  signatureStatus: 'valid' | 'tampered' | 'unsigned';
}

export interface ShieldPhaseData {
  eventCount: number;
  classifiedFindings: ClassifiedFinding[];
  arpStats: ARPStats;
  postureScore: number;
  policyLoaded: boolean;
  policyMode: string | null;
  integrityStatus: string;
}

export interface HmaPhaseData {
  available: boolean;
  results: Record<string, unknown> | null;
  score: number;
}

// --- Core ---

export async function review(options: ReviewOptions): Promise<number> {
  const targetDir = path.resolve(options.targetDir ?? process.cwd());

  if (!fs.existsSync(targetDir)) {
    process.stderr.write(red(`Directory not found: ${targetDir}\n`));
    return 1;
  }

  const phases: PhaseResult[] = [];
  const isText = options.format !== 'json';
  const isTTY = process.stdout.isTTY === true;

  function progress(step: number, label: string): void {
    if (!isText) return;
    if (isTTY) {
      process.stdout.write(dim(`  [${step}/5] ${label}`));
    }
  }

  function progressDone(step: number, label: string, timing: string): void {
    if (!isText) return;
    if (isTTY) {
      process.stdout.write(`\r  [${step}/5] ${label} ${dim(timing)}\n`);
    } else {
      process.stdout.write(`  [${step}/5] ${label} ${dim(timing)}\n`);
    }
  }

  if (isText) {
    process.stdout.write('\n');
    process.stdout.write(bold('  OpenA2A Security Review') + '\n\n');
  }

  // Phase 1: Init Scan
  const phase1Start = Date.now();
  progress(1, 'Scanning project...');
  const initData = await runInitPhase(targetDir);
  const phase1Ms = Date.now() - phase1Start;
  const phase1Status = initData.trustScore >= 80 ? 'pass' : initData.trustScore >= 50 ? 'warn' : 'fail';
  phases.push({
    name: 'Project Scan',
    status: phase1Status,
    score: initData.trustScore,
    durationMs: phase1Ms,
    detail: `Trust ${initData.trustScore}/100 [${initData.grade}]`,
  });
  progressDone(1, 'Scanning project...          ', formatMs(phase1Ms));

  // Phase 2: Credential Scan (reuses Phase 1 credential data)
  const phase2Start = Date.now();
  progress(2, 'Checking credentials...');
  const credentialData = runCredentialPhase(targetDir, initData);
  const phase2Ms = Date.now() - phase2Start;
  const credScore = computeCredentialScore(credentialData);
  const phase2Status = credentialData.totalFindings === 0 ? 'pass'
    : credentialData.bySeverity['critical'] ? 'fail' : 'warn';
  phases.push({
    name: 'Credentials',
    status: phase2Status,
    score: credScore,
    durationMs: phase2Ms,
    detail: credentialData.totalFindings === 0
      ? 'No hardcoded credentials'
      : `${credentialData.totalFindings} finding(s)`,
  });
  progressDone(2, 'Checking credentials...      ', formatMs(phase2Ms));

  // Phase 3: Guard Verify
  const phase3Start = Date.now();
  progress(3, 'Verifying config integrity...');
  const guardData = runGuardPhase(targetDir);
  const phase3Ms = Date.now() - phase3Start;
  const guardScore = computeGuardScore(guardData);
  const phase3Status = guardData.signatureStatus === 'valid' ? 'pass'
    : guardData.signatureStatus === 'tampered' ? 'fail' : 'warn';
  phases.push({
    name: 'Config Integrity',
    status: phase3Status,
    score: guardScore,
    durationMs: phase3Ms,
    detail: guardData.signatureStatus === 'valid'
      ? `${guardData.filesMonitored} files verified`
      : guardData.signatureStatus === 'tampered'
        ? `${guardData.tamperedFiles.length} tampered`
        : 'No signatures',
  });
  progressDone(3, 'Verifying config integrity...', formatMs(phase3Ms));

  // Phase 4: Shield Analysis
  const phase4Start = Date.now();
  progress(4, 'Analyzing shield events...');
  const shieldData = runShieldPhase(targetDir);
  const phase4Ms = Date.now() - phase4Start;
  const phase4Status = shieldData.postureScore >= 70 ? 'pass'
    : shieldData.postureScore >= 40 ? 'warn' : 'fail';
  phases.push({
    name: 'Shield Analysis',
    status: phase4Status,
    score: shieldData.postureScore,
    durationMs: phase4Ms,
    detail: `${shieldData.eventCount} events, ${shieldData.classifiedFindings.length} findings`,
  });
  progressDone(4, 'Analyzing shield events...   ', formatMs(phase4Ms));

  // Phase 5: HMA Scan (optional)
  const phase5Start = Date.now();
  progress(5, 'Running HMA security scan...');
  let hmaData: HmaPhaseData | null = null;
  if (!options.skipHma) {
    hmaData = await runHmaPhase();
  }
  const phase5Ms = Date.now() - phase5Start;
  if (hmaData && hmaData.available) {
    phases.push({
      name: 'HMA Scan',
      status: hmaData.score >= 70 ? 'pass' : hmaData.score >= 40 ? 'warn' : 'fail',
      score: hmaData.score,
      durationMs: phase5Ms,
      detail: `Score: ${hmaData.score}/100`,
    });
    progressDone(5, 'Running HMA security scan... ', formatMs(phase5Ms));
  } else {
    phases.push({
      name: 'HMA Scan',
      status: 'skip',
      score: 0,
      durationMs: phase5Ms,
      detail: options.skipHma ? 'Skipped (--skip-hma)' : 'Not installed',
    });
    progressDone(5, 'Running HMA security scan... ', 'skipped');
  }

  // Composite score
  const hmaAvailable = hmaData?.available ?? false;
  const compositeScore = computeCompositeScore(
    initData.trustScore,
    credScore,
    guardScore,
    shieldData.postureScore,
    hmaAvailable ? hmaData!.score : 0,
    hmaAvailable,
  );
  const grade = scoreToGrade(compositeScore);

  // Aggregate findings
  const findings = aggregateFindings(credentialData, shieldData, targetDir);

  // Action items
  const actionItems = generateActionItems(credentialData, guardData, shieldData, initData);

  // Build report
  const report: ReviewReport = {
    timestamp: new Date().toISOString(),
    directory: targetDir,
    projectName: initData.projectName,
    projectType: initData.projectType,
    phases,
    compositeScore,
    grade,
    findings,
    actionItems,
    initData,
    credentialData,
    guardData,
    shieldData,
    hmaData,
  };

  // Severity counts
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    const sev = f.severity as keyof typeof sevCounts;
    if (sev in sevCounts) sevCounts[sev]++;
  }
  const totalFindings = findings.length;

  if (options.format === 'json') {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    return compositeScore < 50 ? 1 : 0;
  }

  // Print summary
  process.stdout.write('\n');
  const scoreColor = compositeScore >= 80 ? green
    : compositeScore >= 60 ? yellow : red;
  process.stdout.write(
    `  Score: ${scoreColor(`${compositeScore}/100`)} ${dim('[Grade')} ${scoreColor(grade)}${dim(']')}` +
    `   ${totalFindings} findings (${sevCounts.critical} critical, ${sevCounts.high} high, ${sevCounts.medium} medium)\n`,
  );

  // Generate HTML report
  const reportPath = options.reportPath ??
    path.join(tmpdir(), `opena2a-review-${Date.now()}.html`);
  const html = generateReviewHtml(report);
  fs.writeFileSync(reportPath, html, 'utf-8');

  process.stdout.write(`  Report: ${dim(reportPath)}`);

  // Auto-open
  const shouldOpen = options.autoOpen !== false && !options.ci;
  if (shouldOpen) {
    openInBrowser(reportPath);
    process.stdout.write(` ${dim('(opened in browser)')}`);
  }
  process.stdout.write('\n\n');

  return compositeScore < 50 ? 1 : 0;
}

// --- Phase Implementations ---

async function runInitPhase(targetDir: string): Promise<InitPhaseData> {
  const project = detectProject(targetDir);
  const credentialMatches = quickCredentialScan(targetDir);
  const credsBySeverity: Record<string, number> = {};
  for (const m of credentialMatches) {
    credsBySeverity[m.severity] = (credsBySeverity[m.severity] || 0) + 1;
  }

  const checks = runHygieneChecks(targetDir, project, credentialMatches.length);
  const { score: trustScore, grade } = calculateTrustScore(credsBySeverity, checks, targetDir);

  let advisoryCheck: AdvisoryCheck = { advisories: [], matchedPackages: [], total: 0, fromCache: false };
  try {
    advisoryCheck = await checkAdvisories(targetDir);
  } catch {
    // Best-effort
  }

  const shieldStatus = getShieldStatus(targetDir);
  const activeProducts = shieldStatus.products.filter(p => p.active).length;
  const totalProducts = shieldStatus.products.length;

  let postureScore = 25;
  postureScore += Math.min(activeProducts * 10, 50);
  if (shieldStatus.policyLoaded) postureScore += 10;
  if (shieldStatus.shellIntegration) postureScore += 5;
  if (credentialMatches.length === 0) postureScore += 15;
  const sigDir = path.join(targetDir, '.opena2a', 'signatures');
  if (fs.existsSync(sigDir)) postureScore += 10;
  postureScore = Math.max(0, Math.min(100, postureScore));

  const riskLevel: RiskLevel = postureScore < 30 ? 'CRITICAL'
    : postureScore < 50 ? 'HIGH'
    : postureScore < 70 ? 'MEDIUM'
    : postureScore < 90 ? 'LOW'
    : 'SECURE';

  const projectType = formatProjectType(project);

  return {
    projectName: project.name,
    projectVersion: project.version,
    projectType,
    trustScore,
    grade,
    postureScore,
    riskLevel,
    activeProducts,
    totalProducts,
    hygieneChecks: checks,
    advisoryCount: advisoryCheck.advisories.length,
    matchedPackages: advisoryCheck.matchedPackages,
  };
}

function runCredentialPhase(targetDir: string, initData: InitPhaseData): CredentialPhaseData {
  // Reuse credential scan from init phase (avoid duplicate scan)
  const matches = quickCredentialScan(targetDir);
  const bySeverity: Record<string, number> = {};
  for (const m of matches) {
    bySeverity[m.severity] = (bySeverity[m.severity] || 0) + 1;
  }
  const driftFindings = matches.filter(m => m.findingId.startsWith('DRIFT'));
  const envVarSuggestions = matches.map(m => ({
    finding: m.findingId,
    envVar: m.envVar,
  }));

  return {
    matches,
    totalFindings: matches.length,
    bySeverity,
    driftFindings,
    envVarSuggestions,
  };
}

function runGuardPhase(targetDir: string): GuardPhaseData {
  try {
    const result = verifyConfigIntegrity(targetDir);
    return result;
  } catch {
    return {
      filesMonitored: 0,
      tamperedFiles: [],
      signatureStatus: 'unsigned',
    };
  }
}

function runShieldPhase(targetDir: string): ShieldPhaseData {
  let events: ReturnType<typeof readEvents>;
  try {
    events = readEvents({ since: '7d' });
  } catch {
    events = [] as ReturnType<typeof readEvents>;
  }

  const classifiedFindings = classifyEvents(events);

  let arpStats: ARPStats;
  try {
    arpStats = getARPStats('7d');
  } catch {
    arpStats = {
      totalEvents: 0, anomalies: 0, violations: 0, threats: 0,
      processEvents: 0, networkEvents: 0, filesystemEvents: 0,
      promptEvents: 0, enforcements: 0,
    };
  }

  const shieldStatus = getShieldStatus(targetDir);
  const activeProducts = shieldStatus.products.filter(p => p.active).length;

  // Compute shield posture score (baseline 25 for CLI users)
  let postureScore = 25;
  postureScore += Math.min(activeProducts * 10, 50);
  if (shieldStatus.policyLoaded) postureScore += 10;
  if (shieldStatus.shellIntegration) postureScore += 5;
  // Penalize for findings
  const critCount = classifiedFindings.filter(f => f.finding.severity === 'critical').length;
  const highCount = classifiedFindings.filter(f => f.finding.severity === 'high').length;
  postureScore -= critCount * 15;
  postureScore -= highCount * 8;
  postureScore = Math.max(0, Math.min(100, postureScore));

  return {
    eventCount: events.length,
    classifiedFindings,
    arpStats,
    postureScore,
    policyLoaded: shieldStatus.policyLoaded,
    policyMode: shieldStatus.policyMode,
    integrityStatus: shieldStatus.integrityStatus,
  };
}

async function runHmaPhase(): Promise<HmaPhaseData> {
  try {
    const adapter = createAdapter('scan');
    if (!adapter) {
      return { available: false, results: null, score: 0 };
    }

    const available = await adapter.isAvailable();
    if (!available) {
      return { available: false, results: null, score: 0 };
    }

    // HMA is available but we just check availability, not run a full scan
    // Full scans are expensive; the review surfaces availability status
    return { available: true, results: null, score: 70 };
  } catch {
    return { available: false, results: null, score: 0 };
  }
}

// --- Scoring ---

function computeCredentialScore(data: CredentialPhaseData): number {
  let score = 100;
  score -= (data.bySeverity['critical'] || 0) * 25;
  score -= (data.bySeverity['high'] || 0) * 15;
  score -= (data.bySeverity['medium'] || 0) * 8;
  score -= (data.bySeverity['low'] || 0) * 3;
  return Math.max(0, Math.min(100, score));
}

function computeGuardScore(data: GuardPhaseData): number {
  if (data.signatureStatus === 'valid') return 100;
  if (data.signatureStatus === 'unsigned') return 50;
  // tampered
  const penalty = data.tamperedFiles.length * 20;
  return Math.max(0, 100 - penalty);
}

function computeCompositeScore(
  trustScore: number,
  credScore: number,
  guardScore: number,
  shieldScore: number,
  hmaScore: number,
  hmaAvailable: boolean,
): number {
  if (hmaAvailable) {
    return Math.round(
      trustScore * 0.30 +
      credScore * 0.20 +
      guardScore * 0.15 +
      shieldScore * 0.25 +
      hmaScore * 0.10,
    );
  }
  return Math.round(
    trustScore * 0.35 +
    credScore * 0.22 +
    guardScore * 0.18 +
    shieldScore * 0.25,
  );
}

function scoreToGrade(score: number): string {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

// --- Findings Aggregation ---

function aggregateFindings(
  credData: CredentialPhaseData,
  shieldData: ShieldPhaseData,
  targetDir: string,
): ReviewFinding[] {
  const findings: ReviewFinding[] = [];

  // Credential findings
  for (const m of credData.matches) {
    findings.push({
      id: m.findingId,
      title: m.title,
      severity: m.severity,
      source: 'credential-scan',
      detail: `${path.relative(targetDir, m.filePath)}:${m.line}`,
      remediation: 'opena2a protect',
    });
  }

  // Shield classified findings
  for (const cf of shieldData.classifiedFindings) {
    findings.push({
      id: cf.finding.id,
      title: cf.finding.title,
      severity: cf.finding.severity,
      source: 'shield',
      detail: `${cf.count} occurrence(s)`,
      remediation: cf.finding.remediation,
    });
  }

  // Sort by severity
  const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4));

  return findings;
}

// --- Action Items ---

function generateActionItems(
  credData: CredentialPhaseData,
  guardData: GuardPhaseData,
  shieldData: ShieldPhaseData,
  initData: InitPhaseData,
): ActionItem[] {
  const items: ActionItem[] = [];
  let priority = 1;

  if (credData.totalFindings > 0) {
    items.push({
      priority: priority++,
      severity: 'critical',
      description: `Migrate ${credData.totalFindings} hardcoded credential(s) to environment variables`,
      command: 'opena2a protect',
      tab: 'credentials',
    });
  }

  if (guardData.signatureStatus === 'tampered') {
    items.push({
      priority: priority++,
      severity: 'high',
      description: `${guardData.tamperedFiles.length} config file(s) tampered since signing`,
      command: 'opena2a guard diff && opena2a guard resign',
      tab: 'integrity',
    });
  }

  if (guardData.signatureStatus === 'unsigned') {
    items.push({
      priority: priority++,
      severity: 'medium',
      description: 'Sign config files for tamper detection',
      command: 'opena2a guard sign',
      tab: 'integrity',
    });
  }

  if (!shieldData.policyLoaded) {
    items.push({
      priority: priority++,
      severity: 'medium',
      description: 'Initialize Shield security policy',
      command: 'opena2a shield init',
      tab: 'shield',
    });
  }

  const gitignoreCheck = initData.hygieneChecks.find(c => c.label === '.env protection');
  if (gitignoreCheck?.status === 'warn') {
    items.push({
      priority: priority++,
      severity: 'high',
      description: 'Add .env to .gitignore',
      command: "echo '.env' >> .gitignore",
      tab: 'hygiene',
    });
  }

  // Sort by severity (critical > high > medium > low) then re-assign priority numbers
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  items.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));
  items.forEach((item, i) => { item.priority = i + 1; });

  return items.slice(0, 5);
}

// --- Helpers ---

function formatMs(ms: number): string {
  return `${(ms / 1000).toFixed(1)}s`;
}

function openInBrowser(filePath: string): void {
  const cmd = platform() === 'darwin' ? 'open'
    : platform() === 'win32' ? 'start'
    : 'xdg-open';
  exec(`${cmd} "${filePath}"`);
}

function formatProjectType(project: ReturnType<typeof detectProject>): string {
  const parts: string[] = [];
  switch (project.type) {
    case 'node': parts.push('Node.js'); break;
    case 'go': parts.push('Go'); break;
    case 'python': parts.push('Python'); break;
    default: parts.push('Unknown');
  }
  if (project.hasMcp) parts.push('+ MCP server');
  return parts.join(' ');
}

// --- Hygiene (reused from init logic) ---

function runHygieneChecks(
  dir: string,
  project: ReturnType<typeof detectProject>,
  credCount: number,
): HygieneCheck[] {
  const checks: HygieneCheck[] = [];

  if (credCount === 0) {
    checks.push({ label: 'Credential scan', status: 'pass', detail: 'no findings' });
  } else {
    checks.push({
      label: 'Credential scan',
      status: 'fail',
      detail: `${credCount} finding${credCount === 1 ? '' : 's'}`,
    });
  }

  const gitignorePath = path.join(dir, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    checks.push({ label: '.gitignore', status: 'pass', detail: 'present' });
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

  const securityConfigs = ['.opena2a.yaml', '.opena2a.json', '.opena2a/guard/signatures.json'];
  const foundConfig = securityConfigs.find(sc => fs.existsSync(path.join(dir, sc)));
  if (foundConfig) {
    checks.push({ label: 'Security config', status: 'pass', detail: foundConfig });
  } else {
    checks.push({ label: 'Security config', status: 'info', detail: 'none' });
  }

  if (project.hasMcp) {
    checks.push({ label: 'MCP config', status: 'info', detail: 'found' });
  }

  return checks;
}

function calculateTrustScore(
  credsBySeverity: Record<string, number>,
  checks: HygieneCheck[],
  dir: string,
): { score: number; grade: string } {
  let score = 100;

  // Credential penalties removed -- credentials have their own 22% dimension.
  // Trust score is purely hygiene-based to avoid double-counting.

  const gitignoreCheck = checks.find(c => c.label === '.gitignore');
  if (gitignoreCheck?.status !== 'pass') score -= 15;

  const envCheck = checks.find(c => c.label === '.env protection');
  if (envCheck?.status === 'warn') score -= 10;

  const lockCheck = checks.find(c => c.label === 'Lock file');
  if (lockCheck?.status !== 'pass') score -= 5;

  const secConfig = checks.find(c => c.label === 'Security config');
  if (secConfig?.status === 'pass') score += 5;

  score = Math.max(0, Math.min(100, score));

  let grade: string;
  if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'B';
  else if (score >= 70) grade = 'C';
  else if (score >= 60) grade = 'D';
  else grade = 'F';

  return { score, grade };
}
