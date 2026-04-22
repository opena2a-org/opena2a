/**
 * opena2a review -- One-command unified security review.
 *
 * Runs all meaningful security checks (init scan, credential scan,
 * config integrity, shield analysis, optional HMA scan, shadow AI
 * detection), aggregates results into a composite score, generates
 * a self-contained HTML dashboard, and auto-opens it in the browser.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { platform, tmpdir } from 'node:os';
import { bold, green, yellow, red, cyan, dim, gray } from '../util/colors.js';

/** Local structural subset of @opena2a/cli-ui types. Duplicated here
 *  because this package is CJS and cli-ui is ESM; static type imports
 *  from ESM require a resolution-mode attribute unsupported by our
 *  toolchain. The shape matches cli-ui's CategorizableFinding + VerdictFinding
 *  exactly so the runtime values flow through unchanged. */
type LocalSeverity = 'critical' | 'high' | 'medium' | 'low';
interface LocalCategorizableFinding {
  checkId?: string;
  name?: string;
  category?: string;
  passed: boolean;
  severity: LocalSeverity;
}
interface LocalVerdictFinding {
  severity: LocalSeverity;
  name?: string;
  checkId?: string;
  file?: string;
  line?: number;
}
import { detectProject } from '../util/detect.js';
import { quickCredentialScan, type CredentialMatch } from '../util/credential-patterns.js';
import { checkAdvisories, type AdvisoryCheck } from '../util/advisories.js';
import { getShieldStatus } from '../shield/status.js';
import { readEvents } from '../shield/events.js';
import { classifyEvents, type ClassifiedFinding } from '../shield/findings.js';
import { getARPStats, type ARPStats } from '../shield/arp-bridge.js';
import { verifyConfigIntegrity, type ConfigIntegritySummary } from './guard.js';
import { calculateGovernanceScore } from '../util/governance-scoring.js';
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
  grade: string; // kept for backward compat in JSON; not displayed as letter grade in CLI/HTML
  recoverySummary: RecoverySummary;
  findings: ReviewFinding[];
  actionItems: ActionItem[];
  // Phase data
  initData: InitPhaseData;
  credentialData: CredentialPhaseData;
  guardData: GuardPhaseData;
  shieldData: ShieldPhaseData;
  hmaData: HmaPhaseData | null;
  detectData: DetectPhaseData;
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
  activeTools: number;
  totalTools: number;
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

export interface HmaFinding {
  checkId: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  passed: boolean;
  message: string;
  file?: string;
  line?: number;
  fixable: boolean;
  fix: string;
  guidance: string;
  count: number;
  sampleFiles: string[];
}

export interface HmaPhaseData {
  available: boolean;
  score: number;
  maxScore: number;
  totalChecks: number;
  passed: number;
  failed: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  /** Top 30 findings, deduped by checkId, for the HMA tab in the HTML report.
   *  Display-only — do NOT use for severity counts. See allFailedFindings. */
  topFindings: HmaFinding[];
  /** Every failed HMA finding (not deduped, not capped). Used by aggregateFindings.
   *  topFindings keeps the deduped-by-checkId + slice(0,30) list for the HMA tab
   *  in the HTML report; this field preserves the raw set so the Observations
   *  block and overview severity counts match `hackmyagent secure`. */
  allFailedFindings: HmaFinding[];
}

export interface DetectPhaseData {
  governanceScore: number;
  agents: { name: string; category: string; identityStatus: string; governanceStatus: string }[];
  mcpServers: { name: string; transport: string; source: string; verified: boolean; capabilities: string[]; risk: string }[];
  aiConfigs: { file: string; tool: string; risk: string; details: string }[];
  identity: { aimIdentities: number; mcpIdentities: number; soulFiles: number; capabilityPolicies: number };
  findings: { severity: string; title: string; whyItMatters: string; remediation: string }[];
  recoverablePoints: number;
}

export interface RecoveryOpportunity {
  dimension: string;
  pointsRecoverable: number;
  action: string;
}

export interface RecoverySummary {
  currentScore: number;
  potentialScore: number;
  totalRecoverable: number;
  opportunities: RecoveryOpportunity[];
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
      process.stdout.write(dim(`  [${step}/6] ${label}`));
    }
  }

  function progressDone(step: number, label: string, timing: string): void {
    if (!isText) return;
    if (isTTY) {
      process.stdout.write(`\r  [${step}/6] ${label} ${dim(timing)}\n`);
    } else {
      process.stdout.write(`  [${step}/6] ${label} ${dim(timing)}\n`);
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
    detail: `Trust ${initData.trustScore}/100`,
  });
  progressDone(1, 'Scanning project...          ', formatMs(phase1Ms));

  // Phase 2: Credential Scan (reuses Phase 1 credential data)
  const phase2Start = Date.now();
  progress(2, 'Checking credentials...');
  const credentialData = runCredentialPhase(targetDir);
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
    hmaData = await runHmaPhase(targetDir);
  }
  const phase5Ms = Date.now() - phase5Start;
  if (hmaData && hmaData.available) {
    phases.push({
      name: 'HMA Scan',
      status: hmaData.score >= 70 ? 'pass' : hmaData.score >= 40 ? 'warn' : 'fail',
      score: hmaData.score,
      durationMs: phase5Ms,
      detail: `${hmaData.score}/${hmaData.maxScore} (${hmaData.failed} issues)`,
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

  // Phase 6: Shadow AI Detection
  const phase6Start = Date.now();
  progress(6, 'Detecting shadow AI...');
  const detectData = await runDetectPhase(targetDir);
  const phase6Ms = Date.now() - phase6Start;
  const phase6Status = detectData.governanceScore >= 70 ? 'pass'
    : detectData.governanceScore >= 40 ? 'warn' : 'fail';
  phases.push({
    name: 'Shadow AI',
    status: phase6Status,
    score: detectData.governanceScore,
    durationMs: phase6Ms,
    detail: `Governance ${detectData.governanceScore}/100`,
  });
  progressDone(6, 'Detecting shadow AI...       ', formatMs(phase6Ms));

  // Composite score
  const hmaAvailable = hmaData?.available ?? false;
  const compositeScore = computeCompositeScore(
    initData.trustScore,
    credScore,
    guardScore,
    shieldData.postureScore,
    hmaAvailable ? hmaData!.score : 0,
    hmaAvailable,
    detectData.governanceScore,
  );
  const grade = scoreToGrade(compositeScore);
  const recoverySummary = computeRecoverySummary(
    initData.trustScore, credScore, guardScore,
    shieldData.postureScore, hmaAvailable ? hmaData!.score : 0,
    hmaAvailable, compositeScore, detectData.governanceScore,
  );

  // Aggregate findings
  const findings = aggregateFindings(credentialData, shieldData, targetDir, hmaData);

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
    recoverySummary,
    findings,
    actionItems,
    initData,
    credentialData,
    guardData,
    shieldData,
    hmaData,
    detectData,
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
  // Recovery-framed output: show path forward, not punitive grade
  const topRecovery = recoverySummary.opportunities.slice(0, 3)
    .map(o => `+${o.pointsRecoverable} ${o.dimension.toLowerCase()}`)
    .join(', ');
  const recoveryHint = recoverySummary.totalRecoverable > 0
    ? ` -- path to ${recoverySummary.potentialScore} available (${topRecovery})`
    : '';
  process.stdout.write(
    `  Score: ${scoreColor(`${compositeScore}/100`)}${dim(recoveryHint)}` +
    `\n  ${totalFindings} findings (${sevCounts.critical} critical, ${sevCounts.high} high, ${sevCounts.medium} medium)\n`,
  );

  // ── Observations + Verdict ──────────────────────────────────────────
  // Shared block from @opena2a/cli-ui so review/scan output stays
  // consistent with hackmyagent secure output per [CA-030]. Dynamic
  // import because cli-ui is ESM and this package is CJS (same pattern
  // as @opena2a/shared / @opena2a/contribute usage elsewhere).
  try {
    const cliUi = await import('@opena2a/cli-ui');
    const projectLabel = report.projectType && report.projectType !== 'unknown'
      ? report.projectType
      : 'project';
    const categorizable: LocalCategorizableFinding[] = findings.map(f => ({
      checkId: f.id,
      name: f.title,
      category: f.source,
      passed: false,
      severity: f.severity as LocalSeverity,
    }));
    const verdictFindings: LocalVerdictFinding[] = findings.map(f => ({
      severity: f.severity as LocalSeverity,
      name: f.title,
      checkId: f.id,
    }));
    const categorySummaries = cliUi.buildCategorySummaries(categorizable);
    const verdict = cliUi.buildVerdict(
      { critical: sevCounts.critical, high: sevCounts.high, medium: sevCounts.medium, low: sevCounts.low },
      { kind: projectLabel },
      verdictFindings,
    );
    const { lines } = cliUi.renderObservationsBlock({
      surfaces: { kind: projectLabel },
      checks: {
        staticCount: phases.length,
        semanticCount: 0,
      },
      categories: categorySummaries,
      verdict,
      verbose: !!options.verbose,
    });
    process.stdout.write('\n');
    const toneColor = (tone: 'default' | 'good' | 'warning' | 'critical'): (s: string) => string => {
      if (tone === 'good') return green;
      if (tone === 'warning') return yellow;
      if (tone === 'critical') return red;
      return (s: string): string => s;
    };
    const LABEL_WIDTH = 12;
    for (const line of lines) {
      const labelPad = line.label.padEnd(LABEL_WIDTH, ' ');
      const color = toneColor(line.tone);
      process.stdout.write(`  ${dim(labelPad)}${color(line.value)}\n`);
    }
    process.stdout.write('\n');
  } catch (err: unknown) {
    // cli-ui import failed — non-critical, skip the Observations block.
    // The existing Score + findings summary above still carries the result.
    // Log in verbose mode so debugging isn't silent.
    if (options.verbose) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(dim(`  [observations] skipped — ${msg}\n`));
    }
  }

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

  // Community contribution
  try {
    const { recordScanAndMaybePrompt, isContributeEnabled, getRegistryUrl, submitScanReport } =
      await import('../util/report-submission.js');
    await recordScanAndMaybePrompt();

    if (await isContributeEnabled()) {
      const registryUrl = await getRegistryUrl();
      if (registryUrl) {
        await submitScanReport(registryUrl, {
          packageName: report.projectName ?? 'unknown',
          packageType: report.projectType ?? 'unknown',
          scannerName: 'opena2a-review',
          scannerVersion: '0.6.3',
          overallScore: compositeScore,
          scanDurationMs: phases.reduce((sum, p) => sum + p.durationMs, 0),
          criticalCount: sevCounts.critical,
          highCount: sevCounts.high,
          mediumCount: sevCounts.medium,
          lowCount: sevCounts.low,
          infoCount: 0,
          verdict: compositeScore >= 80 ? 'pass' : compositeScore >= 50 ? 'warnings' : 'fail',
          findings: findings.map((f, i) => ({
            findingId: f.id || `REVIEW-${String(i + 1).padStart(3, '0')}`,
            severity: f.severity,
            category: f.source,
            title: f.title,
            description: f.detail,
          })),
        }, options.verbose);
      }
    }
  } catch {
    // Non-critical
  }

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
  const activeTools = shieldStatus.tools.filter(p => p.active).length;
  const totalTools = shieldStatus.tools.length;

  let postureScore = 25;
  postureScore += Math.min(activeTools * 10, 50);
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
    activeTools,
    totalTools,
    hygieneChecks: checks,
    advisoryCount: advisoryCheck.advisories.length,
    matchedPackages: advisoryCheck.matchedPackages,
  };
}

function runCredentialPhase(targetDir: string): CredentialPhaseData {
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
  const activeTools = shieldStatus.tools.filter(p => p.active).length;

  // Compute shield posture score (baseline 25 for CLI users)
  let postureScore = 25;
  postureScore += Math.min(activeTools * 10, 50);
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

async function runHmaPhase(targetDir: string): Promise<HmaPhaseData> {
  const emptyResult: HmaPhaseData = {
    available: false, score: 0, maxScore: 100,
    totalChecks: 0, passed: 0, failed: 0,
    bySeverity: {}, byCategory: {}, topFindings: [], allFailedFindings: [],
  };

  try {
    const versionCheck = await new Promise<boolean>((resolve) => {
      const proc = spawn('npx', ['hackmyagent', '--version'], { stdio: 'pipe' });
      proc.on('close', (code) => resolve(code === 0));
      proc.on('error', () => resolve(false));
    });
    if (!versionCheck) return emptyResult;

    const output = await new Promise<string>((resolve, reject) => {
      const proc = spawn('npx', ['hackmyagent', 'secure', '--format', 'json', targetDir], {
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 120_000,
      });
      let stdout = '';
      proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
      proc.on('close', () => resolve(stdout));
      proc.on('error', reject);
    });

    const parsed = JSON.parse(output);
    const allFindings: HmaFinding[] = (parsed.findings || []).map((f: Record<string, unknown>) => ({
      checkId: (f.checkId as string) ?? '',
      name: (f.name as string) ?? '',
      description: (f.description as string) ?? '',
      category: (f.category as string) ?? '',
      severity: (f.severity as string) ?? 'medium',
      passed: (f.passed as boolean) ?? false,
      message: (f.message as string) ?? '',
      file: f.file as string | undefined,
      line: f.line as number | undefined,
      fixable: (f.fixable as boolean) ?? false,
      fix: (f.fix as string) ?? '',
      guidance: (f.guidance as string) ?? '',
      count: 1,
      sampleFiles: [],
    }));

    const failedFindings = allFindings.filter(f => !f.passed);
    const passedFindings = allFindings.filter(f => f.passed);

    const bySeverity: Record<string, number> = {};
    const byCategory: Record<string, number> = {};
    for (const f of failedFindings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      byCategory[f.category] = (byCategory[f.category] || 0) + 1;
    }

    // Deduplicate by checkId — one entry per unique check with occurrence count
    const byCheck = new Map<string, { finding: HmaFinding; files: string[] }>();
    for (const f of failedFindings) {
      const existing = byCheck.get(f.checkId);
      if (existing) {
        existing.files.push(f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : '');
      } else {
        byCheck.set(f.checkId, {
          finding: { ...f },
          files: [f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : ''],
        });
      }
    }
    const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    const topFindings = Array.from(byCheck.values())
      .map(({ finding, files }) => ({
        ...finding,
        count: files.length,
        sampleFiles: files.filter(Boolean).slice(0, 5),
      }))
      .sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9))
      .slice(0, 30);

    return {
      available: true,
      score: (parsed.score as number) ?? 0,
      maxScore: (parsed.maxScore as number) ?? 100,
      totalChecks: allFindings.length,
      passed: passedFindings.length,
      failed: failedFindings.length,
      bySeverity,
      byCategory,
      topFindings,
      allFailedFindings: failedFindings,
    };
  } catch {
    return emptyResult;
  }
}

async function runDetectPhase(targetDir: string): Promise<DetectPhaseData> {
  const { scanProcesses, scanMcpServers, scanIdentity, scanAiConfigs } = await import('./detect.js');

  const detectedAgents = scanProcesses();
  const detectedMcpServers = scanMcpServers(targetDir);
  const detectedIdentity = scanIdentity(targetDir);
  const detectedAiConfigs = scanAiConfigs(targetDir);

  // Enrich agents with identity/governance from project context
  if (detectedIdentity.aimIdentities > 0) {
    for (const agent of detectedAgents) {
      agent.identityStatus = 'identified';
    }
  }
  if (detectedIdentity.soulFiles > 0 || detectedIdentity.capabilityPolicies > 0) {
    for (const agent of detectedAgents) {
      agent.governanceStatus = 'governed';
    }
  }

  // Enrich MCP servers with signing status
  const mcpIdDir = path.join(targetDir, '.opena2a', 'mcp-identities');
  if (fs.existsSync(mcpIdDir)) {
    for (const server of detectedMcpServers) {
      const idFile = path.join(mcpIdDir, `${server.name}.json`);
      if (fs.existsSync(idFile)) {
        server.verified = true;
      }
    }
  }

  // Calculate governance score using shared utility
  const { governanceScore, deductions: governanceDeductions } = calculateGovernanceScore({
    agents: detectedAgents,
    mcpServers: detectedMcpServers,
    aiConfigs: detectedAiConfigs,
    identity: detectedIdentity,
  });

  // Build detect findings
  const detectFindings: DetectPhaseData['findings'] = [];
  const ungovernedAgents = detectedAgents.filter(a => a.governanceStatus === 'no governance');
  if (ungovernedAgents.length > 0) {
    detectFindings.push({
      severity: 'high',
      title: `${ungovernedAgents.length} AI agent${ungovernedAgents.length !== 1 ? 's' : ''} running without governance`,
      whyItMatters: 'These agents can take actions in your project but have no rules defining what they should or should not do.',
      remediation: 'opena2a init && opena2a harden-soul',
    });
  }
  if (detectedIdentity.aimIdentities === 0 && detectedAgents.length > 0) {
    detectFindings.push({
      severity: 'high',
      title: 'No agent identity registered for this project',
      whyItMatters: 'Without an identity, agent actions cannot be traced back to a specific tool or session.',
      remediation: 'opena2a identity create --name my-agent',
    });
  }
  const projectCriticalMcp = detectedMcpServers.filter(
    s => s.risk === 'critical' && !s.verified && s.source.includes('(project)')
  );
  if (projectCriticalMcp.length > 0) {
    detectFindings.push({
      severity: 'critical',
      title: `${projectCriticalMcp.length} project MCP server${projectCriticalMcp.length !== 1 ? 's' : ''} with sensitive access`,
      whyItMatters: 'These MCP servers grant access to sensitive operations like running commands or accessing databases.',
      remediation: 'opena2a mcp audit',
    });
  }
  const criticalConfigs = detectedAiConfigs.filter(c => c.risk === 'critical');
  if (criticalConfigs.length > 0) {
    detectFindings.push({
      severity: 'critical',
      title: 'AI config files contain credential references',
      whyItMatters: 'API keys or tokens appear to be stored directly in configuration files.',
      remediation: 'opena2a protect',
    });
  }
  if (detectedIdentity.soulFiles === 0 && detectedAgents.length > 0) {
    detectFindings.push({
      severity: 'medium',
      title: 'No SOUL.md governance file in this project',
      whyItMatters: 'Without a SOUL.md, agents rely entirely on their defaults which may not match your expectations.',
      remediation: 'opena2a harden-soul',
    });
  }

  return {
    governanceScore,
    agents: detectedAgents.map(a => ({ name: a.name, category: a.category, identityStatus: a.identityStatus, governanceStatus: a.governanceStatus })),
    mcpServers: detectedMcpServers.map(s => ({ name: s.name, transport: s.transport, source: s.source, verified: s.verified, capabilities: s.capabilities, risk: s.risk })),
    aiConfigs: detectedAiConfigs.map(c => ({ file: c.file, tool: c.tool, risk: c.risk, details: c.details })),
    identity: { aimIdentities: detectedIdentity.aimIdentities, mcpIdentities: detectedIdentity.mcpIdentities, soulFiles: detectedIdentity.soulFiles, capabilityPolicies: detectedIdentity.capabilityPolicies },
    findings: detectFindings,
    recoverablePoints: governanceDeductions,
  };
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
  shadowAiScore: number,
): number {
  if (hmaAvailable) {
    // With HMA: 25% trust + 18% cred + 12% integrity + 22% shield + 8% HMA + 15% shadowAI
    return Math.round(
      trustScore * 0.25 +
      credScore * 0.18 +
      guardScore * 0.12 +
      shieldScore * 0.22 +
      hmaScore * 0.08 +
      shadowAiScore * 0.15,
    );
  }
  // Without HMA: 30% trust + 20% cred + 15% integrity + 20% shield + 15% shadowAI
  return Math.round(
    trustScore * 0.30 +
    credScore * 0.20 +
    guardScore * 0.15 +
    shieldScore * 0.20 +
    shadowAiScore * 0.15,
  );
}

function scoreToGrade(score: number): string {
  // Kept for JSON backward compatibility; not displayed in CLI or HTML output
  if (score >= 90) return 'strong';
  if (score >= 80) return 'good';
  if (score >= 70) return 'moderate';
  if (score >= 60) return 'improving';
  return 'needs-attention';
}

function computeRecoverySummary(
  trustScore: number,
  credScore: number,
  guardScore: number,
  shieldScore: number,
  hmaScore: number,
  hmaAvailable: boolean,
  compositeScore: number,
  shadowAiScore: number,
): RecoverySummary {
  const opportunities: RecoveryOpportunity[] = [];

  // Compute how many composite points each dimension could recover (score gap * weight)
  const dims = hmaAvailable
    ? [
        { name: 'Credentials', score: credScore, weight: 0.18, action: 'opena2a protect' },
        { name: 'Shield', score: shieldScore, weight: 0.22, action: 'opena2a shield init' },
        { name: 'Hygiene', score: trustScore, weight: 0.25, action: 'opena2a init' },
        { name: 'Config integrity', score: guardScore, weight: 0.12, action: 'opena2a guard sign' },
        { name: 'HMA scan', score: hmaScore, weight: 0.08, action: 'npx hackmyagent scan' },
        { name: 'Shadow AI', score: shadowAiScore, weight: 0.15, action: 'opena2a detect' },
      ]
    : [
        { name: 'Credentials', score: credScore, weight: 0.20, action: 'opena2a protect' },
        { name: 'Shield', score: shieldScore, weight: 0.20, action: 'opena2a shield init' },
        { name: 'Hygiene', score: trustScore, weight: 0.30, action: 'opena2a init' },
        { name: 'Config integrity', score: guardScore, weight: 0.15, action: 'opena2a guard sign' },
        { name: 'Shadow AI', score: shadowAiScore, weight: 0.15, action: 'opena2a detect' },
      ];

  for (const d of dims) {
    const gap = 100 - d.score;
    if (gap <= 0) continue;
    const recoverable = Math.round(gap * d.weight);
    if (recoverable > 0) {
      opportunities.push({
        dimension: d.name,
        pointsRecoverable: recoverable,
        action: d.action,
      });
    }
  }

  // Sort by most recoverable first
  opportunities.sort((a, b) => b.pointsRecoverable - a.pointsRecoverable);

  const totalRecoverable = opportunities.reduce((s, o) => s + o.pointsRecoverable, 0);
  const potentialScore = Math.min(100, compositeScore + totalRecoverable);

  return {
    currentScore: compositeScore,
    potentialScore,
    totalRecoverable,
    opportunities,
  };
}

// --- Findings Aggregation ---

/** HMA check-ID prefixes that indicate a credential-related finding.
 *  Used to scope the prefer-HMA dedupe: only credential HMA findings
 *  suppress credential-scan matches. Non-credential HMA findings on the
 *  same file (e.g. GIT-002 on .gitignore) MUST NOT hide a credential that
 *  quickCredentialScan found in that file. */
const HMA_CREDENTIAL_PREFIXES = [
  'CRED', 'AST-CRED', 'WEBCRED', 'SEM-CRED', 'AGENT-CRED',
  'ENVLEAK', 'CLIPASS', 'DRIFT',
];

function isHmaCredentialFinding(checkId: string): boolean {
  const id = (checkId || '').toUpperCase();
  for (const p of HMA_CREDENTIAL_PREFIXES) {
    if (id === p || id.startsWith(p + '-')) return true;
  }
  return false;
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function maxSeverity(a: string, b: string): string {
  return (SEV_RANK[a] ?? 0) >= (SEV_RANK[b] ?? 0) ? a : b;
}

export function aggregateFindings(
  credData: CredentialPhaseData,
  shieldData: ShieldPhaseData,
  targetDir: string,
  hmaData: HmaPhaseData | null,
): ReviewFinding[] {
  const findings: ReviewFinding[] = [];

  // HMA findings first so we can dedupe credential-scan matches against them.
  // HMA's credential detection is context-gated across 200+ check IDs, so we
  // prefer HMA for the credential surface. IMPORTANT: HMA often emits findings
  // without a line number (e.g. file-level checks on .gitignore, package.json,
  // and some credential patterns). We therefore key dedupe by BOTH `file:line`
  // AND `file` alone, scoped to credential-category HMA findings only.
  const hmaCredLineKeys = new Set<string>();
  const hmaCredFileKeys = new Set<string>();
  const hmaCredSevByKey = new Map<string, string>();
  if (hmaData && hmaData.available) {
    for (const f of hmaData.allFailedFindings) {
      const cred = isHmaCredentialFinding(f.checkId);
      if (cred && f.file) {
        hmaCredFileKeys.add(f.file);
        if (f.line != null) {
          const k = `${f.file}:${f.line}`;
          hmaCredLineKeys.add(k);
          hmaCredSevByKey.set(k, f.severity);
        } else {
          hmaCredSevByKey.set(f.file, f.severity);
        }
      }
      findings.push({
        id: f.checkId,
        title: f.name,
        severity: f.severity,
        source: 'hma',
        detail: f.file
          ? (f.line != null ? `${f.file}:${f.line}` : f.file)
          : (f.message || ''),
        remediation: f.fix || f.guidance || '',
      });
    }
  }

  // Credential findings — skip any that duplicate an HMA credential finding
  // at the same location. When dedupe fires, upgrade the surviving HMA
  // finding's severity to the max of the two so we don't silently narrow
  // from credData's "critical" to HMA's "high".
  // Defense in depth. credData.matches originates from walkFiles(targetDir,
  // ...) in credential-patterns.ts and so should always be rooted inside
  // targetDir, but if a symlink escape or upstream contract change ever
  // leaks an out-of-scope path into the aggregation layer we drop it rather
  // than render a misleading row in the review output. Resolve both sides
  // and require the credential file to be inside the target tree — catches
  // absolute paths, parent-traversal, and the Windows-drive-letter-on-Unix
  // case that a plain rel.startsWith('..') check misses.
  const resolvedTarget = path.resolve(targetDir);
  for (const m of credData.matches) {
    const resolvedFile = path.resolve(m.filePath);
    if (resolvedFile !== resolvedTarget && !resolvedFile.startsWith(resolvedTarget + path.sep)) continue;
    const rel = path.relative(resolvedTarget, resolvedFile);
    const lineKey = `${rel}:${m.line}`;
    const matchedLine = hmaCredLineKeys.has(lineKey);
    const matchedFile = hmaCredFileKeys.has(rel);
    if (matchedLine || matchedFile) {
      const hmaKey = matchedLine ? lineKey : rel;
      const prevSev = hmaCredSevByKey.get(hmaKey);
      if (prevSev && SEV_RANK[m.severity] > SEV_RANK[prevSev]) {
        // Upgrade the surviving HMA finding's severity.
        for (const f of findings) {
          if (f.source === 'hma' && (f.detail === lineKey || f.detail === rel)) {
            f.severity = maxSeverity(f.severity, m.severity);
          }
        }
        hmaCredSevByKey.set(hmaKey, maxSeverity(prevSev, m.severity));
      }
      continue;
    }
    findings.push({
      id: m.findingId,
      title: m.title,
      severity: m.severity,
      source: 'credential-scan',
      detail: lineKey,
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
      tab: 'hygiene',
    });
  }

  if (guardData.signatureStatus === 'unsigned') {
    items.push({
      priority: priority++,
      severity: 'medium',
      description: 'Sign config files for tamper detection',
      command: 'opena2a guard sign',
      tab: 'hygiene',
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
  spawn(cmd, [filePath], { detached: true, stdio: 'ignore' }).unref();
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
  if (score >= 90) grade = 'strong';
  else if (score >= 80) grade = 'good';
  else if (score >= 70) grade = 'moderate';
  else if (score >= 60) grade = 'improving';
  else grade = 'needs-attention';

  return { score, grade };
}
