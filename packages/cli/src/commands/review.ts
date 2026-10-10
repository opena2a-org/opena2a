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
import { spawn, type ChildProcess } from 'node:child_process';
import { platform, tmpdir } from 'node:os';
import { childEnv } from '../adapters/registry.js';
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
import { detectProject, type NameSource } from '../util/detect.js';
import { getVersion } from '../util/version.js';
import { CREDENTIAL_PATTERNS, scanCredentialsWithCoverage, type CredentialMatch, type CredentialScanResult } from '../util/credential-patterns.js';
import { maskValue } from '../util/mask-value.js';
import { checkAdvisories, type AdvisoryCheck } from '../util/advisories.js';
import { getShieldStatus } from '../shield/status.js';
import { chainBreakEvent, readVerifiedEvents, type VerifiedEventsResult } from '../shield/events.js';
import { classifyEvents, filterEventsToTarget, type ClassifiedFinding } from '../shield/findings.js';
import { computeARPStats, type ARPStats } from '../shield/arp-bridge.js';
import { verifyConfigIntegrity, defaultSigningFiles, type ConfigIntegritySummary } from './guard.js';
import { collectEnvFileFacts, type EnvFileFact } from './review-facts.js';
import { buildReviewFindings, type HardeningItem, type ReportFinding, type ScoreModel } from './review-findings.js';
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
  /** The global `--format` value, unvalidated: Commander accepts any string,
   *  so review() checks it against REVIEW_FORMATS before doing any work. */
  format?: string;
  verbose?: boolean;
  /** The global `--quiet`: keep the result, drop progress and commentary. */
  quiet?: boolean;
}

/** Output formats review produces. Anything else (the global `--format`
 *  advertises `sarif`) is refused rather than falling through to text. */
const REVIEW_FORMATS = ['text', 'json'] as const;

/** A user-supplied value made safe to echo on one terminal line: control
 *  characters (ESC, newline, the rest of C0 and C1, and DEL) are removed, so
 *  a crafted `--format` or `--report` value cannot inject an escape sequence
 *  or forge a line of its own. */
function printable(value: string): string {
  return value.replace(/[\x00-\x1f\x7f-\x9f]/g, '');
}

/** Terminal Verdict when nothing was found because the credential check
 *  opened no file. `opena2a review .` pastes and runs without editing. */
const NO_FILES_SCANNED_VERDICT =
  'No files were scanned for credentials, so this is not a clean result. '
  + 'Run `opena2a review .` from the folder that holds your code.';

export interface PhaseResult {
  name: string;
  status: 'pass' | 'warn' | 'fail' | 'skip';
  score: number;
  durationMs: number;
  detail: string;
  /** True when this phase could not see everything it normally scores, so its
   *  score is "not fully measured", not "clean". Mirrors the report-level
   *  `provisional` flag at phase granularity. */
  provisional?: boolean;
  /** Why the phase is provisional, in one sentence. Present iff `provisional`. */
  provisionalReason?: string;
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
  /** True when the deepest target-malice analyzer (HMA) did not run, so the
   *  dominant-analyzer floor could not see HMA-only threats and the verdict is
   *  not authoritative. Machine consumers should treat a passing score with
   *  `provisional: true` as "not fully scanned", not "clean". See #175. */
  provisional: boolean;
  grade: string; // kept for backward compat in JSON; not displayed as letter grade in CLI/HTML
  recoverySummary: RecoverySummary;
  findings: ReviewFinding[];
  actionItems: ActionItem[];
  /** Every analyzer's findings in one prioritized list (review-findings.ts). */
  reportFindings: ReportFinding[];
  /** Fingerprints of at most three findings to fix first. */
  fixFirst: string[];
  optionalHardening: HardeningItem[];
  scoreModel: ScoreModel;
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
  /** Published advisories that match this project's packages. */
  advisories: { id: string; summary: string; severity: string | null; packages: string[] }[];
  /** Env files in the tree with their git state, value count and mode. */
  envFiles: EnvFileFact[];
}

export interface CredentialPhaseData {
  matches: CredentialMatch[];
  totalFindings: number;
  /** Files the credential scan opened and read. Zero findings over zero files
   *  is "nothing examined", not "clean". */
  filesScanned: number;
  bySeverity: Record<string, number>;
  driftFindings: CredentialMatch[];
  envVarSuggestions: { finding: string; envVar: string }[];
  /** What the built-in credential scan read and what it left out. */
  coverage: CredentialCoverage;
}

export interface CredentialCoverage {
  filesRead: number;
  /** Matches dropped as published examples or placeholders. */
  placeholdersSkipped: number;
  /** Folder names the scan did not enter. */
  skippedDirs: string[];
}

export interface GuardPhaseData {
  filesMonitored: number;
  tamperedFiles: string[];
  signatureStatus: 'valid' | 'tampered' | 'unsigned';
  /** Files a bare `opena2a guard sign` would sign here. */
  candidates: string[];
}

/** Classified-finding counts by severity, deduplicated the same way
 *  `classifyEvents` deduplicates (one entry per finding id, not per event). */
export interface ShieldFindingCounts {
  critical: number;
  high: number;
  medium: number;
}

export interface ShieldPhaseData {
  eventCount: number;
  classifiedFindings: ClassifiedFinding[];
  arpStats: ARPStats;
  /** True when the event log's hash chain is broken (see readVerifiedEvents). */
  chainBroken: boolean;
  /** Events at or after the break that were excluded from classification. */
  untrustedEventsExcluded: number;
  /** Chronological index of the first untrusted event, or null if intact. */
  brokenAt: number | null;
  /**
   * Finding counts over trusted + untrusted events — what the same log would
   * have classified had its chain been intact. Present only when the chain is
   * broken.
   *
   * Used ONLY to floor the shield scores (shieldPostureScore here,
   * shieldCompositeScore and shieldRiskFloorScore downstream). The findings it
   * counts are never added to `classifiedFindings`, never reach
   * `report.findings`, and never render — trusting their content would readmit
   * the forgery vectors the chain exclusion closes. They exist to lower a
   * number, nothing else.
   */
  preExclusionCounts?: ShieldFindingCounts;
  /**
   * Runtime posture of the Shield layer: active tools, policy, shell
   * integration, penalized by classified findings.
   *
   * NOT the same quantity as `InitPhaseData.postureScore`, which scores the
   * project's governance and does not know about Shield at all. Both were
   * called `postureScore` and both rendered under the label "Posture Score",
   * so one review report showed `postureScore` 52 on Overview and 35 on
   * Shield with nothing saying they measured different things — and
   * `init --json | jq .postureScore` agreed with neither reliably. The name
   * now states which posture it is.
   */
  shieldPostureScore: number;
  policyLoaded: boolean;
  policyMode: string | null;
  integrityStatus: string;
}

/** Pass-through mirrors of HMA Finding v2 schema (hackmyagent commit dc8d344,
 *  src/types/finding-evidence.ts). opena2a-cli is a wrapper consumer; these
 *  types are kept structurally compatible so runtime values flow through
 *  JSON parse → render unchanged. Do NOT narrow or author values here. */
export interface HmaPositiveEvidenceLine {
  /** 1-based line number in the artifact. */
  n: number;
  /** Verbatim line content as the detector saw it. */
  content: string;
  /** What makes this line dangerous in context. */
  why?: string;
}
export interface HmaPositiveEvidence {
  kind: 'positive';
  lines: HmaPositiveEvidenceLine[];
}
export interface HmaAbsenceEvidence {
  kind: 'absence';
  observed: {
    lines: Array<{ n: number; content: string }>;
    summary: string;
  };
  expected: Array<{ constraint: string; rationale: string }>;
}
export interface HmaMixedEvidence {
  kind: 'mixed';
  positive: Omit<HmaPositiveEvidence, 'kind'>;
  absence: Omit<HmaAbsenceEvidence, 'kind'>;
}
export type HmaEvidence = HmaPositiveEvidence | HmaAbsenceEvidence | HmaMixedEvidence;
export interface HmaRationale {
  plainEnglish: string;
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
  /** HMA Finding v2 — structured evidence (positive lines, absence-of-defense, or mixed). */
  evidence?: HmaEvidence;
  /** HMA Finding v2 — plain-English rationale grounded in the evidence. */
  rationale?: HmaRationale;
  /** HMA Finding v2 — concept tag for an unfamiliar primitive a fix recommends. */
  concept?: string;
  /** HMA #138 — taxonomy attackClass label populated on every static-check finding. */
  attackClass?: string;
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
  /** How the HMA run ended. `available` is false for every status but `ran`. */
  run: HmaRunStatus;
}

export type HmaRunStatusCode = 'ran' | 'skipped' | 'notFound' | 'timedOut' | 'badOutput' | 'exitError';

export interface HmaRunStatus {
  status: HmaRunStatusCode;
  /** One line on why HMA produced no result; null when it ran. */
  reason: string | null;
  /** First line of `hackmyagent --version` as npx resolved it; null when unknown. */
  version: string | null;
  durationMs: number;
}

export interface DetectPhaseData {
  governanceScore: number;
  agents: { name: string; category: string; identityStatus: string; governanceStatus: string }[];
  mcpServers: { name: string; transport: string; source: string; verified: boolean; capabilities: string[]; risk: string }[];
  aiConfigs: { file: string; tool: string; risk: string; details: string }[];
  identity: { aimIdentities: number; mcpIdentities: number; soulFiles: number; capabilityPolicies: number };
  findings: DetectFinding[];
  recoverablePoints: number;
}

export interface DetectFinding {
  /** Stable identifier, also used as the finding id in the review findings list. */
  id: string;
  severity: string;
  title: string;
  /** `project`: the signal is in the scanned tree itself (the same signals
   *  targetGovernanceFloorScore floors the composite on), so review counts it
   *  as a finding. `host`: it reflects AI tools running on the developer's
   *  machine, not the target, so it stays in the Shadow AI phase only. */
  scope: 'project' | 'host';
  /** What the finding points at (files, server names), when it has one. */
  detail?: string;
  whyItMatters: string;
  remediation: string;
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
  // Refuse an output format review cannot produce before running any phase.
  // It used to fall through to text output and an HTML report with exit 0, so
  // a `--format sarif` pipeline received neither SARIF nor an error. Exit 2
  // keeps a CI gate red and stays distinct from findings (exit 1).
  const format = options.format ?? 'text';
  if (!(REVIEW_FORMATS as readonly string[]).includes(format)) {
    process.stderr.write(red(`opena2a review does not support --format ${printable(format)}.\n`));
    process.stderr.write(dim('  Supported: --format text (summary plus HTML report) or --format json (report on stdout).\n'));
    return 2;
  }
  // --quiet and --verbose ask for opposite output; honouring either one would
  // silently ignore the other.
  if (options.quiet && options.verbose) {
    process.stderr.write(red('opena2a review cannot use --quiet and --verbose together.\n'));
    process.stderr.write(dim('  Pass one: --quiet prints the score, finding counts and report path; --verbose adds detail.\n'));
    return 2;
  }
  // --quiet keeps the result (score line, finding counts, report path) and the
  // stderr notices that qualify the verdict. It drops the banner, the phase
  // progress lines, the Observations block, the report confirmation under
  // --format json and the contribute prompt.
  const quiet = options.quiet === true;

  const targetDir = path.resolve(options.targetDir ?? process.cwd());

  // A missing target is a command error (exit 2), not a score below 50
  // (exit 1): a gate that reads only the exit code must not take a run that
  // produced no result for a reviewed project.
  if (!fs.existsSync(targetDir)) {
    process.stderr.write(red(`Directory not found: ${printable(targetDir)}\n`));
    return 2;
  }

  const phases: PhaseResult[] = [];
  const showProgress = options.format !== 'json' && !quiet;
  const isTTY = process.stdout.isTTY === true;

  function progress(step: number, label: string): void {
    if (!showProgress) return;
    if (isTTY) {
      process.stdout.write(dim(`  [${step}/6] ${label}`));
    }
  }

  function progressDone(step: number, label: string, timing: string): void {
    if (!showProgress) return;
    if (isTTY) {
      process.stdout.write(`\r  [${step}/6] ${label} ${dim(timing)}\n`);
    } else {
      process.stdout.write(`  [${step}/6] ${label} ${dim(timing)}\n`);
    }
  }

  if (showProgress) {
    process.stdout.write('\n');
    process.stdout.write(bold('  OpenA2A Security Review') + '\n\n');
  }

  // Phase 1: Init Scan
  const phase1Start = Date.now();
  progress(1, 'Scanning project...');
  // One credential walk per review: Phase 1 scores what it found and Phase 2
  // reports it, so the tree is read once, not once per phase.
  const credentialScan = await scanCredentialsWithCoverage(targetDir);
  const initData = await runInitPhase(targetDir, credentialScan.matches);
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
  const credentialData = runCredentialPhase(credentialScan);
  const phase2Ms = Date.now() - phase2Start;
  const credScore = computeCredentialScore(credentialData);
  const phase2Status = credentialData.totalFindings === 0 ? 'pass'
    : credentialData.bySeverity['critical'] ? 'fail' : 'warn';
  phases.push({
    name: 'Credentials',
    status: phase2Status,
    score: credScore,
    durationMs: phase2Ms,
    detail: credentialData.totalFindings > 0
      ? `${credentialData.totalFindings} finding(s)`
      : credentialData.filesScanned === 0
        ? 'No files scanned for credentials'
        : 'No hardcoded credentials',
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
  const phase4Status = shieldData.shieldPostureScore >= 70 ? 'pass'
    : shieldData.shieldPostureScore >= 40 ? 'warn' : 'fail';
  // A chain break makes this phase partially blind: the events at and after
  // the break were excluded, so the counts below describe what SURVIVED
  // verification, not what the log contains. Say so in the detail line and
  // flag the phase provisional — otherwise the terminal shows a small, clean
  // "N events, M findings" and nothing indicates the exclusion happened.
  phases.push({
    name: 'Shield Analysis',
    status: phase4Status,
    score: shieldData.shieldPostureScore,
    durationMs: phase4Ms,
    detail: shieldData.chainBroken
      ? `${shieldData.eventCount} events, ${shieldData.classifiedFindings.length} findings`
        + ` (${shieldData.untrustedEventsExcluded} excluded, chain broken at ${shieldData.brokenAt})`
      : `${shieldData.eventCount} events, ${shieldData.classifiedFindings.length} findings`,
    ...(shieldData.chainBroken
      ? {
        provisional: true,
        provisionalReason: `Event log hash chain broken at index ${shieldData.brokenAt};`
          + ` ${shieldData.untrustedEventsExcluded} untrusted events were excluded from classification.`,
      }
      : {}),
  });
  progressDone(4, 'Analyzing shield events...   ', formatMs(phase4Ms));

  // Phase 5: HMA Scan (optional)
  const phase5Start = Date.now();
  progress(5, 'Running HMA security scan...');
  const hmaData: HmaPhaseData = options.skipHma
    ? emptyHmaData({ status: 'skipped', reason: 'skipped by --skip-hma', version: null, durationMs: 0 })
    : await runHmaPhase(targetDir);
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
    const noResult = describeHmaNoResult(hmaData.run);
    phases.push({
      name: 'HMA Scan',
      status: 'skip',
      score: 0,
      durationMs: phase5Ms,
      detail: noResult.detail,
    });
    progressDone(5, 'Running HMA security scan... ', noResult.label);
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
  const hmaAvailable = hmaData.available;
  // Adoption-as-recovery (not penalty): a clean target must not be scored down
  // for opt-in OpenA2A tooling it simply hasn't adopted. Shield posture and the
  // raw governance score conflate "the target is dangerous" with "the developer
  // hasn't set up Shield / registered an identity / signed configs". For the
  // composite we use risk-only views — neutral-high unless a genuine target-risk
  // signal fired — and surface adoption as recovery opportunities instead. See
  // shieldCompositeScore / governanceCompositeScore.
  // Dominant-analyzer floor (#175): force the composite verdict to agree in
  // direction with the harshest *target-malice* analyzer. Only analyzers whose
  // critical-band score unambiguously means "the target itself is dangerous"
  // participate — see buildFloorParticipants for which are in/out and why.
  const scoreState: ScoreState = {
    hygieneChecks: initData.hygieneChecks,
    credentials: credentialData,
    guard: guardData,
    shield: shieldData,
    hma: { available: hmaAvailable, score: hmaData.score },
    detect: detectData,
  };
  const scored = scoreReview(scoreState);
  const compositeScore = scored.composite;
  const grade = scoreToGrade(compositeScore);

  // Aggregate findings
  const findings = aggregateFindings(credentialData, shieldData, targetDir, hmaData, detectData);

  // Action items
  const actionItems = generateActionItems(credentialData, guardData, shieldData, initData);

  // One findings list, Fix first, optional hardening and recovery re-scored
  // with scoreReview itself.
  const { reportFindings, fixFirst, optionalHardening, scoreModel, recoverySummary } = buildReviewFindings({
    targetDir, initData, credentialData, guardData, shieldData, hmaData, detectData, findings,
    state: scoreState, score: scoreReview, floorBand: CRITICAL_BAND,
  });

  // Build report
  const report: ReviewReport = {
    timestamp: new Date().toISOString(),
    directory: targetDir,
    projectName: initData.projectName,
    projectType: initData.projectType,
    phases,
    compositeScore,
    provisional: !hmaAvailable,
    grade,
    recoverySummary,
    findings,
    actionItems,
    reportFindings,
    fixFirst,
    optionalHardening,
    scoreModel,
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

  // Degraded-mode notice (#175 / C1): the dominant-analyzer floor's deepest
  // target-malice signal is HMA `secure`. When HMA did not run, a malicious
  // project that only HMA would catch is NOT floored, so this verdict can read
  // more reassuring than a full scan would. Emit to STDERR so it is visible on
  // every output path — including `--json` (whose JSON stays on stdout, with a
  // top-level `provisional: true` flag) and `--ci` — and so it appears above
  // the verdict rather than scrolling past below it (CISO Rule 11 — no
  // misleading verdicts).
  if (!hmaAvailable) {
    const noResult = describeHmaNoResult(hmaData.run);
    process.stderr.write(
      yellow(`  Provisional verdict — deep scan (HMA) ${noResult.headline}.\n`) +
      dim(`  Lightweight checks only; HMA-only threats are not reflected. ${noResult.next}.\n\n`),
    );
  }

  // Chain-break notice (#204 / C6). The exclusion is the whole point of chain
  // verification, but a SILENT exclusion reads as a clean phase: the only
  // machine-readable trace was buried in
  // shieldData.classifiedFindings[0].examples[0].detail, and the human saw a
  // small event count and nothing else. Same stderr placement and rationale as
  // the HMA notice above — emitted before the `--json` branch so it reaches
  // both output paths without polluting stdout.
  if (shieldData.chainBroken) {
    process.stderr.write(
      yellow('  Shield events partially excluded — event log hash chain broken.\n') +
      dim(`  ${shieldData.untrustedEventsExcluded} untrusted events at/after index ${shieldData.brokenAt}`
        + ' were not classified; the Shield phase is provisional. Inspect: opena2a shield selfcheck.\n\n'),
    );
  }

  if (options.format === 'json') {
    // An explicit --report path is honoured here too; it used to be dropped
    // silently. The confirmation goes to stderr so stdout stays pure JSON, and
    // no browser opens in this machine-readable mode.
    //
    // The JSON goes out first: a report path that cannot be written must not
    // cost the caller the document it asked for on stdout. That failure exits
    // 2, as an unsupported --format does, so a gate can tell "an output was
    // not produced" from the score verdict (exit 1 below 50).
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    if (options.reportPath) {
      try {
        writeReviewHtml(options.reportPath, report);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        process.stderr.write(red(`Report not written: ${printable(msg)}\n`));
        return 2;
      }
      if (!quiet) process.stderr.write(dim(`  Report: ${printable(options.reportPath)}\n`));
    }
    return compositeScore < 50 ? 1 : 0;
  }

  // Print summary
  if (!quiet) process.stdout.write('\n');
  const scoreColor = compositeScore >= 80 ? green
    : compositeScore >= 60 ? yellow : red;
  // Recovery-framed output: show path forward, not punitive grade
  const topRecovery = recoverySummary.opportunities.slice(0, 3)
    .map(o => `+${o.pointsRecoverable} ${o.dimension.toLowerCase()}`)
    .join(', ');
  const recoveryHint = recoverySummary.totalRecoverable > 0
    ? ` -- path to ${recoverySummary.potentialScore} available (${topRecovery})`
    : '';
  // Scope label (#252). The composite is NOT an average — applyDominantAnalyzerFloor
  // caps it at the worst participating dimension once that dimension is in the
  // critical band, so a single critical credential legitimately drags the whole
  // review down while `scan` (static code checks only) stays high. Saying so
  // turns an apparent contradiction between commands into two stated scopes.
  // The floor is driven by risk-only views, not by the phase scores shown
  // above, so the count, the average and the check that capped it all come
  // from scoreModel, the record the JSON and HTML reports carry. A skipped
  // phase is not a dimension of the composite.
  const usedDimensions = scoreModel.weights.filter(w => w.weight > 0).length;
  const heldBy = scoreModel.floorHeldBy;
  const cappedBy = heldBy.length === 1
    ? `a critical ${heldBy[0]} result`
    : `critical ${heldBy.slice(0, -1).join(', ')} and ${heldBy[heldBy.length - 1]} results`;
  const scopeNote = heldBy.length > 0
    ? `  (${usedDimensions} dimensions average ${scoreModel.weightedScore}; capped at ${compositeScore} by ${cappedBy})`
    : `  (composite across ${usedDimensions} dimensions)`;
  // The finding count above is what survived chain verification. When events
  // were excluded, the summary must say so on the same screen as the count it
  // qualifies, not only on stderr.
  const chainNote = shieldData.chainBroken
    ? `\n  ${shieldData.untrustedEventsExcluded} shield events excluded — event log chain broken at index ${shieldData.brokenAt}`
    : '';
  process.stdout.write(
    `  Score: ${scoreColor(`${compositeScore}/100`)}${dim(recoveryHint)}${dim(scopeNote)}` +
    `\n  ${totalFindings} findings (${sevCounts.critical} critical, ${sevCounts.high} high, ${sevCounts.medium} medium)` +
    `${yellow(chainNote)}\n`,
  );

  // ── Observations + Verdict ──────────────────────────────────────────
  // Shared block from @opena2a/cli-ui so review/scan output stays
  // consistent with hackmyagent secure output per [CA-030]. Dynamic
  // import because cli-ui is ESM and this package is CJS (same pattern
  // as @opena2a/shared / @opena2a/contribute usage elsewhere). Skipped under
  // --quiet: the Score line above already carries the result.
  if (!quiet) {
    try {
      const cliUi = await import('@opena2a/cli-ui');
      // formatProjectType reports an undetected type as "Unknown" (or
      // "Unknown + MCP server"); never print that as the noun of the verdict.
      const projectLabel = report.projectType && !/^unknown\b/i.test(report.projectType)
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
      // A credential check that opened no file found nothing because it read
      // nothing. The block must not list credentials as clear, close the
      // category list with "(all clear)" or call the directory safe to use.
      // A credential finding another check (HMA) reported in the same run is
      // still a finding: it stays on the Categories line, and the check is
      // not reported as skipped next to it.
      const allCategories = cliUi.buildCategorySummaries(categorizable);
      const credentialsUnread = credentialData.filesScanned === 0
        && !allCategories.some(c => c.name === 'credentials' && !c.clear);
      const categorySummaries = allCategories
        .filter(c => !(credentialsUnread && c.name === 'credentials'));
      let verdict = cliUi.buildVerdict(
        { critical: sevCounts.critical, high: sevCounts.high, medium: sevCounts.medium, low: sevCounts.low },
        { kind: projectLabel },
        verdictFindings,
        // Pass the composite (target-risk) score so the verdict line reconciles
        // with the headline band instead of disagreeing in direction (#221).
        compositeScore,
      );
      if (credentialsUnread && verdict.status === 'safe') {
        verdict = { status: 'unknown', message: NO_FILES_SCANNED_VERDICT };
      }
      const { lines } = cliUi.renderObservationsBlock({
        surfaces: { kind: projectLabel },
        checks: {
          staticCount: phases.length,
          semanticCount: 0,
          skipped: credentialsUnread
            ? [{ category: 'credentials', reason: 'no files scanned' }]
            : undefined,
        },
        categories: categorySummaries,
        verdict,
        verbose: !!options.verbose,
      });
      if (credentialsUnread && categorySummaries.every(c => c.clear)) {
        for (const line of lines) {
          if (line.label !== 'Categories') continue;
          line.value = 'no findings · credentials not examined (no files scanned)';
          line.tone = 'default';
        }
      }
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
  }

  // Generate HTML report
  const reportPath = options.reportPath ??
    path.join(tmpdir(), `opena2a-review-${Date.now()}.html`);
  // An unwritable path exits 2, as it does under --format json: the summary
  // above is printed, but the report the run was asked for was not produced.
  try {
    writeReviewHtml(reportPath, report);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(red(`Report not written: ${printable(msg)}\n`));
    return 2;
  }

  process.stdout.write(`  Report: ${dim(printable(reportPath))}`);

  // Auto-open
  const shouldOpen = shouldAutoOpenReport(options, isTTY);
  if (shouldOpen) {
    openInBrowser(reportPath);
    process.stdout.write(` ${dim('(opened in browser)')}`);
  }
  process.stdout.write(quiet ? '\n' : '\n\n');

  // Community contribution
  try {
    const { recordScanAndMaybePrompt, isContributeEnabled, getRegistryUrl, submitScanReport } =
      await import('../util/report-submission.js');
    // The contribute prompt is guidance, so --quiet suppresses it the same way
    // machine-readable mode does; the scan is still counted.
    await recordScanAndMaybePrompt({ machineReadable: quiet });

    if (await isContributeEnabled()) {
      const registryUrl = await getRegistryUrl();
      // The Registry files a contributed scan by package name and ecosystem,
      // and files one without an ecosystem under npm, so only a project with
      // a package name in npm or PyPI is sent. The ecosystem follows the
      // manifest the name was read from, not the project type: a tree with a
      // package.json and a requirements.txt is a Python project whose name is
      // the npm package name.
      const project = detectProject(targetDir);
      const ecosystem = registryEcosystem(project.nameSource);
      if (registryUrl && typeof project.name === 'string' && project.name !== '' && ecosystem) {
        await submitScanReport(registryUrl, {
          packageName: project.name,
          ecosystem,
          scannerName: 'opena2a-review',
          scannerVersion: getVersion(),
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

async function runInitPhase(targetDir: string, credentialMatches: CredentialMatch[]): Promise<InitPhaseData> {
  const project = detectProject(targetDir);

  const checks = runHygieneChecks(targetDir, project, credentialMatches.length);
  const { score: trustScore, grade } = calculateTrustScore(checks);

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
    advisories: advisoryCheck.advisories.map(a => ({
      id: a.id, summary: a.summary, severity: a.severity?.[0]?.score ?? null,
      packages: [...new Set((a.affected ?? []).map(x => x.package?.name).filter((n): n is string => !!n))],
    })),
    envFiles: collectEnvFileFacts(targetDir),
  };
}

function runCredentialPhase(scan: CredentialScanResult): CredentialPhaseData {
  // Redacted here, where the phase data is built, not per output format: this
  // object is serialised verbatim into `--json` and into the HTML report's
  // embedded payload, so any format that forgot to mask would ship the secret
  // (#267). The finding needs file:line and a recognisable preview, never the
  // value. The scan itself keeps the raw value: `protect` needs it
  // to rewrite the source.
  const matches = scan.matches.map(m => ({ ...m, value: maskValue(m.value) }));
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
    filesScanned: scan.filesScanned,
    bySeverity,
    driftFindings,
    envVarSuggestions,
    coverage: {
      filesRead: scan.filesScanned,
      placeholdersSkipped: scan.placeholdersSkipped,
      skippedDirs: scan.skippedDirs,
    },
  };
}

function runGuardPhase(targetDir: string): GuardPhaseData {
  let candidates: string[] = [];
  try {
    candidates = defaultSigningFiles(targetDir);
  } catch {
    // Best-effort: an unreadable tree has no candidates to list.
  }
  try {
    return { ...verifyConfigIntegrity(targetDir), candidates };
  } catch {
    return {
      filesMonitored: 0,
      tamperedFiles: [],
      signatureStatus: 'unsigned',
      candidates,
    };
  }
}

export function runShieldPhase(targetDir: string): ShieldPhaseData {
  // Chain-verified read (issue #204, "Option 2" of #111): events at or after
  // the first hash-chain break are forged/tampered and must not classify
  // into findings.  Verification happens on the full log before the 7d
  // window is applied, so the genesis anchor stays intact.
  let verified: VerifiedEventsResult;
  try {
    verified = readVerifiedEvents({ since: '7d' });
  } catch {
    // A log we could not read is UNKNOWN, and unknown is not intact. This
    // previously reported `chainBroken: false` with zero events, which renders
    // an unreadable log as a clean one -- the same fail-open shape this phase
    // exists to close, one layer up. `readVerifiedEvents` currently swallows
    // its own I/O errors and the chain check is total over JSON-derived input,
    // so this block is unreachable today; it is corrected now because it goes live
    // the moment either of those properties changes, and because an unreachable
    // branch is exactly where a wrong default survives unnoticed.
    verified = {
      events: [], untrusted: [], chainBroken: true, brokenAt: 0,
      untrustedCount: 0, firstUntrusted: null,
    };
  }
  const events = verified.events;

  const scopedEvents = filterEventsToTarget(events, targetDir);

  // Surface the break itself as the single SHIELD-INT-002 finding: one
  // synthetic in-memory event (never written to the log) classified through
  // the normal pipeline, so it dedupes, sorts, and scores like any other
  // integrity critical.  The excluded events contribute nothing else.
  if (verified.chainBroken) {
    scopedEvents.push(chainBreakEvent(verified, 'review'));
  }

  const classifiedFindings = classifyEvents(scopedEvents);

  // Counterfactual counts for the score FLOOR: what this same log would have
  // classified had its chain been intact (trusted + untrusted, minus the
  // synthetic break finding, which only exists because the chain broke).
  //
  // Without it, an append-only adversary who corrupts a single line blinds the
  // phase into a BETTER score than leaving the log alone — every genuine
  // finding written after the corruption is excluded and only the one
  // chain-break critical remains. That makes blinding the sensor cheaper than
  // forging into it, which inverts the point of the exclusion. Flooring is the
  // right shape rather than a fixed penalty: a genuine tail with no critical
  // already scores WORSE when broken, and a fixed penalty would double-count.
  //
  // COUNTS ONLY. These findings never enter `classifiedFindings`, so they
  // never reach `report.findings` and never render. Untrusted content is
  // permitted to lower a number and nothing else.
  const preExclusionCounts = verified.chainBroken
    ? shieldFindingCounts(
      classifyEvents(filterEventsToTarget([...events, ...verified.untrusted], targetDir)),
    )
    : undefined;

  // Same trust boundary as classification: stats come from the verified
  // 7d window (`events`), not a second unverified read of the raw log —
  // otherwise forged ARP events past a break would still inflate the
  // report's runtime-protection numbers.  Mirrors getARPStats('7d')
  // semantics (source filter, newest-first count cap) minus the
  // untrusted tail.
  let arpStats: ARPStats;
  try {
    arpStats = computeARPStats(events.filter(e => e.source === 'arp').slice(0, 10000));
  } catch {
    arpStats = {
      totalEvents: 0, anomalies: 0, violations: 0, threats: 0,
      processEvents: 0, networkEvents: 0, filesystemEvents: 0,
      promptEvents: 0, enforcements: 0,
    };
  }

  const shieldStatus = getShieldStatus(targetDir);
  const activeTools = shieldStatus.tools.filter(p => p.active).length;

  // Adoption baseline (25 for CLI users), before finding penalties.
  let baseline = 25;
  baseline += Math.min(activeTools * 10, 50);
  if (shieldStatus.policyLoaded) baseline += 10;
  if (shieldStatus.shellIntegration) baseline += 5;

  // Penalize for findings, then floor at the intact-chain counterfactual so a
  // break can never score better than the same log unbroken.
  let shieldPostureScore = shieldPostureFromCounts(
    baseline, shieldFindingCounts(classifiedFindings),
  );
  if (preExclusionCounts) {
    shieldPostureScore = Math.min(
      shieldPostureScore, shieldPostureFromCounts(baseline, preExclusionCounts),
    );
  }

  return {
    eventCount: events.length,
    classifiedFindings,
    arpStats,
    chainBroken: verified.chainBroken,
    untrustedEventsExcluded: verified.untrustedCount,
    brokenAt: verified.brokenAt,
    preExclusionCounts,
    shieldPostureScore,
    policyLoaded: shieldStatus.policyLoaded,
    policyMode: shieldStatus.policyMode,
    integrityStatus: shieldStatus.integrityStatus,
  };
}

/**
 * Shield posture arithmetic: an adoption baseline reduced by classified
 * findings. Extracted from runShieldPhase so the identical formula can be
 * applied to a second, counts-only view of the log (see preExclusionCounts).
 */
function shieldPostureFromCounts(
  baseline: number,
  counts: { critical: number; high: number },
): number {
  return Math.max(0, Math.min(100, baseline - counts.critical * 15 - counts.high * 8));
}

/**
 * Runtime guard for HMA Finding v2 Evidence at the JSON parse boundary.
 *
 * opena2a-cli is a wrapper consumer; HMA owns the schema. We narrow on
 * `kind` only and pass the body through unchanged so the renderer (review-
 * html.ts) sees what HMA emitted. Returns false for any value that doesn't
 * have a recognized discriminator.
 */
export function isHmaEvidence(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as { kind?: unknown };
  return v.kind === 'positive' || v.kind === 'absence' || v.kind === 'mixed';
}

/**
 * Runtime guard for HMA Finding v2 Rationale at the JSON parse boundary.
 *
 * Requires `plainEnglish` to be a non-empty string. Empty strings fall
 * through to the legacy `guidance` render path.
 */
export function isHmaRationale(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as { plainEnglish?: unknown };
  return typeof v.plainEnglish === 'string' && v.plainEnglish.trim().length > 0;
}

/**
 * Map a raw HMA finding (as returned by `hackmyagent secure --format json`)
 * into the local HmaFinding shape. Pure function — no I/O — so the parse
 * boundary can be tested deterministically.
 *
 * Optional Finding v2 fields (HMA commit dc8d344) are passed through when
 * present and recognized; absent or malformed values become `undefined` so
 * the renderer falls back to the legacy `guidance` / `legacyRiskKb` path.
 */
export function mapRawHmaFinding(f: Record<string, unknown>): HmaFinding {
  return {
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
    evidence: isHmaEvidence(f.evidence) ? (f.evidence as HmaEvidence) : undefined,
    rationale: isHmaRationale(f.rationale) ? (f.rationale as HmaRationale) : undefined,
    concept: typeof f.concept === 'string' ? f.concept : undefined,
    attackClass: typeof f.attackClass === 'string' ? f.attackClass : undefined,
  };
}

/**
 * Derive HMA tab counts from HMA's JSON envelope.
 *
 * HMA emits two arrays:
 *   - `findings`    — failed checks only, un-deduped occurrences
 *   - `allFindings` — every check that ran, both passed and failed
 *
 * Older HMA versions only emit `findings`. When `allFindings` is present we
 * derive `totalChecks` and `passed` from it; otherwise both fall back to the
 * failed count (legacy behaviour displays "0 Passed", which is what we are
 * fixing here for current HMA builds).
 */
export function deriveHmaCounts(
  parsed: Record<string, unknown>,
  failedCount: number,
): { totalChecks: number; passed: number } {
  const fullSet = parsed.allFindings as Record<string, unknown>[] | undefined;
  if (!Array.isArray(fullSet)) {
    return { totalChecks: failedCount, passed: 0 };
  }
  const passed = fullSet.filter(f => f.passed === true).length;
  return { totalChecks: fullSet.length, passed };
}

/** HMA phase data for a run that produced no result. */
export function emptyHmaData(run: HmaRunStatus): HmaPhaseData {
  return {
    available: false, score: 0, maxScore: 100,
    totalChecks: 0, passed: 0, failed: 0,
    bySeverity: {}, byCategory: {}, topFindings: [], allFailedFindings: [],
    run,
  };
}

/**
 * How the terminal names an HMA run that produced no result, read from
 * `run.status`: the word on the progress line, the phase detail, and the
 * headline and next step of the provisional-verdict notice. A scan that timed
 * out, failed or printed no report is never named as skipped or not installed.
 */
export function describeHmaNoResult(run: HmaRunStatus): {
  label: string; detail: string; headline: string; next: string;
} {
  const seeOutput = 'Run npx hackmyagent secure on this directory to see its output';
  switch (run.status) {
    case 'skipped':
      return { label: 'skipped', detail: 'Skipped (--skip-hma)', headline: 'did not run', next: 'Re-run without --skip-hma' };
    case 'timedOut':
      return { label: 'timed out', detail: 'Timed out', headline: 'produced no result', next: `${run.reason}. ${seeOutput}` };
    case 'exitError':
      return { label: 'failed', detail: 'Scan failed', headline: 'produced no result', next: `${run.reason}. ${seeOutput}` };
    case 'badOutput':
      return { label: 'output unreadable', detail: 'Output not readable', headline: 'produced no result', next: `${run.reason}` };
    default:
      return { label: 'not installed', detail: 'Not installed', headline: 'did not run', next: 'Install it: npm i -g hackmyagent' };
  }
}

/** How long one HMA child process may run before review stops waiting. */
export const HMA_TIMEOUT_MS = 120_000;

interface ChildOutcome {
  code: number | null;
  stdout: string;
  stderr: string;
  spawnError: Error | null;
  timedOut: boolean;
}

/** Run a child to completion or to the deadline, whichever comes first. At the
 *  deadline the child is killed and the result returned at once, even if a
 *  grandchild still holds the output pipes open. Only the direct child (`npx`)
 *  is signalled: a process it started stops only if `npx` passes the signal
 *  on, and may otherwise outlive the result. */
function runChild(start: () => ChildProcess, timeoutMs: number): Promise<ChildOutcome> {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (code: number | null, spawnError: Error | null, timedOut: boolean): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({ code, stdout, stderr, spawnError, timedOut });
    };
    let proc: ChildProcess;
    try {
      proc = start();
    } catch (err) {
      finish(null, err instanceof Error ? err : new Error(String(err)), false);
      return;
    }
    proc.stdout?.on('data', (d: Buffer) => { stdout += d.toString(); });
    proc.stderr?.on('data', (d: Buffer) => { if (stderr.length < 4096) stderr += d.toString(); });
    proc.on('close', (code: number | null) => finish(code, null, false));
    proc.on('error', (err: Error) => finish(null, err, false));
    timer = setTimeout(() => {
      proc.kill?.();
      proc.stdout?.destroy?.();
      proc.stderr?.destroy?.();
      finish(null, null, true);
    }, timeoutMs);
  });
}

/** Replace the password of every URL with user information: the part after
 *  the user name's colon (the name may be empty, as in `redis://:…@host`), up
 *  to the last `@` before whitespace. A scanner's error text need not be a
 *  valid URL, so the password may hold `/` or `@`. Each run of text without
 *  whitespace is read once, front to back, so the time grows with the length
 *  of the text rather than its square. */
function redactUrlPasswords(text: string): string {
  return text.replace(/\S+/g, (run) => {
    const lastAt = run.lastIndexOf('@');
    for (let sep = run.indexOf('://'); sep !== -1 && sep < lastAt; sep = run.indexOf('://', sep + 3)) {
      if (sep === 0 || !/[a-z0-9+.-]/i.test(run[sep - 1])) continue;
      let end = sep + 3;
      while (end < run.length && !'/@:'.includes(run[end])) end++;
      if (run[end] !== ':' || end + 1 >= lastAt) continue;
      return `${run.slice(0, end + 1)}[redacted]${run.slice(lastAt)}`;
    }
    return run;
  });
}

/** Text a child process printed may carry a credential: a scanner that
 *  fails on a line names that line. Every URL password and every value the
 *  credential catalog recognises is replaced, so the `hmaData.run` reason and
 *  version never carry one. */
function redactCredentials(text: string): string {
  let out = redactUrlPasswords(text);
  for (const p of CREDENTIAL_PATTERNS) out = out.replace(p.pattern, '[redacted]');
  return out;
}

/** One printable line: escape sequences and control characters removed,
 *  credentials redacted, whitespace collapsed, clipped. */
function oneLine(text: string, max = 200): string {
  const clean = redactCredentials(text
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '')
    .replace(/[\x00-\x1f\x7f]+/g, ' '))
    .replace(/\s+/g, ' ')
    .trim();
  return clean.length > max ? clean.slice(0, max) + '…' : clean;
}

/** The first line with printable text, cleaned by {@link oneLine}. Lines after
 *  it are not read. */
function firstLine(text: string, max = 200): string | null {
  for (const raw of text.split(/\r?\n/)) {
    const line = oneLine(raw, max);
    if (line.length > 0) return line;
  }
  return null;
}

function seconds(ms: number): string {
  return `${Number((ms / 1000).toFixed(1))} s`;
}

/**
 * Exported so the child-environment wiring tests can run the real spawn under
 * a mocked `node:child_process` (#246); `review` is its only production caller.
 * `timeoutMs` exists for tests; review uses HMA_TIMEOUT_MS.
 *
 * Every way HMA can fail to produce a result is kept apart in `run.status`,
 * with the reason, so a run that timed out or printed something unreadable is
 * never reported as "not installed".
 */
export async function runHmaPhase(
  targetDir: string,
  options: { timeoutMs?: number } = {},
): Promise<HmaPhaseData> {
  const started = Date.now();
  const timeoutMs = options.timeoutMs ?? HMA_TIMEOUT_MS;
  let version: string | null = null;
  const noResult = (status: HmaRunStatusCode, reason: string): HmaPhaseData =>
    emptyHmaData({ status, reason, version, durationMs: Date.now() - started });

  try {
    const probe = await runChild(() => spawn('npx', ['hackmyagent', '--version'], { stdio: 'pipe' }), timeoutMs);
    if (probe.timedOut) return noResult('timedOut', `hackmyagent --version did not finish within ${seconds(timeoutMs)}`);
    if (probe.spawnError) return noResult('notFound', `npx could not be started (${oneLine(probe.spawnError.message)})`);
    if (probe.code !== 0) {
      return noResult('notFound', `npx could not start hackmyagent (${firstLine(probe.stderr) ?? `exit code ${probe.code}`})`);
    }
    version = firstLine(probe.stdout, 40);

    const run = await runChild(() => spawn('npx', ['hackmyagent', 'secure', '--format', 'json', targetDir], {
      stdio: ['ignore', 'pipe', 'pipe'],
      // The same `hackmyagent` contract every other route to the scanner
      // uses (#246); previously this spawn inherited the whole environment.
      env: childEnv('hackmyagent'),
    }), timeoutMs);
    if (run.timedOut) return noResult('timedOut', `HMA stopped after ${seconds(timeoutMs)} on this tree`);
    if (run.spawnError) return noResult('notFound', `npx could not be started (${oneLine(run.spawnError.message)})`);

    let parsed: { findings?: Record<string, unknown>[]; score?: number; maxScore?: number } & Record<string, unknown>;
    try {
      parsed = JSON.parse(run.stdout);
    } catch {
      // HMA exits non-zero when it finds critical issues, so the exit code
      // alone is not a failure: only output that is not a report is.
      if (run.code !== 0) {
        return noResult('exitError', `hackmyagent secure exited with code ${run.code} (${firstLine(run.stderr) ?? 'no message'})`);
      }
      return noResult('badOutput', `HMA output is not a JSON report (${run.stdout.length} characters, exit code ${run.code}); run hackmyagent secure --format json on this directory to see it`);
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return noResult('badOutput', 'HMA output is JSON but not a report object');
    }

    const allFindings: HmaFinding[] = (parsed.findings || []).map(
      (f: Record<string, unknown>) => mapRawHmaFinding(f),
    );

    const failedFindings = allFindings.filter(f => !f.passed);

    const { totalChecks: totalChecksRun, passed: passedCount } =
      deriveHmaCounts(parsed, failedFindings.length);

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
      totalChecks: totalChecksRun,
      passed: passedCount,
      failed: failedFindings.length,
      bySeverity,
      byCategory,
      topFindings,
      allFailedFindings: failedFindings,
      run: { status: 'ran', reason: null, version, durationMs: Date.now() - started },
    };
  } catch (err) {
    return noResult('badOutput', `HMA output could not be read (${oneLine(err instanceof Error ? err.message : String(err))})`);
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
      id: 'SHADOW-AI-AGENTS',
      severity: 'high',
      scope: 'host',
      title: `${ungovernedAgents.length} AI agent${ungovernedAgents.length !== 1 ? 's' : ''} running without governance`,
      whyItMatters: 'These agents can take actions in your project but have no rules defining what they should or should not do.',
      remediation: 'opena2a init && opena2a harden-soul',
    });
  }
  if (detectedIdentity.aimIdentities === 0 && detectedAgents.length > 0) {
    detectFindings.push({
      id: 'SHADOW-AI-IDENTITY',
      severity: 'high',
      scope: 'host',
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
      id: 'SHADOW-AI-MCP',
      severity: 'critical',
      scope: 'project',
      title: `${projectCriticalMcp.length} project MCP server${projectCriticalMcp.length !== 1 ? 's' : ''} with sensitive access`,
      detail: projectCriticalMcp.map(s => s.name).join(', '),
      whyItMatters: 'These MCP servers grant access to sensitive operations like running commands or accessing databases.',
      remediation: 'opena2a mcp audit',
    });
  }
  const criticalConfigs = detectedAiConfigs.filter(c => c.risk === 'critical');
  if (criticalConfigs.length > 0) {
    detectFindings.push({
      id: 'SHADOW-AI-CONFIG',
      severity: 'critical',
      scope: 'project',
      title: 'AI config files contain credential references',
      detail: criticalConfigs.map(c => c.file).join(', '),
      whyItMatters: 'API keys or tokens appear to be stored directly in configuration files.',
      remediation: 'opena2a protect',
    });
  }
  if (detectedIdentity.soulFiles === 0 && detectedAgents.length > 0) {
    detectFindings.push({
      id: 'SHADOW-AI-SOUL',
      severity: 'medium',
      scope: 'host',
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
  // "unsigned" is the DEFAULT state of any project that hasn't adopted config
  // signing — an opt-in feature, not a security defect. Score it as neutral-good
  // (adoption-as-recovery, not penalty); reserve low scores for actual tampering.
  // Signing remains a small recovery opportunity (see computeRecoverySummary).
  if (data.signatureStatus === 'unsigned') return 90;
  // tampered — a signature exists but files changed under it. Real integrity problem.
  const penalty = data.tamperedFiles.length * 20;
  return Math.max(0, 100 - penalty);
}

/** Severity histogram of Shield's classified runtime findings. */
function shieldFindingCounts(classifiedFindings: { finding: { severity: string } }[]): {
  critical: number; high: number; medium: number;
} {
  let critical = 0, high = 0, medium = 0;
  for (const cf of classifiedFindings) {
    const s = cf.finding.severity;
    if (s === 'critical') critical++;
    else if (s === 'high') high++;
    else if (s === 'medium') medium++;
  }
  return { critical, high, medium };
}

/**
 * Shield posture for the COMPOSITE weighted average (adoption-as-recovery, #175).
 *
 * The raw postureScore is dominated by whether the developer has SET UP Shield
 * on their machine (active tools, loaded policy, shell integration, signing dir)
 * — environment state, not how dangerous the scanned target is. Using it
 * directly drags every clean project on a Shield-less machine down (~40–55), and
 * even WITH a real critical finding the posture stays ~75 (a false "good"). So
 * the composite ignores posture entirely: it starts neutral (90, no penalty for
 * un-adopted Shield) and is reduced ONLY by genuine classified RUNTIME findings
 * on the target. Critical/high findings additionally drive the dominant-analyzer
 * floor (see shieldRiskFloorScore) so they can pull the verdict to "needs
 * attention", which the weighted average alone cannot.
 */
export function shieldCompositeScore(shield: {
  classifiedFindings: { finding: { severity: string } }[];
  preExclusionCounts?: ShieldFindingCounts;
}): number {
  const reported = shieldCompositeFromCounts(shieldFindingCounts(shield.classifiedFindings));
  // Chain-break floor: excluding the untrusted tail removed genuine findings
  // from `classifiedFindings` too, so score at the harsher of "what survived"
  // and "what an intact chain would have classified". Fixing this on the phase
  // posture alone would leave a LARGER reward here: on a one-junk-line fixture
  // this input rose while the final composite did not move at all, because the
  // synthetic break critical happened to pin the risk floor. That masking is
  // incidental to the fixture, not a defence, so the floor is applied at both
  // layers.
  if (!shield.preExclusionCounts) return reported;
  return Math.min(reported, shieldCompositeFromCounts(shield.preExclusionCounts));
}

function shieldCompositeFromCounts(counts: ShieldFindingCounts): number {
  const { critical, high, medium } = counts;
  return Math.max(0, Math.min(100, 90 - critical * 30 - high * 15 - medium * 6));
}

/**
 * Shield RUNTIME-RISK floor signal (adoption-as-recovery, #175).
 *
 * Only the genuine target-risk slice of Shield participates in the dominant-
 * analyzer floor — NOT the adoption baseline (which is exactly why the raw
 * posture was excluded from the floor). A classified critical/high runtime
 * finding is a real attack signal on the target and must be able to pull the
 * verdict to "needs attention"; absence of such a finding (un-configured Shield,
 * or only medium/low) does not participate (`ran: false`) and cannot clamp a
 * clean repo.
 */
export function shieldRiskFloorScore(shield: {
  classifiedFindings: { finding: { severity: string } }[];
  preExclusionCounts?: ShieldFindingCounts;
}): { score: number; ran: boolean } {
  const reported = shieldRiskFloorFromCounts(shieldFindingCounts(shield.classifiedFindings));
  // Same chain-break floor as shieldCompositeScore: the excluded tail may have
  // carried the only critical/high runtime signal on the target, and losing it
  // must not relax the floor. Inert today — runShieldPhase always injects a
  // critical chain-break finding, so `reported` is already at the harshest band
  // whenever preExclusionCounts exists — and kept as defence-in-depth so the
  // invariant survives a change to that synthetic finding's severity.
  if (!shield.preExclusionCounts) return reported;
  const preExclusion = shieldRiskFloorFromCounts(shield.preExclusionCounts);
  if (!preExclusion.ran) return reported;
  if (!reported.ran) return preExclusion;
  return preExclusion.score < reported.score ? preExclusion : reported;
}

function shieldRiskFloorFromCounts(
  counts: { critical: number; high: number },
): { score: number; ran: boolean } {
  if (counts.critical > 0) return { score: CRITICAL_BAND - 10, ran: true };
  if (counts.high > 0) return { score: CRITICAL_BAND - 5, ran: true };
  return { score: 100, ran: false };
}

/**
 * Shadow-AI governance for the COMPOSITE (adoption-as-recovery, #175 follow-up).
 *
 * The raw governanceScore deducts for no registered identity / no SOUL.md
 * (adoption) and for ambient host AI processes from `ps aux` (environment) —
 * neither means the scanned target is dangerous. For the composite, governance
 * contributes a penalty only when a TARGET-LOCAL critical signal fired (the same
 * in-repo critical MCP / AI-config check the dominant-analyzer floor uses);
 * otherwise it is neutral-high. Registering an identity / adding a SOUL.md stays
 * a recovery opportunity, not a composite penalty.
 */
export function governanceCompositeScore(projectGovernance: { score: number; ran: boolean }): number {
  return projectGovernance.ran ? projectGovernance.score : 90;
}

/**
 * Credentials floor score (adoption-as-recovery, #175 follow-up).
 *
 * A confirmed real credential exposure is a target-malice signal, not an
 * adoption gap. With the adoption dimensions neutralized, such a finding would
 * otherwise be diluted to a "good" verdict by the weighted average (one finding
 * moves the composite only a few points). So the dominant-analyzer floor sees a
 * critical-band credential score — a committed production secret must pull the
 * verdict to "needs attention". Both critical and high severities floor: the
 * scanner already suppresses examples/placeholders, so a surviving high-severity
 * match is a real secret. Medium/low hints use the real credScore (no clamp).
 * The weighted-average composite keeps using the real credScore separately.
 */
export function credentialFloorScore(credScore: number, bySeverity: Record<string, number>): number {
  if ((bySeverity['critical'] ?? 0) > 0) return Math.min(credScore, CRITICAL_BAND - 10);
  if ((bySeverity['high'] ?? 0) > 0) return Math.min(credScore, CRITICAL_BAND - 5);
  return credScore;
}

export type ScoreDimension = 'trust' | 'credentials' | 'integrity' | 'shield' | 'hma' | 'shadowAi';

/** The composite's weights, by whether HMA ran. The one table the composite,
 *  the recovery simulation and the report's score model read. */
export const COMPOSITE_WEIGHTS: Readonly<Record<'withHma' | 'withoutHma', Readonly<Record<ScoreDimension, number>>>> = {
  withHma: { trust: 0.25, credentials: 0.18, integrity: 0.12, shield: 0.22, hma: 0.08, shadowAi: 0.15 },
  withoutHma: { trust: 0.30, credentials: 0.20, integrity: 0.15, shield: 0.20, hma: 0, shadowAi: 0.15 },
};

function computeCompositeScore(inputs: Record<ScoreDimension, number>, hmaAvailable: boolean): number {
  const w = hmaAvailable ? COMPOSITE_WEIGHTS.withHma : COMPOSITE_WEIGHTS.withoutHma;
  return Math.round(
    inputs.trust * w.trust +
    inputs.credentials * w.credentials +
    inputs.integrity * w.integrity +
    inputs.shield * w.shield +
    (hmaAvailable ? inputs.hma * w.hma : 0) +
    inputs.shadowAi * w.shadowAi,
  );
}

/** The analyzer results the composite is computed from. Recovery is simulated
 *  by changing what a fix changes here and scoring again. */
export interface ScoreState {
  hygieneChecks: HygieneCheck[];
  credentials: CredentialPhaseData;
  guard: GuardPhaseData;
  shield: Pick<ShieldPhaseData, 'classifiedFindings' | 'preExclusionCounts'>;
  hma: { available: boolean; score: number };
  detect: Pick<DetectPhaseData, 'mcpServers' | 'aiConfigs'>;
}

export interface ScoreResult {
  composite: number;
  /** The weighted average before the dominant-analyzer floor. */
  weighted: number;
  weightSet: 'withHma' | 'withoutHma';
  weights: Readonly<Record<ScoreDimension, number>>;
  /** Each dimension's input to the weighted average. */
  inputs: Record<ScoreDimension, number>;
  participants: FloorParticipant[];
}

/** The composite exactly as review() reports it: risk-only dimension views,
 *  the weighted average, then the dominant-analyzer floor (see the notes where
 *  review() calls it). */
export function scoreReview(state: ScoreState): ScoreResult {
  const trustScore = calculateTrustScore(state.hygieneChecks).score;
  const credScore = computeCredentialScore(state.credentials);
  const guardScore = computeGuardScore(state.guard);
  const hmaAvailable = state.hma.available;
  const hmaScore = hmaAvailable ? state.hma.score : 0;
  const projectGovernance = targetGovernanceFloorScore(state.detect);
  const shieldRisk = shieldRiskFloorScore(state.shield);
  const inputs: Record<ScoreDimension, number> = {
    trust: trustScore,
    credentials: credScore,
    integrity: guardScore,
    shield: shieldCompositeScore(state.shield),
    hma: hmaScore,
    shadowAi: governanceCompositeScore(projectGovernance),
  };
  const weighted = computeCompositeScore(inputs, hmaAvailable);
  const participants = buildFloorParticipants({
    trustScore,
    credScore: credentialFloorScore(credScore, state.credentials.bySeverity),
    guardScore,
    hmaScore,
    hmaAvailable,
    projectGovernanceScore: projectGovernance.score,
    projectGovernanceRan: projectGovernance.ran,
    shieldRiskScore: shieldRisk.score,
    shieldRiskRan: shieldRisk.ran,
  });
  const weightSet = hmaAvailable ? 'withHma' : 'withoutHma';
  return {
    composite: applyDominantAnalyzerFloor(weighted, participants),
    weighted,
    weightSet,
    weights: COMPOSITE_WEIGHTS[weightSet],
    inputs,
    participants,
  };
}

/** The critical band. An analyzer scoring below this is reporting a critical
 *  problem with the *target*, and the composite must not present a verdict
 *  that disagrees in direction. See #175. */
export const CRITICAL_BAND = 30;

/** One analyzer's contribution to the dominant-analyzer floor. */
export interface FloorParticipant {
  name: string;
  score: number;
  /** false when the analyzer was skipped/unavailable — excluded from the floor. */
  ran: boolean;
}

/** Inputs needed to build the dominant-analyzer floor participant set. */
export interface FloorParticipantInputs {
  trustScore: number;
  credScore: number;
  guardScore: number;
  hmaScore: number;
  hmaAvailable: boolean;
  /** Target-local governance floor score (see targetGovernanceFloorScore) —
   *  derived ONLY from in-repo critical MCP servers / AI configs, never the
   *  host process scan. */
  projectGovernanceScore: number;
  /** True only when a target-local critical governance signal exists, so a
   *  clean repo never participates via governance. */
  projectGovernanceRan: boolean;
  /** Shield runtime-risk floor score (see shieldRiskFloorScore) — the genuine
   *  target-risk slice of Shield (classified critical/high runtime findings),
   *  never the adoption baseline posture. */
  shieldRiskScore: number;
  /** True only when a classified critical/high Shield runtime finding fired. */
  shieldRiskRan: boolean;
}

/**
 * Target-local governance floor signal (#175 follow-up).
 *
 * `detectData.governanceScore` is NOT a safe floor input because it blends a
 * host process scan (`ps aux`) — which reflects the developer's machine, not
 * the scanned project. This helper extracts ONLY the target-local critical
 * signals that runDetectPhase also surfaces as critical findings: an in-repo
 * (`source` contains "(project)"), unverified MCP server declared at the
 * `critical` risk tier, or an AI config file at the `critical` risk tier
 * (credential references). When either is present the target itself is
 * dangerous, so governance participates in the floor at score 0; otherwise it
 * does not participate (`ran: false`) and cannot clamp a clean repo.
 */
export function targetGovernanceFloorScore(detect: {
  mcpServers: { risk: string; source: string; verified: boolean }[];
  aiConfigs: { risk: string }[];
}): { score: number; ran: boolean } {
  const projectCriticalMcp = detect.mcpServers.some(
    s => s.risk === 'critical' && !s.verified && s.source.includes('(project)'),
  );
  const criticalConfig = detect.aiConfigs.some(c => c.risk === 'critical');
  if (projectCriticalMcp || criticalConfig) return { score: 0, ran: true };
  return { score: 100, ran: false };
}

/**
 * Build the participant set for the dominant-analyzer floor (#175).
 *
 * Only analyzers whose critical-band score is an *unambiguous target-malice
 * signal* participate — a low score must mean "the target itself is dangerous",
 * never "the developer's environment is unconfigured". Two analyzers are
 * deliberately EXCLUDED:
 *
 *   - Shield Analysis: posture score has a baseline of 25 for any user who has
 *     not run `opena2a shield init` (see runShieldPhase). A low Shield score
 *     signals "defensive tooling not set up", not target malice.
 *   - Shadow AI / governance (the raw governanceScore): partly derived from a
 *     host process scan (runDetectPhase → scanProcesses → `ps aux`), so it
 *     reflects AI tools running on the *developer's machine* (Claude Code,
 *     Cursor, …), not the scanned project. A clean repo on a dev box running
 *     ungoverned agents can drop governanceScore below the critical band, which
 *     would wrongly clamp the verdict (#175 follow-up — false-positive). The
 *     governanceScore as a whole is therefore NOT a floor input.
 *
 * Governance is NOT dropped entirely, though — that would narrow detection (a
 * target whose only critical signal is an in-repo malicious MCP server / AI
 * config would escape the floor). Instead the *target-local* slice of
 * governance participates via `projectGovernanceScore` (see
 * targetGovernanceFloorScore), which is computed only from in-repo critical
 * declarations and never from the host process scan.
 *
 * Participants — Project Scan (trust), Credentials, Config Integrity, HMA Scan,
 * Project Governance, and Shield Runtime Risk — are all scoped to the target.
 * HMA Scan only participates when it actually ran (`hmaAvailable`); Project
 * Governance only when a target-local critical signal exists
 * (`projectGovernanceRan`); Shield Runtime Risk only when a classified
 * critical/high runtime finding fired (`shieldRiskRan`) — NOT the adoption
 * baseline posture. HMA's score is coerced to a finite number so a malformed
 * HMA payload cannot poison the floor with NaN.
 *
 * NOTE: a target whose only critical signal is what HMA `secure` catches (and
 * which declares no in-repo critical MCP/config) is floored ONLY by HMA. When
 * HMA does not run, the caller must surface that the verdict is provisional
 * (see review() degraded-mode warning + `provisional` JSON flag) rather than
 * present a non-floored "improving" score.
 */
export function buildFloorParticipants(inputs: FloorParticipantInputs): FloorParticipant[] {
  const hmaScore = Number.isFinite(inputs.hmaScore) ? inputs.hmaScore : 0;
  return [
    { name: 'Project Scan', score: inputs.trustScore, ran: true },
    { name: 'Credentials', score: inputs.credScore, ran: true },
    { name: 'Config Integrity', score: inputs.guardScore, ran: true },
    { name: 'HMA Scan', score: hmaScore, ran: inputs.hmaAvailable },
    { name: 'Project Governance', score: inputs.projectGovernanceScore, ran: inputs.projectGovernanceRan },
    { name: 'Shield Runtime Risk', score: inputs.shieldRiskScore, ran: inputs.shieldRiskRan },
  ];
}

/**
 * Dominant-analyzer floor (#175).
 *
 * The composite is a weighted average, so a single analyzer reporting a
 * critical problem (e.g. HMA `secure` 0/100 on a kitchen-sink fixture) can be
 * out-voted by clean dimensions and float the composite into an "improving"
 * band. That is a DIRECTION disagreement: `opena2a review` says recoverable
 * while `opena2a check` says 0/100. This floor forces direction agreement —
 * when any participating analyzer lands in the critical band, the composite is
 * clamped down to the lowest such score. See buildFloorParticipants for which
 * analyzers participate and why.
 *
 * Non-finite participant scores are filtered out so a malformed analyzer payload
 * cannot silently disable the floor (NaN < 30 is false, which would otherwise
 * skip the clamp entirely).
 */
export function applyDominantAnalyzerFloor(
  composite: number,
  participants: FloorParticipant[],
): number {
  const scores = participants.filter(p => p.ran && Number.isFinite(p.score)).map(p => p.score);
  if (scores.length === 0) return composite;
  const minScore = Math.min(...scores);
  if (minScore < CRITICAL_BAND) return Math.min(composite, minScore);
  return composite;
}

function scoreToGrade(score: number): string {
  // Kept for JSON backward compatibility; not displayed in CLI or HTML output
  if (score >= 90) return 'strong';
  if (score >= 80) return 'good';
  if (score >= 70) return 'moderate';
  if (score >= 60) return 'improving';
  return 'needs-attention';
}

// --- Findings Aggregation ---

/** HMA check-ID prefixes that indicate a credential-related finding.
 *  Used to scope the prefer-HMA dedupe: only credential HMA findings
 *  suppress credential-scan matches. Non-credential HMA findings on the
 *  same file (e.g. GIT-002 on .gitignore) MUST NOT hide a credential that
 *  the credential scan found in that file. */
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
  detectData?: Pick<DetectPhaseData, 'findings'> | null,
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

  // Shadow AI findings about the scanned tree itself. These are the signals
  // that floor the composite (targetGovernanceFloorScore), so leaving them out
  // printed "0 findings" and a safe verdict beside the 0/100 they caused.
  // Host-scoped findings describe the developer's machine and stay in the
  // Shadow AI phase.
  for (const f of detectData?.findings ?? []) {
    if (f.scope !== 'project') continue;
    findings.push({
      id: f.id,
      title: f.title,
      severity: f.severity,
      source: 'shadow-ai',
      detail: f.detail || f.whyItMatters,
      remediation: f.remediation,
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

function writeReviewHtml(reportPath: string, report: ReviewReport): void {
  // Owner-only: the report names every finding's file:line and is written to a
  // shared temp directory by default. `mode` applies only when the file is
  // created, so an existing --report path keeps its own permissions.
  fs.writeFileSync(reportPath, generateReviewHtml(report), { encoding: 'utf-8', mode: 0o600 });
}

/**
 * Open the HTML report only for a person at a terminal. A pipe, a redirect or
 * a CI job has nobody to look at the browser window, so stdout must be a TTY
 * as well as auto-open being on and --ci being off.
 */
export function shouldAutoOpenReport(
  options: Pick<ReviewOptions, 'autoOpen' | 'ci'>,
  stdoutIsTTY: boolean,
): boolean {
  return options.autoOpen !== false && !options.ci && stdoutIsTTY;
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

/**
 * The Registry ecosystem a reviewed project's package name belongs to: npm
 * when the name was read from package.json, pypi when it was read from
 * pyproject.toml, null for any other source or none. The Registry accepts
 * npm, pypi and github as a contributed scan's ecosystem.
 */
export function registryEcosystem(nameSource: NameSource | null): 'npm' | 'pypi' | null {
  if (nameSource === 'package.json') return 'npm';
  if (nameSource === 'pyproject.toml') return 'pypi';
  return null;
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

function calculateTrustScore(checks: HygieneCheck[]): { score: number; grade: string } {
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
