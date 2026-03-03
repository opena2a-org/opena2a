/**
 * opena2a init -- Initialize security posture assessment for a project.
 *
 * Findings-first design: shows what was found, explains why it matters,
 * calculates a unified security score, and generates prioritized actions.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { bold, green, yellow, red, cyan, dim, gray } from '../util/colors.js';
import { detectProject, type ProjectInfo, type ProjectType } from '../util/detect.js';
import { quickCredentialScan, type CredentialMatch } from '../util/credential-patterns.js';
import { checkAdvisories, printAdvisoryWarnings, type AdvisoryCheck } from '../util/advisories.js';
import { wordWrap } from '../util/format.js';
import { getVersion } from '../util/version.js';
import { Spinner } from '../util/spinner.js';
import { writeEvent, getShieldDir } from '../shield/events.js';
import { getShieldStatus } from '../shield/status.js';
import type { EventSeverity, RiskLevel } from '../shield/types.js';

// --- Types ---

export interface InitOptions {
  targetDir?: string;
  ci?: boolean;
  format?: 'text' | 'json';
  verbose?: boolean;
}

interface HygieneCheck {
  label: string;
  status: 'pass' | 'warn' | 'fail' | 'info';
  detail: string;
}

interface ScoreBreakdown {
  credentials: { deduction: number; detail: string };
  environment: { deduction: number; detail: string };
  configuration: { deduction: number; detail: string };
}

interface GroupedFinding {
  findingId: string;
  title: string;
  severity: string;
  count: number;
  explanation: string;
  businessImpact: string;
  locations: { file: string; line: number }[];
}

interface ActionItem {
  description: string;
  command: string;
  why: string;
  approach?: string;
  detail?: string;
}

interface NextStep {
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  command: string;
}

interface InitReport {
  version: 2;
  projectName: string | null;
  projectVersion: string | null;
  projectType: string;
  directory: string;
  credentialFindings: number;
  credentialsBySeverity: Record<string, number>;
  hygieneChecks: HygieneCheck[];
  securityScore: number;
  securityGrade: string;
  scoreBreakdown: ScoreBreakdown;
  findings: GroupedFinding[];
  actions: ActionItem[];
  nextSteps: NextStep[];
  advisories: { count: number; matchedPackages: string[] };
  hmaAvailable: boolean;
  // Backward compat aliases (v1 consumers)
  trustScore: number;
  grade: string;
  postureScore: number;
  riskLevel: RiskLevel;
  activeTools: number;
  totalTools: number;
}

// --- Core ---

export async function init(options: InitOptions): Promise<number> {
  const targetDir = path.resolve(options.targetDir ?? process.cwd());

  if (!fs.existsSync(targetDir)) {
    process.stderr.write(red(`Directory not found: ${targetDir}\n`));
    return 1;
  }

  const startTime = Date.now();
  const isTTY = process.stderr.isTTY && options.format !== 'json';
  const spinner = new Spinner('Scanning project...');
  if (isTTY) spinner.start();

  // 1. Detect project type
  const project = detectProject(targetDir);

  // 2. Quick credential scan
  if (isTTY) spinner.update('Scanning for credentials...');
  const credentialMatches = quickCredentialScan(targetDir);
  const credsBySeverity: Record<string, number> = {};
  for (const m of credentialMatches) {
    credsBySeverity[m.severity] = (credsBySeverity[m.severity] || 0) + 1;
  }

  // 3. Security hygiene checks
  if (isTTY) spinner.update('Checking environment...');
  const checks = await runHygieneChecks(targetDir, project, credentialMatches.length);

  // 4. Check advisories (non-blocking)
  let advisoryCheck: AdvisoryCheck = { advisories: [], matchedPackages: [], total: 0, fromCache: false };
  try {
    advisoryCheck = await checkAdvisories(targetDir);
  } catch {
    // Advisory check is best-effort
  }

  // 5. HMA integration (optional dynamic import)
  if (isTTY) spinner.update('Scanning shell environment...');
  let hmaAvailable = false;
  const hmaFindings: { severity: string; checkId: string; message: string }[] = [];
  try {
    const hma = await import('hackmyagent');
    hmaAvailable = true;
    if (typeof hma.checkShellEnvironment === 'function') {
      const shellEnv = await hma.checkShellEnvironment();
      if (Array.isArray(shellEnv)) hmaFindings.push(...shellEnv);
    }
    if (typeof hma.checkShellHistory === 'function') {
      const shellHistory = await hma.checkShellHistory();
      if (Array.isArray(shellHistory)) hmaFindings.push(...shellHistory);
    }
  } catch {
    // HMA not installed -- skip silently
  }

  // 6. Group findings
  const groupedFindings = groupFindings(credentialMatches, checks, hmaFindings);

  // 7. Calculate unified security score
  if (isTTY) spinner.update('Assessing security posture...');
  const hmaBySeverity: Record<string, number> = {};
  for (const f of hmaFindings) {
    hmaBySeverity[f.severity] = (hmaBySeverity[f.severity] || 0) + 1;
  }
  const { score, grade, breakdown } = calculateSecurityScore(credsBySeverity, checks, hmaBySeverity);

  // 8. Generate actions
  const actions = generateActions(credentialMatches, credsBySeverity, checks, groupedFindings);

  // 9. Generate legacy next steps (backward compat)
  const nextSteps = generateNextSteps(credentialMatches.length, credsBySeverity, checks, project.type);

  // 10. Shield tool status (for backward compat and tip line)
  const shieldStatus = getShieldStatus(targetDir);
  const activeTools = shieldStatus.tools.filter(p => p.active).length;
  const totalTools = shieldStatus.tools.length;

  // 11. Write shield events
  try {
    getShieldDir(targetDir);
    const riskLevel = scoreToRiskLevel(score);
    writeEvent({
      source: 'shield',
      category: 'shield.posture',
      severity: (riskLevel === 'CRITICAL' ? 'critical' : riskLevel === 'HIGH' ? 'high' : riskLevel === 'MEDIUM' ? 'medium' : 'info') as EventSeverity,
      agent: null,
      sessionId: null,
      action: 'posture-assessment',
      target: targetDir,
      outcome: 'monitored',
      detail: { score, grade, breakdown, activeTools, totalTools },
      orgId: null,
      managed: false,
      agentId: null,
    }, targetDir);
    for (const cred of credentialMatches) {
      writeEvent({
        source: 'shield',
        category: 'shield.credential',
        severity: (cred.severity === 'critical' ? 'critical' : cred.severity === 'high' ? 'high' : 'medium') as EventSeverity,
        agent: null,
        sessionId: null,
        action: 'credential-finding',
        target: cred.filePath,
        outcome: 'monitored',
        detail: { findingId: cred.findingId, title: cred.title, line: cred.line },
        orgId: null,
        managed: false,
        agentId: null,
      }, targetDir);
    }
  } catch {
    // Shield event writing is best-effort
  }

  if (isTTY) spinner.stop();

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  // 12. Build report
  const riskLevel = scoreToRiskLevel(score);
  const report: InitReport = {
    version: 2,
    projectName: project.name,
    projectVersion: project.version,
    projectType: formatProjectType(project),
    directory: targetDir,
    credentialFindings: credentialMatches.length,
    credentialsBySeverity: credsBySeverity,
    hygieneChecks: checks,
    securityScore: score,
    securityGrade: grade,
    scoreBreakdown: breakdown,
    findings: groupedFindings,
    actions,
    nextSteps,
    advisories: {
      count: advisoryCheck.advisories.length,
      matchedPackages: advisoryCheck.matchedPackages,
    },
    hmaAvailable,
    // Backward compat aliases
    trustScore: score,
    grade,
    postureScore: score,
    riskLevel,
    activeTools,
    totalTools,
  };

  // 13. Output
  if (options.format === 'json') {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    printReport(report, elapsed, options.verbose);

    // Drift detection callout (always shown when drift findings exist)
    const driftFindings = credentialMatches.filter(m => m.findingId.startsWith('DRIFT'));
    if (driftFindings.length > 0) {
      process.stdout.write(yellow(bold('  Scope Drift Detected')) + '\n');
      process.stdout.write(gray('  ' + '-'.repeat(47)) + '\n');
      for (const d of driftFindings) {
        const relPath = path.relative(targetDir, d.filePath);
        const driftType = d.findingId === 'DRIFT-001' ? 'Google Maps key may access Gemini AI' : 'AWS key may access Bedrock AI';
        process.stdout.write(`  ${yellow(d.findingId)} ${driftType}\n`);
        process.stdout.write(`  ${dim('  ' + relPath + ':' + d.line)}\n`);
      }
      process.stdout.write('\n');
      process.stdout.write(dim('  Scope drift: keys provisioned for one service silently') + '\n');
      process.stdout.write(dim('  gain access to AI services, expanding attack surface.') + '\n');
      process.stdout.write(dim('  Run: opena2a protect') + '\n');
      process.stdout.write('\n');
    }

    // Show advisory warnings after main report
    if (advisoryCheck.advisories.length > 0) {
      printAdvisoryWarnings(advisoryCheck);
    }
  }

  const hasCritical = nextSteps.some(s => s.severity === 'critical');
  return hasCritical ? 1 : 0;
}

// --- Hygiene checks ---

async function runHygieneChecks(
  dir: string,
  project: ReturnType<typeof detectProject>,
  credCount: number,
): Promise<HygieneCheck[]> {
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

  // MCP config
  if (project.hasMcp) {
    checks.push({ label: 'MCP config', status: 'info', detail: 'found' });
  }

  // LLM server exposure (lightweight probe of common ports)
  const llmCheck = await checkLLMServerExposure();
  if (llmCheck) {
    checks.push(llmCheck);
  }

  return checks;
}

// --- LLM server exposure check ---

const LLM_PROBE_PORTS = [
  { name: 'Ollama', port: 11434, path: '/api/tags' },
  { name: 'LM Studio', port: 1234, path: '/v1/models' },
];

async function checkLLMServerExposure(): Promise<HygieneCheck | null> {
  for (const server of LLM_PROBE_PORTS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2000);
    try {
      const resp = await fetch(`http://127.0.0.1:${server.port}${server.path}`, {
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (resp.ok || resp.status < 500) {
        // Check if no auth required
        const noAuth = resp.status !== 401 && resp.status !== 403;
        if (noAuth) {
          return {
            label: 'LLM server exposure',
            status: 'warn',
            detail: `${server.name} on :${server.port} (no auth)`,
          };
        }
        return {
          label: 'LLM server exposure',
          status: 'info',
          detail: `${server.name} on :${server.port}`,
        };
      }
    } catch {
      clearTimeout(timer);
      // Server not running on this port, continue
    }
  }
  return null;
}

// --- Finding grouping ---

function groupFindings(
  creds: CredentialMatch[],
  checks: HygieneCheck[],
  hmaFindings: { severity: string; checkId: string; message: string }[],
): GroupedFinding[] {
  const groups = new Map<string, GroupedFinding>();

  // Group credential findings by findingId
  for (const cred of creds) {
    const existing = groups.get(cred.findingId);
    if (existing) {
      existing.count++;
      existing.locations.push({
        file: cred.filePath,
        line: cred.line,
      });
    } else {
      groups.set(cred.findingId, {
        findingId: cred.findingId,
        title: cred.title,
        severity: cred.severity,
        count: 1,
        explanation: cred.explanation ?? '',
        businessImpact: cred.businessImpact ?? '',
        locations: [{ file: cred.filePath, line: cred.line }],
      });
    }
  }

  // Add hygiene findings as grouped findings
  const llmCheck = checks.find(c => c.label === 'LLM server exposure' && c.status === 'warn');
  if (llmCheck) {
    groups.set('ENV-LLM', {
      findingId: 'ENV-LLM',
      title: llmCheck.detail,
      severity: 'high',
      count: 1,
      explanation: 'Local LLM server is responding without authentication. Adding auth limits access to authorized users.',
      businessImpact: 'Unauthenticated model access. Adding auth ensures only intended users can query.',
      locations: [],
    });
  }

  const envCheck = checks.find(c => c.label === '.env protection' && c.status === 'warn');
  if (envCheck) {
    groups.set('ENV-DOTENV', {
      findingId: 'ENV-DOTENV',
      title: '.env not in .gitignore',
      severity: 'medium',
      count: 1,
      explanation: 'Environment files may be committed to version control.',
      businessImpact: 'Adding .env to .gitignore keeps secrets out of version control.',
      locations: [],
    });
  }

  // Add HMA findings
  for (const f of hmaFindings) {
    const key = `HMA-${f.checkId}`;
    const existing = groups.get(key);
    if (existing) {
      existing.count++;
    } else {
      groups.set(key, {
        findingId: key,
        title: f.message,
        severity: f.severity,
        count: 1,
        explanation: '',
        businessImpact: '',
        locations: [],
      });
    }
  }

  // Sort by severity order: critical > high > medium > low
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return Array.from(groups.values()).sort((a, b) => {
    const sa = severityOrder[a.severity] ?? 4;
    const sb = severityOrder[b.severity] ?? 4;
    if (sa !== sb) return sa - sb;
    return b.count - a.count;
  });
}

// --- Unified Security Score ---

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

  const credDetail = credCount(critCount, highCount, medCount, lowCount);

  // --- Environment category (cap at -25) ---
  let envDeduction = 0;
  const llmCheck = checks.find(c => c.label === 'LLM server exposure');
  if (llmCheck?.status === 'warn') envDeduction += 10;

  const envProtection = checks.find(c => c.label === '.env protection');
  if (envProtection?.status === 'warn') envDeduction += 8;

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
  if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'B';
  else if (score >= 70) grade = 'C';
  else if (score >= 60) grade = 'D';
  else grade = 'F';

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

function credCount(crit: number, high: number, med: number, low: number): string {
  const parts: string[] = [];
  if (crit > 0) parts.push(`${crit} critical`);
  if (high > 0) parts.push(`${high} high`);
  if (med > 0) parts.push(`${med} medium`);
  if (low > 0) parts.push(`${low} low`);
  return parts.length > 0 ? parts.join(', ') : 'none';
}

function scoreToRiskLevel(score: number): RiskLevel {
  if (score >= 90) return 'SECURE';
  if (score >= 70) return 'LOW';
  if (score >= 50) return 'MEDIUM';
  if (score >= 30) return 'HIGH';
  return 'CRITICAL';
}

// --- Actions ---

function generateActions(
  creds: CredentialMatch[],
  credsBySeverity: Record<string, number>,
  checks: HygieneCheck[],
  findings: GroupedFinding[],
): ActionItem[] {
  const actions: ActionItem[] = [];

  // Credential migration action
  if (creds.length > 0) {
    // Build breakdown string
    const byTitle = new Map<string, number>();
    for (const c of creds) {
      byTitle.set(c.title, (byTitle.get(c.title) || 0) + 1);
    }
    const breakdownParts = Array.from(byTitle.entries())
      .map(([title, count]) => `${count} ${title.replace(/ \(.*\)/, '')}`)
      .join(', ');

    // Recovery framing: show how many points this action recovers
    const credRecovery = Math.min(
      (credsBySeverity['critical'] || 0) * 20 + (credsBySeverity['high'] || 0) * 12 + (credsBySeverity['medium'] || 0) * 4 + (credsBySeverity['low'] || 0) * 2,
      60,
    );
    const why = credRecovery > 0
      ? `Recover up to ${credRecovery} points. Credentials move to environment variables where they are not committed to source.`
      : 'Moves credentials out of source files into environment variables.';

    actions.push({
      description: `Migrate ${creds.length} hardcoded credential${creds.length === 1 ? '' : 's'}`,
      command: 'opena2a protect',
      why,
      approach: 'Moves keys to environment variables backed by an encrypted vault. Keys rotate without code changes, and access is auditable.',
      detail: `Keys found: ${breakdownParts}`,
    });
  }

  // .env protection
  const envCheck = checks.find(c => c.label === '.env protection');
  if (envCheck?.status === 'warn') {
    actions.push({
      description: 'Add .env to .gitignore',
      command: "echo '.env' >> .gitignore",
      why: 'Recover 8 points. Ensures secrets stay local and never enter version control.',
      approach: 'Adds .env to .gitignore so git never tracks secrets. Existing tracked .env files need git rm --cached .env.',
    });
  }

  // .gitignore
  const gitignoreCheck = checks.find(c => c.label === '.gitignore');
  if (gitignoreCheck?.status !== 'pass') {
    actions.push({
      description: 'Create .gitignore',
      command: 'npx gitignore node',
      why: 'Recover 8 points. Keeps build artifacts and sensitive files out of version control.',
      approach: 'Generates a language-specific .gitignore that excludes build artifacts, dependencies, and secret files from commits.',
    });
  }

  // LLM server exposure
  const llmCheck = checks.find(c => c.label === 'LLM server exposure' && c.status === 'warn');
  if (llmCheck) {
    actions.push({
      description: 'Secure LLM server',
      command: 'opena2a shield status',
      why: 'Recover 10 points. Adds authentication so only authorized users can access your models.',
      approach: 'Bind LLM servers to localhost only, or add authentication via a reverse proxy before exposing to the network.',
    });
  }

  // Config signing
  actions.push({
    description: 'Sign config files for integrity',
    command: 'opena2a guard sign',
    why: 'Recover 3 points. Establishes a signed baseline so config changes are always intentional.',
    approach: 'Creates cryptographic signatures of config files. Any unauthorized change is detected before code runs.',
  });

  // Cap at 5 actions
  return actions.slice(0, 5);
}

// --- Legacy next steps (backward compat) ---

function generateNextSteps(
  credCount: number,
  credsBySeverity: Record<string, number>,
  checks: HygieneCheck[],
  projectType?: ProjectType | string,
): NextStep[] {
  const steps: NextStep[] = [];

  if (credCount > 0) {
    steps.push({
      severity: 'critical',
      description: `Migrate ${credCount} hardcoded credential${credCount === 1 ? '' : 's'}`,
      command: 'opena2a protect',
    });
  }

  const envCheck = checks.find(c => c.label === '.env protection');
  if (envCheck?.status === 'warn') {
    steps.push({
      severity: 'high',
      description: 'Add .env to .gitignore',
      command: "echo '.env' >> .gitignore",
    });
  }

  const gitignoreCheck = checks.find(c => c.label === '.gitignore');
  if (gitignoreCheck?.status !== 'pass') {
    const gitignoreTemplate = projectType === 'python' ? 'python'
      : projectType === 'go' ? 'go'
      : 'node';
    steps.push({
      severity: 'high',
      description: 'Create .gitignore',
      command: `npx gitignore ${gitignoreTemplate}`,
    });
  }

  steps.push({
    severity: 'medium',
    description: 'Sign config files for integrity',
    command: 'opena2a guard sign',
  });

  steps.push({
    severity: 'low',
    description: 'Start runtime protection',
    command: 'opena2a runtime start',
  });

  return steps;
}

// --- Verification & Recommendation helpers ---

function getVerificationCommand(
  finding: GroupedFinding,
  reportDir: string,
): string | null {
  // Credential/drift findings with file locations
  if (
    (finding.findingId.startsWith('CRED-') || finding.findingId.startsWith('DRIFT-')) &&
    finding.locations.length > 0
  ) {
    const loc = finding.locations[0];
    const rel = path.relative(reportDir, loc.file);
    return `sed -n '${loc.line}p' ${rel}`;
  }

  // HMA findings -- title contains "~/.zshrc:132 contains ..." pattern
  if (finding.findingId.startsWith('HMA-')) {
    const match = finding.title.match(/^(.+?):(\d+)\s+contains\s+/);
    if (match) {
      return `sed -n '${match[2]}p' ${match[1]}`;
    }
  }

  if (finding.findingId === 'ENV-LLM') {
    return 'curl -s http://127.0.0.1:11434/api/tags | head -c 200';
  }
  if (finding.findingId === 'ENV-DOTENV') {
    return "cat .gitignore | grep -c '.env'";
  }
  return null;
}

function getToolRecommendation(
  findingId: string,
): { command: string; label: string } | null {
  if (findingId.startsWith('CRED-') || findingId.startsWith('DRIFT-')) {
    return { command: 'opena2a protect', label: 'opena2a protect' };
  }
  if (findingId === 'ENV-LLM') {
    return { command: 'opena2a shield status', label: 'opena2a shield status' };
  }
  if (findingId === 'ENV-DOTENV') {
    return { command: "echo '.env' >> .gitignore", label: "echo '.env' >> .gitignore" };
  }
  if (findingId.startsWith('HMA-')) {
    return { command: 'opena2a scan secure', label: 'opena2a scan secure' };
  }
  return null;
}

function getContextualTip(
  report: InitReport,
): { text: string; command: string } {
  const hasAnyCreds = report.findings.some(
    f => f.findingId.startsWith('CRED-') || f.findingId.startsWith('DRIFT-'),
  );
  if (hasAnyCreds) {
    const credRecovery = report.scoreBreakdown.credentials.deduction;
    return {
      text: `Migrate credentials to recover ${credRecovery} points`,
      command: 'opena2a protect',
    };
  }

  const hasLLM = report.findings.some(f => f.findingId === 'ENV-LLM');
  if (hasLLM) {
    return {
      text: 'Add authentication to your LLM server to recover 10 points',
      command: 'opena2a shield status',
    };
  }

  const hasEnv = report.findings.some(f => f.findingId === 'ENV-DOTENV');
  if (hasEnv) {
    return {
      text: 'Add .env to .gitignore to recover 8 points',
      command: "echo '.env' >> .gitignore",
    };
  }

  if (report.securityScore >= 90) {
    return {
      text: 'Strong baseline. Run a full 150+ check scan for deeper coverage',
      command: 'opena2a scan secure',
    };
  }
  if (report.securityScore >= 70) {
    return {
      text: 'Good posture. Lock it in with config file integrity signing',
      command: 'opena2a guard sign',
    };
  }

  return {
    text: 'See all available security tools',
    command: 'opena2a shield status',
  };
}

// --- Output ---

function formatProjectType(project: ProjectInfo): string {
  const primary: Record<ProjectType, string> = {
    node: 'Node.js',
    go: 'Go',
    python: 'Python',
    rust: 'Rust',
    java: 'Java',
    ruby: 'Ruby',
    docker: 'Docker',
    generic: 'Project',
  };
  const parts = [primary[project.type]];
  for (const hint of project.frameworkHints) {
    parts.push(`+ ${hint}`);
  }
  return parts.join(' ');
}

function printReport(report: InitReport, elapsed: string, verbose?: boolean): void {
  const VERSION = getVersion();

  process.stdout.write('\n');
  process.stdout.write(bold('  OpenA2A Security Assessment') + dim(`  v${VERSION}`) + dim(`         ${elapsed}s`) + '\n\n');

  // Project info
  const projectDisplay = report.projectName
    ? `${report.projectName}${report.projectVersion ? ' v' + report.projectVersion : ''}`
    : path.basename(report.directory);

  process.stdout.write(`  ${dim('Project')}      ${projectDisplay}\n`);
  process.stdout.write(`  ${dim('Stack')}        ${report.projectType}\n`);
  process.stdout.write(`  ${dim('Directory')}    ${report.directory}\n`);
  process.stdout.write('\n');

  // --- Findings section ---
  if (report.findings.length > 0) {
    process.stdout.write(bold('  Findings') + '\n');
    process.stdout.write(gray('  ' + '-'.repeat(47)) + '\n');

    const maxFindings = verbose ? report.findings.length : 5;
    const displayFindings = report.findings.slice(0, maxFindings);

    for (const finding of displayFindings) {
      const sevTag = finding.severity === 'critical' ? red('CRITICAL')
        : finding.severity === 'high' ? yellow('HIGH    ')
        : finding.severity === 'medium' ? cyan('MEDIUM  ')
        : dim('LOW     ');

      const countPrefix = finding.count > 1 ? `${finding.count} ` : '';
      process.stdout.write(`  ${sevTag}  ${countPrefix}${bold(finding.title)}\n`);

      if (finding.explanation) {
        const wrapped = wordWrap(finding.explanation, 70, 12);
        process.stdout.write(dim(wrapped) + '\n');
      }

      // Show file locations (max 3 unless verbose)
      if (finding.locations.length > 0) {
        const maxLocs = verbose ? finding.locations.length : 3;
        const locs = finding.locations.slice(0, maxLocs);
        const locStrings = locs.map(l => {
          const rel = path.relative(report.directory, l.file);
          return `${rel}:${l.line}`;
        });
        process.stdout.write(dim('            ' + locStrings.join('  ')) + '\n');
        if (finding.locations.length > maxLocs) {
          process.stdout.write(dim(`            +${finding.locations.length - maxLocs} more`) + '\n');
        }
      }

      // Verification command
      const verifyCmd = getVerificationCommand(finding, report.directory);
      if (verifyCmd) {
        process.stdout.write(`            ${dim('Verify:')} ${cyan(verifyCmd)}\n`);
      }

      // Tool recommendation
      const toolRec = getToolRecommendation(finding.findingId);
      if (toolRec) {
        process.stdout.write(`            ${dim('Fix:')}    ${cyan(toolRec.command)}\n`);
      }

      process.stdout.write('\n');
    }

    if (!verbose && report.findings.length > maxFindings) {
      const remaining = report.findings.length - maxFindings;
      process.stdout.write(dim(`  [+${remaining} more finding${remaining === 1 ? '' : 's'} -- run with --verbose to see all]`) + '\n');
      process.stdout.write('\n');
    }
  } else {
    process.stdout.write(green('  No security findings detected.') + '\n\n');
  }

  // --- Security Score ---
  const scoreColor = report.securityScore >= 80 ? green
    : report.securityScore >= 60 ? yellow
    : red;

  // Calculate potential score after fixes
  const breakdown = report.scoreBreakdown;
  const totalRecoverable = breakdown.credentials.deduction
    + breakdown.environment.deduction
    + Math.max(0, breakdown.configuration.deduction);
  const potentialScore = Math.min(100, report.securityScore + totalRecoverable);

  // Show current score with path forward
  if (totalRecoverable > 0 && potentialScore > report.securityScore) {
    process.stdout.write(`  ${bold('Security Score:')} ${scoreColor(`${report.securityScore}`)} ${dim('->')} ${green(`${potentialScore}`)} ${dim('/ 100  (after fixes)')}\n`);
  } else {
    process.stdout.write(`  ${bold('Security Score:')} ${scoreColor(`${report.securityScore} / 100`)}\n`);
  }
  process.stdout.write(gray('  ' + '-'.repeat(47)) + '\n');

  // Breakdown framed as recovery opportunities
  if (breakdown.credentials.deduction > 0) {
    process.stdout.write(`  ${dim('Credentials')}   ${green(`+${breakdown.credentials.deduction}`)} recoverable  ${dim(`(${breakdown.credentials.detail})`)}\n`);
  }
  if (breakdown.environment.deduction > 0) {
    process.stdout.write(`  ${dim('Environment')}   ${green(`+${breakdown.environment.deduction}`)} recoverable  ${dim(`(${breakdown.environment.detail})`)}\n`);
  }
  if (breakdown.configuration.deduction > 0) {
    process.stdout.write(`  ${dim('Configuration')} ${green(`+${breakdown.configuration.deduction}`)} recoverable  ${dim(`(${breakdown.configuration.detail})`)}\n`);
  } else if (breakdown.configuration.deduction < 0) {
    process.stdout.write(`  ${dim('Configuration')} ${green(`+${Math.abs(breakdown.configuration.deduction)}`)} bonus         ${dim(`(${breakdown.configuration.detail})`)}\n`);
  }
  process.stdout.write(gray('  ' + '-'.repeat(47)) + '\n');
  process.stdout.write('\n');

  // --- Actions section ---
  if (report.actions.length > 0) {
    process.stdout.write(bold('  Actions (by impact)') + '\n');
    process.stdout.write(gray('  ' + '-'.repeat(47)) + '\n');

    for (let i = 0; i < report.actions.length; i++) {
      const action = report.actions[i];
      process.stdout.write(`  ${bold(`${i + 1}.`)} ${action.description}\n`);
      process.stdout.write(dim(`     ${action.command}`) + '\n');
      process.stdout.write(dim(`     WHY: ${action.why}`) + '\n');
      if (action.approach && i < 2) {
        const wrapped = wordWrap(action.approach, 70, 10);
        process.stdout.write(dim(`     HOW: ${wrapped.trimStart()}`) + '\n');
      }
      if (action.detail) {
        process.stdout.write(dim(`     ${action.detail}`) + '\n');
      }
      process.stdout.write('\n');
    }

    process.stdout.write(gray('  ' + '-'.repeat(47)) + '\n');
  }

  process.stdout.write('\n');

  // Contextual tip
  const tip = getContextualTip(report);
  process.stdout.write(dim(`  Tip: ${tip.command} -- ${tip.text}`) + '\n');
  process.stdout.write('\n');
}
