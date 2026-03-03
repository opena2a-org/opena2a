/**
 * opena2a init -- Initialize security posture assessment for a project.
 *
 * Detects project type, scans for credentials, checks hygiene,
 * calculates trust score, and generates prioritized next steps.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { bold, green, yellow, red, cyan, dim, gray } from '../util/colors.js';
import { detectProject } from '../util/detect.js';
import { quickCredentialScan } from '../util/credential-patterns.js';
import { checkAdvisories, printAdvisoryWarnings, type AdvisoryCheck } from '../util/advisories.js';
import { getVersion } from '../util/version.js';
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

interface NextStep {
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  command: string;
}

interface InitReport {
  projectName: string | null;
  projectVersion: string | null;
  projectType: string;
  directory: string;
  credentialFindings: number;
  credentialsBySeverity: Record<string, number>;
  hygieneChecks: HygieneCheck[];
  trustScore: number;
  grade: string;
  nextSteps: NextStep[];
  advisories: { count: number; matchedPackages: string[] };
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

  // 1. Detect project type
  const project = detectProject(targetDir);

  // 2. Quick credential scan
  const credentialMatches = quickCredentialScan(targetDir);
  const credsBySeverity: Record<string, number> = {};
  for (const m of credentialMatches) {
    credsBySeverity[m.severity] = (credsBySeverity[m.severity] || 0) + 1;
  }

  // 3. Security hygiene checks
  const checks = await runHygieneChecks(targetDir, project, credentialMatches.length);

  // 4. Check advisories (non-blocking)
  let advisoryCheck: AdvisoryCheck = { advisories: [], matchedPackages: [], total: 0, fromCache: false };
  try {
    advisoryCheck = await checkAdvisories(targetDir);
  } catch {
    // Advisory check is best-effort, don't fail init
  }

  // 5. Calculate trust score
  const { score, grade } = calculateTrustScore(credsBySeverity, checks, targetDir);

  // 6. Generate next steps
  const nextSteps = generateNextSteps(credentialMatches.length, credsBySeverity, checks, project.type);

  // 6.5. Compute posture score from Shield tool detection
  const shieldStatus = getShieldStatus(targetDir);
  const activeTools = shieldStatus.tools.filter(p => p.active).length;
  const totalTools = shieldStatus.tools.length;
  let postureScore = 0;
  postureScore += Math.min(activeTools * 10, 60);
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

  // 6.6. Write shield events for posture and credential findings
  // Events are written to the project-local .opena2a/shield/ when available,
  // falling back to the global ~/.opena2a/shield/.
  try {
    getShieldDir(targetDir);
    writeEvent({
      source: 'shield',
      category: 'shield.posture',
      severity: (riskLevel === 'CRITICAL' ? 'critical' : riskLevel === 'HIGH' ? 'high' : riskLevel === 'MEDIUM' ? 'medium' : 'info') as EventSeverity,
      agent: null,
      sessionId: null,
      action: 'posture-assessment',
      target: targetDir,
      outcome: 'monitored',
      detail: { score: postureScore, riskLevel, activeTools, totalTools, trustScore: score, grade },
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

  // 7. Build report
  const report: InitReport = {
    projectName: project.name,
    projectVersion: project.version,
    projectType: formatProjectType(project),
    directory: targetDir,
    credentialFindings: credentialMatches.length,
    credentialsBySeverity: credsBySeverity,
    hygieneChecks: checks,
    trustScore: score,
    grade,
    nextSteps,
    advisories: {
      count: advisoryCheck.advisories.length,
      matchedPackages: advisoryCheck.matchedPackages,
    },
    postureScore,
    riskLevel,
    activeTools,
    totalTools,
  };

  // 8. Output
  if (options.format === 'json') {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    printReport(report, options.verbose);

    // Verbose: show individual credential findings
    if (options.verbose && credentialMatches.length > 0) {
      process.stdout.write(bold('  Credential Details') + '\n');
      process.stdout.write(gray('  ' + '-'.repeat(47)) + '\n');
      for (const m of credentialMatches) {
        const sev = m.severity === 'critical' ? red('[CRITICAL]')
          : m.severity === 'high' ? yellow('[HIGH]')
          : cyan('[MEDIUM]');
        const relPath = path.relative(targetDir, m.filePath);
        process.stdout.write(`  ${sev} ${bold(m.findingId)}: ${m.title}\n`);
        process.stdout.write(`  ${dim('  File:')} ${relPath}:${m.line}\n`);
        if (m.explanation) {
          process.stdout.write(`  ${dim('  Why:')} ${m.explanation}\n`);
        }
        process.stdout.write('\n');
      }
    }

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

// --- Trust score ---

function calculateTrustScore(
  credsBySeverity: Record<string, number>,
  checks: HygieneCheck[],
  dir: string,
): { score: number; grade: string } {
  let score = 100;

  // Credential penalties
  score -= (credsBySeverity['critical'] || 0) * 25;
  score -= (credsBySeverity['high'] || 0) * 15;
  score -= (credsBySeverity['medium'] || 0) * 8;
  score -= (credsBySeverity['low'] || 0) * 3;

  // Hygiene penalties
  const gitignoreCheck = checks.find(c => c.label === '.gitignore');
  if (gitignoreCheck?.status !== 'pass') score -= 15;

  const envCheck = checks.find(c => c.label === '.env protection');
  if (envCheck?.status === 'warn') score -= 10;

  const lockCheck = checks.find(c => c.label === 'Lock file');
  if (lockCheck?.status !== 'pass') score -= 5;

  // Bonus for security config
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

// --- Next steps ---

function generateNextSteps(
  credCount: number,
  credsBySeverity: Record<string, number>,
  checks: HygieneCheck[],
  projectType?: string,
): NextStep[] {
  const steps: NextStep[] = [];

  // Credentials -> protect
  if (credCount > 0) {
    steps.push({
      severity: 'critical',
      description: `Migrate ${credCount} hardcoded credential${credCount === 1 ? '' : 's'}`,
      command: 'opena2a protect',
    });
  }

  // .env protection
  const envCheck = checks.find(c => c.label === '.env protection');
  if (envCheck?.status === 'warn') {
    steps.push({
      severity: 'high',
      description: 'Add .env to .gitignore',
      command: "echo '.env' >> .gitignore",
    });
  }

  // No .gitignore
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

  // Sign config files
  steps.push({
    severity: 'medium',
    description: 'Sign config files for integrity',
    command: 'opena2a guard sign',
  });

  // Runtime protection
  steps.push({
    severity: 'low',
    description: 'Start runtime protection',
    command: 'opena2a runtime start',
  });

  return steps;
}

// --- Output ---

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

function printReport(report: InitReport, _verbose?: boolean): void {
  const VERSION = getVersion();

  process.stdout.write('\n');
  process.stdout.write(bold('  OpenA2A Security Initialization') + dim(`  v${VERSION}`) + '\n\n');

  // Project info
  const projectDisplay = report.projectName
    ? `${report.projectName}${report.projectVersion ? ' v' + report.projectVersion : ''}`
    : path.basename(report.directory);

  process.stdout.write(`  ${dim('Project')}      ${projectDisplay}\n`);
  process.stdout.write(`  ${dim('Type')}         ${report.projectType}\n`);
  process.stdout.write(`  ${dim('Directory')}    ${report.directory}\n`);
  process.stdout.write('\n');

  // Security posture
  process.stdout.write(bold('  Security Posture') + '\n');
  process.stdout.write(gray('  ' + '-'.repeat(47)) + '\n');

  for (const check of report.hygieneChecks) {
    const statusDisplay = check.status === 'pass' ? green(check.detail)
      : check.status === 'fail' ? red(check.detail)
      : check.status === 'warn' ? yellow(check.detail)
      : dim(check.detail);

    process.stdout.write(`  ${dim(check.label.padEnd(20))} ${statusDisplay}\n`);
  }

  process.stdout.write(gray('  ' + '-'.repeat(47)) + '\n');

  // Trust score
  const scoreColor = report.trustScore >= 80 ? green
    : report.trustScore >= 60 ? yellow
    : red;

  process.stdout.write(`  ${dim('Trust Score')}      ${scoreColor(`${report.trustScore} / 100`)}  ${dim('[Grade:')} ${scoreColor(report.grade)}${dim(']')}\n`);

  // Shield posture
  const postureColor = report.postureScore >= 70 ? green
    : report.postureScore >= 40 ? yellow
    : red;
  const riskColor = report.riskLevel === 'SECURE' || report.riskLevel === 'LOW' ? green
    : report.riskLevel === 'MEDIUM' ? yellow
    : red;
  process.stdout.write(`  ${dim('Shield Posture')}   ${postureColor(`${report.postureScore} / 100`)}  ${dim('[Risk:')} ${riskColor(report.riskLevel)}${dim(']')}\n`);
  process.stdout.write(`  ${dim('Tools')}            ${report.activeTools} / ${report.totalTools} active\n`);
  process.stdout.write('\n');

  // Next steps
  if (report.nextSteps.length > 0) {
    process.stdout.write(bold('  Next Steps') + '\n');
    process.stdout.write(gray('  ' + '-'.repeat(47)) + '\n');

    for (const step of report.nextSteps) {
      const severityTag = step.severity === 'critical' ? red(`[CRITICAL]`)
        : step.severity === 'high' ? yellow(`[HIGH]`)
        : step.severity === 'medium' ? cyan(`[MEDIUM]`)
        : dim(`[LOW]`);

      process.stdout.write(`  ${severityTag.padEnd(22)} ${step.description}\n`);
      process.stdout.write(`  ${' '.repeat(12)} ${dim(step.command)}\n\n`);
    }

    process.stdout.write(gray('  ' + '-'.repeat(47)) + '\n');
  }

  process.stdout.write('\n');

  // Quick start hints for new users
  process.stdout.write(dim('  Tip: Try these commands to explore further:') + '\n');
  process.stdout.write(dim('    opena2a shield status   View Shield tool status') + '\n');
  process.stdout.write(dim('    opena2a shield report   Generate security posture report') + '\n');
  process.stdout.write(dim('    opena2a shield monitor  Start ARP runtime monitoring') + '\n');
  process.stdout.write(dim('    opena2a ~<query>        Search commands (e.g. opena2a ~drift)') + '\n');
  process.stdout.write('\n');
}
