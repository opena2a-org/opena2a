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
import { wordWrap, severityLabel, severityColor } from '../util/format.js';
import { getVersion } from '../util/version.js';
import { Spinner } from '../util/spinner.js';
import { printFooter } from '../util/footer.js';
import { writeEvent, getShieldDir } from '../shield/events.js';
import { getShieldStatus } from '../shield/status.js';
import type { EventSeverity, RiskLevel } from '../shield/types.js';
import { scanMcpConfig, scanMcpCredentials, scanAiConfigFiles, scanSkillFiles, scanSoulFile } from '../util/ai-config.js';
import {
  calculateSecurityScore as calculateSecurityScoreShared,
  scoreToRiskLevel as scoreToRiskLevelShared,
  formatCredCount,
  type HygieneCheck as HygieneCheckShared,
  type ScoreBreakdown as ScoreBreakdownShared,
} from '../util/scoring.js';

// --- Types ---

export interface InitOptions {
  targetDir?: string;
  ci?: boolean;
  format?: 'text' | 'json';
  verbose?: boolean;
}

// HygieneCheck and ScoreBreakdown imported from util/scoring.ts
type HygieneCheck = HygieneCheckShared;
type ScoreBreakdown = ScoreBreakdownShared;

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

  // 2. Quick credential scan (source files + MCP configs)
  if (isTTY) spinner.update('Scanning for credentials...');
  const credentialMatches = quickCredentialScan(targetDir);

  // Scan MCP config files for credentials (these are skipped by walkFiles)
  const mcpCreds = scanMcpCredentials(targetDir);
  const seenCredValues = new Set(credentialMatches.map(m => m.value));
  for (const mc of mcpCreds) {
    if (!seenCredValues.has(mc.value)) {
      credentialMatches.push(mc);
      seenCredValues.add(mc.value);
    }
  }

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

      // Group by drift type and show once per type with count
      const driftByType = new Map<string, typeof driftFindings>();
      for (const d of driftFindings) {
        const existing = driftByType.get(d.findingId) ?? [];
        existing.push(d);
        driftByType.set(d.findingId, existing);
      }

      for (const [findingId, items] of driftByType) {
        const first = items[0];
        const relPath = path.relative(targetDir, first.filePath);
        const extra = items.length > 1 ? ` (+${items.length - 1} more)` : '';

        if (findingId === 'DRIFT-001') {
          process.stdout.write(`  ${yellow(findingId)}  Google Maps key may access Gemini AI  (${items.length} location${items.length === 1 ? '' : 's'})\n`);
          process.stdout.write(`  ${dim('  ' + relPath + ':' + first.line + extra)}\n`);
          process.stdout.write(`  ${dim('  Keys provisioned for Maps silently authenticate to Gemini if the')}\n`);
          process.stdout.write(`  ${dim('  Generative Language API is enabled in the same GCP project.')}\n`);
          process.stdout.write(`  ${dim('  Scan:    opena2a protect --dry-run')}\n`);
          process.stdout.write(`  ${dim('           (scans and reports drift, no live API checks)')}\n`);
          process.stdout.write(`  ${dim('  Verify:  opena2a protect')}\n`);
          process.stdout.write(`  ${dim('           (runs live Gemini API access check and applies fixes)')}\n`);
        } else if (findingId === 'DRIFT-002') {
          process.stdout.write(`  ${yellow(findingId)}  AWS key may access Bedrock AI  (${items.length} location${items.length === 1 ? '' : 's'})\n`);
          process.stdout.write(`  ${dim('  ' + relPath + ':' + first.line + extra)}\n`);
          process.stdout.write(`  ${dim('  IAM policies frequently over-provision. A key scoped for S3/EC2')}\n`);
          process.stdout.write(`  ${dim('  may also pass STS auth and call Bedrock LLM endpoints.')}\n`);
          process.stdout.write(`  ${dim('  Scan:    opena2a protect --dry-run')}\n`);
          process.stdout.write(`  ${dim('           (scans and reports drift, no live API checks)')}\n`);
          process.stdout.write(`  ${dim('  Verify:  opena2a protect')}\n`);
          process.stdout.write(`  ${dim('           (runs live STS + Bedrock access check and applies fixes)')}\n`);
        } else {
          process.stdout.write(`  ${yellow(findingId)}  Credential scope drift  (${items.length} location${items.length === 1 ? '' : 's'})\n`);
          process.stdout.write(`  ${dim('  ' + relPath + ':' + first.line + extra)}\n`);
          process.stdout.write(`  ${dim('  Scan:    opena2a protect --dry-run')}\n`);
          process.stdout.write(`  ${dim('           (scans and reports drift, no live API checks)')}\n`);
          process.stdout.write(`  ${dim('  Verify:  opena2a protect')}\n`);
          process.stdout.write(`  ${dim('           (runs live access check and applies fixes)')}\n`);
        }
        process.stdout.write('\n');
      }
    }

    // Show advisory warnings after main report
    if (advisoryCheck.advisories.length > 0) {
      printAdvisoryWarnings(advisoryCheck);
    }

    // Contextual tip
    const tip = getContextualTip(report);
    process.stdout.write(dim(`  Tip: ${tip.command}`) + '\n');
    const wrappedTipText = wordWrap(tip.text, 68, 7);
    process.stdout.write(dim(wrappedTipText) + '\n');
    process.stdout.write('\n');

    // Shield init hint
    process.stdout.write(dim('  To set up full Shield protection (11-step orchestration): opena2a shield init') + '\n');

    // Deeper analysis hint
    process.stdout.write(dim('  For deeper analysis (147 checks): opena2a scan --deep') + '\n');

    // Global install hint (only when running via npx)
    if (isRunningViaNpx()) {
      process.stdout.write(dim('  Tip: Install globally for easier access: npm install -g opena2a-cli') + '\n');
    }

    process.stdout.write('\n');

    // OpenA2A footer (shared)
    printFooter({ ci: options.ci });
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

  // AI-specific configuration scans
  for (const f of scanMcpConfig(dir)) {
    checks.push({ label: f.label, status: f.status, detail: f.detail });
  }
  const aiCfg = scanAiConfigFiles(dir);
  if (aiCfg) checks.push({ label: aiCfg.label, status: aiCfg.status, detail: aiCfg.detail });
  const skills = scanSkillFiles(dir);
  if (skills) checks.push({ label: skills.label, status: skills.status, detail: skills.detail });
  const soul = scanSoulFile(dir);
  if (soul) checks.push({ label: soul.label, status: soul.status, detail: soul.detail });

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

  // Add AI config findings
  const mcpToolsCheck = checks.find(c => c.label === 'MCP high-risk tools' && c.status === 'warn');
  if (mcpToolsCheck) {
    groups.set('MCP-TOOLS', {
      findingId: 'MCP-TOOLS',
      title: mcpToolsCheck.detail,
      severity: 'high',
      count: 1,
      explanation: 'MCP servers with filesystem or shell access can read, modify, or delete files on your system when invoked by an AI assistant.',
      businessImpact: 'Review server permissions to ensure each server has only the access it needs.',
      locations: [],
    });
  }

  const mcpCredCheck = checks.find(c => c.label === 'MCP credentials' && c.status === 'warn');
  if (mcpCredCheck) {
    groups.set('MCP-CRED', {
      findingId: 'MCP-CRED',
      title: mcpCredCheck.detail,
      severity: 'high',
      count: 1,
      explanation: 'API keys hardcoded in MCP config files are readable by anyone with access to the project directory.',
      businessImpact: 'Move credentials to environment variables so they are not stored in plaintext.',
      locations: [],
    });
  }

  const aiConfigCheck = checks.find(c => c.label === 'AI config exposure' && c.status === 'warn');
  if (aiConfigCheck) {
    groups.set('AI-CONFIG', {
      findingId: 'AI-CONFIG',
      title: aiConfigCheck.detail,
      severity: 'medium',
      count: 1,
      explanation: 'AI instruction files (CLAUDE.md, .cursorrules, etc.) reveal tooling choices and system prompts when committed to a public repository.',
      businessImpact: 'Add these files to .git/info/exclude to keep them local without modifying .gitignore.',
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

/**
 * Re-export from shared module for backward compatibility.
 * Tests (security-score.test.ts) import this from init.ts.
 */
export const calculateSecurityScore = calculateSecurityScoreShared;

const scoreToRiskLevel = scoreToRiskLevelShared;

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

    actions.push({
      description: `Migrate ${creds.length} hardcoded credential${creds.length === 1 ? '' : 's'} to a vault`,
      command: 'opena2a protect',
      why: 'Credentials in source files are readable by anyone with repo access. A vault stores them encrypted, rotates them automatically, and provides an audit trail.',
      approach: 'Moves keys to environment variables backed by an encrypted vault. Keys rotate without code changes, and access is auditable.',
      detail: `Keys found: ${breakdownParts}`,
    });
  }

  // .env protection
  const envCheck = checks.find(c => c.label === '.env protection');
  if (envCheck?.status === 'warn') {
    actions.push({
      description: 'Add .env to .gitignore',
      command: 'opena2a protect',
      why: 'Adding .env to .gitignore prevents secrets from entering version control. Existing tracked .env files also need `git rm --cached .env`.',
    });
  }

  // .gitignore
  const gitignoreCheck = checks.find(c => c.label === '.gitignore');
  if (gitignoreCheck?.status !== 'pass') {
    actions.push({
      description: 'Create .gitignore with .env exclusion',
      command: 'opena2a protect',
      why: 'Without a .gitignore, build artifacts and sensitive files can be committed accidentally. Protect creates one with .env exclusion to prevent secret leaks.',
    });
  }

  // Shell environment findings (from HMA)
  const hmaFindings = findings.filter(f => f.findingId.startsWith('HMA-'));
  if (hmaFindings.length > 0) {
    const totalHma = hmaFindings.reduce((n, f) => n + f.count, 0);
    actions.push({
      description: `Clean ${totalHma} shell environment finding${totalHma === 1 ? '' : 's'}`,
      command: 'opena2a scan --deep',
      why: 'Shell config files and history can contain API keys in plaintext. Rotating exposed keys and clearing history entries removes persistent exposure.',
    });
  }

  // LLM server exposure
  const llmCheck = checks.find(c => c.label === 'LLM server exposure' && c.status === 'warn');
  if (llmCheck) {
    actions.push({
      description: 'Secure LLM server',
      command: 'opena2a shield status',
      why: 'A local LLM server without authentication accepts requests from any process on the network. Binding to localhost or adding auth limits access.',
    });
  }

  // MCP high-risk tools
  const mcpToolsFinding = findings.find(f => f.findingId === 'MCP-TOOLS');
  if (mcpToolsFinding) {
    actions.push({
      description: 'Review MCP server permissions',
      command: 'opena2a shield status',
      why: 'MCP servers with filesystem or shell access can read, modify, or delete files when invoked by an AI assistant. Review each server to confirm it has only the access it needs.',
    });
  }

  // MCP credentials
  const mcpCredFinding = findings.find(f => f.findingId === 'MCP-CRED');
  if (mcpCredFinding) {
    actions.push({
      description: 'Move MCP config credentials to environment variables',
      command: 'opena2a protect',
      why: 'API keys hardcoded in MCP config files are stored in plaintext. Environment variables keep credentials out of the project directory and version control.',
    });
  }

  // AI config exposure
  const aiConfigFinding = findings.find(f => f.findingId === 'AI-CONFIG');
  if (aiConfigFinding) {
    actions.push({
      description: 'Exclude AI instruction files from git',
      command: 'opena2a protect',
      why: 'AI instruction files reveal tooling choices and system prompts when committed to a public repository. Adding them to .git/info/exclude keeps them local without modifying .gitignore.',
    });
  }

  // Config signing (only suggest if fewer than 5 actions already -- lower priority)
  const secConfig = checks.find(c => c.label === 'Security config');
  if (actions.length < 5 && secConfig?.status !== 'pass') {
    actions.push({
      description: 'Sign config files for integrity monitoring',
      command: 'opena2a protect',
      why: 'Signed baselines let you detect unintended config changes before they affect runtime behavior.',
    });
  }

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
      command: 'opena2a protect',
    });
  }

  const gitignoreCheck = checks.find(c => c.label === '.gitignore');
  if (gitignoreCheck?.status !== 'pass') {
    steps.push({
      severity: 'high',
      description: 'Create .gitignore with .env exclusion',
      command: 'opena2a protect',
    });
  }

  steps.push({
    severity: 'medium',
    description: 'Sign config files for integrity',
    command: 'opena2a protect',
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
  if (finding.findingId === 'MCP-TOOLS') {
    // Show the first MCP config file found
    for (const f of ['mcp.json', '.mcp.json', '.claude/settings.json', '.cursor/mcp.json']) {
      if (fs.existsSync(path.join(reportDir, f))) {
        return `cat ${f}`;
      }
    }
    return 'cat mcp.json';
  }
  if (finding.findingId === 'MCP-CRED') {
    for (const f of ['mcp.json', '.mcp.json', '.claude/settings.json', '.cursor/mcp.json']) {
      if (fs.existsSync(path.join(reportDir, f))) {
        return `cat ${f}`;
      }
    }
    return 'cat mcp.json';
  }
  if (finding.findingId === 'AI-CONFIG') {
    return 'cat .gitignore';
  }
  if (finding.findingId === 'AI-SKILLS') {
    return 'ls *.skill.md SKILL.md 2>/dev/null';
  }
  if (finding.findingId === 'AI-SOUL') {
    return 'head -20 soul.md';
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
    return { command: 'opena2a protect', label: 'opena2a protect' };
  }
  if (findingId.startsWith('HMA-')) {
    return { command: 'opena2a scan --deep', label: 'opena2a scan --deep' };
  }
  if (findingId === 'MCP-TOOLS') {
    return { command: 'opena2a shield status', label: 'opena2a shield status' };
  }
  if (findingId === 'MCP-CRED') {
    return { command: 'opena2a protect', label: 'opena2a protect' };
  }
  if (findingId === 'AI-CONFIG') {
    return { command: 'opena2a protect', label: 'opena2a protect' };
  }
  if (findingId === 'AI-SKILLS') {
    return { command: 'opena2a guard sign --skills', label: 'opena2a guard sign --skills' };
  }
  if (findingId === 'AI-SOUL') {
    return { command: 'opena2a guard sign', label: 'opena2a guard sign' };
  }
  return null;
}

function getContextualTip(
  report: InitReport,
): { text: string; command: string } {
  const credCount = report.credentialFindings;
  const criticalCount = report.credentialsBySeverity['critical'] ?? 0;
  const driftFindings = report.findings.filter(f => f.findingId.startsWith('DRIFT-'));
  const hasDrift = driftFindings.length > 0;
  const hasAwsDrift = report.findings.some(f => f.findingId === 'DRIFT-002');
  const hasGcpDrift = report.findings.some(f => f.findingId === 'DRIFT-001');

  if (credCount > 0) {
    if (hasDrift && hasAwsDrift) {
      return {
        text: `${credCount} credential${credCount === 1 ? '' : 's'} in source files, including AWS keys with potential Bedrock access. opena2a protect moves them to Secretless AI (encrypted local vault) and runs a live STS + Bedrock check to confirm actual exposure.`,
        command: 'opena2a protect',
      };
    }
    if (hasDrift && hasGcpDrift) {
      return {
        text: `${credCount} credential${credCount === 1 ? '' : 's'} in source files, including Google keys with potential Gemini access. opena2a protect moves them to Secretless AI (local vault, OS keychain, 1Password, Vault, or GCP Secret Manager) and verifies live Generative Language API access.`,
        command: 'opena2a protect',
      };
    }
    if (criticalCount > 0) {
      return {
        text: `${criticalCount} critical credential${criticalCount === 1 ? '' : 's'} in source files — anyone with repo access can use them now. opena2a protect moves them to Secretless AI (local vault, OS keychain, 1Password, Vault, or GCP Secret Manager) and rewrites the source files to reference env vars.`,
        command: 'opena2a protect',
      };
    }
    return {
      text: `${credCount} credential${credCount === 1 ? '' : 's'} in source files. opena2a protect moves them to Secretless AI, rewrites the source to use env var references, and updates .gitignore.`,
      command: 'opena2a protect',
    };
  }

  const hasMcpCred = report.findings.some(f => f.findingId === 'MCP-CRED');
  if (hasMcpCred) {
    return {
      text: 'Credentials in MCP config files are read by every AI tool that loads the config. opena2a protect moves them to Secretless AI (1Password, GCP Secret Manager, Vault, or local vault) and injects them as env vars at runtime — no more plaintext in config files.',
      command: 'opena2a protect',
    };
  }

  const hasAiConfig = report.findings.some(f => f.findingId === 'AI-CONFIG');
  if (hasAiConfig) {
    return {
      text: 'AI tool config files (Claude, Cursor, Copilot) have fixable issues. opena2a protect applies all auto-fixable changes in one pass and signs the files so Guard can detect future unauthorized changes.',
      command: 'opena2a protect',
    };
  }

  const hasLLM = report.findings.some(f => f.findingId === 'ENV-LLM');
  if (hasLLM) {
    return {
      text: 'An unauthenticated LLM server is running locally. opena2a shield status shows which Shield modules are active and what ARP is monitoring at the process and network level.',
      command: 'opena2a shield status',
    };
  }

  if (report.securityScore >= 90) {
    return {
      text: 'Strong baseline. HackMyAgent runs 147 checks including agent-layer attacks, MCP exploitation, and OASB-1 + OASB-2 compliance scoring.',
      command: 'npx hackmyagent secure',
    };
  }
  if (report.securityScore >= 70) {
    return {
      text: 'Good posture. opena2a guard sign creates signed baselines for your config files — Guard will alert if anything changes without a new signature.',
      command: 'opena2a guard sign',
    };
  }

  return {
    text: 'opena2a shield status shows all active protections: ARP runtime monitoring, Guard config integrity, Secretless credential management, and HackMyAgent scan coverage.',
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

    // Always show all critical + high; truncate medium/low at 2 (unless verbose)
    const important = report.findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    const minor     = report.findings.filter(f => f.severity !== 'critical' && f.severity !== 'high');
    const maxMinor  = verbose ? minor.length : 2;
    const displayFindings = [...important, ...minor.slice(0, maxMinor)];
    const hiddenCount = verbose ? 0 : minor.length - maxMinor;

    for (const finding of displayFindings) {
      const sevPad = finding.severity === 'critical' ? ''
        : finding.severity === 'high' ? '    '
        : finding.severity === 'medium' ? '  '
        : '     ';
      const sevTag = severityColor(finding.severity)(finding.severity.toUpperCase()) + sevPad;

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

    if (hiddenCount > 0) {
      process.stdout.write(dim(`  [+${hiddenCount} lower-severity finding${hiddenCount === 1 ? '' : 's'} -- run with --verbose to see all]`) + '\n');
      process.stdout.write('\n');
    }
  } else {
    process.stdout.write(green('  No security findings detected.') + '\n\n');
  }

  // --- Security Score ---
  const scoreColor = report.securityScore >= 80 ? green
    : report.securityScore >= 60 ? yellow
    : red;

  const breakdown = report.scoreBreakdown;

  process.stdout.write(`  ${bold('Security Score:')} ${scoreColor(`${report.securityScore}`)} ${dim('/ 100')}\n`);
  process.stdout.write('\n');

  // Breakdown as factual deductions
  if (breakdown.credentials.deduction > 0) {
    process.stdout.write(`  ${dim('Credentials')}    ${red(`-${breakdown.credentials.deduction}`)}  ${dim(breakdown.credentials.detail)}\n`);
  }
  if (breakdown.environment.deduction > 0) {
    process.stdout.write(`  ${dim('Environment')}    ${red(`-${breakdown.environment.deduction}`)}  ${dim(breakdown.environment.detail)}\n`);
  }
  if (breakdown.configuration.deduction > 0) {
    process.stdout.write(`  ${dim('Configuration')}  ${red(`-${breakdown.configuration.deduction}`)}  ${dim(breakdown.configuration.detail)}\n`);
  } else if (breakdown.configuration.deduction < 0) {
    process.stdout.write(`  ${dim('Configuration')}  ${green(`+${Math.abs(breakdown.configuration.deduction)}`)}  ${dim(breakdown.configuration.detail)}\n`);
  }

  // "After fixes" line when improvements are possible
  const totalRecoverable = breakdown.credentials.deduction
    + breakdown.environment.deduction
    + Math.max(0, breakdown.configuration.deduction);
  const potentialScore = Math.min(100, report.securityScore + totalRecoverable);

  if (totalRecoverable > 0 && potentialScore > report.securityScore) {
    process.stdout.write('\n');
    process.stdout.write(`  ${dim('After fixes:')}   ${report.securityScore} ${dim('->')} ${green(String(potentialScore))}\n`);
  }
  process.stdout.write('\n');

  // --- Recommendations section ---
  if (report.actions.length > 0) {
    process.stdout.write(bold('  Recommendations') + '\n');
    process.stdout.write(gray('  ' + '-'.repeat(47)) + '\n');

    for (let i = 0; i < report.actions.length; i++) {
      const action = report.actions[i];
      process.stdout.write(`  ${bold(`${i + 1}.`)} ${action.description}\n`);
      // Prose explanation as a paragraph (word-wrapped)
      const wrapped = wordWrap(action.why, 70, 5);
      process.stdout.write(dim(wrapped) + '\n');
      // Command at bottom with $ prefix
      process.stdout.write(`     ${cyan('$ ' + action.command)}\n`);
      process.stdout.write('\n');
    }

    process.stdout.write(gray('  ' + '-'.repeat(47)) + '\n');
  }

  process.stdout.write('\n');
}

/**
 * Detect if the CLI is running via npx (not globally installed).
 * Checks if process.argv[1] is within an _npx cache directory.
 */
function isRunningViaNpx(): boolean {
  const execPath = process.argv[1] ?? '';
  return execPath.includes('_npx') || execPath.includes('.npm/_npx');
}
