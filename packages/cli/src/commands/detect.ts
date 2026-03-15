/**
 * opena2a detect -- Shadow AI Agent Audit
 *
 * Discovers AI agents running on this machine, MCP servers configured
 * across all platforms, local LLM processes, and AI config files in the
 * project. Reports identity, governance posture, and risk classification.
 */

import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { bold, dim, green, yellow, red, cyan } from '../util/colors.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DetectOptions {
  targetDir: string;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
  reportPath?: string;
  exportCsv?: string;
}

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

export interface DetectedAgent {
  name: string;
  pid: number;
  category: 'ai-assistant' | 'local-llm' | 'ai-plugin';
  identityStatus: 'identified' | 'no identity';
  governanceStatus: 'governed' | 'no governance';
  risk: RiskLevel;
}

export interface DetectedMcpServer {
  name: string;
  transport: 'stdio' | 'sse' | 'unknown';
  source: string;
  verified: boolean;
  capabilities: string[];
  risk: RiskLevel;
}

export interface AiConfigFile {
  file: string;
  tool: string;
  risk: RiskLevel;
  details: string;
}

export interface IdentitySummary {
  aimIdentities: number;
  mcpIdentities: number;
  totalAgents: number;
  soulFiles: number;
  capabilityPolicies: number;
}

export interface DetectResult {
  scanTimestamp: string;
  scanDirectory: string;
  summary: {
    totalAgents: number;
    ungoverned: number;
    mcpServers: number;
    unverifiedServers: number;
    localLlms: number;
    aiConfigs: number;
    /** Governance score: 100 = fully governed, 0 = nothing in place. */
    governanceScore: number;
    /** How many points can be recovered by addressing findings. */
    recoverablePoints: number;
  };
  agents: DetectedAgent[];
  mcpServers: DetectedMcpServer[];
  aiConfigs: AiConfigFile[];
  identity: IdentitySummary;
  findings: Finding[];
}

export interface Finding {
  severity: RiskLevel;
  category: string;
  title: string;
  detail: string;
  whyItMatters: string;
  remediation: string;
}

// ---------------------------------------------------------------------------
// Agent patterns
// ---------------------------------------------------------------------------

const AGENT_PATTERNS: { name: string; category: DetectedAgent['category']; patterns: RegExp[] }[] = [
  // AI coding assistants
  { name: 'Claude Code', category: 'ai-assistant', patterns: [/@anthropic-ai\/claude-code/i, /\bclaude\s*$/im, /\bclaude\s+/i] },
  { name: 'Cursor', category: 'ai-assistant', patterns: [/Cursor\.app/i, /cursor-agent/i] },
  { name: 'GitHub Copilot', category: 'ai-assistant', patterns: [/\bcopilot\b/i] },
  { name: 'Windsurf', category: 'ai-assistant', patterns: [/Windsurf\.app/i, /windsurf-agent/i] },
  { name: 'Aider', category: 'ai-assistant', patterns: [/\baider\b/] },
  { name: 'Continue', category: 'ai-assistant', patterns: [/continue-server/i, /\bcontinue\.dev\b/i] },
  { name: 'Cline', category: 'ai-assistant', patterns: [/\bcline\b/] },
  { name: 'Amazon Q', category: 'ai-assistant', patterns: [/\bamazon-q\b/i, /\bq-developer\b/i] },
  { name: 'Tabnine', category: 'ai-assistant', patterns: [/\btabnine\b/i] },
  { name: 'Sourcegraph Cody', category: 'ai-assistant', patterns: [/\bcody\b/i, /sourcegraph.*cody/i] },
  { name: 'Supermaven', category: 'ai-assistant', patterns: [/\bsupermaven\b/i] },
  { name: 'Augment Code', category: 'ai-assistant', patterns: [/\baugment\b/i] },

  // Local LLM runtimes
  { name: 'Ollama', category: 'local-llm', patterns: [/\bollama\b/] },
  { name: 'LM Studio', category: 'local-llm', patterns: [/lmstudio/i, /LM Studio/] },
  { name: 'LocalAI', category: 'local-llm', patterns: [/\blocalai\b/i] },
  { name: 'llama.cpp', category: 'local-llm', patterns: [/llama-server/i, /llama\.cpp/i, /\bllama-cli\b/i] },
  { name: 'vLLM', category: 'local-llm', patterns: [/\bvllm\b/i] },
  { name: 'Open WebUI', category: 'local-llm', patterns: [/open-webui/i] },
  { name: 'GPT4All', category: 'local-llm', patterns: [/\bgpt4all\b/i] },
  { name: 'Jan', category: 'local-llm', patterns: [/\bjan\.app\b/i, /Jan\.app/] },
];

// ---------------------------------------------------------------------------
// MCP config locations
// ---------------------------------------------------------------------------

interface McpConfigLocation {
  path: string;
  label: string;
}

const MCP_CONFIG_LOCATIONS: McpConfigLocation[] = [
  { path: '.claude/mcp_servers.json', label: 'Claude Code (global)' },
  { path: '.cursor/mcp.json', label: 'Cursor (global)' },
  { path: '.config/windsurf/mcp.json', label: 'Windsurf (global)' },
  { path: '.vscode/globalStorage/saoudrizwan.claude-dev/mcp_servers.json', label: 'Cline (global)' },
];

const PROJECT_MCP_FILES = ['mcp.json', '.mcp.json', '.mcp/config.json'];

// High-risk MCP capability keywords
const HIGH_RISK_CAPABILITIES = ['execute', 'shell', 'bash', 'terminal', 'run', 'eval'];
const MEDIUM_RISK_CAPABILITIES = ['filesystem', 'file', 'write', 'database', 'db', 'sql', 'network', 'http', 'fetch'];

// ---------------------------------------------------------------------------
// AI config files to scan for in project directories
// ---------------------------------------------------------------------------

interface AiConfigPattern {
  /** File names or globs to check (relative to project root). */
  files: string[];
  /** AI tool this config belongs to. */
  tool: string;
}

const AI_CONFIG_PATTERNS: AiConfigPattern[] = [
  { files: ['.cursorrules', '.cursor/config.json', '.cursor/rules'], tool: 'Cursor' },
  { files: ['.claude/settings.json', '.claude/settings.local.json', 'CLAUDE.md'], tool: 'Claude Code' },
  { files: ['.github/copilot-instructions.md', '.copilot'], tool: 'GitHub Copilot' },
  { files: ['.windsurfrules', '.windsurf/config.json'], tool: 'Windsurf' },
  { files: ['.aider.conf.yml', '.aiderignore'], tool: 'Aider' },
  { files: ['.continue/config.json', '.continuerules'], tool: 'Continue' },
  { files: ['SOUL.md', '.opena2a/SOUL.md'], tool: 'OpenA2A SOUL' },
  { files: ['arp.config.yml', 'arp.config.yaml', '.opena2a/arp.config.yml'], tool: 'Agent Runtime Protection' },
  { files: ['langchain.config.js', 'langchain.config.ts'], tool: 'LangChain' },
  { files: ['.env.ai', 'ai.config.json', 'ai.config.yml'], tool: 'AI Framework' },
];

// ---------------------------------------------------------------------------
// Process scanning
// ---------------------------------------------------------------------------

export function scanProcesses(psOutput?: string): DetectedAgent[] {
  let output: string;
  if (psOutput !== undefined) {
    output = psOutput;
  } else {
    try {
      output = execSync('ps aux', { encoding: 'utf-8', timeout: 5000 });
    } catch {
      return [];
    }
  }

  const lines = output.split('\n');
  const agents: DetectedAgent[] = [];
  const seen = new Set<string>();

  for (const line of lines) {
    for (const agent of AGENT_PATTERNS) {
      if (seen.has(agent.name)) continue;
      if (!agent.patterns.some((p) => p.test(line))) continue;

      const parts = line.trim().split(/\s+/);
      const pid = parseInt(parts[1], 10);
      if (isNaN(pid)) continue;

      agents.push({
        name: agent.name,
        pid,
        category: agent.category,
        identityStatus: 'no identity',
        governanceStatus: 'no governance',
        risk: agent.category === 'local-llm' ? 'medium' : 'high',
      });
      seen.add(agent.name);
    }
  }

  return agents;
}

// ---------------------------------------------------------------------------
// MCP config parsing
// ---------------------------------------------------------------------------

export function parseMcpConfig(
  filePath: string,
  label: string
): DetectedMcpServer[] {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const config = JSON.parse(content);
    const servers: DetectedMcpServer[] = [];

    const serversObj = config.mcpServers ?? config.servers ?? config;
    if (typeof serversObj !== 'object' || serversObj === null || Array.isArray(serversObj)) return [];

    for (const [name, entry] of Object.entries(serversObj)) {
      if (typeof entry !== 'object' || entry === null) continue;
      const e = entry as Record<string, unknown>;

      let transport: 'stdio' | 'sse' | 'unknown' = 'unknown';
      if (e.command || e.args) transport = 'stdio';
      if (e.url || e.transport === 'sse') transport = 'sse';
      if (e.transport === 'stdio') transport = 'stdio';

      // Extract capabilities from server name and config
      const capabilities = inferMcpCapabilities(name, e);
      const risk = classifyMcpRisk(name, capabilities, transport);

      servers.push({ name, transport, source: label, verified: false, capabilities, risk });
    }

    return servers;
  } catch {
    return [];
  }
}

/** Capability ID to plain-language description map. */
const CAPABILITY_DESCRIPTIONS: Record<string, string> = {
  'filesystem': 'Can read and write files on your machine',
  'shell-access': 'Can run any command on your computer',
  'database': 'Can read and modify your database',
  'network': 'Can make requests to external services',
  'browser': 'Can control a web browser and visit pages',
  'source-control': 'Can read and push code to your repositories',
  'messaging': 'Can send messages on your behalf',
  'payments': 'Can access payment and billing systems',
  'cloud-services': 'Can access your cloud infrastructure',
  'unknown': 'Capabilities not determined',
};

function capabilityDescription(cap: string): string {
  return CAPABILITY_DESCRIPTIONS[cap] ?? cap;
}

function inferMcpCapabilities(name: string, config: Record<string, unknown>): string[] {
  const caps: string[] = [];
  const nameLower = name.toLowerCase();
  const args = Array.isArray(config.args) ? config.args.map(String) : [];
  const command = typeof config.command === 'string' ? config.command : '';
  const combined = `${nameLower} ${command} ${args.join(' ')}`.toLowerCase();

  if (/filesys|file|fs\b/.test(combined)) caps.push('filesystem');
  if (/shell|bash|terminal|exec/.test(combined)) caps.push('shell-access');
  if (/database|db|sql|postgres|mysql|sqlite/.test(combined)) caps.push('database');
  if (/network|http|fetch|curl|api/.test(combined)) caps.push('network');
  if (/browser|playwright|puppeteer|selenium/.test(combined)) caps.push('browser');
  if (/git\b|github|gitlab/.test(combined)) caps.push('source-control');
  if (/slack|email|discord|teams/.test(combined)) caps.push('messaging');
  if (/stripe|payment|billing/.test(combined)) caps.push('payments');
  if (/supabase|firebase|cloud/.test(combined)) caps.push('cloud-services');

  if (caps.length === 0) caps.push('unknown');
  return caps;
}

function classifyMcpRisk(name: string, capabilities: string[], transport: string): RiskLevel {
  const nameLower = name.toLowerCase();

  // Shell/execute access is always critical
  if (capabilities.includes('shell-access')) return 'critical';

  // Remote SSE servers with sensitive capabilities
  if (transport === 'sse' && (capabilities.includes('database') || capabilities.includes('payments'))) {
    return 'critical';
  }

  // Database or payment access
  if (capabilities.includes('database') || capabilities.includes('payments')) return 'high';

  // Network or filesystem access
  if (capabilities.includes('network') || capabilities.includes('filesystem')) return 'medium';

  // Known benign patterns
  if (/\b(context7|greptile|serena)\b/.test(nameLower)) return 'low';

  return 'medium';
}

// ---------------------------------------------------------------------------
// Claude plugin MCP scanning
// ---------------------------------------------------------------------------

function scanClaudePluginMcpServers(): DetectedMcpServer[] {
  const home = os.homedir();
  const servers: DetectedMcpServer[] = [];

  const pluginsBase = path.join(home, '.claude', 'plugins', 'marketplaces');
  try {
    const marketplaces = fs.readdirSync(pluginsBase, { withFileTypes: true });
    for (const marketplace of marketplaces) {
      if (!marketplace.isDirectory()) continue;

      for (const subdir of ['external_plugins', 'plugins']) {
        const dir = path.join(pluginsBase, marketplace.name, subdir);
        try {
          const plugins = fs.readdirSync(dir, { withFileTypes: true });
          for (const plugin of plugins) {
            if (!plugin.isDirectory()) continue;
            const mcpPath = path.join(dir, plugin.name, '.mcp.json');
            servers.push(...parseMcpConfig(mcpPath, `Claude plugin: ${plugin.name}`));
          }
        } catch { /* directory may not exist */ }
      }
    }
  } catch { /* plugins directory may not exist */ }

  return servers;
}

// ---------------------------------------------------------------------------
// MCP server scanning (all platforms)
// ---------------------------------------------------------------------------

export function scanMcpServers(targetDir: string): DetectedMcpServer[] {
  const home = os.homedir();
  const servers: DetectedMcpServer[] = [];

  for (const loc of MCP_CONFIG_LOCATIONS) {
    servers.push(...parseMcpConfig(path.join(home, loc.path), loc.label));
  }

  servers.push(...scanClaudePluginMcpServers());

  const claudeProjectMcp = path.join(home, '.claude', '.mcp.json');
  servers.push(...parseMcpConfig(claudeProjectMcp, 'Claude Code (project)'));

  const vscodeExtDir = path.join(home, '.vscode', 'extensions');
  try {
    const entries = fs.readdirSync(vscodeExtDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      servers.push(
        ...parseMcpConfig(path.join(vscodeExtDir, entry.name, 'mcp.json'), `VS Code: ${entry.name}`)
      );
    }
  } catch { /* directory may not exist */ }

  for (const filename of PROJECT_MCP_FILES) {
    servers.push(...parseMcpConfig(path.join(targetDir, filename), `${filename} (project)`));
  }

  return servers;
}

// ---------------------------------------------------------------------------
// AI config file discovery
// ---------------------------------------------------------------------------

export function scanAiConfigs(targetDir: string): AiConfigFile[] {
  const configs: AiConfigFile[] = [];

  for (const pattern of AI_CONFIG_PATTERNS) {
    for (const file of pattern.files) {
      const fullPath = path.join(targetDir, file);
      if (!fs.existsSync(fullPath)) continue;

      let details = `${pattern.tool} configuration`;
      let risk: RiskLevel = 'low';

      // Check if it contains credential references
      try {
        const content = fs.readFileSync(fullPath, 'utf-8');
        const hasApiKey = /(?:api[_-]?key|secret|token|password)\s*[:=]\s*["']?[a-zA-Z0-9_-]{20,}/i.test(content);
        const hasPermissions = /(?:allow|permit|grant|unrestricted|all\s+bash)/i.test(content);

        if (hasApiKey) {
          risk = 'critical';
          details = `${pattern.tool} config contains credential references`;
        } else if (hasPermissions) {
          risk = 'high';
          details = `${pattern.tool} config grants broad permissions`;
        } else {
          risk = 'low';
        }
      } catch { /* file unreadable */ }

      configs.push({ file, tool: pattern.tool, risk, details });
    }
  }

  return configs;
}

// ---------------------------------------------------------------------------
// Identity & governance scanning
// ---------------------------------------------------------------------------

export function scanIdentity(targetDir: string): IdentitySummary {
  let aimIdentities = 0;
  let mcpIdentities = 0;
  let soulFiles = 0;
  let capabilityPolicies = 0;

  const opena2aDir = path.join(targetDir, '.opena2a');
  if (fs.existsSync(opena2aDir)) {
    aimIdentities++;

    const mcpIdDir = path.join(opena2aDir, 'mcp-identities');
    if (fs.existsSync(mcpIdDir)) {
      try {
        mcpIdentities = fs.readdirSync(mcpIdDir).filter((f) => f.endsWith('.json')).length;
      } catch { /* ignore */ }
    }
  }

  for (const p of [path.join(targetDir, 'SOUL.md'), path.join(targetDir, '.opena2a', 'SOUL.md')]) {
    if (fs.existsSync(p)) soulFiles++;
  }

  const policyPaths = [
    path.join(targetDir, '.opena2a', 'policy.yml'),
    path.join(targetDir, '.opena2a', 'policy.yaml'),
    path.join(targetDir, '.opena2a', 'policy.json'),
    path.join(targetDir, 'opena2a.policy.yml'),
    path.join(targetDir, 'opena2a.policy.yaml'),
  ];
  for (const p of policyPaths) {
    if (fs.existsSync(p)) capabilityPolicies++;
  }

  return { aimIdentities, mcpIdentities, totalAgents: 0, soulFiles, capabilityPolicies };
}

// ---------------------------------------------------------------------------
// Risk scoring
// ---------------------------------------------------------------------------

/**
 * Calculate governance score (0-100, where 100 = fully governed).
 *
 * Internally computes deductions for gaps, then inverts:
 *   governanceScore = 100 - deductions
 *
 * This way users see 100 as the goal and the score goes UP as they fix things.
 */
function calculateGovernanceScore(result: Omit<DetectResult, 'summary' | 'findings'>): { governanceScore: number; deductions: number } {
  let deductions = 0;

  // Ungoverned agents: 15 points each
  for (const agent of result.agents) {
    if (agent.governanceStatus === 'no governance') deductions += 15;
    if (agent.identityStatus === 'no identity') deductions += 10;
  }

  // Unverified MCP servers -- only project-local servers affect the score.
  // Global/machine-wide servers (Claude plugins, ~/.cursor, etc.) are shown
  // for awareness but don't penalize the project governance score because
  // the user cannot verify them at the project level.
  for (const server of result.mcpServers) {
    if (server.verified) continue;
    const isProjectLocal = server.source.includes('(project)');
    if (!isProjectLocal) continue;
    if (server.risk === 'critical') deductions += 20;
    else if (server.risk === 'high') deductions += 12;
    else if (server.risk === 'medium') deductions += 5;
    else deductions += 2;
  }

  // AI config risk
  for (const config of result.aiConfigs) {
    if (config.risk === 'critical') deductions += 25;
    else if (config.risk === 'high') deductions += 15;
    else if (config.risk === 'medium') deductions += 5;
  }

  // Governance gap: no AIM identity is a multiplier
  if (result.identity.aimIdentities === 0 && result.agents.length > 0) deductions += 20;
  if (result.identity.soulFiles === 0 && result.agents.length > 0) deductions += 10;

  // Cap deductions at 100, round
  deductions = Math.min(Math.round(deductions), 100);

  return { governanceScore: 100 - deductions, deductions };
}

// ---------------------------------------------------------------------------
// Finding generation
// ---------------------------------------------------------------------------

function generateFindings(result: Omit<DetectResult, 'findings'>): Finding[] {
  const findings: Finding[] = [];

  // Ungoverned agents (consolidates governance + SOUL.md into one finding)
  const ungoverned = result.agents.filter((a) => a.governanceStatus === 'no governance');
  if (ungoverned.length > 0) {
    const noSoul = result.identity.soulFiles === 0;
    const detail = ungoverned.map((a) => a.name).join(', ')
      + (noSoul ? ' -- no SOUL.md governance file found' : '');
    findings.push({
      severity: 'high',
      category: 'governance',
      title: `${ungoverned.length} AI agent${ungoverned.length !== 1 ? 's' : ''} running without governance`,
      detail,
      whyItMatters: 'These agents can take actions in your project but have no rules defining what they '
        + 'should or should not do. A SOUL.md file sets behavioral boundaries — what agents can and '
        + 'cannot do, and what requires human approval. Without one, agents rely entirely on their defaults.',
      remediation: 'opena2a harden-soul',
    });
  }

  // No AIM identity
  if (result.identity.aimIdentities === 0 && result.agents.length > 0) {
    findings.push({
      severity: 'high',
      category: 'identity',
      title: 'No agent identity registered for this project',
      detail: `${result.agents.length} agent${result.agents.length !== 1 ? 's' : ''} running without a project identity`,
      whyItMatters: 'When something goes wrong, you need to know which agent did what. Without '
        + 'an identity, agent actions cannot be traced back to a specific tool or session.',
      remediation: 'opena2a identity create --name my-agent',
    });
  }

  // Project-local MCP servers with sensitive access (actionable -- affects score)
  const projectCriticalMcp = result.mcpServers.filter(
    (s) => s.risk === 'critical' && !s.verified && s.source.includes('(project)')
  );
  if (projectCriticalMcp.length > 0) {
    const details = projectCriticalMcp.map((s) => {
      const caps = s.capabilities.filter((c) => c !== 'unknown');
      const humanCaps = caps.map((c) => capabilityDescription(c).toLowerCase()).join(', ');
      return `${s.name}: ${humanCaps}`;
    });
    findings.push({
      severity: 'critical',
      category: 'mcp',
      title: `${projectCriticalMcp.length} project MCP server${projectCriticalMcp.length !== 1 ? 's' : ''} with sensitive access`,
      detail: details.join('; '),
      whyItMatters: 'These MCP servers are configured in your project and grant access to sensitive '
        + 'operations like running commands, accessing databases, or processing payments. '
        + 'Verifying them confirms they are the servers you intended to install.',
      remediation: 'opena2a mcp audit',
    });
  }

  // Project-local unverified MCP servers
  const projectUnverified = result.mcpServers.filter(
    (s) => !s.verified && s.source.includes('(project)')
  );
  if (projectUnverified.length > 0 && projectCriticalMcp.length === 0) {
    findings.push({
      severity: 'medium',
      category: 'mcp',
      title: `${projectUnverified.length} project MCP server${projectUnverified.length !== 1 ? 's' : ''} without verified identity`,
      detail: 'These servers are configured in your project but have not been signed.',
      whyItMatters: 'Unverified servers could be modified or replaced without detection. '
        + 'Signing creates a tamper-evident record of exactly which server version is in use.',
      remediation: 'opena2a mcp audit',
    });
  }

  // Config files with credential references
  const criticalConfigs = result.aiConfigs.filter((c) => c.risk === 'critical');
  if (criticalConfigs.length > 0) {
    findings.push({
      severity: 'critical',
      category: 'config',
      title: 'AI config files contain credential references',
      detail: criticalConfigs.map((c) => c.file).join(', '),
      whyItMatters: 'API keys or tokens appear to be stored directly in these configuration files. '
        + 'Anyone with access to the file (or the repository) can see and use these credentials. '
        + 'Moving them to environment variables limits exposure.',
      remediation: 'opena2a protect',
    });
  }

  // Broad permission grants
  const highConfigs = result.aiConfigs.filter((c) => c.risk === 'high');
  if (highConfigs.length > 0) {
    findings.push({
      severity: 'high',
      category: 'config',
      title: 'AI config files grant broad permissions',
      detail: highConfigs.map((c) => c.file).join(', '),
      whyItMatters: 'These configs allow AI agents to perform a wide range of actions without '
        + 'restrictions. Broad permissions increase the surface area if an agent behaves '
        + 'unexpectedly or if the config is modified by a third party.',
      remediation: 'opena2a scan-soul',
    });
  }

  // No SOUL governance (only if agents ARE governed but SOUL is missing --
  // if ungoverned, the governance finding above already covers SOUL.md)
  if (result.identity.soulFiles === 0 && result.agents.length > 0 && ungoverned.length === 0) {
    findings.push({
      severity: 'medium',
      category: 'governance',
      title: 'No SOUL.md governance file in this project',
      detail: 'Agents are governed by capability policies but have no SOUL.md behavioral boundaries.',
      whyItMatters: 'A SOUL.md file defines what an agent should and should not do beyond capability '
        + 'restrictions — handling errors, sensitive data, and when to ask for human approval.',
      remediation: 'opena2a harden-soul',
    });
  }

  // Sort by severity
  const order: Record<RiskLevel, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);

  return findings;
}

// ---------------------------------------------------------------------------
// CSV export -- asset inventory for enterprise tools (ServiceNow, CMDB, etc.)
// ---------------------------------------------------------------------------

function csvEscape(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function generateAssetCsv(result: DetectResult): string {
  const rows: string[] = [];
  const hostname = os.hostname();
  const username = os.userInfo().username;
  const scanTime = result.scanTimestamp;
  const scanDir = result.scanDirectory;

  // Header -- device context columns first for enterprise CMDB import
  rows.push('Hostname,Username,ScanDirectory,ScanTimestamp,Type,Name,Source,Transport,Capabilities,Risk,Identity,Governance,Verified');

  const deviceCols = [csvEscape(hostname), csvEscape(username), csvEscape(scanDir), scanTime].join(',');

  // AI Agents
  for (const agent of result.agents) {
    rows.push([
      deviceCols,
      'AI Agent',
      csvEscape(agent.name),
      'process',
      '',
      agent.category,
      agent.risk,
      agent.identityStatus,
      agent.governanceStatus,
      '',
    ].join(','));
  }

  // MCP Servers
  for (const server of result.mcpServers) {
    const caps = server.capabilities.filter((c) => c !== 'unknown');
    rows.push([
      deviceCols,
      'MCP Server',
      csvEscape(server.name),
      csvEscape(server.source),
      server.transport,
      csvEscape(caps.map((c) => capabilityDescription(c)).join('; ')),
      server.risk,
      '',
      '',
      server.verified ? 'yes' : 'no',
    ].join(','));
  }

  // AI Config Files
  for (const config of result.aiConfigs) {
    rows.push([
      deviceCols,
      'AI Config',
      csvEscape(config.file),
      csvEscape(config.tool),
      '',
      csvEscape(config.details),
      config.risk,
      '',
      '',
      '',
    ].join(','));
  }

  return rows.join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Text formatting
// ---------------------------------------------------------------------------

function riskColor(level: RiskLevel): (text: string) => string {
  switch (level) {
    case 'critical': return red;
    case 'high': return (t: string) => `\x1b[38;5;208m${t}\x1b[39m`; // orange
    case 'medium': return yellow;
    case 'low': return green;
  }
}

function riskLabel(level: RiskLevel): string {
  return riskColor(level)(level.toUpperCase());
}

function buildSummaryLine(result: DetectResult): string {
  const { summary } = result;
  const parts: string[] = [];

  if (summary.totalAgents === 0 && summary.mcpServers === 0 && summary.aiConfigs === 0) {
    return dim('No AI agents, MCP servers, or AI configs detected.');
  }

  if (summary.totalAgents > 0) {
    parts.push(`${bold(String(summary.totalAgents))} AI agent${summary.totalAgents !== 1 ? 's' : ''}`);
  }
  if (summary.mcpServers > 0) {
    parts.push(`${bold(String(summary.mcpServers))} MCP server${summary.mcpServers !== 1 ? 's' : ''}`);
  }
  if (summary.aiConfigs > 0) {
    parts.push(`${bold(String(summary.aiConfigs))} AI config${summary.aiConfigs !== 1 ? 's' : ''}`);
  }
  if (summary.localLlms > 0) {
    parts.push(`${bold(String(summary.localLlms))} local LLM${summary.localLlms !== 1 ? 's' : ''}`);
  }

  return parts.join(' | ');
}

/**
 * Build the governance score summary with recovery framing.
 * 100 = fully governed (the goal), 0 = nothing in place.
 *
 *   "Governance: 35/100 -> 82/100 by addressing 3 findings"
 */
function buildGovernanceSummary(result: DetectResult): string {
  const { summary } = result;
  const score = summary.governanceScore;

  if (score === 100) {
    return green('Governance: 100/100 -- fully governed');
  }

  const scoreColor = score >= 70 ? green : score >= 40 ? yellow : red;
  const projected = Math.min(100, score + summary.recoverablePoints);

  let line = `Governance: ${scoreColor(bold(String(score)))}/100`;
  if (result.findings.length > 0 && projected > score) {
    line += ` -> ${green(bold(String(projected)))}/100 by addressing ${result.findings.length} finding${result.findings.length !== 1 ? 's' : ''}`;
  }

  return line;
}

/**
 * Build a plain-language explanation of what was found, for people
 * who do not think in security terminology.
 */
function buildWhatThisMeans(result: DetectResult): string[] {
  const lines: string[] = [];
  const { summary } = result;

  if (summary.totalAgents === 0 && summary.mcpServers === 0) return lines;

  lines.push(bold('What This Means'));

  // Explain agent detection
  if (summary.totalAgents > 0) {
    const governed = summary.totalAgents - summary.ungoverned;
    if (summary.ungoverned === 0) {
      lines.push(`  Your ${summary.totalAgents === 1 ? 'AI agent has' : 'AI agents have'} `
        + `governance in place. Actions are bounded by the rules you defined.`);
    } else if (governed > 0) {
      lines.push(`  ${summary.totalAgents} AI tool${summary.totalAgents !== 1 ? 's are' : ' is'} running on this machine. `
        + `${governed} ${governed === 1 ? 'has' : 'have'} governance rules, `
        + `${summary.ungoverned} ${summary.ungoverned === 1 ? 'does' : 'do'} not.`);
    } else {
      lines.push(`  ${summary.totalAgents} AI tool${summary.totalAgents !== 1 ? 's are' : ' is'} running `
        + `without governance. This means there are no documented rules limiting what `
        + `${summary.totalAgents === 1 ? 'it' : 'they'} can do in this project.`);
    }
  }

  // Explain MCP servers
  if (summary.mcpServers > 0) {
    const verified = summary.mcpServers - summary.unverifiedServers;
    lines.push(`  ${summary.mcpServers} MCP server${summary.mcpServers !== 1 ? 's give' : ' gives'} your AI agents `
      + `additional capabilities (file access, database queries, API calls, etc.).`);
    if (summary.unverifiedServers > 0 && verified > 0) {
      lines.push(`  ${verified} ${verified === 1 ? 'has' : 'have'} verified identities, `
        + `${summary.unverifiedServers} ${summary.unverifiedServers === 1 ? 'does' : 'do'} not.`);
    } else if (summary.unverifiedServers === summary.mcpServers) {
      lines.push(`  None have verified identities, so there is no tamper-evident record of `
        + `which server version is installed.`);
    }
  }

  lines.push('');
  return lines;
}

function formatText(result: DetectResult, verbose: boolean, targetDir: string): string {
  const lines: string[] = [];

  // Header with machine context
  lines.push(bold('Shadow AI Agent Audit'));
  lines.push(dim(`${os.hostname()} | ${os.userInfo().username} | ${targetDir}`));
  lines.push(dim(result.scanTimestamp.replace('T', ' ').replace(/\.\d+Z$/, ' UTC')));
  lines.push('');

  // Score and summary -- the only thing a Sr. Manager reads
  lines.push(buildGovernanceSummary(result));
  lines.push(buildSummaryLine(result));
  lines.push('');

  // What This Means (plain-language overview for non-security audience)
  lines.push(...buildWhatThisMeans(result));

  // Findings -- the actionable part, front and center
  if (result.findings.length > 0) {
    lines.push(bold(`Findings (${result.findings.length})`));
    for (const finding of result.findings) {
      lines.push('');
      lines.push(`  ${riskLabel(finding.severity)}  ${finding.title}`);
      if (finding.detail) {
        lines.push(`  ${dim(finding.detail)}`);
      }
      lines.push(`  ${finding.whyItMatters}`);
      lines.push(`  ${dim('Fix:')} ${cyan(finding.remediation)}`);
    }
    lines.push('');
  }

  // All clear
  if (result.findings.length === 0) {
    lines.push(green('All detected AI tools have governance in place. No findings.'));
    lines.push('');
  }

  // Running AI Agents -- compact, no PIDs unless verbose
  const assistants = result.agents.filter((a) => a.category === 'ai-assistant');
  const llms = result.agents.filter((a) => a.category === 'local-llm');

  lines.push(bold('Running AI Agents'));
  if (assistants.length === 0 && llms.length === 0) {
    lines.push(dim('  No AI agents detected'));
  } else {
    for (const agent of [...assistants, ...llms]) {
      const nameCol = agent.name.padEnd(22);
      const idStatus = agent.identityStatus === 'identified' ? green('identified') : yellow('no identity');
      const govStatus = agent.governanceStatus === 'governed' ? green('governed') : yellow('ungoverned');
      const pidStr = verbose ? dim(` (PID ${agent.pid})`) : '';
      lines.push(`  ${nameCol}${idStatus}    ${govStatus}${pidStr}`);
    }
  }
  lines.push('');

  // Identity & Governance status
  lines.push(bold('Identity & Governance'));
  lines.push(`  Agent identity:       ${result.identity.aimIdentities > 0 ? green('registered') : yellow('not registered -- agent actions cannot be traced')}`);
  if (result.identity.mcpIdentities > 0) {
    lines.push(`  MCP identities:       ${green(`${result.identity.mcpIdentities} server(s) signed`)}`);
  }
  lines.push(`  Behavioral rules:     ${result.identity.soulFiles === 0 ? yellow('none -- agents rely on their defaults') : green(`${result.identity.soulFiles} SOUL.md defines boundaries`)}`);
  if (result.identity.capabilityPolicies > 0) {
    lines.push(`  Capability policies:  ${green(String(result.identity.capabilityPolicies) + ' policy file(s)')}`);
  }
  lines.push('');

  // MCP Servers -- show summary in default mode, full list in verbose
  const mcpCount = result.mcpServers.length;
  const projectMcp = result.mcpServers.filter((s) => s.source.includes('(project)'));
  const globalMcp = result.mcpServers.filter((s) => !s.source.includes('(project)'));

  lines.push(bold(`MCP Servers (${mcpCount} found)`));
  if (mcpCount === 0) {
    lines.push(dim('  No MCP server configurations found'));
  } else {
    // Always show project-local MCP servers with capabilities (these are actionable)
    if (projectMcp.length > 0) {
      lines.push(`  ${bold('Project-local')} (${projectMcp.length})`);
      const riskOrder: Record<RiskLevel, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      projectMcp.sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk]);
      for (const server of projectMcp) {
        const nameCol = server.name.padEnd(20);
        const verifiedStr = server.verified ? green(' verified') : '';
        const realCaps = server.capabilities.filter((c) => c !== 'unknown');
        const capsStr = realCaps.length > 0
          ? dim(` -- ${realCaps.map((c) => capabilityDescription(c).toLowerCase()).join(', ')}`)
          : '';
        lines.push(`    ${nameCol}${verifiedStr}${capsStr}`);
      }
    }

    // Show global MCP servers as a compact summary (not individually unless verbose)
    if (globalMcp.length > 0) {
      if (verbose) {
        lines.push(`  ${bold('Machine-wide')} (${globalMcp.length})`);
        for (const server of globalMcp) {
          const nameCol = server.name.padEnd(20);
          const realCaps = server.capabilities.filter((c) => c !== 'unknown');
          const capsStr = realCaps.length > 0
            ? dim(` -- ${realCaps.map((c) => capabilityDescription(c).toLowerCase()).join(', ')}`)
            : '';
          lines.push(`    ${nameCol}${capsStr}`);
        }
      } else {
        // Compact: just show the count and which ones have sensitive access
        const sensitiveCaps = globalMcp.filter(
          (s) => s.capabilities.some((c) => ['shell-access', 'database', 'payments', 'cloud-services'].includes(c))
        );
        let globalLine = `  ${dim(`Machine-wide (${globalMcp.length})`)}`;
        if (sensitiveCaps.length > 0) {
          const names = sensitiveCaps.map((s) => s.name).join(', ');
          globalLine += dim(` -- ${sensitiveCaps.length} with sensitive access: ${names}`);
        }
        lines.push(globalLine);
        lines.push(dim(`    Run with --verbose to see full list`));
      }
    }
  }
  lines.push('');

  // AI Config Files -- only show if there are noteworthy ones
  const noteworthyConfigs = result.aiConfigs.filter((c) => c.risk !== 'low');
  if (result.aiConfigs.length > 0) {
    if (noteworthyConfigs.length > 0 || verbose) {
      lines.push(bold(`AI Config Files (${result.aiConfigs.length} found)`));
      const configsToShow = verbose ? result.aiConfigs : noteworthyConfigs;
      for (const config of configsToShow) {
        const fileCol = config.file.padEnd(35);
        const toolCol = config.tool;
        lines.push(`  ${fileCol}${toolCol}`);
        if (config.risk === 'critical') {
          lines.push(`    ${yellow('Contains credential references -- these should be in environment variables')}`);
        } else if (config.risk === 'high') {
          lines.push(`    ${yellow('Grants broad permissions to AI agents in this project')}`);
        }
      }
      if (!verbose && result.aiConfigs.length > noteworthyConfigs.length) {
        lines.push(dim(`  + ${result.aiConfigs.length - noteworthyConfigs.length} low-risk config(s) -- run with --verbose to see all`));
      }
      lines.push('');
    }
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export async function detect(options: DetectOptions): Promise<number> {
  const dir = path.resolve(options.targetDir ?? process.cwd());

  try {
    fs.accessSync(dir, fs.constants.R_OK);
  } catch {
    process.stderr.write(`Cannot access directory: ${dir}\n`);
    return 1;
  }

  // Run all detection strategies
  const agents = scanProcesses();
  const mcpServers = scanMcpServers(dir);
  const identity = scanIdentity(dir);
  const aiConfigs = scanAiConfigs(dir);

  identity.totalAgents = agents.length;

  // Enrich agents with identity/governance from project context
  if (identity.aimIdentities > 0) {
    for (const agent of agents) {
      agent.identityStatus = 'identified';
      agent.risk = agent.risk === 'high' ? 'medium' : agent.risk;
    }
  }
  if (identity.soulFiles > 0 || identity.capabilityPolicies > 0) {
    for (const agent of agents) {
      agent.governanceStatus = 'governed';
      agent.risk = 'low';
    }
  }

  // Enrich MCP servers with signing status
  const mcpIdDir = path.join(dir, '.opena2a', 'mcp-identities');
  if (fs.existsSync(mcpIdDir)) {
    for (const server of mcpServers) {
      const idFile = path.join(mcpIdDir, `${server.name}.json`);
      if (fs.existsSync(idFile)) {
        server.verified = true;
        server.risk = 'low';
      }
    }
  }

  // Calculate governance score
  const partialResult = { scanTimestamp: new Date().toISOString(), scanDirectory: dir, agents, mcpServers, aiConfigs, identity };
  const { governanceScore, deductions } = calculateGovernanceScore(partialResult);

  const ungoverned = agents.filter((a) => a.governanceStatus === 'no governance').length;
  const unverifiedServers = mcpServers.filter((s) => !s.verified).length;
  const localLlms = agents.filter((a) => a.category === 'local-llm').length;

  const result: DetectResult = {
    scanTimestamp: new Date().toISOString(),
    scanDirectory: dir,
    summary: {
      totalAgents: agents.length,
      ungoverned,
      mcpServers: mcpServers.length,
      unverifiedServers,
      localLlms,
      aiConfigs: aiConfigs.length,
      governanceScore,
      // All deductions are recoverable -- every deduction maps to a finding
      // with an actionable fix. Addressing all findings reaches 100/100.
      recoverablePoints: deductions,
    },
    agents,
    mcpServers,
    aiConfigs,
    identity,
    findings: [],
  };

  result.findings = generateFindings(result);

  if (options.format === 'json') {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write(formatText(result, options.verbose ?? false, dir) + '\n');
  }

  // Generate HTML report if requested
  if (options.reportPath) {
    const { generateDetectHtml } = await import('../report/detect-html.js');
    const html = generateDetectHtml(result);
    fs.writeFileSync(options.reportPath, html, 'utf-8');
    if (!options.ci) {
      const { exec } = await import('node:child_process');
      const openCmd = os.platform() === 'darwin' ? 'open' : os.platform() === 'win32' ? 'start' : 'xdg-open';
      exec(`${openCmd} "${options.reportPath}"`);
    }
    process.stdout.write(`Report: ${options.reportPath}\n`);
  }

  // Export CSV asset inventory if requested
  if (options.exportCsv) {
    const csv = generateAssetCsv(result);
    fs.writeFileSync(options.exportCsv, csv, 'utf-8');
    process.stdout.write(`Asset inventory: ${options.exportCsv}\n`);
  }

  return 0;
}
