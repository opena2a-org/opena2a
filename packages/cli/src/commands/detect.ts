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
import { bold, dim, green, yellow, red, cyan, orange } from '../util/colors.js';
import { calculateGovernanceScore } from '../util/governance-scoring.js';
import type { RegistryEnrichment } from '../util/registry-enrichment.js';

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
  registry?: boolean;
  autoScan?: boolean;
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

export interface McpRegistryData {
  trustScore: number;
  trustLevel: number;
  verdict: string;
  communityScans: number;
  verified: boolean;
}

export interface McpScanResult {
  score: number;
  maxScore: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  contributed: boolean;
}

export interface DetectedMcpServer {
  name: string;
  transport: 'stdio' | 'sse' | 'unknown';
  source: string;
  verified: boolean;
  capabilities: string[];
  risk: RiskLevel;
  registryData?: McpRegistryData;
  scanResult?: McpScanResult;
  scanSuggestion?: string;
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
  // SOUL.md is a governance file, not a risk config -- detected by scanIdentity() instead
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

      // Skip files larger than 1MB to prevent memory exhaustion
      const stats = fs.statSync(fullPath);
      if (stats.size > 1024 * 1024) continue;

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
    // Check for actual AIM identity file in project
    const identityFile = path.join(opena2aDir, 'aim', 'identity.json');
    if (fs.existsSync(identityFile)) {
      aimIdentities++;
    }
  }

  // Also check global identity location (~/.opena2a/aim-core/identity.json)
  // This is where `opena2a identity create` writes by default
  const globalIdentity = path.join(os.homedir(), '.opena2a', 'aim-core', 'identity.json');
  if (aimIdentities === 0 && fs.existsSync(globalIdentity)) {
    aimIdentities++;
  }

  if (fs.existsSync(opena2aDir)) {

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

// calculateGovernanceScore is imported from ../util/governance-scoring.js

// ---------------------------------------------------------------------------
// Finding generation
// ---------------------------------------------------------------------------

function generateFindings(result: Omit<DetectResult, 'findings'>): Finding[] {
  const findings: Finding[] = [];

  // No AIM identity -- recommend this first since identity is the foundation
  const hasIdentity = result.identity.aimIdentities > 0;
  if (!hasIdentity && result.agents.length > 0) {
    findings.push({
      severity: 'high',
      category: 'identity',
      title: 'No agent identity for this project',
      detail: `${result.agents.length} AI tool${result.agents.length !== 1 ? 's' : ''} detected but no identity is registered`,
      whyItMatters: 'An agent identity is a cryptographic key pair that lets you track which agent '
        + 'did what in this project. Without one, agent actions cannot be attributed, verified, or '
        + 'audited. This is the first step to managing AI tools in your project.',
      remediation: 'opena2a identity create --name my-project',
    });
  }

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

  // Recommend MCP signing for project-local servers (low priority, after identity + governance)
  const projectMcpCount = result.mcpServers.filter(
    (s) => s.source.includes('(project)')
  ).length;
  const signedMcpCount = result.mcpServers.filter(
    (s) => s.source.includes('(project)') && s.verified
  ).length;
  if (projectMcpCount > 0 && signedMcpCount < projectMcpCount && projectCriticalMcp.length === 0) {
    const unsigned = projectMcpCount - signedMcpCount;
    findings.push({
      severity: 'low',
      category: 'mcp',
      title: `${unsigned} project MCP server${unsigned !== 1 ? 's' : ''} without signed identity`,
      detail: `Signing creates a tamper-evident record of each server's configuration.`,
      whyItMatters: 'Without signing, you cannot detect if an MCP server configuration was modified '
        + 'by an attacker or by another agent. Signing lets you verify that the server you are using '
        + 'is the exact version you approved.',
      remediation: 'opena2a mcp sign',
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

  // Header -- columns designed for enterprise CMDB/ServiceNow import
  rows.push('Hostname,Username,Scan Directory,Scan Timestamp,Asset Type,Name,Installed From,Transport,Capabilities,Risk');

  const deviceCols = [csvEscape(hostname), csvEscape(username), csvEscape(scanDir), scanTime].join(',');

  // AI Agents
  for (const agent of result.agents) {
    rows.push([
      deviceCols,
      'AI Agent',
      csvEscape(agent.name),
      'Running process',
      '',
      agent.category,
      agent.risk,
    ].join(','));
  }

  // MCP Servers
  for (const server of result.mcpServers) {
    const caps = server.capabilities.filter((c) => c !== 'unknown');
    const isProjectLocal = server.source.includes('(project)');
    const scope = isProjectLocal ? 'This project' : 'User machine';
    rows.push([
      deviceCols,
      'MCP Server',
      csvEscape(server.name),
      scope,
      server.transport,
      csvEscape(caps.map((c) => capabilityDescription(c)).join('; ')),
      server.risk,
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
    case 'high': return orange;
    case 'medium': return yellow;
    case 'low': return green;
  }
}

function riskLabel(level: RiskLevel): string {
  return riskColor(level)(level.toUpperCase());
}

/** Format a compact trust label for an MCP server row. Handles three states:
 *  1. Registry data exists -> "Trust: 92/100 | 45 community scans"
 *  2. Scan result exists   -> "Scanned: 95/100 | 0 critical"
 *  3. Neither              -> "No trust data | scan: opena2a detect --registry --auto-scan"
 *
 * Silent-post-consent rule (briefs/scan-result-telemetry-policy.md §5):
 * we no longer surface the "contributed" label on the per-server row.
 * Once the user has opted in to contribution, the act of contributing
 * is invisible. Disclosure lives in the initial consent prompt,
 * --help, and the privacy policy.
 */
function formatMcpTrustLabel(server: DetectedMcpServer): string {
  // State 1: Registry data available
  if (server.registryData) {
    const score = Math.round(server.registryData.trustScore * 100);
    const parts = [`Trust: ${score}/100`];
    if (server.registryData.communityScans > 0) {
      parts.push(`${server.registryData.communityScans} community scan${server.registryData.communityScans !== 1 ? 's' : ''}`);
    }
    return cyan(` ${parts.join(' | ')}`);
  }

  // State 2: Just scanned with HMA
  if (server.scanResult) {
    const parts = [`Scanned: ${server.scanResult.score}/${server.scanResult.maxScore}`];
    parts.push(`${server.scanResult.criticalCount} critical`);
    return cyan(` ${parts.join(' | ')}`);
  }

  // State 3: No data at all -- show actionable suggestion
  if (server.scanSuggestion) {
    return dim(` No trust data | scan: ${server.scanSuggestion}`);
  }

  return '';
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
      const idStatus = agent.identityStatus === 'identified' ? green('project registered') : yellow('project not registered');
      const govStatus = agent.governanceStatus === 'governed' ? green('governed') : yellow('ungoverned');
      const pidStr = verbose ? dim(` (PID ${agent.pid})`) : '';
      lines.push(`  ${nameCol}${idStatus}    ${govStatus}${pidStr}`);
    }
  }
  lines.push('');

  // Identity & Governance details are omitted from default output.
  // The governance score and findings already communicate everything actionable.
  // Show only in verbose mode for debugging.
  if (verbose) {
    lines.push(bold('Identity & Governance'));
    lines.push(`  Project identity:     ${result.identity.aimIdentities > 0 ? green('initialized (.opena2a/)') : yellow('not initialized')}`);
    lines.push(`  Behavioral rules:     ${result.identity.soulFiles === 0 ? yellow('none') : green(`${result.identity.soulFiles} SOUL.md`)}`);
    if (result.identity.mcpIdentities > 0) {
      lines.push(`  MCP identities:       ${green(`${result.identity.mcpIdentities} server(s) signed`)}`);
    }
    lines.push('');
  }

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
        const trustStr = formatMcpTrustLabel(server);
        const realCaps = server.capabilities.filter((c) => c !== 'unknown');
        const capsStr = realCaps.length > 0
          ? dim(` -- ${realCaps.map((c) => capabilityDescription(c).toLowerCase()).join(', ')}`)
          : '';
        lines.push(`    ${nameCol}${verifiedStr}${trustStr}${capsStr}`);
      }
    }

    // Show global MCP servers as a compact summary (not individually unless verbose)
    if (globalMcp.length > 0) {
      if (verbose) {
        lines.push(`  ${bold('Machine-wide')} (${globalMcp.length})`);
        for (const server of globalMcp) {
          const nameCol = server.name.padEnd(20);
          const trustStr = formatMcpTrustLabel(server);
          const realCaps = server.capabilities.filter((c) => c !== 'unknown');
          const capsStr = realCaps.length > 0
            ? dim(` -- ${realCaps.map((c) => capabilityDescription(c).toLowerCase()).join(', ')}`)
            : '';
          lines.push(`    ${nameCol}${trustStr}${capsStr}`);
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
// Auto-scan unknown MCP servers with HMA
// ---------------------------------------------------------------------------

/**
 * Resolve the filesystem path for an MCP server from its command field.
 * Handles common patterns: npx <pkg>, node <path>, direct paths.
 */
function resolveMcpServerPath(server: DetectedMcpServer, projectDir: string): string | null {
  // The source field contains info like "claude_desktop (project)" or "vscode (global)"
  // The name is typically the package name or server identifier
  // Try common resolution paths

  // Check if it exists as a direct path in the project
  const directPath = path.join(projectDir, 'node_modules', server.name);
  if (fs.existsSync(directPath)) return directPath;

  // Check scoped package patterns (e.g., @playwright/mcp -> node_modules/@playwright/mcp)
  if (server.name.includes('/')) {
    const scopedPath = path.join(projectDir, 'node_modules', server.name);
    if (fs.existsSync(scopedPath)) return scopedPath;
  }

  // Try global node_modules
  try {
    const globalPrefix = execSync('npm prefix -g', { encoding: 'utf-8' }).trim();
    const globalPath = path.join(globalPrefix, 'lib', 'node_modules', server.name);
    if (fs.existsSync(globalPath)) return globalPath;
  } catch {
    // npm not available
  }

  // Fall back to the project directory itself (scan around the MCP config context)
  return projectDir;
}

/**
 * Scan unenriched MCP servers using HackMyAgent.
 * Returns a map of server name -> scan result.
 */
async function scanUnknownAssets(
  servers: DetectedMcpServer[],
  projectDir: string,
  verbose?: boolean,
): Promise<Map<string, McpScanResult>> {
  const results = new Map<string, McpScanResult>();

  // Try to import HMA
  let HardeningScanner: any;
  try {
    const hma = await import('hackmyagent') as any;
    HardeningScanner = hma.HardeningScanner ?? hma.default?.HardeningScanner;
  } catch {
    // HMA not installed -- caller handles the fallback message
    return results;
  }

  if (!HardeningScanner) return results;

  // Check contribute status for submission
  let contributeEnabled = false;
  let registryUrl = '';
  try {
    const { isContributeEnabled, getRegistryUrl } = await import('../util/report-submission.js');
    contributeEnabled = await isContributeEnabled();
    registryUrl = await getRegistryUrl();
  } catch {
    // Non-critical
  }

  for (const server of servers) {
    const targetPath = resolveMcpServerPath(server, projectDir);
    if (!targetPath) continue;

    try {
      if (verbose) {
        process.stderr.write(dim(`  Scanning ${server.name}...\n`));
      }

      const scanner = new HardeningScanner();
      const scanResult = await Promise.race([
        scanner.scan({ targetDir: targetPath, ci: true }),
        new Promise<null>((_, reject) => setTimeout(() => reject(new Error('timeout')), 30_000)),
      ]);

      if (!scanResult) continue;

      const score = scanResult.overallScore ?? scanResult.score ?? 0;
      const maxScore = scanResult.maxScore ?? 100;
      const criticalCount = scanResult.criticalCount ?? scanResult.findings?.filter((f: any) => f.severity === 'critical').length ?? 0;
      const highCount = scanResult.highCount ?? scanResult.findings?.filter((f: any) => f.severity === 'high').length ?? 0;
      const mediumCount = scanResult.mediumCount ?? scanResult.findings?.filter((f: any) => f.severity === 'medium').length ?? 0;

      let contributed = false;

      // Submit to registry if contribute is enabled
      if (contributeEnabled && registryUrl) {
        try {
          const { submitScanReport } = await import('../util/report-submission.js');
          const report = {
            packageName: server.name,
            packageType: 'mcp_server',
            scannerName: 'HackMyAgent',
            scannerVersion: scanResult.scannerVersion ?? '1.0.0',
            overallScore: score,
            scanDurationMs: scanResult.scanDurationMs ?? 0,
            criticalCount,
            highCount,
            mediumCount,
            lowCount: scanResult.lowCount ?? 0,
            infoCount: scanResult.infoCount ?? 0,
            verdict: score >= 80 ? 'pass' : score >= 50 ? 'warnings' : 'fail',
            findings: scanResult.findings ?? [],
          };
          contributed = await submitScanReport(registryUrl, report, verbose);
        } catch {
          // Non-critical
        }
      }

      results.set(server.name, {
        score,
        maxScore,
        criticalCount,
        highCount,
        mediumCount,
        contributed,
      });
    } catch (err: any) {
      if (verbose) {
        process.stderr.write(dim(`  Failed to scan ${server.name}: ${err.message}\n`));
      }
    }
  }

  return results;
}

/**
 * Prompt the user to scan unknown MCP servers (interactive, non-CI only).
 * Returns true if the user agrees.
 */
async function promptForScan(count: number): Promise<boolean> {
  const readline = await import('node:readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });

  return new Promise((resolve) => {
    process.stderr.write('\n');
    process.stderr.write(yellow(`${count} MCP server${count !== 1 ? 's have' : ' has'} no trust data in the registry.\n`));
    rl.question(`Scan them now with HackMyAgent to contribute trust data? [y/N] `, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y');
    });
  });
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

  // Registry enrichment (opt-in via --registry)
  let registryEnrichments: Map<string, RegistryEnrichment> | undefined;
  if (options.registry && mcpServers.length > 0) {
    try {
      const { enrichFromRegistry } = await import('../util/registry-enrichment.js');
      const { getRegistryUrl } = await import('../util/report-submission.js');

      const registryUrl = (await getRegistryUrl()) || 'https://api.oa2a.org';
      const assets = mcpServers.map((s) => ({ name: s.name, type: 'mcp_server' }));
      registryEnrichments = await enrichFromRegistry(assets, registryUrl);

      // Attach registry data to each MCP server
      for (const server of mcpServers) {
        const key = `${server.name}:mcp_server`;
        const enrichment = registryEnrichments.get(key);
        if (enrichment) {
          server.registryData = {
            trustScore: enrichment.trustScore,
            trustLevel: enrichment.trustLevel,
            verdict: enrichment.verdict,
            communityScans: enrichment.communityScans,
            verified: enrichment.verified,
          };
        }
      }

      if (options.verbose) {
        const enriched = mcpServers.filter((s) => s.registryData).length;
        process.stderr.write(dim(`Registry: enriched ${enriched}/${mcpServers.length} MCP servers\n`));
      }
    } catch {
      // Registry enrichment is non-critical -- never block the scan
      if (options.verbose) {
        process.stderr.write(dim('Registry: enrichment skipped (unavailable or timed out)\n'));
      }
    }
  }

  // Auto-scan unknown MCP servers (after registry enrichment, before output)
  if (options.registry && mcpServers.length > 0) {
    const unenriched = mcpServers.filter((s) => !s.registryData);

    if (unenriched.length > 0) {
      let shouldScan = false;

      if (options.autoScan) {
        // --auto-scan: scan without prompting
        shouldScan = true;
      } else if (!options.ci && process.stdin.isTTY) {
        // Interactive mode: prompt the user
        shouldScan = await promptForScan(unenriched.length);
      }
      // CI mode without --auto-scan: skip silently

      if (shouldScan) {
        const scanResults = await scanUnknownAssets(unenriched, dir, options.verbose);

        if (scanResults.size > 0) {
          for (const server of unenriched) {
            const result = scanResults.get(server.name);
            if (result) {
              server.scanResult = result;
            }
          }
        } else if (scanResults.size === 0 && unenriched.length > 0) {
          // HMA not installed -- add suggestions
          for (const server of unenriched) {
            server.scanSuggestion = `npm i -g hackmyagent && opena2a scan secure .`;
          }
          if (!options.ci) {
            process.stderr.write(dim('Install hackmyagent to scan unknown packages: npm i -g hackmyagent\n'));
          }
        }
      } else {
        // User declined or CI mode -- add actionable suggestions
        for (const server of unenriched) {
          server.scanSuggestion = `opena2a detect --registry --auto-scan`;
        }
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
      const { spawn } = await import('node:child_process');
      const openCmd = os.platform() === 'darwin' ? 'open' : os.platform() === 'win32' ? 'start' : 'xdg-open';
      spawn(openCmd, [options.reportPath], { detached: true, stdio: 'ignore' }).unref();
    }
    process.stdout.write(`Report: ${options.reportPath}\n`);
  }

  // Export CSV asset inventory if requested
  if (options.exportCsv) {
    const csv = generateAssetCsv(result);
    fs.writeFileSync(options.exportCsv, csv, 'utf-8');
    process.stdout.write(`Asset inventory: ${options.exportCsv}\n`);
  }

  // Community contribution: track scan count and submit when opted in.
  // This lets the registry aggregate shadow AI data across the community:
  // which agents/MCP servers are in use, common governance gaps, etc.
  try {
    const { recordScanAndMaybePrompt, isContributeEnabled, getRegistryUrl, submitScanReport, normalizeDetectReport } =
      await import('../util/report-submission.js');
    await recordScanAndMaybePrompt();

    if (options.ci !== true && (await isContributeEnabled())) {
      const registryUrl = await getRegistryUrl();
      if (registryUrl) {
        const report = normalizeDetectReport(result);
        await submitScanReport(registryUrl, report, options.verbose);
      }
    }
  } catch {
    // Non-critical -- never block on contribution failures
  }

  return 0;
}
