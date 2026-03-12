/**
 * opena2a detect -- Shadow AI Agent Audit
 *
 * Scans the local machine for running AI agents and MCP servers,
 * then reports their identity and governance status.
 */

import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { bold, dim, green, yellow, red, cyan, gray } from '../util/colors.js';

export interface DetectOptions {
  targetDir: string;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
}

export interface DetectedAgent {
  name: string;
  pid: number;
  identityStatus: 'identified' | 'no identity';
  governanceStatus: 'governed' | 'no governance';
}

export interface DetectedMcpServer {
  name: string;
  transport: 'stdio' | 'sse' | 'unknown';
  source: string;
  verified: boolean;
}

export interface IdentitySummary {
  aimIdentities: number;
  mcpIdentities: number;
  totalAgents: number;
  soulFiles: number;
  capabilityPolicies: number;
}

export interface DetectResult {
  agents: DetectedAgent[];
  mcpServers: DetectedMcpServer[];
  identity: IdentitySummary;
}

/** Agent patterns to search for in the process list. */
const AGENT_PATTERNS: { name: string; patterns: RegExp[] }[] = [
  { name: 'Claude Code', patterns: [/\bclaude\b/i, /@anthropic-ai\/claude-code/i] },
  { name: 'Cursor', patterns: [/\bcursor\b/i, /Cursor\.app/i] },
  { name: 'GitHub Copilot', patterns: [/\bcopilot\b/i] },
  { name: 'Windsurf', patterns: [/\bwindsurf\b/i, /Windsurf/] },
  { name: 'Aider', patterns: [/\baider\b/i] },
  { name: 'Continue', patterns: [/\bcontinue\b/i] },
  { name: 'Cline', patterns: [/\bcline\b/i] },
];

/** MCP config file locations (relative to home directory unless absolute). */
interface McpConfigLocation {
  /** Path relative to home dir, or use {cwd} for project-local. */
  path: string;
  /** Label shown in output. */
  label: string;
  /** Whether this is a project-local config. */
  projectLocal?: boolean;
}

const MCP_CONFIG_LOCATIONS: McpConfigLocation[] = [
  { path: '.claude/mcp_servers.json', label: '~/.claude/mcp_servers.json' },
  { path: '.cursor/mcp.json', label: '~/.cursor/mcp.json' },
  { path: '.config/windsurf/mcp.json', label: '~/.config/windsurf/mcp.json' },
];

const PROJECT_MCP_FILES = ['mcp.json', '.mcp.json', '.mcp/config.json'];

/**
 * Scan running processes for AI agents.
 * Runs a single `ps aux` and parses once.
 */
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

      const matches = agent.patterns.some((p) => p.test(line));
      if (!matches) continue;

      // Extract PID from ps aux output (second column)
      const parts = line.trim().split(/\s+/);
      const pid = parseInt(parts[1], 10);
      if (isNaN(pid)) continue;

      agents.push({
        name: agent.name,
        pid,
        identityStatus: 'no identity',
        governanceStatus: 'no governance',
      });
      seen.add(agent.name);
    }
  }

  return agents;
}

/**
 * Parse an MCP config file and extract server entries.
 */
export function parseMcpConfig(
  filePath: string,
  label: string
): DetectedMcpServer[] {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const config = JSON.parse(content);

    const servers: DetectedMcpServer[] = [];

    // MCP config can be { "mcpServers": { ... } } or { "servers": { ... } } or flat object
    const serversObj =
      config.mcpServers ?? config.servers ?? config;

    if (typeof serversObj !== 'object' || serversObj === null) return [];

    for (const [name, entry] of Object.entries(serversObj)) {
      if (typeof entry !== 'object' || entry === null) continue;
      const e = entry as Record<string, unknown>;

      let transport: 'stdio' | 'sse' | 'unknown' = 'unknown';
      if (e.command || e.args) transport = 'stdio';
      if (e.url || e.transport === 'sse') transport = 'sse';
      if (e.transport === 'stdio') transport = 'stdio';

      servers.push({
        name,
        transport,
        source: label,
        verified: false,
      });
    }

    return servers;
  } catch {
    return [];
  }
}

/**
 * Scan for MCP server config files.
 */
export function scanMcpServers(targetDir: string): DetectedMcpServer[] {
  const home = os.homedir();
  const servers: DetectedMcpServer[] = [];

  // Home-directory config locations
  for (const loc of MCP_CONFIG_LOCATIONS) {
    const fullPath = path.join(home, loc.path);
    servers.push(...parseMcpConfig(fullPath, loc.label));
  }

  // VSCode MCP extensions -- scan ~/.vscode/extensions/*/mcp.json
  const vscodeExtDir = path.join(home, '.vscode', 'extensions');
  try {
    const entries = fs.readdirSync(vscodeExtDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const mcpPath = path.join(vscodeExtDir, entry.name, 'mcp.json');
      servers.push(
        ...parseMcpConfig(mcpPath, `~/.vscode/extensions/${entry.name}/mcp.json`)
      );
    }
  } catch {
    // Directory may not exist
  }

  // Project-local MCP config files
  for (const filename of PROJECT_MCP_FILES) {
    const fullPath = path.join(targetDir, filename);
    servers.push(...parseMcpConfig(fullPath, `${filename} (project)`));
  }

  return servers;
}

/**
 * Check for AIM identity and governance files.
 */
export function scanIdentity(targetDir: string): IdentitySummary {
  let aimIdentities = 0;
  let mcpIdentities = 0;
  let soulFiles = 0;
  let capabilityPolicies = 0;

  // Check for .opena2a/ directory in target dir only (project-scoped)
  const opena2aDir = path.join(targetDir, '.opena2a');
  if (fs.existsSync(opena2aDir)) {
    aimIdentities++;

    // Count MCP server identities separately
    const mcpIdDir = path.join(opena2aDir, 'mcp-identities');
    if (fs.existsSync(mcpIdDir)) {
      try {
        const files = fs.readdirSync(mcpIdDir).filter((f) => f.endsWith('.json'));
        mcpIdentities = files.length;
      } catch { /* ignore */ }
    }
  }

  // Check for SOUL.md files
  const soulPaths = [
    path.join(targetDir, 'SOUL.md'),
    path.join(targetDir, '.opena2a', 'SOUL.md'),
  ];
  for (const p of soulPaths) {
    if (fs.existsSync(p)) {
      soulFiles++;
    }
  }

  // Check for capability policy files
  const policyPaths = [
    path.join(targetDir, '.opena2a', 'policy.yml'),
    path.join(targetDir, '.opena2a', 'policy.yaml'),
    path.join(targetDir, '.opena2a', 'policy.json'),
    path.join(targetDir, 'opena2a.policy.yml'),
    path.join(targetDir, 'opena2a.policy.yaml'),
  ];
  for (const p of policyPaths) {
    if (fs.existsSync(p)) {
      capabilityPolicies++;
    }
  }

  return { aimIdentities, mcpIdentities, totalAgents: 0, soulFiles, capabilityPolicies };
}

/**
 * Format text output for the detect command.
 */
function formatText(result: DetectResult, verbose: boolean, targetDir: string): string {
  const lines: string[] = [];

  lines.push(bold('Shadow AI Agent Audit'));
  lines.push('=====================');
  lines.push('');

  // Running AI Agents
  lines.push(bold('Running AI Agents'));
  if (result.agents.length === 0) {
    lines.push(dim('  No AI agents detected in running processes'));
  } else {
    for (const agent of result.agents) {
      const nameCol = agent.name.padEnd(20);
      const pidCol = `PID ${agent.pid}`.padEnd(13);
      const idStatus =
        agent.identityStatus === 'identified'
          ? green(agent.identityStatus)
          : yellow(agent.identityStatus);
      const govStatus =
        agent.governanceStatus === 'governed'
          ? green(agent.governanceStatus)
          : yellow(agent.governanceStatus);
      lines.push(`  ${nameCol}${pidCol}${idStatus}    ${govStatus}`);
    }
  }
  lines.push('');

  // MCP Servers
  const mcpCount = result.mcpServers.length;
  lines.push(bold(`MCP Servers (${mcpCount} found)`));
  if (mcpCount === 0) {
    lines.push(dim('  No MCP server configurations found'));
  } else {
    for (const server of result.mcpServers) {
      const nameCol = server.name.padEnd(20);
      const transportCol = server.transport.padEnd(9);
      const sourceCol = server.source.padEnd(40);
      const verifiedLabel = server.verified
        ? green('verified')
        : dim('not verified');
      lines.push(`  ${nameCol}${transportCol}${sourceCol}${verifiedLabel}`);
    }
  }
  lines.push('');

  // Identity Status
  lines.push(bold('Identity Status'));
  const aimLabel = result.identity.aimIdentities > 0 ? green('initialized') : yellow('not initialized');
  lines.push(`  AIM project:          ${aimLabel}`);
  if (result.identity.mcpIdentities > 0) {
    lines.push(`  MCP identities:       ${result.identity.mcpIdentities} server(s) signed`);
  }
  lines.push(
    `  Governance files:     ${result.identity.soulFiles === 0 ? 'none' : `${result.identity.soulFiles} SOUL.md found`}`
  );
  lines.push(
    `  Capability policies:  ${result.identity.capabilityPolicies === 0 ? 'none' : String(result.identity.capabilityPolicies)}`
  );
  lines.push('');

  // Next Steps
  lines.push(bold('Next Steps'));
  lines.push(
    `  ${cyan('opena2a identity create --name my-agent')}    Create an agent identity`
  );
  lines.push(
    `  ${cyan('opena2a init')}                               Initialize security posture`
  );
  lines.push(
    `  ${cyan('opena2a scan-soul')}                          Scan governance coverage`
  );

  if (verbose) {
    lines.push('');
    lines.push(dim('Detection methods: process list (ps aux), MCP config files, AIM identity directories'));
    lines.push(dim(`Target directory: ${targetDir}`));
  }

  return lines.join('\n');
}

/**
 * Main detect command entry point.
 */
export async function detect(options: DetectOptions): Promise<number> {
  const dir = options.targetDir ?? process.cwd();

  // Validate directory
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

  // Update totalAgents count
  identity.totalAgents = agents.length;

  // Enrich agents with identity info if .opena2a exists in target dir
  if (identity.aimIdentities > 0) {
    // Mark agents as identified if AIM identity exists in the project
    // In a real implementation, this would match agent names to identities
  }

  // Enrich MCP servers with signing status from .opena2a/mcp-identities/
  const mcpIdDir = path.join(dir, '.opena2a', 'mcp-identities');
  if (fs.existsSync(mcpIdDir)) {
    for (const server of mcpServers) {
      const idFile = path.join(mcpIdDir, `${server.name}.json`);
      if (fs.existsSync(idFile)) {
        server.verified = true;
      }
    }
  }

  const result: DetectResult = { agents, mcpServers, identity };

  if (options.format === 'json') {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    return 0;
  }

  process.stdout.write(formatText(result, options.verbose ?? false, dir) + '\n');
  return 0;
}
