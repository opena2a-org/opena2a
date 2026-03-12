/**
 * Shield environment detection.
 *
 * Scans the developer workstation for CLIs, AI coding assistants,
 * MCP server configurations, and active OAuth sessions.  All detection
 * is synchronous so the result can be used during CLI startup without
 * awaiting promises.
 */

import { existsSync, readFileSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { homedir, hostname, platform } from 'node:os';
import { join, resolve } from 'node:path';

import type {
  DetectedAssistant,
  DetectedCli,
  DetectedMcpServer,
  DetectedOAuthSession,
  EnvironmentScan,
  ProjectType,
} from './types.js';

import { detectProject } from '../util/detect.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Run a binary with args without shell interpretation (safe from injection). */
function tryExecFile(binary: string, args: string[]): string | null {
  try {
    return execFileSync(binary, args, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch {
    return null;
  }
}

/** Read a JSON file and return the parsed object, or null on failure. */
function readJson(filePath: string): Record<string, unknown> | null {
  try {
    if (!existsSync(filePath)) return null;
    const raw = readFileSync(filePath, 'utf-8');
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Return ISO-8601 mtime string for a file, or null if unreadable. */
function fileMtime(filePath: string): string | null {
  try {
    return statSync(filePath).mtime.toISOString();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// CLI detection
// ---------------------------------------------------------------------------

interface CliSpec {
  name: string;
  binary: string;
  versionFlag: string;
  configDir: string;
  credentialFiles: string[];
}

const CLI_SPECS: CliSpec[] = [
  {
    name: 'aws',
    binary: 'aws',
    versionFlag: '--version',
    configDir: join(homedir(), '.aws'),
    credentialFiles: ['credentials', 'sso/cache'],
  },
  {
    name: 'az',
    binary: 'az',
    versionFlag: '--version',
    configDir: join(homedir(), '.azure'),
    credentialFiles: ['msal_token_cache.json', 'accessTokens.json'],
  },
  {
    name: 'gcloud',
    binary: 'gcloud',
    versionFlag: '--version',
    configDir: join(homedir(), '.config', 'gcloud'),
    credentialFiles: ['application_default_credentials.json', 'credentials.db'],
  },
  {
    name: 'vercel',
    binary: 'vercel',
    versionFlag: '--version',
    configDir: join(homedir(), '.vercel'),
    credentialFiles: ['auth.json'],
  },
  {
    name: 'gh',
    binary: 'gh',
    versionFlag: '--version',
    configDir: join(homedir(), '.config', 'gh'),
    credentialFiles: ['hosts.yml'],
  },
  {
    name: 'kubectl',
    binary: 'kubectl',
    versionFlag: 'version --client --short',
    configDir: join(homedir(), '.kube'),
    credentialFiles: ['config'],
  },
  {
    name: 'terraform',
    binary: 'terraform',
    versionFlag: '--version',
    configDir: join(homedir(), '.terraform.d'),
    credentialFiles: ['credentials.tfrc.json'],
  },
];

function detectClis(): DetectedCli[] {
  const results: DetectedCli[] = [];

  for (const spec of CLI_SPECS) {
    const binaryPath = tryExecFile('which', [spec.binary]);
    if (!binaryPath) continue;

    // Extract version string -- take only the first line to keep it concise
    let version: string | null = null;
    const rawVersion = tryExecFile(spec.binary, spec.versionFlag.split(/\s+/));
    if (rawVersion) {
      version = rawVersion.split('\n')[0].trim();
    }

    const configDirExists = existsSync(spec.configDir);
    const hasCredentials = configDirExists && spec.credentialFiles.some(f =>
      existsSync(join(spec.configDir, f)),
    );

    results.push({
      name: spec.name,
      path: binaryPath,
      version,
      configDir: configDirExists ? spec.configDir : null,
      hasCredentials,
    });
  }

  return results;
}

// ---------------------------------------------------------------------------
// AI assistant detection
// ---------------------------------------------------------------------------

interface AssistantSpec {
  name: string;
  envVars: string[];
  configDirs: string[];
  processEnv?: string;
}

const ASSISTANT_SPECS: AssistantSpec[] = [
  {
    name: 'Claude Code',
    envVars: ['CLAUDE_CODE'],
    configDirs: [join(homedir(), '.claude')],
    processEnv: 'TERM_PROGRAM',
  },
  {
    name: 'Cursor',
    envVars: ['CURSOR'],
    configDirs: [join(homedir(), '.cursor')],
  },
  {
    name: 'GitHub Copilot',
    envVars: ['GITHUB_COPILOT'],
    configDirs: [join(homedir(), '.config', 'github-copilot')],
  },
  {
    name: 'Windsurf',
    envVars: [],
    configDirs: [join(homedir(), '.windsurf')],
  },
  {
    name: 'Aider',
    envVars: ['AIDER'],
    configDirs: [],
  },
];

function detectAssistants(targetDir: string): DetectedAssistant[] {
  const results: DetectedAssistant[] = [];

  for (const spec of ASSISTANT_SPECS) {
    let detected = false;
    let method: DetectedAssistant['method'] = 'config';
    let detail = '';
    const configPaths: string[] = [];

    // Check process-level env (TERM_PROGRAM for Claude Code)
    if (spec.name === 'Claude Code' && process.env['TERM_PROGRAM'] === 'claude') {
      detected = true;
      method = 'process';
      detail = 'TERM_PROGRAM=claude';
    }

    // Check env vars
    if (!detected) {
      for (const envVar of spec.envVars) {
        if (process.env[envVar]) {
          detected = true;
          method = 'env';
          detail = `${envVar} is set`;
          break;
        }
      }
    }

    // Check config directories
    for (const dir of spec.configDirs) {
      if (existsSync(dir)) {
        if (!detected) {
          detected = true;
          method = 'config';
          detail = `Config directory found: ${dir}`;
        }
        configPaths.push(dir);
      }
    }

    // Aider: also check for .aider* files in the target directory
    if (spec.name === 'Aider') {
      const aiderConfFiles = ['.aider.conf.yml', '.aider.model.settings.yml', '.aider.input.history'];
      for (const f of aiderConfFiles) {
        const p = join(targetDir, f);
        if (existsSync(p)) {
          if (!detected) {
            detected = true;
            method = 'config';
            detail = `Aider config found: ${f}`;
          }
          configPaths.push(p);
        }
      }
    }

    if (detected) {
      results.push({ name: spec.name, detected, method, detail, configPaths });
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// MCP server detection
// ---------------------------------------------------------------------------

/** Paths (relative to project and home) that may contain mcpServers config. */
function mcpConfigPaths(targetDir: string): { label: string; path: string }[] {
  return [
    { label: 'mcp.json', path: join(targetDir, 'mcp.json') },
    { label: '.mcp.json', path: join(targetDir, '.mcp.json') },
    { label: '.mcp/config.json', path: join(targetDir, '.mcp', 'config.json') },
    { label: '.claude/settings.json', path: join(targetDir, '.claude', 'settings.json') },
    { label: '.cursor/mcp.json', path: join(targetDir, '.cursor', 'mcp.json') },
    { label: '~/.claude/settings.json', path: join(homedir(), '.claude', 'settings.json') },
  ];
}

/** Redact values that look like environment variable references or secrets. */
function redactEnv(env: Record<string, unknown>): Record<string, string> {
  const redacted: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (typeof value === 'string' && value.length > 0) {
      redacted[key] = '[REDACTED]';
    } else {
      redacted[key] = String(value ?? '');
    }
  }
  return redacted;
}

function detectMcpServers(targetDir: string): DetectedMcpServer[] {
  const results: DetectedMcpServer[] = [];
  const seen = new Set<string>();

  for (const { label, path: cfgPath } of mcpConfigPaths(targetDir)) {
    const data = readJson(cfgPath);
    if (!data) continue;

    const servers = data['mcpServers'] as Record<string, unknown> | undefined;
    if (!servers || typeof servers !== 'object') continue;

    for (const [name, raw] of Object.entries(servers)) {
      // Deduplicate by server name per source file
      const dedupeKey = `${label}:${name}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      if (!raw || typeof raw !== 'object') continue;
      const entry = raw as Record<string, unknown>;

      const command = typeof entry['command'] === 'string' ? entry['command'] : '';
      const args = Array.isArray(entry['args'])
        ? (entry['args'] as unknown[]).map(a => String(a))
        : [];
      const env = entry['env'] && typeof entry['env'] === 'object'
        ? redactEnv(entry['env'] as Record<string, unknown>)
        : {};

      results.push({
        name,
        source: label,
        command,
        args,
        env,
        tools: [], // Tool enumeration requires MCP handshake; left empty during static scan
      });
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// OAuth session detection
// ---------------------------------------------------------------------------

interface OAuthSpec {
  provider: string;
  configDir: string;
  credentialFiles: string[];
}

function buildOAuthSpecs(detectedClis: DetectedCli[]): OAuthSpec[] {
  const specs: OAuthSpec[] = [];

  for (const cli of detectedClis) {
    if (!cli.configDir) continue;

    switch (cli.name) {
      case 'aws':
        specs.push({
          provider: 'aws',
          configDir: cli.configDir,
          credentialFiles: ['credentials', 'sso/cache'],
        });
        break;
      case 'az':
        specs.push({
          provider: 'azure',
          configDir: cli.configDir,
          credentialFiles: ['msal_token_cache.json', 'accessTokens.json'],
        });
        break;
      case 'gcloud':
        specs.push({
          provider: 'gcp',
          configDir: cli.configDir,
          credentialFiles: ['application_default_credentials.json', 'credentials.db'],
        });
        break;
      case 'gh':
        specs.push({
          provider: 'github',
          configDir: cli.configDir,
          credentialFiles: ['hosts.yml'],
        });
        break;
      case 'vercel':
        specs.push({
          provider: 'vercel',
          configDir: cli.configDir,
          credentialFiles: ['auth.json'],
        });
        break;
      case 'kubectl':
        specs.push({
          provider: 'kubernetes',
          configDir: cli.configDir,
          credentialFiles: ['config'],
        });
        break;
      case 'terraform':
        specs.push({
          provider: 'terraform',
          configDir: cli.configDir,
          credentialFiles: ['credentials.tfrc.json'],
        });
        break;
    }
  }

  return specs;
}

function detectOAuthSessions(detectedClis: DetectedCli[]): DetectedOAuthSession[] {
  const results: DetectedOAuthSession[] = [];
  const specs = buildOAuthSpecs(detectedClis);

  for (const spec of specs) {
    let hasActiveSession = false;
    let latestMtime: string | null = null;

    for (const credFile of spec.credentialFiles) {
      const fullPath = join(spec.configDir, credFile);
      if (!existsSync(fullPath)) continue;

      hasActiveSession = true;
      const mtime = fileMtime(fullPath);
      if (mtime && (!latestMtime || mtime > latestMtime)) {
        latestMtime = mtime;
      }
    }

    results.push({
      provider: spec.provider,
      configDir: spec.configDir,
      hasActiveSession,
      lastModified: latestMtime,
      scopes: [], // Scope extraction would require parsing provider-specific token formats
    });
  }

  return results;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scan the current developer workstation and project directory for
 * CLIs, AI assistants, MCP servers, and OAuth sessions.
 *
 * @param targetDir - Directory to scan for project-level artifacts.
 *                    Defaults to `process.cwd()`.
 */
export function detectEnvironment(targetDir?: string): EnvironmentScan {
  const dir = resolve(targetDir ?? process.cwd());

  // CLI detection
  const clis = detectClis();

  // Assistant detection
  const assistants = detectAssistants(dir);

  // MCP server detection
  const mcpServers = detectMcpServers(dir);

  // OAuth session detection (depends on detected CLIs)
  const oauthSessions = detectOAuthSessions(clis);

  // Project detection (reuse existing utility)
  const project = detectProject(dir);

  return {
    timestamp: new Date().toISOString(),
    hostname: hostname(),
    platform: platform(),
    shell: process.env['SHELL'] ?? 'unknown',
    clis,
    assistants,
    mcpServers,
    oauthSessions,
    projectType: project.type as ProjectType,
    projectName: project.name,
  };
}
