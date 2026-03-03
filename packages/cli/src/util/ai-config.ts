/**
 * AI-specific configuration scanning.
 *
 * Detects MCP misconfigurations, unprotected AI instruction files,
 * unsigned skill files, and prompt-injection patterns in soul files.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

// --- Types ---

export interface AiConfigFinding {
  findingId: string;
  label: string;
  status: 'warn' | 'info';
  detail: string;
  items?: string[];
}

// --- Constants ---

const MCP_CONFIG_FILES = ['mcp.json', '.mcp.json', '.claude/settings.json', '.cursor/mcp.json'];

const HIGH_RISK_SERVER_PATTERNS = [
  'filesystem', 'shell', 'bash', 'database', 'exec',
];

const CREDENTIAL_PREFIXES = ['sk-ant-', 'sk-', 'ghp_', 'AKIA', 'AIza'];

const AI_CONFIG_FILES: { path: string; isDir: boolean }[] = [
  { path: 'CLAUDE.md', isDir: false },
  { path: '.claude', isDir: true },
  { path: '.cursorrules', isDir: false },
  { path: '.windsurfrules', isDir: false },
  { path: '.clinerules', isDir: false },
  { path: 'soul.md', isDir: false },
  { path: 'SOUL.md', isDir: false },
  { path: '.copilot', isDir: true },
];

const AIDER_PATTERNS = ['.aider.conf.yml', '.aiderignore', '.aider.model.settings.yml'];

const INJECTION_PATTERNS = [
  'you are now',
  'ignore previous',
  'do not remind',
  'forget your',
  'new persona',
  'disregard',
  'override your',
];

// --- Scan functions ---

/**
 * Scan project-level MCP config files for high-risk servers and hardcoded credentials.
 */
export function scanMcpConfig(dir: string): AiConfigFinding[] {
  const findings: AiConfigFinding[] = [];

  for (const configFile of MCP_CONFIG_FILES) {
    const fullPath = path.join(dir, configFile);
    if (!fs.existsSync(fullPath)) continue;

    let parsed: Record<string, unknown>;
    try {
      const raw = fs.readFileSync(fullPath, 'utf-8');
      parsed = JSON.parse(raw);
    } catch {
      continue; // Malformed JSON -- skip silently
    }

    const servers = (parsed['mcpServers'] ?? parsed['mcp_servers'] ?? {}) as Record<string, unknown>;
    if (typeof servers !== 'object' || servers === null) continue;

    const riskyServers: string[] = [];
    const credServers: string[] = [];

    for (const [name, config] of Object.entries(servers)) {
      const cfg = config as Record<string, unknown> | undefined;
      if (!cfg || typeof cfg !== 'object') continue;

      // Check server name and command for high-risk patterns
      const command = String(cfg['command'] ?? '');
      const args = Array.isArray(cfg['args']) ? cfg['args'].map(String) : [];
      const nameAndCommand = `${name} ${command} ${args.join(' ')}`.toLowerCase();

      const isHighRisk = HIGH_RISK_SERVER_PATTERNS.some(p => nameAndCommand.includes(p))
        || args.some(a => a.includes('--no-sandbox'));

      if (isHighRisk) {
        riskyServers.push(name);
      }

      // Check env values for hardcoded credentials
      const env = cfg['env'] as Record<string, unknown> | undefined;
      if (env && typeof env === 'object') {
        for (const [, val] of Object.entries(env)) {
          const strVal = String(val ?? '');
          if (strVal.startsWith('$')) continue; // Environment variable reference -- safe
          const hasCredPrefix = CREDENTIAL_PREFIXES.some(prefix => strVal.startsWith(prefix));
          if (hasCredPrefix) {
            credServers.push(name);
            break;
          }
        }
      }
    }

    if (riskyServers.length > 0) {
      findings.push({
        findingId: 'MCP-TOOLS',
        label: 'MCP high-risk tools',
        status: 'warn',
        detail: `${riskyServers.length} server${riskyServers.length === 1 ? '' : 's'} with filesystem/shell access in ${configFile}`,
        items: riskyServers,
      });
    }

    if (credServers.length > 0) {
      findings.push({
        findingId: 'MCP-CRED',
        label: 'MCP credentials',
        status: 'warn',
        detail: `hardcoded credentials in ${configFile}`,
        items: credServers,
      });
    }
  }

  return findings;
}

/**
 * Check whether AI instruction files (CLAUDE.md, .cursorrules, etc.) are
 * excluded from git tracking. Only runs when .git/ exists.
 */
export function scanAiConfigFiles(dir: string): AiConfigFinding | null {
  const gitDir = path.join(dir, '.git');
  if (!fs.existsSync(gitDir)) return null;

  // Read .gitignore and .git/info/exclude for exclusion patterns
  const exclusionPatterns: string[] = [];
  const gitignorePath = path.join(dir, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    try {
      const content = fs.readFileSync(gitignorePath, 'utf-8');
      exclusionPatterns.push(...content.split('\n').map(l => l.trim()));
    } catch { /* ignore read errors */ }
  }
  const excludePath = path.join(dir, '.git', 'info', 'exclude');
  if (fs.existsSync(excludePath)) {
    try {
      const content = fs.readFileSync(excludePath, 'utf-8');
      exclusionPatterns.push(...content.split('\n').map(l => l.trim()));
    } catch { /* ignore read errors */ }
  }

  const tracked: string[] = [];

  for (const entry of AI_CONFIG_FILES) {
    const fullPath = path.join(dir, entry.path);
    const exists = fs.existsSync(fullPath);
    if (!exists) continue;

    // Simple exclusion check: does any pattern match the filename or directory?
    const isExcluded = exclusionPatterns.some(pattern => {
      if (!pattern || pattern.startsWith('#')) return false;
      const clean = pattern.replace(/^\//, '').replace(/\/$/, '');
      return clean === entry.path || entry.path.startsWith(clean + '/') || clean === entry.path + '/';
    });

    if (!isExcluded) {
      tracked.push(entry.path);
    }
  }

  // Check aider patterns (glob-like: .aider*)
  for (const pattern of AIDER_PATTERNS) {
    const fullPath = path.join(dir, pattern);
    if (!fs.existsSync(fullPath)) continue;
    const isExcluded = exclusionPatterns.some(p => {
      if (!p || p.startsWith('#')) return false;
      const clean = p.replace(/^\//, '').replace(/\/$/, '');
      // Match exact or .aider* glob
      return clean === pattern || clean === '.aider*';
    });
    if (!isExcluded) {
      tracked.push(pattern);
    }
  }

  if (tracked.length === 0) return null;

  return {
    findingId: 'AI-CONFIG',
    label: 'AI config exposure',
    status: 'warn',
    detail: `${tracked.length} AI config file${tracked.length === 1 ? '' : 's'} not excluded from git`,
    items: tracked,
  };
}

/**
 * Check for SKILL.md and *.skill.md files and whether they carry
 * an opena2a-guard signature block.
 */
export function scanSkillFiles(dir: string): AiConfigFinding | null {
  const skillFiles: string[] = [];

  // Check for SKILL.md
  const skillMd = path.join(dir, 'SKILL.md');
  if (fs.existsSync(skillMd)) skillFiles.push('SKILL.md');

  // Check for *.skill.md (non-recursive)
  try {
    const entries = fs.readdirSync(dir);
    for (const entry of entries) {
      if (entry.endsWith('.skill.md') && entry !== 'SKILL.md') {
        skillFiles.push(entry);
      }
    }
  } catch { /* ignore read errors */ }

  if (skillFiles.length === 0) return null;

  // Check if any have the guard signature
  let signedCount = 0;
  for (const file of skillFiles) {
    try {
      const content = fs.readFileSync(path.join(dir, file), 'utf-8');
      if (content.includes('<!-- opena2a-guard')) {
        signedCount++;
      }
    } catch { /* ignore read errors */ }
  }

  if (signedCount === skillFiles.length) {
    return {
      findingId: 'AI-SKILLS',
      label: 'Skill files',
      status: 'info',
      detail: `${skillFiles.length} skill file${skillFiles.length === 1 ? '' : 's'}, all signed`,
      items: skillFiles,
    };
  }

  const unsigned = skillFiles.length - signedCount;
  return {
    findingId: 'AI-SKILLS',
    label: 'Skill files',
    status: 'warn',
    detail: `${unsigned} unsigned skill file${unsigned === 1 ? '' : 's'}`,
    items: skillFiles,
  };
}

/**
 * Check soul.md / SOUL.md for existence and prompt-injection patterns.
 */
export function scanSoulFile(dir: string): AiConfigFinding | null {
  let soulPath: string | null = null;
  let soulName: string | null = null;

  for (const name of ['soul.md', 'SOUL.md']) {
    const full = path.join(dir, name);
    if (fs.existsSync(full)) {
      soulPath = full;
      soulName = name;
      break;
    }
  }

  if (!soulPath || !soulName) return null;

  let content: string;
  try {
    content = fs.readFileSync(soulPath, 'utf-8');
  } catch {
    return null;
  }

  const lower = content.toLowerCase();
  const matched = INJECTION_PATTERNS.filter(p => lower.includes(p));

  if (matched.length > 0) {
    return {
      findingId: 'AI-SOUL',
      label: 'Soul file',
      status: 'warn',
      detail: `${soulName} contains ${matched.length} override pattern${matched.length === 1 ? '' : 's'}`,
      items: matched,
    };
  }

  return {
    findingId: 'AI-SOUL',
    label: 'Soul file',
    status: 'info',
    detail: `${soulName} present, no override patterns detected`,
  };
}
