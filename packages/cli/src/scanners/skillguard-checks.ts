/**
 * Extended SkillGuard checks (SKILL-020 through SKILL-024).
 *
 * These complement the base SkillGuard plugin in hackmyagent (SKILL-001 through
 * SKILL-019), adding checks for frontmatter validation, overprivileged permissions,
 * env exfiltration, obfuscated code, and unbounded tool chaining.
 *
 * IDs start at 020 to avoid collision with HMA's existing SKILL checks:
 *   HMA SKILL-001 = Unsigned Skill
 *   HMA SKILL-003 = Heartbeat Installation
 *   HMA SKILL-007 = ClickFix Social Engineering
 *   HMA SKILL-009 = Typosquatting Name
 *   HMA SKILL-010 = Env File Exfiltration
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

// --- Types ---

export interface SkillFinding {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  filePath: string;
  autoFixable: boolean;
}

export interface ParsedFrontmatter {
  raw: string;
  fields: Record<string, unknown>;
  valid: boolean;
  body: string;
}

// --- Constants ---

const MAX_SCAN_DEPTH = 5;

const REQUIRED_FRONTMATTER_FIELDS = ['name', 'version', 'capabilities'];

const DANGEROUS_CAPABILITY_COMBOS: Array<{
  combo: [string, string];
  reason: string;
}> = [
  {
    combo: ['filesystem:*', 'network:outbound'],
    reason: 'filesystem:* + network:outbound enables data exfiltration',
  },
  {
    combo: ['credential:read', 'network:outbound'],
    reason: 'credential:read + network:outbound enables credential exfiltration',
  },
];

const ENV_ACCESS_PATTERNS = [
  /process\.env/,
  /os\.environ/,
  /\$ENV\{/,
  /System\.getenv/,
];

const OUTBOUND_PATTERNS = [
  /network:outbound/,
  /fetch\s*\(/,
  /https?:\/\//,
  /XMLHttpRequest/,
  /\.send\s*\(/,
  /curl\s/,
  /wget\s/,
];

const OBFUSCATION_PATTERNS = [
  { pattern: /atob\s*\(/, label: 'atob() base64 decode' },
  { pattern: /Buffer\.from\s*\(/, label: 'Buffer.from() decode' },
  { pattern: /eval\s*\(/, label: 'eval() dynamic execution' },
  { pattern: /String\.fromCharCode/, label: 'String.fromCharCode obfuscation' },
  { pattern: /\\x[0-9a-fA-F]{2}/, label: 'hex-encoded string' },
  { pattern: /(?:atob|Buffer\.from)\s*\([^)]+\)[\s\S]*?eval\s*\(/, label: 'base64+eval combo' },
];

// --- File discovery ---

export function findSkillFiles(dir: string, depth = 0): string[] {
  if (depth > MAX_SCAN_DEPTH) return [];
  const results: string[] = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...findSkillFiles(fullPath, depth + 1));
      } else if (entry.name === 'SKILL.md' || entry.name.endsWith('.skill.md')) {
        results.push(fullPath);
      }
    }
  } catch {
    // Not readable
  }
  return results;
}

// --- Frontmatter parsing ---

export function parseFrontmatter(content: string): ParsedFrontmatter {
  const fmMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!fmMatch) {
    return { raw: '', fields: {}, valid: false, body: content };
  }

  const raw = fmMatch[1];
  const body = content.slice(fmMatch[0].length).trim();
  const fields: Record<string, unknown> = {};

  // Simple YAML key-value parser (handles top-level scalars and arrays)
  const lines = raw.split('\n');
  let currentKey = '';
  let currentArray: string[] | null = null;

  for (const line of lines) {
    const trimmed = line.trimEnd();
    // Array item
    if (trimmed.match(/^\s+-\s+/) && currentKey) {
      const value = trimmed.replace(/^\s+-\s+/, '').replace(/^["']|["']$/g, '');
      if (currentArray) {
        currentArray.push(value);
      }
      continue;
    }

    // Save previous array
    if (currentArray && currentKey) {
      fields[currentKey] = currentArray;
      currentArray = null;
    }

    // Key-value pair
    const kvMatch = trimmed.match(/^([a-zA-Z_][a-zA-Z0-9_-]*):\s*(.*)/);
    if (kvMatch) {
      currentKey = kvMatch[1];
      const value = kvMatch[2].trim();
      if (value === '' || value === '[]') {
        currentArray = [];
        fields[currentKey] = [];
      } else if (value === '{}') {
        fields[currentKey] = {};
      } else {
        fields[currentKey] = value.replace(/^["']|["']$/g, '');
        currentArray = null;
      }
    }
  }

  // Save last array
  if (currentArray && currentKey) {
    fields[currentKey] = currentArray;
  }

  return { raw, fields, valid: true, body };
}

// --- Check implementations ---

/** SKILL-020: Missing/invalid frontmatter */
function checkFrontmatter(filePath: string, content: string, relativePath: string): SkillFinding[] {
  const findings: SkillFinding[] = [];
  const fm = parseFrontmatter(content);

  if (!fm.valid) {
    findings.push({
      id: 'SKILL-020',
      title: 'Missing YAML frontmatter',
      description: `${relativePath}: Skill file lacks required YAML frontmatter (---). Add frontmatter with name, version, and capabilities fields.`,
      severity: 'high',
      filePath: relativePath,
      autoFixable: true,
    });
    return findings;
  }

  const missing = REQUIRED_FRONTMATTER_FIELDS.filter(f => !(f in fm.fields));
  if (missing.length > 0) {
    findings.push({
      id: 'SKILL-020',
      title: 'Incomplete frontmatter',
      description: `${relativePath}: Missing required frontmatter fields: ${missing.join(', ')}. These are needed for capability declaration and version tracking.`,
      severity: 'high',
      filePath: relativePath,
      autoFixable: true,
    });
  }

  return findings;
}

/** SKILL-021: Overprivileged permissions (dangerous combos) */
function checkOverprivileged(filePath: string, content: string, relativePath: string): SkillFinding[] {
  const findings: SkillFinding[] = [];
  const fm = parseFrontmatter(content);

  // Check capabilities from frontmatter and body for dangerous combos
  const capabilities = extractCapabilities(fm, content);

  for (const { combo, reason } of DANGEROUS_CAPABILITY_COMBOS) {
    const hasFirst = capabilities.some(c => matchCapability(c, combo[0]));
    const hasSecond = capabilities.some(c => matchCapability(c, combo[1]));

    if (hasFirst && hasSecond) {
      findings.push({
        id: 'SKILL-021',
        title: 'Overprivileged permissions',
        description: `${relativePath}: ${reason}. Restrict filesystem access to specific paths or remove outbound network access.`,
        severity: 'high',
        filePath: relativePath,
        autoFixable: false,
      });
    }
  }

  return findings;
}

/** SKILL-022: Environment variable exfiltration */
function checkEnvExfiltration(filePath: string, content: string, relativePath: string): SkillFinding[] {
  const findings: SkillFinding[] = [];

  const hasEnvAccess = ENV_ACCESS_PATTERNS.some(p => p.test(content));
  const hasOutbound = OUTBOUND_PATTERNS.some(p => p.test(content));

  if (hasEnvAccess && hasOutbound) {
    findings.push({
      id: 'SKILL-022',
      title: 'Environment variable exfiltration risk',
      description: `${relativePath}: Skill accesses environment variables AND has outbound network capability. This combination can exfiltrate secrets via network requests.`,
      severity: 'critical',
      filePath: relativePath,
      autoFixable: false,
    });
  }

  return findings;
}

/** SKILL-023: Obfuscated code patterns */
function checkObfuscation(filePath: string, content: string, relativePath: string): SkillFinding[] {
  const findings: SkillFinding[] = [];

  for (const { pattern, label } of OBFUSCATION_PATTERNS) {
    if (pattern.test(content)) {
      findings.push({
        id: 'SKILL-023',
        title: 'Obfuscated code pattern',
        description: `${relativePath}: Detected ${label}. Obfuscated code in skills can hide malicious behavior and should be reviewed.`,
        severity: 'high',
        filePath: relativePath,
        autoFixable: false,
      });
      break; // One finding per file for obfuscation
    }
  }

  return findings;
}

/** SKILL-024: Unbounded tool chaining */
function checkUnboundedChaining(filePath: string, content: string, relativePath: string): SkillFinding[] {
  const findings: SkillFinding[] = [];
  const fm = parseFrontmatter(content);
  const capabilities = extractCapabilities(fm, content);

  const hasToolChain = capabilities.some(c => c.includes('tool:chain'));
  if (!hasToolChain) return findings;

  // Check for iteration limits in frontmatter
  const hasMaxIterations = fm.valid && (
    'maxIterations' in fm.fields ||
    'iterationLimit' in fm.fields ||
    fm.raw.includes('maxIterations') ||
    fm.raw.includes('iterationLimit')
  );

  if (!hasMaxIterations) {
    findings.push({
      id: 'SKILL-024',
      title: 'Unbounded tool chaining',
      description: `${relativePath}: Skill declares tool:chain capability without maxIterations or iterationLimit. Unbounded chaining can lead to infinite loops or resource exhaustion.`,
      severity: 'medium',
      filePath: relativePath,
      autoFixable: true,
    });
  }

  return findings;
}

// --- Helpers ---

function extractCapabilities(fm: ParsedFrontmatter, content: string): string[] {
  const caps: string[] = [];

  // From frontmatter capabilities array
  if (fm.valid && Array.isArray(fm.fields.capabilities)) {
    caps.push(...(fm.fields.capabilities as string[]));
  }

  // Also scan body for capability-like patterns (e.g., inline references)
  const capMatches = content.match(/(?:filesystem|network|credential|tool):[a-z*]+/g);
  if (capMatches) {
    for (const m of capMatches) {
      if (!caps.includes(m)) caps.push(m);
    }
  }

  return caps;
}

function matchCapability(actual: string, pattern: string): boolean {
  if (actual === pattern) return true;
  // filesystem:* matches filesystem:read, filesystem:write, etc.
  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1); // e.g., "filesystem:"
    return actual.startsWith(prefix);
  }
  // actual = filesystem:* should match pattern = filesystem:read (wildcard on actual side)
  if (actual.endsWith(':*')) {
    const prefix = actual.slice(0, -1);
    return pattern.startsWith(prefix);
  }
  return false;
}

// --- Public API ---

/**
 * Run all extended skill checks on a single file.
 */
export function scanSkillFile(filePath: string, agentDir: string): SkillFinding[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  const relativePath = path.relative(agentDir, filePath);
  const findings: SkillFinding[] = [];

  findings.push(...checkFrontmatter(filePath, content, relativePath));
  findings.push(...checkOverprivileged(filePath, content, relativePath));
  findings.push(...checkEnvExfiltration(filePath, content, relativePath));
  findings.push(...checkObfuscation(filePath, content, relativePath));
  findings.push(...checkUnboundedChaining(filePath, content, relativePath));

  return findings;
}

/**
 * Run all extended skill checks on a directory.
 */
export function scanSkillDirectory(agentDir: string): SkillFinding[] {
  const skillFiles = findSkillFiles(agentDir);
  const findings: SkillFinding[] = [];

  for (const file of skillFiles) {
    findings.push(...scanSkillFile(file, agentDir));
  }

  return findings;
}

/**
 * IDs of all checks implemented in this module.
 */
export const EXTENDED_SKILL_CHECK_IDS = [
  'SKILL-020',
  'SKILL-021',
  'SKILL-022',
  'SKILL-023',
  'SKILL-024',
] as const;
