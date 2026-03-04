/**
 * Shield: Policy loading, evaluation, and default generation.
 *
 * Loads YAML-formatted policies (stored as JSON with .yaml extension),
 * evaluates actions against allow/deny rules, and generates default
 * policies from environment scans.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, statSync } from 'node:fs';
import { join, dirname, resolve, normalize } from 'node:path';
import { homedir } from 'node:os';

import type {
  ShieldPolicy,
  PolicyRules,
  PolicyDecision,
  PolicyMode,
  EnvironmentScan,
} from './types.js';

import {
  SHIELD_DIR,
  SHIELD_POLICY_FILE,
  SHIELD_POLICY_CACHE,
} from './types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Return the path to the user-level shield directory. */
function getShieldDir(): string {
  return join(homedir(), '.opena2a', 'shield');
}

/** Expand leading ~/ to the user home directory. */
function expandHomedir(pattern: string): string {
  if (pattern.startsWith('~/')) {
    return join(homedir(), pattern.slice(2));
  }
  return pattern;
}

// ---------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------

/**
 * Glob-like pattern matching.
 *
 * Supports:
 *   - `*` matches any sequence of characters
 *   - Exact string match
 *   - Path prefix matching: pattern ending with `/` matches anything under
 *     that path (e.g. `~/.ssh/` matches `~/.ssh/id_rsa`)
 */
export function matchesPattern(value: string, pattern: string): boolean {
  // Universal wildcard
  if (pattern === '*') {
    return true;
  }

  // Path prefix matching: pattern ending with '/' matches anything under it
  if (pattern.endsWith('/')) {
    const prefix = pattern;
    return value === pattern.slice(0, -1) || value.startsWith(prefix);
  }

  // Glob with wildcards
  if (pattern.includes('*')) {
    const parts = pattern.split('*');
    if (parts.length === 2) {
      const [prefix, suffix] = parts;
      return value.startsWith(prefix) && value.endsWith(suffix);
    }
    // Multi-wildcard: convert to regex
    const escaped = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*');
    return new RegExp(`^${escaped}$`).test(value);
  }

  // Exact match
  return value === pattern;
}

// ---------------------------------------------------------------------------
// Default rules
// ---------------------------------------------------------------------------

/** Return sensible default policy rules for a developer workstation. */
export function getDefaultPolicyRules(): PolicyRules {
  return {
    processes: {
      deny: ['aws', 'gcloud', 'az', 'kubectl', 'terraform', 'rm -rf'],
      allow: [
        'git', 'npm', 'node', 'npx', 'tsc', 'eslint', 'prettier',
        'cargo', 'go', 'python', 'pip', 'pytest', 'bun', 'deno',
      ],
    },
    credentials: {
      deny: ['~/.ssh/*', '~/.aws/*', '~/.config/gcloud/*', '~/.azure/*'],
      allow: [],
    },
    network: {
      deny: [],
      allow: ['localhost', '127.0.0.1', 'registry.npmjs.org', 'github.com'],
    },
    filesystem: {
      deny: ['~/.ssh/', '~/.gnupg/'],
      allow: [],
    },
    mcpServers: {
      deny: [],
      allow: [],
    },
    supplyChain: {
      requireTrustScore: 0,
      blockAdvisories: false,
    },
  };
}

// ---------------------------------------------------------------------------
// Policy creation
// ---------------------------------------------------------------------------

/** Create a default policy with standard rules and no agent-specific overrides. */
export function createDefaultPolicy(mode: PolicyMode = 'adaptive'): ShieldPolicy {
  return {
    version: 1,
    mode,
    default: getDefaultPolicyRules(),
    agents: {},
  };
}

// ---------------------------------------------------------------------------
// Policy generation from environment scan
// ---------------------------------------------------------------------------

/** Map project types to additional tools that should be in the allow list. */
const PROJECT_TYPE_TOOLS: Record<string, string[]> = {
  node: ['node', 'npm', 'npx', 'tsc', 'eslint', 'prettier'],
  go: ['go', 'golangci-lint', 'gopls'],
  python: ['python', 'pip', 'pytest', 'ruff', 'mypy'],
};

/**
 * Generate a policy tailored to the scanned environment.
 * Detected CLIs are added to the process deny list. Detected MCP servers
 * are added to the mcpServers allow list. Project-type-appropriate tools
 * are added to the process allow list. Mode is set to 'adaptive'.
 */
export function generatePolicyFromScan(scan: EnvironmentScan): ShieldPolicy {
  const policy = createDefaultPolicy('adaptive');

  // Add detected cloud CLIs to processes.deny
  for (const cli of scan.clis) {
    if (!policy.default.processes.deny.includes(cli.name)) {
      policy.default.processes.deny.push(cli.name);
    }
  }

  // Add detected CLI config dirs to filesystem.deny
  for (const cli of scan.clis) {
    if (cli.configDir && !policy.default.filesystem.deny.includes(cli.configDir)) {
      policy.default.filesystem.deny.push(cli.configDir);
    }
  }

  // Add project-appropriate dev tools to processes.allow based on projectType
  const tools = PROJECT_TYPE_TOOLS[scan.projectType];
  if (tools) {
    for (const tool of tools) {
      if (!policy.default.processes.allow.includes(tool)) {
        policy.default.processes.allow.push(tool);
      }
    }
  }

  // Add detected MCP server names to mcpServers.allow
  for (const server of scan.mcpServers) {
    if (!policy.default.mcpServers.allow.includes(server.name)) {
      policy.default.mcpServers.allow.push(server.name);
    }
  }

  return policy;
}

// ---------------------------------------------------------------------------
// Policy persistence
// ---------------------------------------------------------------------------

/**
 * Load a shield policy from disk.
 *
 * Checks the user-level policy file at `~/.opena2a/shield/policy.yaml`.
 * The file is stored as JSON despite the .yaml extension (simplest approach
 * since we control the format).
 *
 * Returns null if no policy file exists or it cannot be parsed.
 */
export function loadPolicy(targetDir?: string): ShieldPolicy | null {
  // Try project-level first if a target directory is provided
  if (targetDir) {
    const projectPolicyPath = join(targetDir, SHIELD_DIR, SHIELD_POLICY_FILE);
    try {
      if (existsSync(projectPolicyPath)) {
        const raw = readFileSync(projectPolicyPath, 'utf-8');
        return JSON.parse(raw) as ShieldPolicy;
      }
    } catch {
      // Fall through to user-level
    }
  }

  // Try user-level
  const userPolicyPath = join(homedir(), SHIELD_DIR, SHIELD_POLICY_FILE);
  try {
    if (existsSync(userPolicyPath)) {
      const raw = readFileSync(userPolicyPath, 'utf-8');
      return JSON.parse(raw) as ShieldPolicy;
    }
  } catch {
    return null;
  }

  return null;
}

/**
 * Write a policy to disk as JSON with restrictive permissions (0o600).
 * Creates parent directories if they do not exist.
 */
export function savePolicy(policy: ShieldPolicy, path: string): void {
  const dir = dirname(path);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(path, JSON.stringify(policy, null, 2) + '\n', { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// Policy cache
// ---------------------------------------------------------------------------

/** Return the path to the policy cache file. */
function getPolicyCachePath(): string {
  return join(getShieldDir(), SHIELD_POLICY_CACHE);
}

/** Return the path to the user-level policy file. */
function getUserPolicyPath(): string {
  return join(getShieldDir(), SHIELD_POLICY_FILE);
}

/**
 * Load the cached policy. Returns null if the cache does not exist or
 * if the policy file has been modified more recently than the cache.
 */
export function loadPolicyCache(): ShieldPolicy | null {
  const cachePath = getPolicyCachePath();
  if (!existsSync(cachePath)) {
    return null;
  }

  // Invalidate cache if the policy file is newer
  const policyPath = getUserPolicyPath();
  if (existsSync(policyPath)) {
    try {
      const cacheStat = statSync(cachePath);
      const policyStat = statSync(policyPath);
      if (policyStat.mtimeMs > cacheStat.mtimeMs) {
        return null;
      }
    } catch {
      return null;
    }
  }

  try {
    const raw = readFileSync(cachePath, 'utf-8');
    return JSON.parse(raw) as ShieldPolicy;
  } catch {
    return null;
  }
}

/** Save a policy to the cache file with restrictive permissions. */
export function savePolicyCache(policy: ShieldPolicy): void {
  const cachePath = getPolicyCachePath();
  const dir = dirname(cachePath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(cachePath, JSON.stringify(policy, null, 2) + '\n', { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// Policy evaluation
// ---------------------------------------------------------------------------

/**
 * Map action strings (used by callers like shield evaluate) to policy
 * rule category keys. This allows callers to pass either an action string
 * like 'process.spawn' or a direct category name like 'processes'.
 */
const ACTION_CATEGORY_MAP: Record<string, keyof PolicyRules> = {
  'process.spawn': 'processes',
  'credential.read': 'credentials',
  'file.access': 'filesystem',
  'network.connect': 'network',
  'mcp.call': 'mcpServers',
};

/** Valid category keys that can be used directly. */
const VALID_CATEGORIES = new Set<string>([
  'processes', 'credentials', 'network', 'filesystem', 'mcpServers',
]);

/**
 * Merge agent-specific rule overrides onto a base set of rules.
 * Agent-specific rules completely replace the base for any category they define.
 */
function mergeRules(base: PolicyRules, overrides: Partial<PolicyRules>): PolicyRules {
  const merged: PolicyRules = JSON.parse(JSON.stringify(base));

  for (const key of ['credentials', 'processes', 'network', 'filesystem', 'mcpServers'] as const) {
    const override = overrides[key];
    if (override && 'allow' in override && 'deny' in override) {
      merged[key] = {
        allow: [...override.allow],
        deny: [...override.deny],
      };
    }
  }

  if (overrides.supplyChain) {
    merged.supplyChain = { ...merged.supplyChain, ...overrides.supplyChain };
  }

  return merged;
}

/**
 * Evaluate an action against the policy.
 *
 * Resolution order:
 *   1. Agent-specific rules are merged over default rules if the agent
 *      has overrides defined.
 *   2. Deny rules are checked first -- deny takes precedence over allow.
 *   3. In adaptive/monitor mode, denied actions are logged but not blocked
 *      (outcome='monitored'). In enforce mode, they are blocked
 *      (outcome='blocked').
 *   4. If no rule matches, the action is implicitly allowed.
 *
 * @param policy  - The loaded shield policy.
 * @param agent   - Agent identifier (or null for unknown agents).
 * @param category - The action or category string (e.g. 'process.spawn' or 'processes').
 * @param target  - The target of the action (e.g. binary name, file path, hostname).
 */
export function evaluatePolicy(
  policy: ShieldPolicy,
  agent: string | null,
  category: string,
  target: string,
): PolicyDecision {
  // Resolve effective rules: agent-specific merged over defaults
  let effectiveRules = policy.default;
  if (agent && policy.agents[agent]) {
    effectiveRules = mergeRules(policy.default, policy.agents[agent]);
  }

  // Resolve category: support both action strings and direct category names
  let resolvedCategory: string | undefined = ACTION_CATEGORY_MAP[category];
  if (!resolvedCategory && VALID_CATEGORIES.has(category)) {
    resolvedCategory = category;
  }

  if (!resolvedCategory) {
    return {
      allowed: true,
      outcome: 'allowed',
      rule: `no-policy-for-action:${category}`,
      agent,
    };
  }

  const rules = effectiveRules[resolvedCategory as keyof PolicyRules];

  // supplyChain does not have allow/deny arrays
  if (!rules || !('allow' in rules) || !('deny' in rules)) {
    return {
      allowed: true,
      outcome: 'allowed',
      rule: `${resolvedCategory}:no-allow-deny-rules`,
      agent,
    };
  }

  const { allow, deny } = rules as { allow: string[]; deny: string[] };

  // For credentials and filesystem categories, expand ~ in patterns and
  // canonicalize the target path to prevent traversal attacks (e.g. ../../.ssh/id_rsa)
  const isPathCategory = resolvedCategory === 'filesystem' || resolvedCategory === 'credentials';
  const expandPattern = isPathCategory ? expandHomedir : (p: string) => p;
  const canonicalTarget = isPathCategory ? normalize(resolve(target)) : target;

  // Check deny first (deny takes precedence)
  for (const pattern of deny) {
    const expanded = expandPattern(pattern);
    if (matchesPattern(canonicalTarget, expanded)) {
      if (policy.mode === 'enforce') {
        return {
          allowed: false,
          outcome: 'blocked',
          rule: `${resolvedCategory}.deny:${pattern}`,
          agent,
        };
      }
      // adaptive or monitor mode: allow but mark as monitored
      return {
        allowed: true,
        outcome: 'monitored',
        rule: `${resolvedCategory}.deny:${pattern}`,
        agent,
      };
    }
  }

  // Check allow
  for (const pattern of allow) {
    const expanded = expandPattern(pattern);
    if (matchesPattern(canonicalTarget, expanded)) {
      return {
        allowed: true,
        outcome: 'allowed',
        rule: `${resolvedCategory}.allow:${pattern}`,
        agent,
      };
    }
  }

  // No explicit match: implicitly allowed
  return {
    allowed: true,
    outcome: 'allowed',
    rule: `${resolvedCategory}:no-match`,
    agent,
  };
}
