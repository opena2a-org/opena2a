/**
 * Per-subcommand --help support for opena2a subtree commands
 * (guard, shield, identity, runtime, skill, mcp).
 *
 * Each parent registers as a single Commander command with manual
 * subcommand routing, so Commander's auto-help only knows about the
 * parent. Without intercept, `opena2a guard sign --help` prints the
 * `guard` parent help instead of `sign`-specific help — CISO Rule 7
 * (discoverability) violation flagged in #132.
 *
 * Each parent's action calls `printSubcommandHelp(parent, sub)` after
 * detecting `--help` / `-h` in the incoming args.
 */

export interface SubcommandHelp {
  /** One-line summary printed on the Usage line. */
  summary: string;
  /** Optional usage string after `opena2a <parent> <sub>`. */
  usage?: string;
  /** Option flag descriptions. */
  options?: Array<{ flag: string; description: string }>;
  /** Concrete invocations users can copy/paste. */
  examples?: string[];
}

export type SubcommandHelpRegistry = Record<string, SubcommandHelp>;

/**
 * Print per-subcommand --help text. Returns true if a subcommand-specific
 * block was printed; false if `sub` is unknown (caller should fall back
 * to parent help).
 */
export function printSubcommandHelp(
  parent: string,
  sub: string,
  registry: SubcommandHelpRegistry,
): boolean {
  const help = registry[sub];
  if (!help) return false;

  const usage = help.usage ?? '';
  process.stdout.write(`Usage: opena2a ${parent} ${sub}${usage ? ' ' + usage : ''}\n\n`);
  process.stdout.write(`${help.summary}\n`);

  if (help.options && help.options.length > 0) {
    process.stdout.write(`\nOptions:\n`);
    const maxFlagWidth = Math.max(...help.options.map(o => o.flag.length));
    for (const o of help.options) {
      process.stdout.write(`  ${o.flag.padEnd(maxFlagWidth + 2)}${o.description}\n`);
    }
  }

  if (help.examples && help.examples.length > 0) {
    process.stdout.write(`\nExamples:\n`);
    for (const ex of help.examples) {
      process.stdout.write(`  ${ex}\n`);
    }
  }
  return true;
}

/**
 * Detect a help request. Treats `--help` / `-h` anywhere in the raw
 * `process.argv` as a help request, mirroring Commander's behavior.
 *
 * Uses argv directly because subtree commands have varied arg shapes
 * ([args...] vs [directory] vs [name]) and `--help` may not surface in
 * the action's parameters under `allowUnknownOption(true)`.
 */
export function isHelpRequest(args?: ReadonlyArray<string>): boolean {
  const source = args ?? process.argv.slice(2);
  for (const a of source) {
    if (a === '--help' || a === '-h') return true;
  }
  return false;
}

// --- Registries per parent command ---

export const GUARD_HELP: SubcommandHelpRegistry = {
  sign: {
    summary: 'Sign config files for integrity verification.',
    usage: '[directory]',
    options: [
      { flag: '--files <files...>', description: 'Sign specific files (defaults to scanning the directory)' },
      { flag: '--skills', description: 'Include SKILL.md files in the signing set' },
      { flag: '--heartbeats', description: 'Include HEARTBEAT.md files in the signing set' },
    ],
    examples: [
      'opena2a guard sign',
      'opena2a guard sign --files package.json tsconfig.json',
      'opena2a guard sign --skills',
    ],
  },
  verify: {
    summary: 'Verify signed config files have not been tampered with.',
    usage: '[directory]',
    options: [
      { flag: '--enforce', description: 'Exit with code 3 on any tampered file (quarantine mode)' },
    ],
    examples: [
      'opena2a guard verify',
      'opena2a guard verify --enforce',
    ],
  },
  status: {
    summary: 'Show current guard status (signed / unsigned / tampered file counts).',
    usage: '[directory]',
    examples: [
      'opena2a guard status',
      'opena2a guard status --format json',
    ],
  },
  watch: {
    summary: 'Watch for config file changes and emit tamper events on the shield event log.',
    usage: '[directory]',
    examples: ['opena2a guard watch'],
  },
  diff: {
    summary: 'Show changes since last signing for each tracked file.',
    usage: '[directory]',
    examples: ['opena2a guard diff'],
  },
  policy: {
    summary: 'Manage guard policies (which files to track, severity, etc.).',
    usage: '[action]',
    examples: [
      'opena2a guard policy show',
      'opena2a guard policy set strict',
    ],
  },
  hook: {
    summary: 'Install / manage git hooks (pre-commit verification).',
    usage: '[action]',
    examples: [
      'opena2a guard hook install',
      'opena2a guard hook uninstall',
    ],
  },
  resign: {
    summary: 'Re-sign tracked files after intentional changes.',
    usage: '[directory]',
    examples: ['opena2a guard resign'],
  },
  snapshot: {
    summary: 'Take a config snapshot for later diff / rollback.',
    usage: '[action]',
    examples: [
      'opena2a guard snapshot take',
      'opena2a guard snapshot list',
    ],
  },
  harden: {
    summary: 'Auto-fix config security issues (file permissions, missing signatures, etc.).',
    usage: '[directory]',
    options: [
      { flag: '--fix', description: 'Apply fixes (default is dry-run)' },
      { flag: '--dry-run', description: 'Preview fixes without applying' },
    ],
    examples: [
      'opena2a guard harden --dry-run',
      'opena2a guard harden --fix',
    ],
  },
};

export const SHIELD_HELP: SubcommandHelpRegistry = {
  init: {
    summary: 'Run the full 11-step Shield setup for the current project.',
    options: [
      { flag: '--shell-hook', description: 'Install the shell preexec hook' },
      { flag: '--ai-tools', description: 'Configure AI tool settings' },
    ],
    examples: ['opena2a shield init', 'opena2a shield init --shell-hook --ai-tools'],
  },
  status: {
    summary: 'Show current Shield protection status (sessions, policies, integrity).',
    examples: ['opena2a shield status', 'opena2a shield status --format json'],
  },
  log: {
    summary: 'Query the Shield security event log.',
    options: [
      { flag: '--count <n>', description: 'Number of events to return' },
      { flag: '--since <timespec>', description: 'Time filter: 7d, 1w, 1m, ISO 8601' },
      { flag: '--severity <level>', description: 'Severity filter: low, medium, high, critical' },
      { flag: '--source <source>', description: 'Source filter (agent, system, etc.)' },
      { flag: '--category <cat>', description: 'Category filter (auth, integrity, policy, etc.)' },
      { flag: '--agent <name>', description: 'Filter by agent name' },
    ],
    examples: [
      'opena2a shield log --since 24h',
      'opena2a shield log --severity high --count 50',
    ],
  },
  selfcheck: {
    summary: 'Verify Shield integrity (binary signatures, policy hashes, event-log chain).',
    examples: ['opena2a shield selfcheck'],
  },
  policy: {
    summary: 'View or update Shield policies.',
    usage: '[action]',
    examples: ['opena2a shield policy show', 'opena2a shield policy set strict'],
  },
  evaluate: {
    summary: 'Evaluate the current project against active Shield policies.',
    examples: ['opena2a shield evaluate'],
  },
  recover: {
    summary: 'Recover from Shield lockdown (after a tamper event).',
    options: [
      { flag: '--verify', description: 'Verify before recovering' },
      { flag: '--reset', description: 'Force exit lockdown without verification' },
      { flag: '--forensic', description: 'Forensic mode (read-only, no changes)' },
    ],
    examples: ['opena2a shield recover --verify'],
  },
  report: {
    summary: 'Write an HTML security posture report.',
    options: [
      { flag: '--report <path>', description: 'Output path (default: shield-report.html)' },
    ],
    examples: ['opena2a shield report --report ./out.html'],
  },
  session: {
    summary: 'Show or manage the current local Ed25519 session identity.',
    examples: ['opena2a shield session'],
  },
  baseline: {
    summary: 'Establish a baseline for future drift detection.',
    examples: ['opena2a shield baseline'],
  },
  suggest: {
    summary: 'Suggest policy / configuration changes based on observed events.',
    options: [
      { flag: '--analyze', description: 'Enable LLM analysis of the event corpus' },
    ],
    examples: ['opena2a shield suggest --analyze'],
  },
  explain: {
    summary: 'Explain a Shield event, finding, or policy decision.',
    examples: ['opena2a shield explain <event-id>'],
  },
  triage: {
    summary: 'Triage open security events into actionable groups.',
    examples: ['opena2a shield triage'],
  },
};

export const IDENTITY_HELP: SubcommandHelpRegistry = {
  list: {
    summary: 'List all known agent identities.',
    examples: ['opena2a identity list', 'opena2a identity list --format json'],
  },
  init: {
    summary: 'Initialize a new local agent identity (generates an Ed25519 keypair).',
    examples: ['opena2a identity init'],
  },
  create: {
    summary: 'Create a new named agent identity.',
    options: [
      { flag: '--name <name>', description: 'Identity name' },
    ],
    examples: ['opena2a identity create --name production-agent'],
  },
  trust: {
    summary: 'Manage trust relationships between agent identities.',
    usage: '[action]',
    examples: ['opena2a identity trust add <agent>', 'opena2a identity trust list'],
  },
  audit: {
    summary: 'Audit identity events and trust changes.',
    examples: ['opena2a identity audit'],
  },
  log: {
    summary: 'Show the identity event log.',
    options: [
      { flag: '--limit <n>', description: 'Maximum events to return' },
    ],
    examples: ['opena2a identity log --limit 100'],
  },
  policy: {
    summary: 'Manage identity policies.',
    examples: ['opena2a identity policy show'],
  },
  check: {
    summary: 'Check identity status against active policies.',
    examples: ['opena2a identity check'],
  },
  sign: {
    summary: 'Sign an artifact with the current identity.',
    examples: ['opena2a identity sign <file>'],
  },
  verify: {
    summary: 'Verify an artifact signature against a known identity.',
    examples: ['opena2a identity verify <file>'],
  },
  integrate: {
    summary: 'Integrate the current identity with an external system.',
    examples: ['opena2a identity integrate'],
  },
  detach: {
    summary: 'Detach the current identity from an external integration.',
    examples: ['opena2a identity detach'],
  },
  sync: {
    summary: 'Sync identity state with the Registry.',
    examples: ['opena2a identity sync'],
  },
  connect: {
    summary: 'Connect to a remote agent identity.',
    examples: ['opena2a identity connect <agent>'],
  },
  disconnect: {
    summary: 'Disconnect from a remote agent identity.',
    examples: ['opena2a identity disconnect <agent>'],
  },
  tag: {
    summary: 'Tag an identity with arbitrary labels.',
    examples: ['opena2a identity tag <agent> <label>'],
  },
  mcp: {
    summary: 'Show or manage MCP server identities.',
    examples: ['opena2a identity mcp'],
  },
  activity: {
    summary: 'Show recent identity activity.',
    examples: ['opena2a identity activity'],
  },
  suspend: {
    summary: 'Suspend an agent identity (revoke trust temporarily).',
    examples: ['opena2a identity suspend <agent>'],
  },
  reactivate: {
    summary: 'Reactivate a suspended agent identity.',
    examples: ['opena2a identity reactivate <agent>'],
  },
};

export const RUNTIME_HELP: SubcommandHelpRegistry = {
  start: {
    summary: 'Start the runtime monitor for the current project.',
    usage: '[directory]',
    examples: ['opena2a runtime start'],
  },
  status: {
    summary: 'Show runtime monitor status.',
    usage: '[directory]',
    examples: ['opena2a runtime status', 'opena2a runtime status --format json'],
  },
  tail: {
    summary: 'Tail the runtime event stream.',
    usage: '[directory]',
    examples: ['opena2a runtime tail'],
  },
  init: {
    summary: 'Initialize runtime configuration for a project.',
    usage: '[directory]',
    examples: ['opena2a runtime init'],
  },
};

export const SKILL_HELP: SubcommandHelpRegistry = {
  create: {
    summary: 'Create a new secure skill (frontmatter + signing + heartbeat).',
    usage: '[name]',
    options: [
      { flag: '--template <name>', description: 'Template: basic, mcp-tool, data-processor (default: basic)' },
      { flag: '--output <dir>', description: 'Output directory (default: current)' },
      { flag: '--no-sign', description: 'Skip auto-signing of skill files' },
    ],
    examples: [
      'opena2a skill create my-skill',
      'opena2a skill create my-skill --template mcp-tool',
    ],
  },
};

export const MCP_HELP: SubcommandHelpRegistry = {
  audit: {
    summary: 'Audit MCP server configurations for security issues.',
    usage: '[server]',
    options: [
      { flag: '--dir <path>', description: 'Target directory' },
    ],
    examples: ['opena2a mcp audit', 'opena2a mcp audit my-server'],
  },
  sign: {
    summary: 'Sign an MCP server configuration for integrity verification.',
    usage: '[server]',
    examples: ['opena2a mcp sign my-server'],
  },
  verify: {
    summary: 'Verify a signed MCP server configuration.',
    usage: '[server]',
    examples: ['opena2a mcp verify my-server'],
  },
};
