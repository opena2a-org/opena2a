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

import { wordWrap } from './format.js';

/** Every help screen fits a standard 80-column terminal. */
export const HELP_WIDTH = 80;

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
  // Own entries only: `identity constructor --help` is not a subcommand.
  const help = Object.prototype.hasOwnProperty.call(registry, sub) ? registry[sub] : undefined;
  if (!help) return false;

  const usage = help.usage ?? '';
  process.stdout.write(`Usage: opena2a ${parent} ${sub}${usage ? ' ' + usage : ''}\n\n`);
  process.stdout.write(`${wordWrap(help.summary, HELP_WIDTH, 0)}\n`);

  if (help.options && help.options.length > 0) {
    process.stdout.write(`\nOptions:\n`);
    const maxFlagWidth = Math.max(...help.options.map(o => o.flag.length));
    const descColumn = 2 + maxFlagWidth + 2;
    for (const o of help.options) {
      // Wrap with a hanging indent, then put the flag into the first line's
      // indent so continuation lines align under the description.
      const wrapped = wordWrap(o.description, HELP_WIDTH, descColumn);
      process.stdout.write(`  ${o.flag.padEnd(maxFlagWidth + 2)}${wrapped.slice(descColumn)}\n`);
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

/**
 * The words each parent's handler routes, aliases included, in the order of
 * its dispatch. __tests__/util/subcommand-help.test.ts reads them back from
 * the handlers' source, so a word a handler adds is listed here too.
 */
export const SUBCOMMAND_ROUTES: Readonly<Record<string, ReadonlyArray<string>>> = {
  guard: ['sign', 'verify', 'status', 'watch', 'diff', 'policy', 'hook', 'resign', 'snapshot', 'harden'],
  runtime: ['start', 'status', 'tail', 'init'],
  identity: [
    'list', 'show', 'init', 'create', 'trust', 'audit', 'log', 'policy', 'check', 'sign', 'verify',
    'integrate', 'attach', 'detach', 'sync', 'connect', 'disconnect', 'tag', 'mcp', 'activity',
    'suspend', 'reactivate', 'revoke',
  ],
  shield: [
    'init', 'status', 'log', 'selfcheck', 'check', 'policy', 'evaluate', 'recover', 'report',
    'session', 'baseline', 'suggest', 'explain', 'triage', 'monitor',
  ],
  admin: ['sensors', 'list-pending', 'pending', 'ls', 'approve', 'reject'],
  skill: ['create'],
  mcp: ['audit', 'sign', 'verify'],
};

/**
 * Answer a help request for `opena2a <parent> [sub]` without running
 * anything: the subcommand's own block when the registry has one, the
 * parent's help for any other word the handler routes, and for a word it
 * does not route the same answer the handler gives (unknown subcommand,
 * exit 1). Returns false when no help flag is present, so the caller goes
 * on to run the command.
 *
 * Intercepting only registered subcommands let `--help` fall through to the
 * handler for every other word it accepts: `opena2a identity revoke --ci
 * --help` revoked the agent on the AIM server instead of printing help.
 */
export function answerHelpRequest(
  parent: string,
  sub: string | undefined,
  registry: SubcommandHelpRegistry,
  parentHelp: () => string,
  args?: ReadonlyArray<string>,
): boolean {
  if (!isHelpRequest(args)) return false;
  if (sub && printSubcommandHelp(parent, sub, registry)) return true;
  // A typo such as `guard signs --help` must not read as a valid command.
  if (sub && !sub.startsWith('-') && !(SUBCOMMAND_ROUTES[parent] ?? []).includes(sub)) {
    process.stderr.write(`Unknown ${parent} subcommand: ${sub}\n\n`);
    process.stderr.write(parentHelp());
    process.exitCode = 1;
    return true;
  }
  process.stdout.write(parentHelp());
  return true;
}

// --- Registries per parent command ---

// Every example in these registries runs as shown: __tests__/help-examples.test.ts
// runs each one from the build and fails on the handler's usage-error path.

export const GUARD_HELP: SubcommandHelpRegistry = {
  sign: {
    summary: 'Sign config files for integrity verification. Git-ignored files are skipped: the store is committed with the repository.',
    usage: '[directory]',
    options: [
      { flag: '--files <files...>', description: 'Sign specific files, git-ignored ones included (defaults to scanning the directory)' },
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
    summary:
      'Watch the signed files and record a tamper event in the Shield event log when one changes or is deleted. Runs until Ctrl+C.',
    usage: '[directory]',
    examples: ['opena2a guard watch'],
  },
  diff: {
    summary: 'Show changes since last signing for each tracked file.',
    usage: '[directory]',
    examples: ['opena2a guard diff'],
  },
  policy: {
    summary:
      'Create the guard policy (init) or show it (show, the default). The policy lists the files that must be signed, whether verify fails on an unsigned one, and whether a tampered file disables the heartbeat.',
    usage: '[init|show]',
    examples: [
      'opena2a guard policy init',
      'opena2a guard policy show',
    ],
  },
  hook: {
    summary: 'Install, remove or check the git pre-commit hook that runs guard verify.',
    usage: '<install|uninstall|status>',
    examples: [
      'opena2a guard hook install',
      'opena2a guard hook status',
      'opena2a guard hook uninstall',
    ],
  },
  resign: {
    summary: 'Re-sign tracked files after intentional changes.',
    usage: '[directory]',
    options: [
      { flag: '--ci', description: 'Re-sign without confirmation (required when stdin is not a terminal or with --format json)' },
    ],
    examples: ['opena2a guard resign'],
  },
  snapshot: {
    summary:
      'Save the signature store as a snapshot (create), list the snapshots (list, the default) or restore one (restore <id>). A snapshot holds the recorded signatures, not the files.',
    usage: '[create|list|restore] [id]',
    examples: [
      'opena2a guard snapshot create',
      'opena2a guard snapshot list',
    ],
  },
  harden: {
    summary:
      "Check the SKILL.md and HEARTBEAT.md files against the scanner's skill and heartbeat checks. Findings are reported; --fix applies the fixable ones.",
    usage: '[directory]',
    options: [
      { flag: '--fix', description: 'Apply the fixable findings' },
      { flag: '--dry-run', description: 'Show what --fix would change, without writing' },
    ],
    examples: [
      'opena2a guard harden --dry-run',
      'opena2a guard harden --fix',
    ],
  },
};

export const SHIELD_HELP: SubcommandHelpRegistry = {
  init: {
    summary: 'Run the full 11-step Shield setup for a project: the directory named, or the current one.',
    usage: '[directory]',
    options: [
      { flag: '--dir <path>', description: 'Project directory (same as the positional)' },
      { flag: '--shell-hook', description: 'Install the shell preexec hook' },
      { flag: '--ai-tools', description: 'Configure AI tool settings' },
    ],
    examples: [
      'opena2a shield init',
      'opena2a shield init ./my-project',
      'opena2a shield init --shell-hook --ai-tools',
    ],
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
    summary: 'Show a summary of the loaded Shield policy: its mode and the rule counts per category.',
    examples: ['opena2a shield policy', 'opena2a shield policy --format json'],
  },
  evaluate: {
    summary: 'Check an action against the Shield policy and print the verdict. Exits 1 when the policy blocks it.',
    options: [
      { flag: '--action <action>', description: 'Action to check, e.g. process.spawn or network.connect' },
      { flag: '--target <target>', description: 'What the action acts on: a binary, host or path' },
      { flag: '--agent <name>', description: 'Agent whose policy overrides apply' },
    ],
    examples: [
      'opena2a shield evaluate --action process.spawn --target /usr/bin/curl',
    ],
  },
  recover: {
    summary: 'Recover from Shield lockdown, or retire a broken event log.',
    options: [
      { flag: '--verify', description: 'Run integrity checks before lifting lockdown' },
      {
        flag: '--archive-log',
        description: 'Archive a broken event log and start a fresh chain (works outside lockdown)',
      },
    ],
    examples: ['opena2a shield recover --verify', 'opena2a shield recover --archive-log'],
  },
  report: {
    summary: 'Print a security posture report over the recent Shield events, or write it as HTML with --report.',
    options: [
      { flag: '--report <path>', description: 'Write the report as HTML to this file' },
      { flag: '--since <timespec>', description: 'Period to cover: 7d (default), 1w, 1m, ISO 8601' },
      { flag: '--analyze', description: 'Add a summary written by an LLM backend' },
    ],
    examples: ['opena2a shield report', 'opena2a shield report --report ./out.html'],
  },
  session: {
    summary: 'Show which AI coding assistant, if any, drives the current terminal session, and its session ID.',
    examples: ['opena2a shield session'],
  },
  baseline: {
    summary: 'Show the adaptive enforcement baselines Shield has recorded per agent.',
    options: [
      { flag: '--agent <name>', description: 'Show the baseline of this agent only' },
    ],
    examples: ['opena2a shield baseline'],
  },
  suggest: {
    summary: 'Suggest policy changes from the recorded events, using an LLM backend.',
    options: [
      { flag: '--agent <name>', description: 'Agent whose events to use (default: the agent of the latest event)' },
    ],
    examples: ['opena2a shield suggest'],
  },
  explain: {
    summary: 'Explain the newest Shield events that match the filters.',
    options: [
      { flag: '--count <n>', description: 'Number of newest events to explain (default 1; 0 for all)' },
      { flag: '--severity <level>', description: 'Only events of exactly this severity' },
      { flag: '--agent <name>', description: 'Only events from this agent' },
    ],
    examples: [
      'opena2a shield explain',
      'opena2a shield explain --count 5 --severity high',
    ],
  },
  triage: {
    summary: 'Triage open security events into actionable groups.',
    options: [
      { flag: '--severity <level>', description: 'Lowest severity to triage (default high: high and critical)' },
      { flag: '--count <n>', description: 'Number of newest matching events to triage (default 10)' },
      { flag: '--agent <name>', description: 'Only events from this agent' },
    ],
    examples: ['opena2a shield triage', 'opena2a shield triage --severity medium'],
  },
  monitor: {
    summary: 'Import ARP runtime events into the Shield event log and summarize runtime protection.',
    options: [
      { flag: '--dir <path>', description: 'Project directory whose ARP events are imported' },
      { flag: '--since <timespec>', description: 'Period summarized (default 7d)' },
    ],
    examples: ['opena2a shield monitor', 'opena2a shield monitor --format json'],
  },
};

export const IDENTITY_HELP: SubcommandHelpRegistry = {
  list: {
    summary: 'Show the local agent identity.',
    examples: ['opena2a identity list', 'opena2a identity list --format json'],
  },
  init: {
    summary: 'Create a named local agent identity (an Ed25519 key pair). Same as create.',
    usage: '<name>',
    options: [
      { flag: '--name <name>', description: 'Identity name, instead of the positional' },
    ],
    examples: ['opena2a identity init production-agent'],
  },
  create: {
    summary:
      'Create a named local agent identity (an Ed25519 key pair). With --server, or when you are logged in, it is also registered on the AIM server.',
    usage: '<name>',
    options: [
      { flag: '--name <name>', description: 'Identity name, instead of the positional' },
      { flag: '--server <url>', description: 'AIM server URL (e.g. localhost:8080, cloud)' },
      { flag: '--api-key <key>', description: 'AIM API key for that server' },
    ],
    examples: [
      'opena2a identity create production-agent',
      'opena2a identity create --name production-agent',
    ],
  },
  trust: {
    summary:
      "Show the trust score of the local agent identity with its factor breakdown, and the AIM server's trust data when the identity is registered there.",
    examples: ['opena2a identity trust', 'opena2a identity trust --format json'],
  },
  audit: {
    summary: 'Show recent audit events of the local agent identity.',
    options: [
      { flag: '--limit <n>', description: 'Number of events to show (default: 10)' },
    ],
    examples: ['opena2a identity audit', 'opena2a identity audit --limit 50'],
  },
  log: {
    summary: 'Record an audit event for the local agent identity.',
    options: [
      { flag: '--action <action>', description: 'What the agent did, e.g. db:read (required)' },
      { flag: '--target <target>', description: 'What it acted on, e.g. customers' },
      { flag: '--result <result>', description: 'allowed (default), denied or error' },
      { flag: '--plugin <plugin>', description: 'Plugin that performed the action' },
    ],
    examples: ['opena2a identity log --action db:read --target customers --result allowed'],
  },
  policy: {
    summary:
      "Show the local capability policy. --file loads a YAML policy instead, and --server lists the AIM server's security policies.",
    options: [
      { flag: '--file <path>', description: 'YAML capability policy to load' },
      { flag: '--server <url>', description: 'AIM server whose policies to list' },
    ],
    examples: ['opena2a identity policy', 'opena2a identity policy --format json'],
  },
  check: {
    summary:
      'Check whether the local capability policy allows a capability. Exits 0 when it is allowed and 1 when it is denied; with --json it exits 0 and the JSON carries the result.',
    usage: '<capability>',
    options: [
      { flag: '--plugin <plugin>', description: 'Plugin asking for the capability' },
    ],
    examples: ['opena2a identity check db:read', 'opena2a identity check db:read --plugin reporter'],
  },
  sign: {
    summary: 'Sign a string or a file with the private key of the local agent identity.',
    options: [
      { flag: '--data <data>', description: 'String to sign' },
      { flag: '--file <path>', description: 'File to sign' },
    ],
    examples: ['opena2a identity sign --data hello', 'opena2a identity sign --file package.json'],
  },
  verify: {
    summary: 'Verify a signature over a string against the signer\'s public key.',
    options: [
      { flag: '--data <data>', description: 'The signed string' },
      { flag: '--signature <sig>', description: 'Base64 signature' },
      { flag: '--public-key <key>', description: 'Base64 public key of the signer' },
    ],
    examples: ['opena2a identity verify --data hello --signature <sig> --public-key <key>'],
  },
  integrate: {
    summary:
      'Wire security tools to the local agent identity, so their events feed its audit log and trust score. Without --tools or --all, every tool is enabled the first time and the saved selection is kept after that.',
    options: [
      { flag: '--tools <list>', description: 'Comma-separated: secretless, configguard, arp, hma, shield' },
      { flag: '--all', description: 'Enable every tool' },
      { flag: '--auto-sync', description: 'Sync tool events whenever the trust score is calculated' },
      { flag: '--dir <path>', description: 'Project directory (default: current directory)' },
    ],
    examples: ['opena2a identity integrate', 'opena2a identity integrate --tools shield,hma'],
  },
  detach: {
    summary: 'Remove the tool wiring that integrate added. The local identity is kept.',
    options: [
      { flag: '--dir <path>', description: 'Project directory (default: current directory)' },
    ],
    examples: ['opena2a identity detach'],
  },
  sync: {
    summary:
      'Import new events from the integrated tools into the audit log of the local agent identity and refresh its trust score. Run integrate first.',
    options: [
      { flag: '--dir <path>', description: 'Project directory (default: current directory)' },
    ],
    examples: ['opena2a identity sync'],
  },
  connect: {
    summary: 'Register the local agent identity on an AIM server and keep the connection.',
    usage: '<url>',
    options: [
      { flag: '--api-key <key>', description: 'AIM API key for the server (required)' },
    ],
    examples: ['opena2a identity connect localhost:8080 --api-key <key>'],
  },
  disconnect: {
    summary: 'Remove the stored AIM server connection. The local identity is kept.',
    examples: ['opena2a identity disconnect'],
  },
  tag: {
    summary:
      "List the organization's tags, or add or remove a tag on the agent connected to the AIM server. Log in first with opena2a login.",
    usage: '<list|add|remove> [name]',
    examples: ['opena2a identity tag list', 'opena2a identity tag add production'],
  },
  mcp: {
    summary:
      'List, add or remove the MCP servers of the agent connected to the AIM server; attach discovers and adds all of them. Log in first with opena2a login.',
    usage: '<list|add|remove|attach> [id]',
    examples: ['opena2a identity mcp list', 'opena2a identity mcp attach'],
  },
  activity: {
    summary: 'Show recent activity events of the agent connected to the AIM server. Log in first with opena2a login.',
    options: [
      { flag: '--limit <n>', description: 'Number of events to show (default: 10)' },
    ],
    examples: ['opena2a identity activity', 'opena2a identity activity --limit 50'],
  },
  suspend: {
    summary:
      'Suspend the agent connected to the AIM server; it stops all operations until reactivated. Log in first with opena2a login.',
    examples: ['opena2a identity suspend'],
  },
  reactivate: {
    summary: 'Reactivate the suspended or revoked agent connected to the AIM server. Log in first with opena2a login.',
    examples: ['opena2a identity reactivate'],
  },
  revoke: {
    summary:
      'Revoke the agent connected to the AIM server; reactivate restores it. Without --ci or --json it only prints a warning and exits 1. Log in first with opena2a login.',
    examples: ['opena2a identity revoke'],
  },
};

export const RUNTIME_HELP: SubcommandHelpRegistry = {
  start: {
    summary:
      'Start ARP monitoring for the project with its arp.yaml, arp.yml or arp.json (runtime init writes one). Runs until Ctrl+C.',
    usage: '[directory]',
    options: [
      { flag: '--config <path>', description: 'ARP config file to use instead' },
    ],
    examples: ['opena2a runtime start'],
  },
  status: {
    summary: 'Show runtime monitor status.',
    usage: '[directory]',
    examples: ['opena2a runtime status', 'opena2a runtime status --format json'],
  },
  tail: {
    summary: 'Show the last runtime events recorded in .opena2a/arp/events.jsonl.',
    usage: '[directory]',
    options: [
      { flag: '--count <n>', description: 'Number of events to show (default: 20)' },
    ],
    examples: ['opena2a runtime tail', 'opena2a runtime tail --count 50'],
  },
  init: {
    summary: 'Write an arp.yaml for the project, generated from its detected type.',
    usage: '[directory]',
    options: [
      { flag: '--force', description: 'Overwrite an existing arp.yaml' },
    ],
    examples: ['opena2a runtime init', 'opena2a runtime init --force'],
  },
};

export const SKILL_HELP: SubcommandHelpRegistry = {
  create: {
    summary: 'Create a new secure skill (frontmatter + hash pin + heartbeat).',
    usage: '[name]',
    options: [
      { flag: '--template <name>', description: 'Template: basic, mcp-tool, data-processor (default: basic)' },
      { flag: '--output <dir>', description: 'Output directory (default: ./<name>)' },
      { flag: '--no-sign', description: 'Skip the opena2a-guard hash pin on skill files' },
      { flag: '--force', description: 'Replace the scaffold files in an existing, non-empty directory' },
    ],
    examples: [
      'opena2a skill create my-skill',
      'opena2a skill create reporter --template mcp-tool',
    ],
  },
};

export const MCP_HELP: SubcommandHelpRegistry = {
  audit: {
    summary:
      'List the MCP servers configured in your home directory and in the project, with their signature status and Registry trust score.',
    options: [
      { flag: '--dir <path>', description: 'Project directory (default: current directory)' },
    ],
    examples: ['opena2a mcp audit', 'opena2a mcp audit --format json'],
  },
  sign: {
    summary:
      'Create a signed identity for a configured MCP server, recording a hash of its command or URL in .opena2a/mcp-identities.',
    usage: '[server]',
    options: [
      { flag: '--server <name>', description: 'Server name (same as the positional)' },
    ],
    examples: ['opena2a mcp sign my-server', 'opena2a mcp sign --server my-server'],
  },
  verify: {
    summary:
      "Check that a signed MCP server's configuration still matches its identity, and show its Registry trust score.",
    usage: '[server]',
    options: [
      { flag: '--server <name>', description: 'Server name (same as the positional)' },
    ],
    examples: ['opena2a mcp verify my-server'],
  },
};
