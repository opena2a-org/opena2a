import { spawn } from 'node:child_process';
import { createAdapter } from './adapters/index.js';
import type { AdapterConfig, RunOptions } from './adapters/types.js';
import { protect } from './commands/protect.js';
import { isContributeEnabled, getRegistryUrl, submitScanReport, normalizeGovernanceReport, recordScanAndMaybePrompt } from './util/report-submission.js';
import { checkMinHmaVersion } from './util/hma-version.js';

export type InputType = 'subcommand' | 'search' | 'context' | 'natural' | 'guided';

export interface ClassifiedInput {
  type: InputType;
  /** The raw input after the operator (e.g., query after ~) */
  value: string;
  /** Remaining args */
  args: string[];
}

/**
 * Three-tier input classifier:
 * 1. ~ prefix  -> semantic search
 * 2. ? prefix  -> contextual advisor
 * 3. "quoted"  -> natural language
 * 4. known cmd -> subcommand dispatch
 * 5. no args   -> guided interactive mode
 */
export function classifyInput(argv: string[]): ClassifiedInput {
  if (argv.length === 0) {
    return { type: 'guided', value: '', args: [] };
  }

  const first = argv[0];

  // ~ semantic search operator
  if (first.startsWith('~')) {
    const query = first.slice(1) + (argv.length > 1 ? ' ' + argv.slice(1).join(' ') : '');
    return { type: 'search', value: query.trim(), args: [] };
  }

  // ? contextual operator
  if (first.startsWith('?') || first === '?') {
    const query = first.slice(1) + (argv.length > 1 ? ' ' + argv.slice(1).join(' ') : '');
    return { type: 'context', value: query.trim(), args: [] };
  }

  // Quoted natural language (Commander strips quotes, so check for multi-word non-command)
  if (first.startsWith('"') || first.startsWith("'")) {
    const joined = argv.join(' ');
    const unquoted = joined.replace(/^["']|["']$/g, '');
    return { type: 'natural', value: unquoted, args: [] };
  }

  // Known subcommand
  const KNOWN_COMMANDS = [
    'init', 'check', 'protect', 'status', 'publish',
    'scan', 'runtime', 'benchmark', 'crypto', 'secrets',
    'identity', 'registry', 'train',
    'guard', 'broker', 'config', 'self-register',
    'verify', 'baselines', 'review',
    'scan-soul', 'harden-soul', 'harden-skill', 'detect', 'mcp', 'demo',
    'trust', 'claim',
  ];

  if (KNOWN_COMMANDS.includes(first)) {
    return { type: 'subcommand', value: first, args: argv.slice(1) };
  }

  // Unknown single word -- try natural language
  if (argv.length > 1) {
    return { type: 'natural', value: argv.join(' '), args: [] };
  }

  // Single unknown word -- suggest search
  return { type: 'search', value: first, args: [] };
}

/**
 * Dispatch a classified subcommand to the appropriate adapter.
 */
export async function dispatchCommand(
  command: string,
  args: string[],
  globalOptions: Partial<RunOptions> = {}
): Promise<number> {
  // Handle 'protect' directly (not adapter-based — it orchestrates HMA + Secretless)
  if (command === 'protect') {
    const targetDir = args[0] ?? process.cwd();
    return protect({
      targetDir,
      dryRun: args.includes('--dry-run'),
      verbose: globalOptions.verbose ?? false,
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as 'text' | 'json') ?? 'text',
      skipVerify: args.includes('--skip-verify'),
    });
  }

  // 'init' is registered directly in Commander (index.ts).
  // Only dispatch here when called from guided wizard / natural language,
  // which bypass Commander parsing.
  if (command === 'init') {
    const { init } = await import('./commands/init.js');
    return init({
      targetDir: args[0] ?? process.cwd(),
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as 'text' | 'json') ?? 'text',
      verbose: globalOptions.verbose ?? false,
    });
  }

  // Handle 'guard' directly (ConfigGuard)
  if (command === 'guard') {
    const { guard } = await import('./commands/guard.js');
    const subcommand = args[0] ?? 'status';
    const remainingArgs = args.slice(1);
    // Subcommands that take an action argument (not a directory) as their first positional arg
    const actionSubcommands = ['hook', 'policy', 'snapshot'];
    const isActionSub = actionSubcommands.includes(subcommand);
    // Extract directory from first remaining arg only if it's not an action subcommand
    const dirFromArgs = !isActionSub && remainingArgs.length > 0 && !remainingArgs[0]?.startsWith('-')
      ? remainingArgs.shift()
      : undefined;
    return guard({
      subcommand: subcommand as 'sign' | 'verify' | 'status' | 'policy',
      targetDir: dirFromArgs ?? process.cwd(),
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as 'text' | 'json') ?? 'text',
      verbose: globalOptions.verbose ?? false,
      args: remainingArgs,
    });
  }

  // Handle 'identity' directly (aim-core native)
  if (command === 'identity') {
    const { identity } = await import('./commands/identity.js');
    const subcommand = args[0] ?? 'list';
    const nameIdx = args.indexOf('--name');
    const limitIdx = args.indexOf('--limit');
    return identity({
      subcommand,
      name: nameIdx >= 0 ? args[nameIdx + 1] : undefined,
      limit: limitIdx >= 0 ? parseInt(args[limitIdx + 1], 10) : undefined,
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as string) ?? 'text',
      verbose: globalOptions.verbose ?? false,
    });
  }

  // Handle 'runtime' directly (ARP wrapper)
  if (command === 'runtime') {
    const { runtime } = await import('./commands/runtime.js');
    const subcommand = args[0] ?? 'status';
    // Extract directory from second arg if it looks like a path
    const dirFromArgs = args[1] && !args[1].startsWith('-') ? args[1] : undefined;
    return runtime({
      subcommand: subcommand as 'start' | 'status' | 'tail' | 'init',
      targetDir: dirFromArgs ?? process.cwd(),
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as 'text' | 'json') ?? 'text',
      verbose: globalOptions.verbose ?? false,
    });
  }

  // Handle 'scan-soul' directly (SoulScanner programmatic API)
  if (command === 'scan-soul') {
    const { scanSoul } = await import('./commands/soul.js');
    return scanSoul({
      targetDir: args[0] && !args[0].startsWith('-') ? args[0] : process.cwd(),
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as string) ?? 'text',
      verbose: globalOptions.verbose ?? false,
      strict: args.includes('--strict'),
      deep: globalOptions.deep ?? false,
    });
  }

  // Handle 'harden-soul' directly (SoulScanner programmatic API)
  if (command === 'harden-soul') {
    const { hardenSoul } = await import('./commands/soul.js');
    return hardenSoul({
      targetDir: args[0] && !args[0].startsWith('-') ? args[0] : process.cwd(),
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as string) ?? 'text',
      verbose: globalOptions.verbose ?? false,
      dryRun: args.includes('--dry-run'),
    });
  }

  // Handle 'harden-skill' directly (skill hardening)
  if (command === 'harden-skill') {
    const { hardenSkill } = await import('./commands/harden-skill.js');
    return hardenSkill({
      file: args[0] && !args[0].startsWith('-') ? args[0] : undefined,
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as string) ?? 'text',
      verbose: globalOptions.verbose ?? false,
      dryRun: args.includes('--dry-run'),
    });
  }

  // Handle 'benchmark' directly (OASB benchmark programmatic API)
  if (command === 'benchmark') {
    const { benchmark: runBenchmark } = await import('./commands/benchmark.js');
    const levelIdx = args.indexOf('--level');
    return runBenchmark({
      targetDir: args[0] && !args[0].startsWith('-') ? args[0] : process.cwd(),
      level: levelIdx >= 0 ? args[levelIdx + 1] : 'L1',
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as string) ?? 'text',
      verbose: globalOptions.verbose ?? false,
    });
  }

  // Handle 'detect' directly (shadow AI agent audit)
  if (command === 'detect') {
    const { detect } = await import('./commands/detect.js');
    return detect({
      targetDir: args[0] && !args[0].startsWith('-') ? args[0] : process.cwd(),
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as string) ?? 'text',
      verbose: globalOptions.verbose ?? false,
      registry: args.includes('--registry'),
      autoScan: args.includes('--auto-scan'),
    });
  }

  // Handle 'demo' directly
  if (command === 'demo') {
    const { demo } = await import('./commands/demo.js');
    return demo({
      scenario: args[0] && !args[0].startsWith('-') ? args[0] : 'aim',
      interactive: args.includes('--interactive'),
      keep: args.includes('--keep'),
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as string) ?? 'text',
      verbose: globalOptions.verbose ?? false,
    });
  }

  // Handle 'status' directly (not adapter-based)
  if (command === 'status') {
    const { status: runStatus } = await import('./commands/status.js');
    return runStatus({
      targetDir: args[0] && !args[0].startsWith('-') ? args[0] : process.cwd(),
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as string) ?? 'text',
      verbose: globalOptions.verbose ?? false,
    });
  }

  // Handle 'mcp' directly (MCP server identity management)
  if (command === 'mcp') {
    const { mcpCommand } = await import('./commands/mcp-audit.js');
    const subcommand = args[0] ?? 'audit';
    const server = args[1] && !args[1].startsWith('-') ? args[1] : undefined;
    return mcpCommand({
      subcommand,
      server,
      targetDir: process.cwd(),
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as string) ?? 'text',
      verbose: globalOptions.verbose ?? false,
    });
  }

  // Handle 'trust' directly (ATP trust lookup)
  if (command === 'trust') {
    const { trust: runTrust } = await import('./commands/trust.js');
    const packageName = args[0] && !args[0].startsWith('-') ? args[0] : undefined;
    const sourceIdx = args.indexOf('--source');
    return runTrust({
      packageName,
      source: sourceIdx >= 0 ? args[sourceIdx + 1] : undefined,
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as 'text' | 'json') ?? 'text',
      verbose: globalOptions.verbose ?? false,
    });
  }

  // Handle 'claim' directly (ATP claim flow)
  if (command === 'claim') {
    const { claim: runClaim } = await import('./commands/claim.js');
    const packageName = args[0] && !args[0].startsWith('-') ? args[0] : undefined;
    const sourceIdx = args.indexOf('--source');
    return runClaim({
      packageName,
      source: sourceIdx >= 0 ? args[sourceIdx + 1] : undefined,
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as 'text' | 'json') ?? 'text',
      verbose: globalOptions.verbose ?? false,
    });
  }

  // check + npm package name → delegate to hackmyagent check
  if (command === 'check' && args.length > 0) {
    const target = args[0];
    if (target && !target.startsWith('-')) {
      // Rich-block prefix (skill: / mcp:) — names commonly contain
      // slashes (opena2a/code-review-skill, @modelcontextprotocol/...).
      // The isNpmTarget gate's slash-rejection would block these, so
      // recognize the prefix explicitly and pass through to HMA which
      // owns the rich-block dispatch in src/check/.
      // Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§3, §8)
      if (isRichTarget(target)) {
        return spawnHmaCheckFromRouter(target, args.slice(1), globalOptions);
      }
      if (isNpmTarget(target)) {
        return spawnHmaCheckFromRouter(target, args.slice(1), globalOptions);
      }
      // Unrecognized target format -- show helpful error
      process.stderr.write(`Unknown target: ${target}\n`);
      process.stderr.write(`Accepted formats:\n`);
      process.stderr.write(`  opena2a check express                  npm package\n`);
      process.stderr.write(`  opena2a check @scope/pkg               scoped npm package\n`);
      process.stderr.write(`  opena2a check skill:<name>             registered skill (rich block)\n`);
      process.stderr.write(`  opena2a check mcp:<name>               registered MCP server (rich block)\n`);
      process.stderr.write(`  opena2a check pip:requests             PyPI package\n`);
      process.stderr.write(`  opena2a check owner/repo               GitHub repository\n`);
      process.stderr.write(`  opena2a check ./path                   local directory\n`);
      return 1;
    }
  }

  // Intent commands map to adapters
  const INTENT_MAP: Record<string, { adapter: string; defaultArgs: string[] }> = {
    check: { adapter: 'scan', defaultArgs: [] },
    publish: { adapter: 'registry', defaultArgs: [] },
  };

  const intent = INTENT_MAP[command];
  const adapterName = intent?.adapter ?? command;
  let adapterArgs = intent ? [...intent.defaultArgs, ...args] : args;

  const adapter = createAdapter(adapterName);
  if (!adapter) {
    process.stderr.write(`Unknown command: ${command}\n`);
    process.stderr.write(`Run 'opena2a --help' for available commands.\n`);
    return 1;
  }

  // Prepend subcommand if the adapter config specifies one (e.g. broker, dlp).
  // Strip it from user args if they typed it explicitly (e.g. "scan secure ."
  // should not produce "secure secure .").
  if (adapter.config.subcommand) {
    if (adapterArgs[0] === adapter.config.subcommand) {
      adapterArgs = [adapter.config.subcommand, ...adapterArgs.slice(1)];
    } else {
      adapterArgs = [adapter.config.subcommand, ...adapterArgs];
    }
  }

  const available = await adapter.isAvailable();
  if (!available) {
    process.stderr.write(`${adapter.config.name} is not installed.\n`);
    const installHint = getInstallHint(adapter.config);
    process.stderr.write(`Install: ${installHint}\n`);
    return 1;
  }

  // Inject global flags into adapter args so downstream tools receive them
  if (globalOptions.format && globalOptions.format !== 'text' && !adapterArgs.includes('--format') && !adapterArgs.includes('--json')) {
    adapterArgs.push('--format', globalOptions.format);
  }
  if (globalOptions.deep && !adapterArgs.includes('--deep')) {
    adapterArgs.push('--deep');
  }
  if (globalOptions.analm && !adapterArgs.includes('--analm')) {
    adapterArgs.push('--analm');
  }
  if (globalOptions.staticOnly && !adapterArgs.includes('--static-only')) {
    adapterArgs.push('--static-only');
  }

  const result = await adapter.run({
    args: adapterArgs,
    ...globalOptions,
    cwd: globalOptions.cwd ?? process.cwd(),
  });

  // Track scan count and prompt to contribute after enough scans.
  // This runs on EVERY scan so the prompt can fire when threshold is reached.
  try {
    await recordScanAndMaybePrompt();
  } catch {
    // Non-critical -- never block on contribution failures
  }

  // Community contribution: submit scan reports when contribute is enabled.
  // This is best-effort and non-blocking -- failures are silently ignored.
  if (globalOptions.contribute || await isContributeEnabled()) {
    try {
      const registryUrl = await getRegistryUrl();
      // Parse stdout for scan report JSON (adapters that produce scan results)
      if (result.stdout && (adapterName === 'scan' || adapterName === 'benchmark' || adapterName === 'scan-soul')) {
        try {
          const report = JSON.parse(result.stdout);
          // Governance scans (scan-soul) need normalization to ScanReport format
          const normalized = normalizeGovernanceReport(report);
          if (normalized) {
            await submitScanReport(registryUrl, normalized, globalOptions.verbose);
          } else if (report.overallScore !== undefined || report.findings) {
            await submitScanReport(registryUrl, report, globalOptions.verbose);
          }
        } catch {
          // stdout wasn't valid scan report JSON -- that's fine
        }
      }
    } catch {
      // Non-critical -- never block on contribution failures
    }
  }

  return result.exitCode;
}

function getInstallHint(config: AdapterConfig): string {
  switch (config.method) {
    case 'docker':
      return `docker pull ${config.image ?? config.name}`;
    case 'python':
      return `pip install ${config.pythonModule ?? config.name}`;
    case 'spawn':
      return `npm install -g ${config.command ?? config.name}`;
    case 'import':
    default:
      return `npm install -g ${config.packageName ?? config.name}`;
  }
}

/**
 * Detect a rich-block dispatch target — `skill:<name>` or `mcp:<name>`.
 * HMA's parseRichTarget owns the actual parse; the router only needs
 * to know "this is a rich-target, hand it to HMA without npm-name
 * validation" because rich-target names commonly contain slashes
 * (opena2a/code-review-skill, @modelcontextprotocol/server-filesystem)
 * that the npm gate rejects.
 */
export function isRichTarget(target: string): boolean {
  if (target.startsWith('skill:') && target.length > 'skill:'.length) return true;
  if (target.startsWith('mcp:') && target.length > 'mcp:'.length) return true;
  return false;
}

/**
 * Detect whether a target looks like an npm package name (matches HMA logic).
 */
function isNpmTarget(target: string): boolean {
  if (target.startsWith('@') && target.includes('/')) return true;
  if (target.startsWith('.') || target.startsWith('/') || target.startsWith('~')) return false;
  if (target.includes('.')) return false;
  if (target.includes('/') || target.includes('\\')) return false;
  return true;
}

/**
 * Spawn hackmyagent check from the router path.
 */
function spawnHmaCheckFromRouter(
  packageName: string,
  extraArgs: string[],
  globalOptions: Record<string, unknown>,
): Promise<number> {
  checkMinHmaVersion();
  return new Promise<number>((resolve) => {
    const args = ['check', packageName, ...extraArgs];

    if (globalOptions.format === 'json' && !args.includes('--json') && !args.includes('--format')) {
      args.push('--json');
    }
    if (globalOptions.verbose && !args.includes('--verbose')) {
      args.push('--verbose');
    }
    if (globalOptions.ci && !args.includes('--ci')) {
      args.push('--ci');
    }

    // Environment contract with hackmyagent >= 0.16.6:
    //   HMA_CLI_PREFIX     — binary-level prefix (used for messages that append
    //                        a verb, e.g. "${prefix} rollback <dir>"). Set to
    //                        "opena2a" so any such message reads naturally for
    //                        opena2a users. Messages referring to verbs opena2a
    //                        does not expose (e.g. "opena2a secure") are not
    //                        reached via the check-delegation path and so do
    //                        not surface to users.
    //   HMA_CHECK_COMMAND  — full command string for "run a single-target
    //                        check" hints. Avoids the duplicated-verb bug that
    //                        results from using HMA_CLI_PREFIX="opena2a check".
    //   HMA_FULL_SCAN_HINT — full command string shown in place of HMA's
    //                        default "hackmyagent secure <dir>" recommendation,
    //                        so opena2a users are pointed at `opena2a review`.
    const hmaEnv = {
      ...process.env,
      HMA_CLI_PREFIX: 'opena2a',
      HMA_CHECK_COMMAND: 'opena2a check',
      HMA_FULL_SCAN_HINT: 'opena2a review',
    };

    const child = spawn('hackmyagent', args, {
      cwd: (globalOptions.cwd as string) ?? process.cwd(),
      stdio: 'inherit',
      env: hmaEnv,
    });

    child.on('error', () => {
      const npxChild = spawn('npx', ['hackmyagent', ...args], {
        cwd: (globalOptions.cwd as string) ?? process.cwd(),
        stdio: 'inherit',
        env: hmaEnv,
      });
      npxChild.on('error', () => {
        process.stderr.write(`hackmyagent is not installed.\n`);
        process.stderr.write(`Install: npm install -g hackmyagent\n`);
        resolve(1);
      });
      npxChild.on('close', (code) => resolve(code ?? 1));
    });

    child.on('close', (code) => resolve(code ?? 1));
  });
}
