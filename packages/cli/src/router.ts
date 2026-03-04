import { createAdapter } from './adapters/index.js';
import type { AdapterConfig, RunOptions } from './adapters/types.js';
import { protect } from './commands/protect.js';
import { isContributeEnabled, getRegistryUrl, submitScanReport, normalizeGovernanceReport, recordScanAndMaybePrompt } from './util/report-submission.js';

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
    'scan-soul', 'harden-soul',
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
    // Extract directory from first remaining arg if it looks like a path
    const dirFromArgs = remainingArgs.length > 0 && !remainingArgs[0]?.startsWith('-')
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

  // Intent commands map to adapters
  const INTENT_MAP: Record<string, { adapter: string; defaultArgs: string[] }> = {
    check: { adapter: 'scan', defaultArgs: ['secure'] },
    status: { adapter: 'scan', defaultArgs: ['status'] },
    publish: { adapter: 'registry', defaultArgs: ['check'] },
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

  // Prepend subcommand if the adapter config specifies one (e.g. broker, dlp)
  if (adapter.config.subcommand) {
    adapterArgs = [adapter.config.subcommand, ...adapterArgs];
  }

  const available = await adapter.isAvailable();
  if (!available) {
    process.stderr.write(`${adapter.config.name} is not installed.\n`);
    const installHint = getInstallHint(adapter.config);
    process.stderr.write(`Install: ${installHint}\n`);
    return 1;
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
