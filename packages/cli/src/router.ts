import { createAdapter } from './adapters/index.js';
import type { RunOptions } from './adapters/types.js';
import { protect } from './commands/protect.js';

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
    'identity', 'registry', 'research', 'hunt', 'train',
    'guard', 'dlp', 'broker', 'config', 'self-register',
    'verify', 'baselines', 'review',
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
    return guard({
      subcommand: subcommand as 'sign' | 'verify' | 'status' | 'policy',
      targetDir: process.cwd(),
      ci: globalOptions.ci ?? false,
      format: (globalOptions.format as 'text' | 'json') ?? 'text',
      verbose: globalOptions.verbose ?? false,
      args: args.slice(1),
    });
  }

  // Handle 'runtime' directly (ARP wrapper)
  if (command === 'runtime') {
    const { runtime } = await import('./commands/runtime.js');
    const subcommand = args[0] ?? 'status';
    return runtime({
      subcommand: subcommand as 'start' | 'status' | 'tail' | 'init',
      targetDir: process.cwd(),
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
  const adapterArgs = intent ? [...intent.defaultArgs, ...args] : args;

  const adapter = createAdapter(adapterName);
  if (!adapter) {
    process.stderr.write(`Unknown command: ${command}\n`);
    process.stderr.write(`Run 'opena2a --help' for available commands.\n`);
    return 1;
  }

  const available = await adapter.isAvailable();
  if (!available) {
    process.stderr.write(`${adapter.config.name} is not installed.\n`);
    process.stderr.write(`Install: npm install -g ${adapter.config.packageName ?? adapter.config.command ?? adapter.config.name}\n`);
    return 1;
  }

  const result = await adapter.run({
    args: adapterArgs,
    ...globalOptions,
    cwd: globalOptions.cwd ?? process.cwd(),
  });

  return result.exitCode;
}
