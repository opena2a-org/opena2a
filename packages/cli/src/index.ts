#!/usr/bin/env node

import { Command } from 'commander';
import { printBanner, printCompact } from './branding.js';
import { classifyInput, dispatchCommand } from './router.js';
import { handleSearch } from './semantic/index.js';
import { handleContext } from './contextual/index.js';
import { handleNaturalLanguage, matchIntent } from './natural/index.js';
import { runWizard } from './guided/wizard.js';
import { ADAPTER_REGISTRY } from './adapters/registry.js';
import { getVersion } from './util/version.js';

const VERSION = getVersion();

async function main(): Promise<void> {
  const program = new Command();

  program
    .name('opena2a')
    .description('Open-source security platform for AI agents')
    .version(VERSION, '-v, --version')
    .option('--ci', 'CI mode (no interactive prompts, machine-readable output)')
    .option('--quiet', 'Suppress non-essential output')
    .option('--verbose', 'Verbose output')
    .option('--format <type>', 'Output format: text, json, sarif', 'text')
    .option('--contribute', 'Share anonymized scan results with OpenA2A community')
    .addHelpText('after', `
Quick Start:
  $ opena2a shield init          Unified security setup (scan, policy, hooks)
  $ opena2a init                 Assess your project's security posture
  $ opena2a protect              Detect and migrate hardcoded credentials
  $ opena2a guard sign           Sign config files for tamper detection
  $ opena2a scan secure          Run 150+ security checks on your AI agent
  $ opena2a scan-soul            Scan governance file for behavioral safety (AGS)
  $ opena2a harden-soul          Generate or improve SOUL.md governance file

Smart Features:
  $ opena2a                      Interactive guided mode (no args)
  $ opena2a ~<query>             Search commands (e.g. opena2a ~drift)
  $ opena2a ?                    Get smart recommendations for your project
  $ opena2a find secrets         Natural language command matching
  $ opena2a detect credentials   Natural language command matching

Learn more: https://opena2a.org/docs`);

  // Register all adapter-backed commands
  for (const [name, config] of Object.entries(ADAPTER_REGISTRY)) {
    program
      .command(name)
      .argument('[args...]', 'Subcommand and arguments')
      .description(config.description)
      .allowUnknownOption(true)
      .action(async (args: string[], _opts, cmd) => {
        const globalOpts = program.opts();
        const exitCode = await dispatchCommand(name, args, {
          verbose: globalOpts.verbose,
          quiet: globalOpts.quiet,
          ci: globalOpts.ci,
          format: globalOpts.format,
          contribute: globalOpts.contribute,
        });
        process.exitCode = exitCode;
      });
  }

  // Protect command (direct, not adapter-based)
  program
    .command('protect [directory]')
    .description('Detect and migrate credentials to encrypted vault')
    .option('--dry-run', 'Show what would change without modifying files')
    .option('--report <path>', 'Write interactive HTML report')
    .option('--skip-verify', 'Skip verification re-scan')
    .option('--skip-liveness', 'Skip drift liveness verification (offline/CI)')
    .option('--skip-sign', 'Skip config signing phase')
    .option('--skip-git', 'Skip git hygiene fixes (.gitignore, .git/info/exclude)')
    .option('--dir <path>', 'Target directory')
    .action(async (directory: string | undefined, opts) => {
      const { protect: runProtect } = await import('./commands/protect.js');
      const globalOpts = program.opts();
      process.exitCode = await runProtect({
        targetDir: opts.dir ?? directory ?? process.cwd(),
        dryRun: opts.dryRun,
        verbose: globalOpts.verbose,
        ci: globalOpts.ci,
        format: globalOpts.format as 'text' | 'json',
        skipVerify: opts.skipVerify,
        skipLiveness: opts.skipLiveness,
        skipSign: opts.skipSign,
        skipGit: opts.skipGit,
        report: opts.report,
      });
    });

  // Intent commands (init and protect are handled as direct commands)
  for (const intent of ['check', 'status', 'publish']) {
    if (!ADAPTER_REGISTRY[intent]) {
      program
        .command(intent)
        .description(getIntentDescription(intent))
        .allowUnknownOption(true)
        .action(async (_opts, cmd) => {
          const args = cmd.args ?? [];
          const globalOpts = program.opts();
          const exitCode = await dispatchCommand(intent, args, {
            verbose: globalOpts.verbose,
            quiet: globalOpts.quiet,
            ci: globalOpts.ci,
            format: globalOpts.format,
            contribute: globalOpts.contribute,
          });
          process.exitCode = exitCode;
        });
    }
  }

  // Init command (direct, not adapter-based)
  program
    .command('init [directory]')
    .description('Initialize OpenA2A security in your project')
    .option('--dir <path>', 'Target directory')
    .action(async (directory: string | undefined, opts) => {
      const { init } = await import('./commands/init.js');
      const globalOpts = program.opts();
      process.exitCode = await init({
        targetDir: opts.dir ?? directory,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
      });
    });

  // Guard command (ConfigGuard)
  program
    .command('guard [subcommand] [args...]')
    .description('Config file integrity signing and verification (sign|verify|status|watch|diff|policy|hook|resign|snapshot)')
    .option('--files <files...>', 'Specific files to guard')
    .option('--dir <path>', 'Target directory')
    .option('--enforce', 'Quarantine on tampering (exit code 3)')
    .option('--skills', 'Include SKILL.md files in signing/verification')
    .option('--heartbeats', 'Include HEARTBEAT.md files in signing/verification')
    .action(async (subcommand: string | undefined, args: string[], opts) => {
      if (!subcommand) {
        process.stderr.write('Usage: opena2a guard <sign|verify|status|watch|diff|policy|hook|resign|snapshot>\n');
        process.exitCode = 1;
        return;
      }
      const { guard } = await import('./commands/guard.js');
      const globalOpts = program.opts();
      process.exitCode = await guard({
        subcommand: subcommand as 'sign' | 'verify' | 'status' | 'watch' | 'diff' | 'policy' | 'hook' | 'resign' | 'snapshot',
        files: opts.files,
        targetDir: opts.dir,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
        enforce: opts.enforce,
        skills: opts.skills,
        heartbeats: opts.heartbeats,
        args,
      });
    });

  // Runtime command (ARP wrapper)
  program
    .command('runtime <subcommand>')
    .description('Agent runtime protection (start|status|tail|init)')
    .option('--config <path>', 'Path to ARP config file')
    .option('--count <n>', 'Number of events to show (tail) [default: 20]')
    .option('--dir <path>', 'Target directory')
    .option('--force', 'Overwrite existing config (init)')
    .action(async (subcommand: string, opts) => {
      const { runtime } = await import('./commands/runtime.js');
      const globalOpts = program.opts();
      process.exitCode = await runtime({
        subcommand: subcommand as 'start' | 'status' | 'tail' | 'init',
        configPath: opts.config,
        count: opts.count ? parseInt(opts.count, 10) : undefined,
        targetDir: opts.dir,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
        force: opts.force,
      });
    });

  // Identity command (native, uses @opena2a/aim-core)
  program
    .command('identity [subcommand]')
    .description('Agent identity management (list|create|trust|audit)')
    .option('--name <name>', 'Agent name (for create)')
    .option('--limit <n>', 'Number of audit events to show')
    .option('--dir <path>', 'Target directory')
    .action(async (subcommand: string | undefined, opts) => {
      if (!subcommand) {
        subcommand = 'list';
      }
      const { identity } = await import('./commands/identity.js');
      const globalOpts = program.opts();
      process.exitCode = await identity({
        subcommand,
        name: opts.name,
        limit: opts.limit ? parseInt(opts.limit, 10) : undefined,
        dir: opts.dir,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
      });
    });

  // Shield command (unified security orchestration)
  program
    .command('shield <subcommand> [args...]')
    .description('Unified security orchestration (init|status|log|selfcheck|policy|evaluate|recover|report|session|baseline|suggest|explain|triage)')
    .allowUnknownOption(true)
    .option('--dir <path>', 'Target directory')
    .option('--agent <name>', 'Agent name filter')
    .option('--count <n>', 'Event count (log)')
    .option('--since <timespec>', 'Time filter: 7d, 1w, 1m, ISO 8601')
    .option('--severity <level>', 'Severity filter')
    .option('--source <source>', 'Source filter')
    .option('--category <cat>', 'Category filter')
    .option('--verify', 'Verify before recovering')
    .option('--reset', 'Force exit lockdown')
    .option('--forensic', 'Forensic mode')
    .option('--analyze', 'Enable LLM analysis')
    .option('--report <path>', 'Write HTML posture report to file')
    .action(async (subcommand: string, args: string[], opts) => {
      const { shield } = await import('./commands/shield.js');
      const globalOpts = program.opts();
      process.exitCode = await shield({
        subcommand,
        args,
        ...opts,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
      });
    });

  // Review command (unified security review)
  program
    .command('review [directory]')
    .description('Run all security checks and open unified HTML dashboard')
    .option('--dir <path>', 'Target directory')
    .option('--report <path>', 'Output path for HTML report')
    .option('--no-open', 'Do not auto-open report in browser')
    .option('--skip-hma', 'Skip HMA scan even if available')
    .action(async (directory: string | undefined, opts) => {
      const { review } = await import('./commands/review.js');
      const globalOpts = program.opts();
      process.exitCode = await review({
        targetDir: opts.dir ?? directory ?? process.cwd(),
        reportPath: opts.report,
        autoOpen: opts.open !== false,
        skipHma: opts.skipHma,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
      });
    });

  // Self-register command
  program
    .command('self-register')
    .description('Register OpenA2A tools in the public registry with security scan results')
    .option('--registry-url <url>', 'Registry URL')
    .option('--skip-scan', 'Skip HMA scanning, register metadata only')
    .option('--only <tools>', 'Comma-separated tool names')
    .option('--dry-run', 'Show what would happen without making changes')
    .action(async (opts) => {
      const { selfRegister } = await import('./commands/self-register.js');
      const globalOpts = program.opts();
      process.exitCode = await selfRegister({
        registryUrl: opts.registryUrl,
        skipScan: opts.skipScan,
        only: opts.only?.split(','),
        dryRun: opts.dryRun,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
      });
    });

  // Verify command
  program
    .command('verify')
    .description('Verify binary integrity of installed OpenA2A packages')
    .option('--package <name>', 'Specific package to verify')
    .option('--registry-url <url>', 'Registry URL')
    .action(async (opts) => {
      const { verify } = await import('./commands/verify.js');
      const globalOpts = program.opts();
      process.exitCode = await verify({
        packageName: opts.package,
        registryUrl: opts.registryUrl,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
      });
    });

  // Baselines command
  program
    .command('baselines')
    .description('Collect behavioral observations for crowdsourced agent profiles (opt-in)')
    .requiredOption('--package <name>', 'Package to observe')
    .option('--duration <seconds>', 'Observation duration', '60')
    .option('--registry-url <url>', 'Registry URL')
    .action(async (opts) => {
      const { baselines } = await import('./commands/baselines.js');
      const globalOpts = program.opts();
      process.exitCode = await baselines({
        packageName: opts.package,
        duration: parseInt(opts.duration, 10),
        registryUrl: opts.registryUrl,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
      });
    });

  // Config command
  program
    .command('config <action> [key] [value]')
    .description('Manage OpenA2A configuration')
    .addHelpText('after', `
Valid actions:
  show                  Display current configuration
  contribute [on|off]   Enable or disable community data contributions
  llm [on|off]          Enable or disable LLM-powered features`)
    .action(async (action: string, key?: string, value?: string) => {
      const shared = await import('@opena2a/shared');
      const { loadUserConfig, saveUserConfig, setContributeEnabled } = 'default' in shared ? (shared as any).default : shared;

      if (action === 'contribute') {
        if (key === 'on') {
          setContributeEnabled(true);
          process.stdout.write('Community contributions enabled.\n');
        } else if (key === 'off') {
          setContributeEnabled(false);
          process.stdout.write('Community contributions disabled.\n');
        } else {
          const config = loadUserConfig();
          process.stdout.write(`Contribute: ${config.contribute.enabled ? 'enabled' : 'disabled'}\n`);
          if (config.contribute.consentedAt) {
            process.stdout.write(`Consented: ${config.contribute.consentedAt}\n`);
          }
        }
      } else if (action === 'llm') {
        const { setLlmEnabled: setLlm } = 'default' in shared ? (shared as any).default : shared;
        if (key === 'on') {
          setLlm(true);
          process.stdout.write('LLM features enabled.\n');
        } else if (key === 'off') {
          setLlm(false);
          process.stdout.write('LLM features disabled.\n');
        } else {
          const config = loadUserConfig();
          process.stdout.write(`LLM features: ${config.llm.enabled ? 'enabled' : 'disabled'}\n`);
          if (config.llm.consentedAt) {
            process.stdout.write(`Consented: ${config.llm.consentedAt}\n`);
          }
        }
      } else if (action === 'show') {
        const config = loadUserConfig();
        process.stdout.write(JSON.stringify(config, null, 2) + '\n');
      } else {
        process.stderr.write(`Unknown config action: ${action}\n`);
        process.stderr.write('Usage: opena2a config contribute on|off\n');
        process.stderr.write('       opena2a config llm on|off\n');
        process.stderr.write('       opena2a config show\n');
        process.exitCode = 1;
      }
    });

  const rawArgs = process.argv.slice(2);

  // Let Commander handle --version, --help, and known subcommands/flags
  const isFlag = rawArgs.length > 0 && rawArgs[0].startsWith('-');
  const isSpecialInput = rawArgs.length > 0 && !isFlag && (
    rawArgs[0].startsWith('~') ||
    rawArgs[0].startsWith('?') ||
    rawArgs[0].startsWith('"') ||
    rawArgs[0].startsWith("'")
  );

  if (isSpecialInput) {
    const classified = classifyInput(rawArgs);

    switch (classified.type) {
      case 'search':
        handleSearch(classified.value);
        return;

      case 'context':
        handleContext(classified.value);
        return;

      case 'natural': {
        const command = await handleNaturalLanguage(classified.value);
        if (command) {
          const parts = command.replace('opena2a ', '').split(' ');
          const exitCode = await dispatchCommand(parts[0], parts.slice(1), program.opts());
          process.exitCode = exitCode;
        }
        return;
      }
    }
  }

  // No args -> guided mode
  if (rawArgs.length === 0) {
    printBanner(VERSION);

    const command = await runWizard();
    if (command) {
      const parts = command.replace('opena2a ', '').split(' ');
      const exitCode = await dispatchCommand(parts[0], parts.slice(1), program.opts());
      process.exitCode = exitCode;
    }
    return;
  }

  // NL fallback: multi-word input where the first word is NOT a known command.
  // This handles "scan for secrets" when the shell strips quotes from
  // `opena2a "scan for secrets"`, yielding argv ['scan', 'for', 'secrets'].
  // We only try this when the first word is NOT a registered command, so
  // valid commands like `opena2a scan secure` always reach Commander.
  const KNOWN_COMMANDS = [
    ...Object.keys(ADAPTER_REGISTRY),
    'init', 'protect', 'guard', 'runtime', 'shield', 'review', 'identity',
    'config', 'self-register', 'verify', 'baselines',
    'check', 'status', 'publish',
  ];
  if (!isFlag && rawArgs.length >= 2 && !KNOWN_COMMANDS.includes(rawArgs[0])) {
    const fullPhrase = rawArgs.join(' ');
    const nlMatch = matchIntent(fullPhrase);
    if (nlMatch) {
      const command = await handleNaturalLanguage(fullPhrase);
      if (command) {
        const parts = command.replace('opena2a ', '').split(' ');
        const exitCode = await dispatchCommand(parts[0], parts.slice(1), program.opts());
        process.exitCode = exitCode;
      }
      return;
    }
  }

  // Let Commander parse known subcommands and flags
  await program.parseAsync(process.argv);
}

function getIntentDescription(intent: string): string {
  switch (intent) {
    case 'init': return 'Initialize OpenA2A security in your project';
    case 'check': return 'Quick security check (alias for scan secure)';
    case 'protect': return 'Detect and migrate credentials to encrypted vault';
    case 'status': return 'Show security status of current project';
    case 'publish': return 'Verify package trust score before publishing';
    default: return '';
  }
}

main().catch((err) => {
  process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
