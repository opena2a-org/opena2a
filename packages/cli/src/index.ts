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
import { printFooter } from './util/footer.js';

const VERSION = getVersion();

// Tell downstream tools (hackmyagent, secretless) to use 'opena2a' in user-facing messages
process.env.HMA_CLI_PREFIX = 'opena2a scan';

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
    .option('--json', 'Shorthand for --format json')
    .option('--contribute', 'Share anonymized scan results with OpenA2A community')
    .option('--deep', 'Enable semantic analysis (ML-enhanced)')
    .option('--static-only', 'Disable semantic analysis (static checks only, fast)')
    .hook('preAction', (thisCommand) => {
      const opts = thisCommand.opts();
      if (opts.json) {
        thisCommand.setOptionValue('format', 'json');
      }
    })
    .showHelpAfterError('Run opena2a --help for available commands.')
    .addHelpText('beforeAll', `
Quick start:
  $ opena2a init                    Security assessment (30 seconds)
  $ opena2a detect                  Discover AI agents on this machine
  $ opena2a protect                 Migrate credentials to secure vault
  $ opena2a shield init             Full 11-step security setup

Commands by category:
  Scan & Harden:  init, scan, check, detect, protect, benchmark, harden-skill
  Identity:       identity, skill, mcp, trust, claim
  Governance:     scan-soul, harden-soul, guard, shield
  Runtime:        runtime, review, status, baselines
  Secrets:        secrets, broker
  Training:       train, demo
  Smart input:    ? (advisor)  ~query (search)  "natural language"
`)
    .addHelpText('after', `
Quick Start:
  $ opena2a shield init          Full 11-step security setup (scan, protect, sign, policy, hooks)
  $ opena2a init                 Read-only security assessment (no changes to your project)
  $ opena2a protect              Detect and migrate hardcoded credentials
  $ opena2a guard sign           Sign config files for tamper detection
  $ opena2a scan secure          Run 204 security checks on your AI agent
  $ opena2a skill create         Scaffold a secure skill (SKILL.md, heartbeat, tests)
  $ opena2a guard harden         Scan skills for security issues (--fix to auto-fix)
  $ opena2a harden-skill         Harden a skill file (frontmatter, permissions, integrity pin)
  $ opena2a scan-soul            Scan governance file for behavioral safety (AGS)
  $ opena2a scan-soul --strict   Fail if critical SOUL controls are missing
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
    const adapterCmd = program
      .command(name)
      .argument('[args...]', 'Subcommand and arguments')
      .description(config.description)
      .allowUnknownOption(true)
      .helpOption(false); // Disable Commander's --help interception so it passes through to the adapter

    adapterCmd.action(async (args: string[], _opts: unknown, _cmd: unknown) => {
        // Handle --help / -h: show adapter info and try to delegate to the underlying tool
        if (args.includes('--help') || args.includes('-h')) {
          const pkgLabel = config.packageName ?? config.command ?? config.image ?? config.pythonModule ?? name;
          process.stdout.write(`${name} - ${config.description}\n\n`);
          process.stdout.write(`This command delegates to ${pkgLabel}.\n`);
          process.stdout.write(`Run \`npx ${pkgLabel} --help\` for full subcommand documentation.\n\n`);
          // Try to pass --help through to the adapter for real help output
          const globalOpts = program.opts();
          const exitCode = await dispatchCommand(name, args, {
            verbose: globalOpts.verbose,
            quiet: globalOpts.quiet,
            ci: globalOpts.ci,
            format: globalOpts.format,
            contribute: globalOpts.contribute,
            deep: globalOpts.deep,
            staticOnly: globalOpts.staticOnly,
          });
          process.exitCode = exitCode;
          return;
        }

        // For 'registry' with no args, show usage instead of crashing
        if (name === 'registry' && args.length === 0) {
          process.stdout.write(`registry - ${config.description}\n\n`);
          process.stdout.write('Usage: opena2a registry <package-name>\n');
          process.stdout.write('       opena2a registry express\n');
          process.stdout.write('       opena2a registry langchain\n\n');
          process.stdout.write('Queries the OpenA2A Trust Registry for security data on a package.\n');
          process.exitCode = 0;
          return;
        }

        const globalOpts = program.opts();
        const exitCode = await dispatchCommand(name, args, {
          verbose: globalOpts.verbose,
          quiet: globalOpts.quiet,
          ci: globalOpts.ci,
          format: globalOpts.format,
          contribute: globalOpts.contribute,
          deep: globalOpts.deep,
          staticOnly: globalOpts.staticOnly,
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
      printFooter({ ci: globalOpts.ci, json: globalOpts.format === 'json' });
    });

  // Check command (alias for scan secure, supports [directory])
  if (!ADAPTER_REGISTRY['check']) {
    program
      .command('check [directory]')
      .description('Quick security check (alias for scan secure)')
      .allowUnknownOption(true)
      .action(async (directory: string | undefined, _opts, cmd) => {
        const args = cmd.args ?? [];
        if (directory) args.unshift(directory);
        const globalOpts = program.opts();
        const exitCode = await dispatchCommand('check', args, {
          verbose: globalOpts.verbose,
          quiet: globalOpts.quiet,
          ci: globalOpts.ci,
          format: globalOpts.format,
          contribute: globalOpts.contribute,
          deep: globalOpts.deep,
          staticOnly: globalOpts.staticOnly,
        });
        process.exitCode = exitCode;
      });
  }

  // Status command (direct, shows project security status)
  program
    .command('status [directory]')
    .description('Show security status of current project')
    .option('--dir <path>', 'Target directory')
    .action(async (directory: string | undefined, opts) => {
      const { status: runStatus } = await import('./commands/status.js');
      const globalOpts = program.opts();
      process.exitCode = await runStatus({
        targetDir: opts.dir ?? directory ?? process.cwd(),
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
      });
    });

  // Publish intent command
  if (!ADAPTER_REGISTRY['publish']) {
    program
      .command('publish')
      .description('Verify package trust score before publishing')
      .allowUnknownOption(true)
      .action(async (_opts, cmd) => {
        const args = cmd.args ?? [];
        const globalOpts = program.opts();
        const exitCode = await dispatchCommand('publish', args, {
          verbose: globalOpts.verbose,
          quiet: globalOpts.quiet,
          ci: globalOpts.ci,
          format: globalOpts.format,
          contribute: globalOpts.contribute,
          deep: globalOpts.deep,
          staticOnly: globalOpts.staticOnly,
        });
        process.exitCode = exitCode;
      });
  }

  // Init command (direct, not adapter-based)
  program
    .command('init [directory]')
    .description('Assess your project security posture (read-only scan; use "shield init" for full setup)')
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
    .description('Config file integrity signing and verification (sign|verify|status|watch|diff|policy|hook|resign|snapshot|harden)')
    .option('--files <files...>', 'Specific files to guard')
    .option('--dir <path>', 'Target directory')
    .option('--enforce', 'Quarantine on tampering (exit code 3)')
    .option('--skills', 'Include SKILL.md files in signing/verification')
    .option('--heartbeats', 'Include HEARTBEAT.md files in signing/verification')
    .option('--fix', 'Auto-fix fixable issues (harden subcommand)')
    .option('--dry-run', 'Preview fixes without applying (harden subcommand)')
    .action(async (subcommand: string | undefined, args: string[], opts) => {
      const validSubs = ['sign', 'verify', 'status', 'watch', 'diff', 'policy', 'hook', 'resign', 'snapshot', 'harden'];
      if (!subcommand) {
        process.stderr.write('Usage: opena2a guard <subcommand> [directory]\n\n');
        process.stderr.write('Subcommands:\n');
        process.stderr.write('  sign       Sign config files for integrity verification\n');
        process.stderr.write('  verify     Verify config file signatures\n');
        process.stderr.write('  status     Show current guard status\n');
        process.stderr.write('  watch      Watch for config file changes\n');
        process.stderr.write('  diff       Show changes since last signing\n');
        process.stderr.write('  policy     Manage guard policies\n');
        process.stderr.write('  hook       Install/manage git hooks\n');
        process.stderr.write('  resign     Re-sign after intentional changes\n');
        process.stderr.write('  snapshot   Take a config snapshot\n');
        process.stderr.write('  harden     Auto-fix config security issues\n');
        process.exitCode = 1;
        return;
      }
      // If the "subcommand" looks like a directory path, treat it as a directory and default to "status"
      let resolvedSub = subcommand;
      let dirOverride: string | undefined;
      if (!validSubs.includes(subcommand)) {
        // Check if it's a path (starts with /, ./, ../, is ".", or contains path separators)
        if (subcommand === '.' || subcommand.startsWith('/') || subcommand.startsWith('./') || subcommand.startsWith('..') || subcommand.includes('/')) {
          dirOverride = subcommand;
          resolvedSub = 'status';
        } else {
          // Not a valid subcommand and not a path -- let guard() handle the error
        }
      }
      const { guard } = await import('./commands/guard.js');
      const globalOpts = program.opts();
      // Subcommands that take action args (not directory) as first positional
      const actionSubs = ['hook', 'policy', 'snapshot'];
      const isActionSub = actionSubs.includes(resolvedSub);
      // Extract directory from positional args only for non-action subcommands
      const dirFromArgs = !isActionSub && args.length > 0 && !args[0]?.startsWith('-') ? args.shift() : undefined;
      process.exitCode = await guard({
        subcommand: resolvedSub as 'sign' | 'verify' | 'status' | 'watch' | 'diff' | 'policy' | 'hook' | 'resign' | 'snapshot' | 'harden',
        files: opts.files,
        targetDir: opts.dir ?? dirOverride ?? dirFromArgs,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
        enforce: opts.enforce,
        skills: opts.skills,
        heartbeats: opts.heartbeats,
        fix: opts.fix,
        dryRun: opts.dryRun,
        args,
      });
      printFooter({ ci: globalOpts.ci, json: globalOpts.format === 'json' });
    });

  // Runtime command (ARP wrapper)
  program
    .command('runtime [subcommand] [directory]')
    .description('Agent runtime protection (start|status|tail|init)')
    .option('--config <path>', 'Path to ARP config file')
    .option('--count <n>', 'Number of events to show (tail) [default: 20]')
    .option('--dir <path>', 'Target directory')
    .option('--force', 'Overwrite existing config (init)')
    .action(async (subcommand: string | undefined, directory: string | undefined, opts) => {
      if (!subcommand) {
        process.stderr.write('Usage: opena2a runtime <subcommand> [directory]\n\n');
        process.stderr.write('Subcommands:\n');
        process.stderr.write('  start   Start ARP monitoring\n');
        process.stderr.write('  status  Show protection status, monitors, budget\n');
        process.stderr.write('  tail    Read last N events from event log\n');
        process.stderr.write('  init    Auto-generate arp.yaml from detected project type\n');
        process.exitCode = 1;
        return;
      }
      const { runtime } = await import('./commands/runtime.js');
      const globalOpts = program.opts();
      process.exitCode = await runtime({
        subcommand: subcommand as 'start' | 'status' | 'tail' | 'init',
        configPath: opts.config,
        count: opts.count ? parseInt(opts.count, 10) : undefined,
        targetDir: opts.dir ?? directory,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
        force: opts.force,
      });
      printFooter({ ci: globalOpts.ci, json: globalOpts.format === 'json' });
    });

  // Login command (browser-based OAuth device flow)
  program
    .command('login')
    .description('Authenticate with an AIM server via browser login')
    .option('--server <url>', 'AIM server URL (default: cloud, i.e. aim.opena2a.org)')
    .option('--json', 'Output as JSON')
    .action(async (opts) => {
      const { login } = await import('./commands/login.js');
      const globalOpts = program.opts();
      process.exitCode = await login({
        server: opts.server,
        ci: globalOpts.ci,
        format: globalOpts.format,
        json: opts.json,
      });
    });

  // Logout command
  program
    .command('logout')
    .description('Remove stored authentication credentials')
    .option('--json', 'Output as JSON')
    .action(async (opts) => {
      const { logout } = await import('./commands/login.js');
      const globalOpts = program.opts();
      process.exitCode = await logout({
        format: globalOpts.format,
        json: opts.json,
      });
    });

  // Whoami command
  program
    .command('whoami')
    .description('Show current authentication status')
    .option('--json', 'Output as JSON')
    .action(async (opts) => {
      const { whoami } = await import('./commands/login.js');
      const globalOpts = program.opts();
      process.exitCode = await whoami({
        format: globalOpts.format,
        json: opts.json,
      });
    });

  // Identity command (native, uses @opena2a/aim-core)
  program
    .command('identity [subcommand] [args...]')
    .description('Agent identity management (list|init|create|trust|audit|log|policy|check|sign|verify|integrate|detach|sync|connect|disconnect|tag|mcp|activity|suspend|reactivate)')
    .option('--name <name>', 'Agent name (for create)')
    .option('--limit <n>', 'Number of audit events to show')
    .option('--dir <path>', 'Target directory')
    .option('--server <url>', 'AIM server URL (e.g. localhost:8080, cloud)')
    .option('--api-key <key>', 'AIM API key for server authentication')
    .option('--json', 'Output as JSON (alias for --format json)')
    .option('--action <action>', 'Audit event action (for log)')
    .option('--target <target>', 'Audit event target (for log)')
    .option('--result <result>', 'Audit event result: allowed|denied|error (for log)')
    .option('--plugin <plugin>', 'Plugin name (for log, check)')
    .option('--file <path>', 'Policy file path (for policy load)')
    .option('--data <data>', 'Data to sign or verify')
    .option('--signature <sig>', 'Base64 signature (for verify)')
    .option('--public-key <key>', 'Base64 public key (for verify)')
    .option('--tools <list>', 'Comma-separated tools to enable (attach)')
    .option('--all', 'Enable all detected tools (attach)')
    .option('--auto-sync', 'Auto-sync events on trust calculation (attach)')
    .action(async (subcommand: string | undefined, args: string[], opts) => {
      if (!subcommand) {
        subcommand = 'list';
      }
      // For "check", the capability is the first positional arg
      const capability = subcommand === 'check' ? args[0] : undefined;
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
        action: opts.action,
        target: opts.target,
        result: opts.result,
        plugin: opts.plugin,
        file: opts.file,
        data: opts.data,
        signature: opts.signature,
        publicKey: opts.publicKey,
        capability,
        tools: opts.tools,
        all: opts.all,
        autoSync: opts.autoSync,
        server: opts.server,
        apiKey: opts.apiKey,
        json: opts.json,
        args,
      });
    });

  // Shield command (unified security orchestration)
  program
    .command('shield [subcommand] [args...]')
    .description('Unified security orchestration ("shield init" runs full 11-step setup; also:|status|log|selfcheck|policy|evaluate|recover|report|session|baseline|suggest|explain|triage)')
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
    .option('--shell-hook', 'Install shell preexec hook (shield init only)')
    .option('--ai-tools', 'Configure AI tool settings (shield init only)')
    .action(async (subcommand: string | undefined, args: string[], opts) => {
      if (!subcommand) {
        process.stderr.write('Usage: opena2a shield <subcommand>\n\n');
        process.stderr.write('Subcommands:\n');
        process.stderr.write('  init       Full environment scan, policy generation, shell hooks\n');
        process.stderr.write('  status     Tool availability, policy mode, integrity state\n');
        process.stderr.write('  log        Query the tamper-evident event log\n');
        process.stderr.write('  selfcheck  Run integrity checks\n');
        process.stderr.write('  policy     Show loaded policy summary\n');
        process.stderr.write('  evaluate   Evaluate an action against the policy\n');
        process.stderr.write('  recover    Exit lockdown mode\n');
        process.stderr.write('  report     Generate a security posture report\n');
        process.stderr.write('  session    Show current AI coding assistant session identity\n');
        process.stderr.write('  baseline   View adaptive enforcement baselines for agents\n');
        process.stderr.write('  suggest    LLM-powered policy suggestions from observed behavior\n');
        process.stderr.write('  explain    LLM-powered anomaly explanations for events\n');
        process.stderr.write('  triage     LLM-powered incident classification and response\n');
        process.exitCode = 1;
        return;
      }
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
      printFooter({ ci: globalOpts.ci, json: globalOpts.format === 'json' });
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
      printFooter({ ci: globalOpts.ci, json: globalOpts.format === 'json' });
    });

  // Scan-soul command (governance scanner, uses hackmyagent SoulScanner API)
  program
    .command('scan-soul [directory]')
    .description('Scan governance file for behavioral safety coverage (ABGS)')
    .option('--dir <path>', 'Target directory')
    .option('--profile <name>', 'Agent profile (conversational|code-assistant|tool-agent|autonomous|orchestrator)')
    .option('--tier <level>', 'Force tier (BASIC|STANDARD|AGENTIC)')
    .option('--deep', 'Enable LLM-assisted deep analysis')
    .option('--strict', 'Fail if any critical SOUL control is missing (SOUL-IH-003, SOUL-HB-001)')
    .action(async (directory: string | undefined, opts) => {
      const { scanSoul } = await import('./commands/soul.js');
      const globalOpts = program.opts();
      process.exitCode = await scanSoul({
        targetDir: opts.dir ?? directory ?? process.cwd(),
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
        profile: opts.profile,
        tier: opts.tier,
        deep: opts.deep,
        strict: opts.strict,
      });
      printFooter({ ci: globalOpts.ci, json: globalOpts.format === 'json' });
    });

  // Harden-soul command (governance generator, uses hackmyagent SoulScanner API)
  program
    .command('harden-soul [directory]')
    .description('Generate or improve governance file with ABGS templates')
    .option('--dir <path>', 'Target directory')
    .option('--profile <name>', 'Agent profile (conversational|code-assistant|tool-agent|autonomous|orchestrator)')
    .option('--tier <level>', 'Force tier (BASIC|STANDARD|AGENTIC)')
    .option('--dry-run', 'Show what would be generated without writing')
    .action(async (directory: string | undefined, opts) => {
      const { hardenSoul } = await import('./commands/soul.js');
      const globalOpts = program.opts();
      process.exitCode = await hardenSoul({
        targetDir: opts.dir ?? directory ?? process.cwd(),
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
        profile: opts.profile,
        tier: opts.tier,
        dryRun: opts.dryRun,
      });
      printFooter({ ci: globalOpts.ci, json: globalOpts.format === 'json' });
    });

  // Harden-skill command (skill hardening with frontmatter validation and permission boundaries)
  program
    .command('harden-skill [file]')
    .description('Harden a skill file: add frontmatter, permission boundaries, and integrity pin')
    .option('--file <path>', 'Skill file to harden')
    .option('--dry-run', 'Show what would be changed without writing')
    .action(async (file: string | undefined, opts) => {
      const { hardenSkill } = await import('./commands/harden-skill.js');
      const globalOpts = program.opts();
      process.exitCode = await hardenSkill({
        file: opts.file ?? file,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
        dryRun: opts.dryRun,
      });
      printFooter({ ci: globalOpts.ci, json: globalOpts.format === 'json' });
    });

  // Benchmark command (OASB security benchmark, uses hackmyagent programmatic API)
  program
    .command('benchmark [directory]')
    .description('Run OASB security benchmark against AI agent')
    .option('--dir <path>', 'Target directory')
    .option('--level <level>', 'Benchmark level: L1, L2, L3', 'L1')
    .action(async (directory: string | undefined, opts) => {
      const { benchmark: runBenchmark } = await import('./commands/benchmark.js');
      const globalOpts = program.opts();
      process.exitCode = await runBenchmark({
        targetDir: opts.dir ?? directory ?? process.cwd(),
        level: opts.level,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
      });
      printFooter({ ci: globalOpts.ci, json: globalOpts.format === 'json' });
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

  // Trust command (ATP trust lookup)
  program
    .command('trust [package]')
    .description('Look up the trust profile for an AI agent or MCP server')
    .option('--source <source>', 'Package source (npm, pypi, github)')
    .option('--registry-url <url>', 'Registry URL')
    .option('--json', 'Output as JSON (alias for --format json)')
    .addHelpText('after', `
Examples:
  $ opena2a trust express                    Look up npm package
  $ opena2a trust langchain --source pypi    Look up PyPI package
  $ opena2a trust                            Auto-detect from package.json
  $ opena2a trust express --json             JSON output
  $ opena2a trust https://github.com/org/repo   GitHub URL (auto-detected)`)
    .action(async (packageArg: string | undefined, opts) => {
      const { trust: runTrust } = await import('./commands/trust.js');
      const globalOpts = program.opts();
      process.exitCode = await runTrust({
        packageName: packageArg,
        source: opts.source,
        registryUrl: opts.registryUrl,
        ci: globalOpts.ci,
        format: globalOpts.format,
        json: opts.json,
        verbose: globalOpts.verbose,
      });
      printFooter({ ci: globalOpts.ci, json: opts.json || globalOpts.format === 'json' });
    });

  // Claim command (ATP claim flow)
  program
    .command('claim [package]')
    .description('Claim ownership of a discovered agent in the trust registry')
    .option('--source <source>', 'Package source (npm, pypi, github)')
    .option('--registry-url <url>', 'Registry URL')
    .option('--json', 'Output as JSON (alias for --format json)')
    .addHelpText('after', `
Examples:
  $ opena2a claim my-agent                   Claim via npm ownership
  $ opena2a claim my-agent --source github   Claim via GitHub ownership
  $ opena2a claim                            Auto-detect from package.json
  $ opena2a claim https://github.com/org/repo   GitHub URL (auto-detected)`)
    .action(async (packageArg: string | undefined, opts) => {
      const { claim: runClaim } = await import('./commands/claim.js');
      const globalOpts = program.opts();
      process.exitCode = await runClaim({
        packageName: packageArg,
        source: opts.source,
        registryUrl: opts.registryUrl,
        ci: globalOpts.ci,
        format: globalOpts.format,
        json: opts.json,
        verbose: globalOpts.verbose,
      });
      printFooter({ ci: globalOpts.ci, json: opts.json || globalOpts.format === 'json' });
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

  // Detect command (shadow AI agent audit)
  program
    .command('detect [directory]')
    .description('Discover AI agents running on this machine and check their security posture')
    .option('--dir <path>', 'Target directory for project-local checks')
    .option('--report [path]', 'Generate HTML executive report')
    .option('--export-csv <path>', 'Export asset inventory as CSV for import into CMDB/ServiceNow')
    .option('--registry', 'Enrich results with community trust data from OpenA2A Registry')
    .option('--auto-scan', 'Auto-scan unknown packages with HackMyAgent (no prompt)')
    .action(async (directory: string | undefined, opts) => {
      const { detect } = await import('./commands/detect.js');
      const globalOpts = program.opts();
      let reportPath = opts.report;
      if (reportPath === true) {
        const os = await import('node:os');
        const nodePath = await import('node:path');
        reportPath = nodePath.join(os.tmpdir(), `opena2a-detect-${Date.now()}.html`);
      }
      process.exitCode = await detect({
        targetDir: opts.dir ?? directory ?? process.cwd(),
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
        reportPath,
        exportCsv: opts.exportCsv,
        registry: opts.registry,
        autoScan: opts.autoScan,
      });
      printFooter({ ci: globalOpts.ci, json: globalOpts.format === 'json' });
    });

  // Setup command (one-command AIM onboarding)
  program
    .command('setup [directory]')
    .description('One-command agent setup: authenticate, create identity, discover MCPs, show trust score')
    .option('--dir <path>', 'Target directory')
    .option('--name <name>', 'Override auto-detected agent name')
    .option('--json', 'Output as JSON')
    .action(async (directory: string | undefined, opts) => {
      const { setup: runSetup } = await import('./commands/setup.js');
      const globalOpts = program.opts();
      process.exitCode = await runSetup({
        targetDir: opts.dir ?? directory ?? process.cwd(),
        name: opts.name,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
        json: opts.json,
      });
    });

  // Watch command (live agent activity tail)
  program
    .command('watch')
    .description('Live tail of agent activity events (like kubectl logs)')
    .option('--json', 'Output as NDJSON (one JSON object per line)')
    .option('--interval <seconds>', 'Poll interval in seconds', '3')
    .action(async (opts) => {
      const { watch: runWatch } = await import('./commands/watch.js');
      const globalOpts = program.opts();
      process.exitCode = await runWatch({
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
        json: opts.json,
        interval: opts.interval ? parseInt(opts.interval, 10) : undefined,
      });
    });

  // Demo command (interactive AIM demonstration)
  program
    .command('demo [scenario]')
    .description('Run interactive demos (scenarios: aim, dvaa)')
    .option('--interactive', 'Pause between steps for explanation')
    .option('--keep', 'Keep the sandbox directory after demo completes')
    .option('--dir <path>', 'Use a specific directory instead of temporary sandbox')
    .action(async (scenario: string | undefined, opts) => {
      const { demo } = await import('./commands/demo.js');
      const globalOpts = program.opts();
      process.exitCode = await demo({
        scenario: scenario ?? 'aim',
        interactive: opts.interactive,
        keep: opts.keep,
        dir: opts.dir,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
      });
    });

  // Config command
  program
    .command('config <action> [key] [value]')
    .description('Manage OpenA2A configuration')
    .option('--enable', 'Enable the feature (alias for "on")')
    .option('--disable', 'Disable the feature (alias for "off")')
    .addHelpText('after', `
Valid actions:
  show                             Display current configuration
  contribute [on|off|--enable|--disable]  Enable or disable community data contributions
  llm [on|off|--enable|--disable]         Enable or disable LLM-powered features`)
    .action(async (action: string, key: string | undefined, _value: string | undefined, opts: { enable?: boolean; disable?: boolean }) => {
      const shared = await import('@opena2a/shared');
      const { loadUserConfig, saveUserConfig, setContributeEnabled } = 'default' in shared ? (shared as any).default : shared;

      // Resolve --enable/--disable flags as aliases for on/off
      const resolvedKey = opts.enable ? 'on' : opts.disable ? 'off' : key;

      if (action === 'contribute') {
        if (resolvedKey === 'on') {
          setContributeEnabled(true);
          process.stdout.write('Community contributions enabled.\n');
        } else if (resolvedKey === 'off') {
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
        if (resolvedKey === 'on') {
          setLlm(true);
          process.stdout.write('LLM features enabled.\n');
        } else if (resolvedKey === 'off') {
          setLlm(false);
          process.stdout.write('LLM features disabled.\n');
        } else {
          const config = loadUserConfig();
          process.stdout.write(`LLM features: ${config.llm.enabled ? 'enabled' : 'disabled'}\n`);
          if (config.llm.consentedAt) {
            process.stdout.write(`Consented: ${config.llm.consentedAt}\n`);
          }
        }
      } else if (action === 'show' || action === 'get') {
        const config = loadUserConfig();
        process.stdout.write(JSON.stringify(config, null, 2) + '\n');
      } else {
        process.stderr.write(`Unknown config action: ${action}\n`);
        process.stderr.write('Usage: opena2a config contribute on|off|--enable|--disable\n');
        process.stderr.write('       opena2a config llm on|off|--enable|--disable\n');
        process.stderr.write('       opena2a config show\n');
        process.exitCode = 1;
      }
    });

  // Skill command (noun-verb: skill create)
  program
    .command('skill <subcommand> [name]')
    .description('Skill management: create secure skills with signing and heartbeat')
    .option('--template <name>', 'Template: basic, mcp-tool, data-processor (default: basic)')
    .option('--output <dir>', 'Output directory (default: current)')
    .option('--no-sign', 'Skip auto-signing of skill files')
    .action(async (subcommand: string, name: string | undefined, opts) => {
      if (subcommand === 'create') {
        const { create } = await import('./commands/create/index.js');
        const globalOpts = program.opts();
        process.exitCode = await create({
          type: 'skill',
          name,
          ...opts,
          noSign: opts.sign === false,
          ci: globalOpts.ci,
          format: globalOpts.format,
          verbose: globalOpts.verbose,
        });
        printFooter({ ci: globalOpts.ci, json: globalOpts.format === 'json' });
      } else {
        process.stderr.write(`Unknown skill subcommand: ${subcommand}\n`);
        process.stderr.write('Available: create\n');
        process.exitCode = 1;
      }
    });

  // Backwards-compatible alias: `create skill` still works
  program
    .command('create <type> [name]', { hidden: true })
    .description('Create secure skill or component (type: skill)')
    .option('--template <name>', 'Template: basic, mcp-tool, data-processor')
    .option('--output <dir>', 'Output directory')
    .option('--no-sign', 'Skip auto-signing')
    .action(async (type: string, name: string | undefined, opts) => {
      const { create } = await import('./commands/create/index.js');
      const globalOpts = program.opts();
      process.exitCode = await create({
        type,
        name,
        ...opts,
        noSign: opts.sign === false,
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
      });
      printFooter({ ci: globalOpts.ci, json: globalOpts.format === 'json' });
    });

  // MCP command (MCP server identity management)
  program
    .command('mcp [subcommand] [server]')
    .description('MCP server identity management (audit|sign|verify)')
    .option('--dir <path>', 'Target directory')
    .action(async (subcommand: string | undefined, server: string | undefined, opts) => {
      if (!subcommand) subcommand = 'audit';
      const { mcpCommand } = await import('./commands/mcp-audit.js');
      const globalOpts = program.opts();
      process.exitCode = await mcpCommand({
        subcommand,
        server,
        targetDir: opts.dir ?? process.cwd(),
        ci: globalOpts.ci,
        format: globalOpts.format,
        verbose: globalOpts.verbose,
      });
      printFooter({ ci: globalOpts.ci, json: globalOpts.format === 'json' });
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
    'config', 'self-register', 'verify', 'baselines', 'benchmark',
    'check', 'status', 'publish', 'detect', 'mcp', 'demo', 'setup', 'watch',
    'trust', 'claim', 'create', 'login', 'logout', 'whoami',
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
    case 'init': return 'Assess your project security posture (read-only scan)';
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
