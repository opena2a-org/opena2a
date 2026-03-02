#!/usr/bin/env node

import { Command } from 'commander';
import { printBanner, printCompact } from './branding.js';
import { classifyInput, dispatchCommand } from './router.js';
import { handleSearch } from './semantic/index.js';
import { handleContext } from './contextual/index.js';
import { handleNaturalLanguage } from './natural/index.js';
import { runWizard } from './guided/wizard.js';
import { ADAPTER_REGISTRY } from './adapters/registry.js';

const VERSION = '0.1.0';

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
    .option('--contribute', 'Share anonymized scan results with OpenA2A community');

  // Register all adapter-backed commands
  for (const [name, config] of Object.entries(ADAPTER_REGISTRY)) {
    program
      .command(name)
      .description(config.description)
      .allowUnknownOption(true)
      .action(async (_opts, cmd) => {
        const args = cmd.args ?? [];
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

  // Intent commands
  for (const intent of ['init', 'check', 'protect', 'status', 'publish']) {
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

  // Config command
  program
    .command('config <action> [key] [value]')
    .description('Manage OpenA2A configuration')
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
