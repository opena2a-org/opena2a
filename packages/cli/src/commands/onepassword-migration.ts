/**
 * Guided 1Password migration flow.
 *
 * Called from protect.ts after successful credential migration to local vault.
 * Walks users through migrating secrets to 1Password for team sharing
 * and audit trails. Uses the offerAction pattern for transparency.
 *
 * Secretless already has full 1Password backend, migration infrastructure,
 * and CLI backend switching. This module provides the guided UX layer.
 */

import { bold, cyan, dim, green, red, yellow, gray } from '../util/colors.js';
import { Spinner } from '../util/spinner.js';

interface MigrationContext {
  /** Number of credentials in local vault */
  credentialCount: number;
  /** Whether to skip interactive prompts */
  ci?: boolean;
}

/**
 * Offer to migrate local vault credentials to 1Password.
 * Returns true if migration was performed successfully.
 */
export async function offer1PasswordMigration(ctx: MigrationContext): Promise<boolean> {
  // CI or non-TTY: skip silently
  if (ctx.ci || !process.stdin.isTTY) {
    return false;
  }

  // Check if user previously declined permanently
  let rememberedChoice: boolean | undefined;
  try {
    const shared = await import('@opena2a/shared');
    const mod = 'default' in shared ? (shared as any).default : shared;
    rememberedChoice = mod.getRememberedChoice('1password-skip');
  } catch {
    // shared not available
  }

  if (rememberedChoice === true) {
    // User said "don't ask again"
    return false;
  }

  // Step 1: Offer
  process.stdout.write('\n' + bold('1Password Integration') + '\n\n');
  process.stdout.write(
    `Your ${ctx.credentialCount} credential(s) are in the local encrypted vault.\n` +
    'Migrate to 1Password for team sharing and audit trails?\n\n'
  );

  let userChoice: string;
  try {
    const { select } = await import('@inquirer/prompts');
    userChoice = await select({
      message: 'Migrate to 1Password?',
      choices: [
        { name: 'Yes, set up 1Password', value: 'yes' },
        { name: 'No, keep local vault', value: 'no' },
        { name: 'No, and do not ask again', value: 'never' },
      ],
    });
  } catch {
    return false;
  }

  if (userChoice === 'never') {
    try {
      const shared = await import('@opena2a/shared');
      const mod = 'default' in shared ? (shared as any).default : shared;
      mod.setRememberedChoice('1password-skip', true);
    } catch {
      // ignore
    }
    process.stdout.write(dim('Noted. Enable later: opena2a protect --1password') + '\n');
    return false;
  }

  if (userChoice === 'no') {
    return false;
  }

  // Step 2: Prerequisites
  process.stdout.write('\n' + bold('Prerequisites') + '\n\n');
  process.stdout.write('Before migrating, you need:\n\n');
  process.stdout.write('  1. ' + bold('1Password desktop app') + '\n');
  process.stdout.write('     Download: ' + cyan('https://1password.com/downloads') + '\n\n');
  process.stdout.write('  2. ' + bold('Developer settings enabled') + '\n');
  process.stdout.write('     1Password > Settings > Developer > "Integrate with 1Password CLI"\n\n');
  process.stdout.write('  3. ' + bold('1Password CLI') + '\n');
  process.stdout.write('     Install: ' + cyan('brew install 1password-cli') + '\n\n');
  process.stdout.write('  ' + dim('Tip: If you use 1Password as your SSH agent, set key approval to') + '\n');
  process.stdout.write('  ' + dim('"Until 1Password is locked" to avoid repeated Touch ID prompts') + '\n');
  process.stdout.write('  ' + dim('during AI-assisted development (each git operation triggers approval).') + '\n\n');

  let ready = false;
  try {
    const { confirm } = await import('@inquirer/prompts');
    ready = await confirm({ message: 'Ready?', default: true });
  } catch {
    return false;
  }

  if (!ready) {
    process.stdout.write(dim('Run this flow again after setup: opena2a protect .') + '\n');
    return false;
  }

  // Step 3: Verify 1Password CLI
  const spinner = new Spinner('Checking 1Password CLI...');
  spinner.start();

  const opAvailable = await check1PasswordCli();
  spinner.stop();

  if (!opAvailable) {
    process.stdout.write(red('1Password CLI not found or not authenticated.') + '\n');
    process.stdout.write(dim('Install: brew install 1password-cli') + '\n');
    process.stdout.write(dim('Then: op signin') + '\n');
    return false;
  }

  process.stdout.write(green('1Password CLI verified.') + '\n\n');

  // Step 4: Show plan
  process.stdout.write(cyan('What will happen:') + '\n');
  process.stdout.write(`  1. Create a "Secretless" vault in 1Password (if needed)\n`);
  process.stdout.write(`  2. Copy ${ctx.credentialCount} secret(s) from local vault to 1Password\n`);
  process.stdout.write(`  3. Set 1Password as the default Secretless backend\n\n`);
  process.stdout.write(dim('If anything goes wrong:') + '\n');
  process.stdout.write(`  - Your local vault is preserved (not deleted)\n`);
  process.stdout.write(`  - Run: ${cyan('secretless-ai backend set local')} to revert\n\n`);

  let proceed = false;
  try {
    const { confirm } = await import('@inquirer/prompts');
    proceed = await confirm({ message: 'Proceed with migration?', default: true });
  } catch {
    return false;
  }

  if (!proceed) {
    return false;
  }

  // Step 5: Execute migration
  spinner.update('Migrating secrets to 1Password...');
  spinner.start();

  try {
    const secretless = await (Function('return import("secretless-ai")')() as Promise<any>);
    const mod = 'default' in secretless ? secretless.default : secretless;

    // Attempt migration
    if (mod.migrateSecrets && mod.createBackend) {
      const sourceBackend = mod.createBackend('local');
      const destBackend   = mod.createBackend('1password');
      const result = await mod.migrateSecrets(sourceBackend, destBackend, {
        deleteFromSource: false,
        prefix: 'secret',
      });
      spinner.stop();

      const migrated = result?.migrated ?? 0;
      const failed = result?.failed ?? 0;

      if (failed > 0) {
        process.stdout.write(yellow(`Migrated ${migrated}, failed ${failed} secret(s).`) + '\n');
      } else {
        process.stdout.write(green(`Successfully migrated ${migrated} secret(s) to 1Password.`) + '\n');
      }
    } else {
      spinner.stop();
      process.stdout.write(yellow('Migration API not available in this version of secretless-ai.') + '\n');
      process.stdout.write(dim('Update: npm install -g secretless-ai@latest') + '\n');
      return false;
    }

    // Step 6: Set default backend
    if (mod.writeBackendConfig) {
      mod.writeBackendConfig('1password');
      process.stdout.write(green('Default backend set to 1Password.') + '\n');
    }

    // Remind about SSH agent approval if applicable
    process.stdout.write('\n' + dim('If Touch ID prompts are frequent: 1Password > Settings > Developer >') + '\n');
    process.stdout.write(dim('SSH keys > set approval to "Until 1Password is locked"') + '\n');

    return true;
  } catch (err) {
    spinner.stop();
    process.stderr.write(red('Migration failed: ') + (err instanceof Error ? err.message : String(err)) + '\n');
    process.stdout.write(dim('Your local vault is unchanged. Run: secretless-ai backend set local') + '\n');
    return false;
  }
}

/**
 * Check if 1Password CLI is installed and authenticated.
 */
async function check1PasswordCli(): Promise<boolean> {
  try {
    const { execSync } = await import('node:child_process');
    execSync('op account get', { stdio: 'pipe', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}
