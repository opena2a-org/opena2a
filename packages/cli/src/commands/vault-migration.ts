/**
 * Guided HashiCorp Vault migration flow.
 *
 * Called from protect.ts after successful credential migration to local vault.
 * Walks users through connecting to a Vault server, verifying connectivity,
 * and migrating secrets from the local Secretless vault to Vault.
 *
 * Requires: VAULT_ADDR + VAULT_TOKEN (or guided env var setup).
 * Uses native fetch -- no Vault SDK dependency.
 */

import { bold, cyan, dim, green, red, yellow } from '../util/colors.js';
import { Spinner } from '../util/spinner.js';

interface VaultMigrationContext {
  credentialCount: number;
  ci?: boolean;
}

export async function offerVaultMigration(ctx: VaultMigrationContext): Promise<boolean> {
  if (ctx.ci || !process.stdin.isTTY) return false;

  // Step 1: Detect existing config
  const hasAddr  = !!process.env['VAULT_ADDR'];
  const hasToken = !!process.env['VAULT_TOKEN'];
  const hasConfig = hasAddr && hasToken;

  process.stdout.write('\n' + bold('HashiCorp Vault Setup') + '\n\n');

  if (hasConfig) {
    process.stdout.write(
      `  VAULT_ADDR   ${cyan(process.env['VAULT_ADDR']!)}\n` +
      `  VAULT_TOKEN  ${dim('(set)')}\n\n`
    );
  } else {
    process.stdout.write(
      dim('  VAULT_ADDR and VAULT_TOKEN not detected.\n\n')
    );
  }

  process.stdout.write(
    `Your ${ctx.credentialCount} credential(s) are in the local encrypted vault.\n` +
    'Migrating to HashiCorp Vault gives you:\n\n' +
    '  - Centralized secrets accessible across machines and CI/CD\n' +
    '  - Fine-grained access policies and audit logging\n' +
    '  - Dynamic secrets and automatic rotation (Vault paid tiers)\n\n'
  );

  // Step 2: Do they have a Vault server?
  let vaultMode: string;
  try {
    const { select } = await import('@inquirer/prompts');
    vaultMode = await select({
      message: 'Which Vault setup are you using?',
      choices: [
        {
          name: 'I have a Vault server already (self-hosted or HCP Vault)',
          value: 'existing',
          description: 'You have VAULT_ADDR and VAULT_TOKEN available',
        },
        {
          name: 'Start a local dev server for testing (vault server -dev)',
          value: 'dev',
          description: 'Spins up an in-memory Vault — not for production use',
        },
        {
          name: 'Back',
          value: 'back',
        },
      ],
    });
  } catch {
    return false;
  }

  if (vaultMode === 'back') return false;

  // Step 3: Dev server path
  if (vaultMode === 'dev') {
    process.stdout.write('\n' + bold('Local Dev Server') + '\n\n');
    process.stdout.write(
      'Run this in a separate terminal:\n\n' +
      `  ${cyan('vault server -dev')}\n\n` +
      'Vault will print a root token and address. Copy them:\n\n' +
      `  ${cyan('export VAULT_ADDR=http://127.0.0.1:8200')}\n` +
      `  ${cyan('export VAULT_TOKEN=<root-token-from-output>')}\n\n` +
      dim('  Note: dev server data is in-memory and lost on restart.\n') +
      dim('  For persistent storage use a production Vault setup.\n\n')
    );

    let ready = false;
    try {
      const { confirm } = await import('@inquirer/prompts');
      ready = await confirm({ message: 'Server running and env vars set?', default: false });
    } catch {
      return false;
    }
    if (!ready) {
      process.stdout.write(dim('Run this flow again after setup: opena2a protect\n'));
      return false;
    }
  }

  // Step 4: Collect env vars if not already set
  let vaultAddr  = process.env['VAULT_ADDR']  ?? '';
  let vaultToken = process.env['VAULT_TOKEN'] ?? '';

  if (!vaultAddr || !vaultToken) {
    process.stdout.write('\n' + bold('Connection Details') + '\n\n');
    try {
      const { input, password } = await import('@inquirer/prompts');
      if (!vaultAddr) {
        vaultAddr = await input({
          message: 'Vault address (VAULT_ADDR):',
          default: 'http://127.0.0.1:8200',
        });
      }
      if (!vaultToken) {
        vaultToken = await password({
          message: 'Vault token (VAULT_TOKEN):',
          mask: '*',
        });
      }
    } catch {
      return false;
    }

    if (!vaultAddr || !vaultToken) {
      process.stdout.write(red('Vault address and token are required.\n'));
      return false;
    }

    if (!/^https?:\/\//i.test(vaultAddr)) {
      process.stdout.write(red('Vault address must start with http:// or https://\n'));
      return false;
    }

    // Set for this process so the backend picks them up
    process.env['VAULT_ADDR']  = vaultAddr;
    process.env['VAULT_TOKEN'] = vaultToken;
  }

  // Step 5: Verify connectivity
  const spinner = new Spinner('Checking Vault connectivity...');
  spinner.start();

  const healthy = await checkVaultHealth(vaultAddr, vaultToken);
  spinner.stop();

  if (!healthy) {
    process.stdout.write(red('Cannot reach Vault at ' + vaultAddr + '.\n'));
    process.stdout.write(
      dim('Check that:\n') +
      dim('  - The server is running and unsealed\n') +
      dim('  - VAULT_ADDR is correct (include http:// or https://)\n') +
      dim('  - The token is valid\n\n')
    );
    return false;
  }

  process.stdout.write(green('Connected to Vault at ' + vaultAddr + '.\n\n'));

  // Step 6: Show plan
  process.stdout.write(cyan('What will happen:') + '\n');
  process.stdout.write(`  1. Write ${ctx.credentialCount} secret(s) to Vault KV v2 engine (mount: secret/)\n`);
  process.stdout.write(`  2. Set Vault as the default Secretless backend\n\n`);
  process.stdout.write(dim('If anything goes wrong:\n'));
  process.stdout.write(dim('  - Your local vault is preserved (not deleted)\n'));
  process.stdout.write(dim('  - Run: secretless-ai backend set local  to revert\n\n'));

  let proceed = false;
  try {
    const { confirm } = await import('@inquirer/prompts');
    proceed = await confirm({ message: 'Proceed with migration?', default: true });
  } catch {
    return false;
  }
  if (!proceed) return false;

  // Step 7: Execute migration
  spinner.update('Migrating secrets to Vault...');
  spinner.start();

  try {
    const secretless = await import('secretless-ai') as any;
    const mod = 'default' in secretless ? secretless.default : secretless;

    if (mod.migrateSecrets && mod.createBackend) {
      const sourceBackend = mod.createBackend('local');
      const destBackend   = mod.createBackend('vault', { addr: vaultAddr, token: vaultToken });
      const result = await mod.migrateSecrets(sourceBackend, destBackend, { deleteFromSource: false, prefix: '' });
      spinner.stop();

      const migrated = result?.migrated ?? 0;
      const failed   = result?.failed   ?? 0;

      if (failed > 0) {
        process.stdout.write(yellow(`Migrated ${migrated}, failed ${failed} secret(s).\n`));
      } else {
        process.stdout.write(green(`Successfully migrated ${migrated} secret(s) to Vault.\n`));
      }
    } else {
      spinner.stop();
      process.stdout.write(yellow('Migration API not available in this version of secretless-ai.\n'));
      process.stdout.write(dim('Update: npm install -g secretless-ai@latest\n'));
      return false;
    }

    if (mod.writeBackendConfig) {
      mod.writeBackendConfig('vault');
      process.stdout.write(green('Default backend set to Vault.\n'));
    }

    process.stdout.write(
      '\n' + dim('Add to your shell profile to persist the connection:\n') +
      `  ${cyan(`export VAULT_ADDR=${vaultAddr}`)}\n` +
      `  ${cyan('export VAULT_TOKEN=<your-token>')}\n\n`
    );

    return true;
  } catch (err) {
    spinner.stop();
    process.stderr.write(red('Migration failed: ') + (err instanceof Error ? err.message : String(err)) + '\n');
    process.stdout.write(dim('Your local vault is unchanged. Run: secretless-ai backend set local\n'));
    return false;
  }
}

async function checkVaultHealth(addr: string, token: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5_000);
    const res = await fetch(`${addr}/v1/sys/health`, {
      headers: { 'X-Vault-Token': token },
      signal: controller.signal,
    });
    clearTimeout(timeout);
    // 200 = active, 429/472/473 = standby modes — all connectable
    return [200, 429, 472, 473].includes(res.status);
  } catch {
    return false;
  }
}
