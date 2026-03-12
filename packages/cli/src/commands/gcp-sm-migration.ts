/**
 * Guided GCP Secret Manager migration flow.
 *
 * Called from protect.ts after successful credential migration to local vault.
 * Walks users through connecting to GCP Secret Manager, verifying credentials,
 * and migrating secrets from the local Secretless vault to GCP SM.
 *
 * Requires: Application Default Credentials (ADC) or GOOGLE_APPLICATION_CREDENTIALS.
 * Uses native fetch -- no GCP SDK dependency.
 */

import { bold, cyan, dim, green, red, yellow } from '../util/colors.js';
import { Spinner } from '../util/spinner.js';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

interface GCPSMMigrationContext {
  credentialCount: number;
  ci?: boolean;
}

export async function offerGCPSMMigration(ctx: GCPSMMigrationContext): Promise<boolean> {
  if (ctx.ci || !process.stdin.isTTY) return false;

  // Step 1: Detect existing credentials
  const hasKeyFile = !!process.env['GOOGLE_APPLICATION_CREDENTIALS'] &&
    fs.existsSync(process.env['GOOGLE_APPLICATION_CREDENTIALS']!);
  const adcPath = path.join(os.homedir(), '.config', 'gcloud', 'application_default_credentials.json');
  const hasADC = fs.existsSync(adcPath);
  const hasCredentials = hasKeyFile || hasADC;

  process.stdout.write('\n' + bold('GCP Secret Manager Setup') + '\n\n');

  if (hasKeyFile) {
    process.stdout.write(
      `  Credentials  ${cyan('Service account key found')}\n` +
      `  Key file     ${dim(process.env['GOOGLE_APPLICATION_CREDENTIALS']!)}\n\n`
    );
  } else if (hasADC) {
    process.stdout.write(
      `  Credentials  ${cyan('Application Default Credentials found')}\n\n`
    );
  } else {
    process.stdout.write(
      dim('  No GCP credentials detected.\n\n')
    );
  }

  process.stdout.write(
    `Your ${ctx.credentialCount} credential(s) are in the local encrypted vault.\n` +
    'Migrating to GCP Secret Manager gives you:\n\n' +
    '  - Centralized secrets managed through GCP IAM\n' +
    '  - Automatic versioning and audit logging\n' +
    '  - Native integration with Cloud Run, GKE, and Cloud Functions\n\n'
  );

  // Step 2: Auth method selection
  let authMode: string;
  try {
    const { select } = await import('@inquirer/prompts');
    authMode = await select({
      message: 'How do you authenticate with GCP?',
      choices: [
        {
          name: 'Application Default Credentials (gcloud auth application-default login)',
          value: 'adc',
          description: hasADC ? 'ADC detected on this machine' : 'Run gcloud auth application-default login first',
        },
        {
          name: 'Service account key file (GOOGLE_APPLICATION_CREDENTIALS)',
          value: 'service-account',
          description: hasKeyFile ? 'Key file detected' : 'Set GOOGLE_APPLICATION_CREDENTIALS env var',
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

  if (authMode === 'back') return false;

  // Step 3: Ensure credentials are available
  if (authMode === 'adc' && !hasADC) {
    process.stdout.write('\n' + bold('Set Up Application Default Credentials') + '\n\n');
    process.stdout.write(
      'Run this command to authenticate:\n\n' +
      `  ${cyan('gcloud auth application-default login')}\n\n` +
      dim('This opens a browser to authenticate with your Google account.\n\n')
    );

    let ready = false;
    try {
      const { confirm } = await import('@inquirer/prompts');
      ready = await confirm({ message: 'ADC set up?', default: false });
    } catch {
      return false;
    }
    if (!ready) {
      process.stdout.write(dim('Run this flow again after setup: opena2a protect\n'));
      return false;
    }
  }

  if (authMode === 'service-account' && !hasKeyFile) {
    process.stdout.write('\n' + bold('Service Account Key') + '\n\n');
    let keyPath: string;
    try {
      const { input } = await import('@inquirer/prompts');
      keyPath = await input({
        message: 'Path to service account key JSON file:',
      });
    } catch {
      return false;
    }

    if (!keyPath || !fs.existsSync(keyPath)) {
      process.stdout.write(red('File not found: ' + keyPath + '\n'));
      return false;
    }

    process.env['GOOGLE_APPLICATION_CREDENTIALS'] = keyPath;
  }

  // Step 4: Get project ID
  let projectId = '';

  // Try to auto-detect from credentials
  if (process.env['GOOGLE_APPLICATION_CREDENTIALS']) {
    try {
      const raw = fs.readFileSync(process.env['GOOGLE_APPLICATION_CREDENTIALS'], 'utf-8');
      const key = JSON.parse(raw) as { project_id?: string };
      if (key.project_id) projectId = key.project_id;
    } catch {
      // ignore
    }
  }

  if (!projectId && hasADC) {
    try {
      const raw = fs.readFileSync(adcPath, 'utf-8');
      const adc = JSON.parse(raw) as { quota_project_id?: string };
      if (adc.quota_project_id) projectId = adc.quota_project_id;
    } catch {
      // ignore
    }
  }

  if (!projectId) {
    try {
      const { input } = await import('@inquirer/prompts');
      projectId = await input({
        message: 'GCP project ID:',
      });
    } catch {
      return false;
    }
  } else {
    process.stdout.write(`\n  Detected project: ${cyan(projectId)}\n`);
    try {
      const { confirm } = await import('@inquirer/prompts');
      const useDetected = await confirm({ message: `Use project ${projectId}?`, default: true });
      if (!useDetected) {
        const { input } = await import('@inquirer/prompts');
        projectId = await input({ message: 'GCP project ID:' });
      }
    } catch {
      return false;
    }
  }

  if (!projectId) {
    process.stdout.write(red('Project ID is required.\n'));
    return false;
  }

  // Step 5: Verify connectivity
  const spinner = new Spinner('Checking GCP Secret Manager access...');
  spinner.start();

  try {
    const secretless = await (Function('return import("secretless-ai")')() as Promise<any>);
    const mod = 'default' in secretless ? secretless.default : secretless;

    if (!mod.createBackend) {
      spinner.stop();
      process.stdout.write(yellow('Migration API not available. Update: npm install -g secretless-ai@latest\n'));
      return false;
    }

    const gcpBackend = mod.createBackend('gcp-sm', { projectId }, true);
    const health = await gcpBackend.healthCheck();
    spinner.stop();

    if (!health.healthy) {
      process.stdout.write(red('Cannot access GCP Secret Manager.\n'));
      process.stdout.write(
        dim('Check that:\n') +
        dim('  - The project ID is correct\n') +
        dim('  - Your credentials have Secret Manager Admin role\n') +
        dim('  - The Secret Manager API is enabled in your project\n') +
        dim(`  - Status: ${health.message}\n\n`)
      );
      return false;
    }

    process.stdout.write(green(`Connected to GCP Secret Manager (project: ${projectId}).\n\n`));

    // Step 6: Show plan
    process.stdout.write(cyan('What will happen:') + '\n');
    process.stdout.write(`  1. Write ${ctx.credentialCount} secret(s) to GCP Secret Manager\n`);
    process.stdout.write(`  2. Save project ID to ~/.secretless-ai/config.json\n`);
    process.stdout.write(`  3. Set gcp-sm as the default Secretless backend\n\n`);
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

    // Step 7: Save project ID to config
    try {
      const configDir = path.join(os.homedir(), '.secretless-ai');
      const configPath = path.join(configDir, 'config.json');
      let config: Record<string, unknown> = {};
      try {
        const raw = fs.readFileSync(configPath, 'utf-8');
        config = JSON.parse(raw);
      } catch {
        // Fresh config
      }
      config.gcp = { projectId };
      fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(configPath + '.tmp', JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
      fs.renameSync(configPath + '.tmp', configPath);
    } catch {
      // Config save is best-effort
    }

    // Step 8: Execute migration
    spinner.update('Migrating secrets to GCP Secret Manager...');
    spinner.start();

    const sourceBackend = mod.createBackend('local');
    const destBackend = mod.createBackend('gcp-sm', { projectId }, true);
    const result = await mod.migrateSecrets(sourceBackend, destBackend, { deleteFromSource: false, prefix: '' });
    spinner.stop();

    const migrated = result?.migrated ?? 0;
    const failed = result?.failed ?? 0;

    if (failed > 0) {
      process.stdout.write(yellow(`Migrated ${migrated}, failed ${failed} secret(s).\n`));
      if (result?.errors?.length) {
        for (const err of result.errors) {
          process.stdout.write(dim(`  - ${err.key}: ${err.message}\n`));
        }
      }
    } else {
      process.stdout.write(green(`Successfully migrated ${migrated} secret(s) to GCP Secret Manager.\n`));
    }

    if (mod.writeBackendConfig) {
      mod.writeBackendConfig('gcp-sm');
      process.stdout.write(green('Default backend set to GCP Secret Manager.\n'));
    }

    process.stdout.write(
      '\n' + dim('GCP Secret Manager is now your default backend.\n') +
      dim('Manage secrets: npx secretless-ai secret list\n') +
      dim('View in console: https://console.cloud.google.com/security/secret-manager?project=' + projectId + '\n\n')
    );

    return true;
  } catch (err) {
    spinner.stop();
    process.stderr.write(red('Migration failed: ') + (err instanceof Error ? err.message : String(err)) + '\n');
    process.stdout.write(dim('Your local vault is unchanged. Run: secretless-ai backend set local\n'));
    return false;
  }
}
