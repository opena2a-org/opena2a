import * as path from 'path';
import { bold, dim, green, yellow, gray, cyan } from '../util/colors.js';

interface IdentityOptions {
  subcommand: string;
  name?: string;
  limit?: number;
  dir?: string;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
}

export async function identity(options: IdentityOptions): Promise<number> {
  const sub = options.subcommand;
  switch (sub) {
    case 'list':
    case 'show':
      return handleList(options);
    case 'create':
      return handleCreate(options);
    case 'trust':
      return handleTrust(options);
    case 'audit':
      return handleAudit(options);
    default:
      process.stderr.write(`Unknown identity subcommand: ${sub}\n`);
      process.stderr.write('\nUsage: opena2a identity <list|create|trust|audit>\n\n');
      process.stderr.write('  list               Show local agent identity\n');
      process.stderr.write('  create --name <n>  Create a new agent identity\n');
      process.stderr.write('  trust              Show trust score\n');
      process.stderr.write('  audit [--limit N]  Show recent audit events\n');
      return 1;
  }
}

async function loadAimCore(): Promise<typeof import('@opena2a/aim-core') | null> {
  try {
    return await import('@opena2a/aim-core');
  } catch {
    process.stderr.write('aim-core is not available.\n');
    process.stderr.write('Install: npm install @opena2a/aim-core\n');
    return null;
  }
}

async function handleList(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const isJson = options.format === 'json';

  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    const id = aim.getIdentity();

    if (isJson) {
      process.stdout.write(JSON.stringify(id, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(bold('Agent Identity') + '\n');
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    process.stdout.write(`  Agent ID:    ${cyan(id.agentId)}\n`);
    process.stdout.write(`  Name:        ${id.agentName}\n`);
    process.stdout.write(`  Public Key:  ${dim(id.publicKey.slice(0, 32) + '...')}\n`);
    process.stdout.write(`  Created:     ${id.createdAt}\n`);
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to load identity: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

async function handleCreate(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const name = options.name;
  if (!name) {
    process.stderr.write('Missing required option: --name <name>\n');
    process.stderr.write('Usage: opena2a identity create --name my-agent\n');
    return 1;
  }

  const isJson = options.format === 'json';

  try {
    const aim = new mod.AIMCore({ agentName: name });
    const id = aim.getIdentity();

    if (isJson) {
      process.stdout.write(JSON.stringify(id, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(green('Identity created') + '\n');
    process.stdout.write(`  Agent ID:    ${cyan(id.agentId)}\n`);
    process.stdout.write(`  Name:        ${id.agentName}\n`);
    process.stdout.write(`  Public Key:  ${dim(id.publicKey.slice(0, 32) + '...')}\n`);
    process.stdout.write(`  Stored in:   ${dim(aim.getDataDir())}\n`);
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to create identity: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

async function handleTrust(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const isJson = options.format === 'json';

  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    aim.getIdentity(); // ensure identity exists
    const trust = aim.calculateTrust();

    if (isJson) {
      process.stdout.write(JSON.stringify(trust, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(bold('Trust Score') + '\n');
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    const displayScore = trust.score ?? Math.round((trust.overall ?? 0) * 100);
    const displayGrade = trust.grade ?? (displayScore >= 80 ? 'A' : displayScore >= 60 ? 'B' : displayScore >= 40 ? 'C' : displayScore >= 20 ? 'D' : 'F');
    process.stdout.write(`  Score:  ${bold(String(displayScore))}  Grade: ${bold(displayGrade)}\n`);
    process.stdout.write('\n');
    process.stdout.write('  Factors:\n');
    for (const [factor, value] of Object.entries(trust.factors)) {
      const label = factor.replace(/([A-Z])/g, ' $1').toLowerCase().trim();
      const status = value > 0 ? green('active') : dim('inactive');
      process.stdout.write(`    ${label.padEnd(22)} ${status}\n`);
    }
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to calculate trust: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

async function handleAudit(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const isJson = options.format === 'json';
  const limit = options.limit ?? 10;

  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    const events = aim.readAuditLog({ limit });

    if (isJson) {
      process.stdout.write(JSON.stringify(events, null, 2) + '\n');
      return 0;
    }

    if (events.length === 0) {
      process.stdout.write(dim('No audit events recorded yet.') + '\n');
      process.stdout.write(dim('Events are logged when using aim-core in your agent.') + '\n');
      return 0;
    }

    process.stdout.write(bold(`Audit Log (last ${events.length})`) + '\n');
    process.stdout.write(gray('-'.repeat(70)) + '\n');
    for (const e of events) {
      const ts = e.timestamp.slice(0, 19).replace('T', ' ');
      const resultColor = e.result === 'allowed' ? green : e.result === 'denied' ? yellow : dim;
      process.stdout.write(`  ${dim(ts)}  ${e.action.padEnd(16)} ${e.target.padEnd(16)} ${resultColor(e.result)}\n`);
    }
    process.stdout.write(gray('-'.repeat(70)) + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to read audit log: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}
