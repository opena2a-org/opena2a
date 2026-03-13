import * as path from 'path';
import * as fs from 'fs';
import { bold, dim, green, yellow, red, gray, cyan } from '../util/colors.js';

interface IdentityOptions {
  subcommand: string;
  name?: string;
  limit?: number;
  dir?: string;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
  capability?: string;
  plugin?: string;
  action?: string;
  target?: string;
  result?: string;
  file?: string;
  data?: string;
  signature?: string;
  publicKey?: string;
}

const USAGE = [
  '',
  'Usage: opena2a identity <subcommand>',
  '',
  'Identity & Keys',
  '  list               Show local agent identity',
  '  create --name <n>  Create a new agent identity',
  '  sign --data <d>    Sign data with agent private key',
  '  verify             Verify a signature against a public key',
  '',
  'Trust & Audit',
  '  trust              Show trust score with factor breakdown',
  '  audit [--limit N]  Show recent audit events',
  '  log                Log an audit event manually',
  '',
  'Policy',
  '  policy             Show current capability policy',
  '  policy load <file> Load a YAML capability policy',
  '  check <capability> Check if a capability is allowed',
  '',
].join('\n');

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
    case 'log':
      return handleLog(options);
    case 'policy':
      return handlePolicy(options);
    case 'check':
      return handleCheck(options);
    case 'sign':
      return handleSign(options);
    case 'verify':
      return handleVerify(options);
    default:
      process.stderr.write(`Unknown identity subcommand: ${sub}\n`);
      process.stderr.write(USAGE + '\n');
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

// ---------------------------------------------------------------------------
// list / show
// ---------------------------------------------------------------------------

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
    process.stdout.write(`  Data Dir:    ${dim(aim.getDataDir())}\n`);
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to load identity: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// trust
// ---------------------------------------------------------------------------

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

    const displayScore = trust.score ?? Math.round((trust.overall ?? 0) * 100);
    const displayGrade = trust.grade ?? scoreToGrade(displayScore);
    const gradeColor = displayScore >= 80 ? green : displayScore >= 60 ? yellow : red;

    process.stdout.write(bold('Trust Score') + '\n');
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    process.stdout.write(`  Score:  ${gradeColor(bold(String(displayScore) + '/100'))}  (${gradeColor(displayGrade)})\n`);
    process.stdout.write('\n');
    process.stdout.write(bold('  Factors:') + '\n');
    for (const [factor, value] of Object.entries(trust.factors)) {
      const label = factor.replace(/([A-Z])/g, ' $1').toLowerCase().trim();
      const pct = Math.round((value as number) * 100);
      const bar = progressBar(pct, 20);
      process.stdout.write(`    ${label.padEnd(18)} ${bar} ${pct}%\n`);
    }
    process.stdout.write(gray('-'.repeat(50)) + '\n');

    if (options.verbose && trust.calculatedAt) {
      process.stdout.write(dim(`  Calculated: ${trust.calculatedAt}`) + '\n');
    }
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to calculate trust: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

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
      process.stdout.write(dim('Log events with: opena2a identity log --action <action> --target <target>') + '\n');
      return 0;
    }

    process.stdout.write(bold(`Audit Log (last ${events.length})`) + '\n');
    process.stdout.write(gray('-'.repeat(70)) + '\n');
    for (const e of events) {
      const ts = e.timestamp.slice(0, 19).replace('T', ' ');
      const resultColor = e.result === 'allowed' ? green : e.result === 'denied' ? red : yellow;
      const pluginLabel = e.plugin && e.plugin !== 'unknown' ? dim(` [${e.plugin}]`) : '';
      process.stdout.write(`  ${dim(ts)}  ${(e.action ?? '').padEnd(16)} ${(e.target ?? '').padEnd(16)} ${resultColor(e.result ?? '')}${pluginLabel}\n`);
    }
    process.stdout.write(gray('-'.repeat(70)) + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to read audit log: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// log -- write an audit event
// ---------------------------------------------------------------------------

async function handleLog(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const action = options.action;
  if (!action) {
    process.stderr.write('Missing required option: --action <action>\n');
    process.stderr.write('Usage: opena2a identity log --action db:read --target customers [--result allowed]\n');
    return 1;
  }

  const isJson = options.format === 'json';

  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    aim.getIdentity(); // ensure identity exists

    const event = aim.logEvent({
      action,
      target: options.target ?? '',
      result: (options.result as 'allowed' | 'denied' | 'error') ?? 'allowed',
      plugin: options.plugin ?? 'cli',
    });

    if (isJson) {
      process.stdout.write(JSON.stringify(event, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(green('Event logged') + '\n');
    process.stdout.write(`  Action:  ${event.action}\n`);
    process.stdout.write(`  Target:  ${event.target}\n`);
    process.stdout.write(`  Result:  ${event.result}\n`);
    process.stdout.write(`  Time:    ${dim(event.timestamp)}\n`);
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to log event: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// policy -- show or load capability policy
// ---------------------------------------------------------------------------

async function handlePolicy(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const isJson = options.format === 'json';
  const args = options.file ? ['load', options.file] : [];

  // If first positional arg is "load", load a YAML policy
  if (args[0] === 'load' || options.file) {
    return handlePolicyLoad(mod, options);
  }

  // Otherwise show the current policy
  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    const p = aim.loadPolicy() as { defaultAction: string; rules: Array<{ capability: string; action: string; plugins?: string[] }> };

    if (isJson) {
      process.stdout.write(JSON.stringify(p, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(bold('Capability Policy') + '\n');
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    process.stdout.write(`  Default: ${p.defaultAction === 'deny' ? red('deny') : green('allow')}\n`);
    process.stdout.write(`  Rules:   ${p.rules.length}\n`);
    process.stdout.write('\n');

    if (p.rules.length === 0) {
      process.stdout.write(dim('  No rules defined.') + '\n');
      process.stdout.write(dim('  Load a policy: opena2a identity policy --file policy.yaml') + '\n');
    } else {
      for (const rule of p.rules) {
        const actionColor = rule.action === 'allow' ? green : red;
        const pluginNote = rule.plugins?.length ? dim(` (plugins: ${rule.plugins.join(', ')})`) : '';
        process.stdout.write(`  ${actionColor(rule.action.padEnd(5))}  ${rule.capability}${pluginNote}\n`);
      }
    }
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to read policy: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

async function handlePolicyLoad(mod: typeof import('@opena2a/aim-core'), options: IdentityOptions): Promise<number> {
  const filePath = options.file;
  if (!filePath) {
    process.stderr.write('Missing file path.\n');
    process.stderr.write('Usage: opena2a identity policy --file policy.yaml\n');
    return 1;
  }

  const isJson = options.format === 'json';
  const resolved = path.resolve(filePath);

  if (!fs.existsSync(resolved)) {
    process.stderr.write(`File not found: ${resolved}\n`);
    return 1;
  }

  try {
    const content = fs.readFileSync(resolved, 'utf-8');
    let parsed: any;

    if (resolved.endsWith('.json')) {
      parsed = JSON.parse(content);
    } else {
      // Simple YAML parsing for policy files
      // Supports the common format: version, defaultAction, rules[]
      const yaml = await import('node:fs');
      // For now, only support JSON policies. YAML requires a parser.
      process.stderr.write('Only JSON policy files are supported. Convert your YAML to JSON.\n');
      process.stderr.write('Example: { "version": "1", "defaultAction": "deny", "rules": [{"capability": "db:read", "action": "allow"}] }\n');
      return 1;
    }

    const aim = new mod.AIMCore({ agentName: 'default' });
    (aim as any).savePolicy(parsed);

    if (isJson) {
      process.stdout.write(JSON.stringify({ loaded: true, rules: parsed.rules?.length ?? 0, path: resolved }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(green('Policy loaded') + '\n');
    process.stdout.write(`  File:    ${dim(resolved)}\n`);
    process.stdout.write(`  Default: ${parsed.defaultAction}\n`);
    process.stdout.write(`  Rules:   ${parsed.rules?.length ?? 0}\n`);
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to load policy: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// check -- check if a capability is allowed
// ---------------------------------------------------------------------------

async function handleCheck(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const capability = options.capability;
  if (!capability) {
    process.stderr.write('Missing capability to check.\n');
    process.stderr.write('Usage: opena2a identity check <capability> [--plugin <name>]\n');
    return 1;
  }

  const isJson = options.format === 'json';

  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    aim.loadPolicy(); // load from file

    const allowed = aim.checkCapability(capability, options.plugin);

    if (isJson) {
      process.stdout.write(JSON.stringify({ capability, allowed, plugin: options.plugin ?? null }, null, 2) + '\n');
      return 0;
    }

    const label = allowed ? green('ALLOWED') : red('DENIED');
    process.stdout.write(`${label}  ${capability}`);
    if (options.plugin) process.stdout.write(dim(` (plugin: ${options.plugin})`));
    process.stdout.write('\n');
    return allowed ? 0 : 1;
  } catch (err) {
    process.stderr.write(`Failed to check capability: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// sign -- sign data with agent private key
// ---------------------------------------------------------------------------

async function handleSign(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const data = options.data;
  if (!data) {
    process.stderr.write('Missing required option: --data <string>\n');
    process.stderr.write('Usage: opena2a identity sign --data "message to sign"\n');
    return 1;
  }

  const isJson = options.format === 'json';

  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    const id = aim.getIdentity();
    const dataBytes = new TextEncoder().encode(data);
    const signature = aim.sign(dataBytes);
    const sigBase64 = Buffer.from(signature).toString('base64');

    if (isJson) {
      process.stdout.write(JSON.stringify({
        data,
        signature: sigBase64,
        publicKey: id.publicKey,
        agentId: id.agentId,
      }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(bold('Signature') + '\n');
    process.stdout.write(`  Data:       ${dim(data.length > 60 ? data.slice(0, 60) + '...' : data)}\n`);
    process.stdout.write(`  Signature:  ${sigBase64}\n`);
    process.stdout.write(`  Public Key: ${dim(id.publicKey)}\n`);
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to sign: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// verify -- verify a signature
// ---------------------------------------------------------------------------

async function handleVerify(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const data = options.data;
  const signature = options.signature;
  const publicKey = options.publicKey;

  if (!data || !signature || !publicKey) {
    process.stderr.write('Missing required options.\n');
    process.stderr.write('Usage: opena2a identity verify --data "message" --signature <base64> --public-key <base64>\n');
    return 1;
  }

  const isJson = options.format === 'json';

  try {
    const mod2 = await loadAimCore();
    if (!mod2) return 1;

    const aim = new mod2.AIMCore({ agentName: 'default' });
    const dataBytes = new TextEncoder().encode(data);
    const sigBytes = new Uint8Array(Buffer.from(signature, 'base64'));
    const valid = aim.verify(dataBytes, sigBytes, publicKey);

    if (isJson) {
      process.stdout.write(JSON.stringify({ valid, data, publicKey }, null, 2) + '\n');
      return 0;
    }

    if (valid) {
      process.stdout.write(green('VALID') + '  Signature verified\n');
    } else {
      process.stdout.write(red('INVALID') + '  Signature verification failed\n');
    }
    return valid ? 0 : 1;
  } catch (err) {
    process.stderr.write(`Failed to verify: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function scoreToGrade(score: number): string {
  if (score >= 80) return 'strong';
  if (score >= 60) return 'good';
  if (score >= 40) return 'moderate';
  if (score >= 20) return 'improving';
  return 'needs-attention';
}

function progressBar(pct: number, width: number): string {
  const filled = Math.round((pct / 100) * width);
  const empty = width - filled;
  return green('#'.repeat(filled)) + dim('.'.repeat(empty));
}
