import * as path from 'path';
import * as fs from 'fs';
import { bold, dim, green, yellow, red, gray, cyan } from '../util/colors.js';

interface PolicyRule {
  capability: string;
  action: 'allow' | 'deny';
  plugins?: string[];
}

interface Policy {
  version: string;
  defaultAction: 'allow' | 'deny';
  rules: PolicyRule[];
}

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
  tools?: string;
  all?: boolean;
  autoSync?: boolean;
}

const USAGE = [
  '',
  'Usage: opena2a identity <subcommand>',
  '',
  'Identity & Keys',
  '  list               Show local agent identity',
  '  create --name <n>  Create a new agent identity',
  '  sign --data <d>    Sign a string with agent private key',
  '  sign --file <f>    Sign a file with agent private key',
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
  'Cross-Tool Integration',
  '  attach [--tools <list>]  Wire tools to identity (audit + trust)',
  '  attach --all             Enable all detected tools',
  '  detach                   Remove cross-tool wiring',
  '  sync                     Sync events from enabled tools',
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
    case 'attach':
      return handleAttach(options);
    case 'detach':
      return handleDetach(options);
    case 'sync':
      return handleSync(options);
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

    // Check if identity already exists
    let existing = false;
    try {
      const prev = aim.getIdentity();
      if (prev && prev.agentId) {
        existing = true;
      }
    } catch {
      // No existing identity -- good, we'll create one
    }

    const id = aim.getOrCreateIdentity();

    if (isJson) {
      process.stdout.write(JSON.stringify({ ...id, created: !existing }, null, 2) + '\n');
      return 0;
    }

    if (existing) {
      process.stdout.write(yellow('Identity already exists') + '\n');
      process.stdout.write(dim('  aim-core uses a single identity per data directory.') + '\n');
      process.stdout.write(dim('  To start fresh, remove ~/.opena2a/aim-core/ and re-run.') + '\n\n');
    } else {
      process.stdout.write(green('Identity created') + '\n');
    }
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

    // Auto-sync trust hints if a manifest exists (tools are attached)
    const targetDir = path.resolve(options.dir ?? process.cwd());
    let hasManifest = false;
    try {
      const { readManifest } = await import('../identity/manifest.js');
      const { collectTrustHints } = await import('../identity/trust-collector.js');
      const manifest = readManifest(targetDir);
      if (manifest) {
        hasManifest = true;
        const { hints } = collectTrustHints(targetDir, manifest);
        (aim as any).setTrustHints(hints);
      }
    } catch {
      // Identity module not available or manifest missing — that's fine
    }

    const trust = aim.calculateTrust();

    if (isJson) {
      process.stdout.write(JSON.stringify({ ...trust, attached: hasManifest }, null, 2) + '\n');
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

    if (options.verbose) {
      if (trust.calculatedAt) {
        process.stdout.write(dim(`  Calculated: ${trust.calculatedAt}`) + '\n');
      }
      // Show improvement suggestions for factors at 0%
      const zeroFactors = Object.entries(trust.factors).filter(([, v]) => (v as number) === 0);
      if (zeroFactors.length > 0) {
        process.stdout.write('\n' + bold('  How to improve:') + '\n');
        const factorSuggestions: Record<string, string> = {
          secretsManaged: 'npx secretless-ai init',
          configSigned: 'opena2a guard sign',
          skillsVerified: 'npx hackmyagent secure',
          networkControlled: 'opena2a runtime --init',
          heartbeatMonitored: 'opena2a shield init',
        };
        for (const [factor] of zeroFactors) {
          const suggestion = factorSuggestions[factor];
          if (suggestion) {
            const label = factor.replace(/([A-Z])/g, ' $1').toLowerCase().trim();
            process.stdout.write(`    ${label.padEnd(18)} ${dim(suggestion)}\n`);
          }
        }
      }
    }

    if (!hasManifest) {
      process.stdout.write('\n' + dim('  No tools attached. Run: opena2a identity attach --all') + '\n');
      process.stdout.write(dim('  Attaching tools improves trust by syncing real security state.') + '\n');
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

    const validResults = ['allowed', 'denied', 'error'] as const;
    const resultInput = options.result ?? 'allowed';
    if (!validResults.includes(resultInput as typeof validResults[number])) {
      process.stderr.write(`Invalid --result value: ${resultInput}\n`);
      process.stderr.write('Valid values: allowed, denied, error\n');
      return 1;
    }

    const event = aim.logEvent({
      action,
      target: options.target ?? '',
      result: resultInput as 'allowed' | 'denied' | 'error',
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
    const p = aim.loadPolicy() as Policy;

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
    let parsed: Policy;

    if (resolved.endsWith('.json')) {
      parsed = JSON.parse(content);
    } else if (resolved.endsWith('.yaml') || resolved.endsWith('.yml')) {
      parsed = parseSimpleYamlPolicy(content);
    } else {
      process.stderr.write('Unsupported file format. Use .json or .yaml/.yml\n');
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

  let data: string | undefined = options.data;
  let label = data;
  let dataBytes: Uint8Array;

  if (options.file && options.subcommand === 'sign') {
    // Sign file contents
    const resolved = path.resolve(options.file);
    if (!fs.existsSync(resolved)) {
      process.stderr.write(`File not found: ${resolved}\n`);
      return 1;
    }
    const fileContents = fs.readFileSync(resolved);
    dataBytes = new Uint8Array(fileContents);
    label = path.basename(resolved);
  } else if (data) {
    dataBytes = new TextEncoder().encode(data);
  } else {
    process.stderr.write('Missing required option: --data <string> or --file <path>\n');
    process.stderr.write('Usage:\n');
    process.stderr.write('  opena2a identity sign --data "message to sign"\n');
    process.stderr.write('  opena2a identity sign --file ./config.json\n');
    return 1;
  }

  const isJson = options.format === 'json';

  try {
    const aim = new mod.AIMCore({ agentName: 'default' });
    const id = aim.getIdentity();
    const signature = aim.sign(dataBytes);
    const sigBase64 = Buffer.from(signature).toString('base64');

    if (isJson) {
      process.stdout.write(JSON.stringify({
        ...(options.file ? { file: path.resolve(options.file) } : { data }),
        signature: sigBase64,
        publicKey: id.publicKey,
        agentId: id.agentId,
      }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(bold('Signature') + '\n');
    const displayLabel = label && label.length > 60 ? label.slice(0, 60) + '...' : (label ?? '');
    if (options.file) {
      process.stdout.write(`  File:       ${dim(path.resolve(options.file))}\n`);
    } else {
      process.stdout.write(`  Data:       ${dim(displayLabel)}\n`);
    }
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
    const aim = new mod.AIMCore({ agentName: 'default' });
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
// attach -- wire tools to identity
// ---------------------------------------------------------------------------

async function handleAttach(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const isJson = options.format === 'json';
  const targetDir = path.resolve(options.dir ?? process.cwd());

  try {
    // 1. Get or create identity
    const agentName = options.name ?? 'default';
    const aim = new mod.AIMCore({ agentName });
    const id = aim.getOrCreateIdentity();

    if (!isJson) {
      process.stdout.write(bold('Attaching identity to tools') + '\n');
      process.stdout.write(gray('-'.repeat(60)) + '\n');
      process.stdout.write(`  Agent:     ${cyan(id.agentId)}\n`);
      process.stdout.write(`  Name:      ${id.agentName}\n`);
      process.stdout.write(`  Directory: ${dim(targetDir)}\n\n`);
    }

    // 2. Determine which tools to enable
    const { readManifest, writeManifest } = await import('../identity/manifest.js');
    const { collectTrustHints } = await import('../identity/trust-collector.js');
    const { importAllToolEvents } = await import('../identity/bridges.js');

    const existing = readManifest(targetDir);
    let enabledTools = {
      secretless: false,
      configguard: false,
      arp: false,
      hma: false,
      shield: false,
    };

    if (options.all) {
      // Enable all
      enabledTools = { secretless: true, configguard: true, arp: true, hma: true, shield: true };
    } else if (options.tools) {
      // Enable specific tools, merge with existing
      const requested = options.tools.split(',').map(t => t.trim().toLowerCase());
      const knownTools = ['secretless', 'configguard', 'guard', 'arp', 'hma', 'hackmyagent', 'shield'];
      const unknown = requested.filter(t => !knownTools.includes(t));
      if (unknown.length > 0) {
        process.stderr.write(`Unknown tool(s): ${unknown.join(', ')}\n`);
        process.stderr.write(`Valid tools: secretless, configguard, arp, hma, shield\n`);
        return 1;
      }
      if (existing) {
        enabledTools = { ...existing.tools };
      }
      for (const tool of requested) {
        if (tool === 'secretless') enabledTools.secretless = true;
        if (tool === 'configguard' || tool === 'guard') enabledTools.configguard = true;
        if (tool === 'arp') enabledTools.arp = true;
        if (tool === 'hma' || tool === 'hackmyagent') enabledTools.hma = true;
        if (tool === 'shield') enabledTools.shield = true;
      }
    } else if (existing) {
      // Re-attach with existing config
      enabledTools = existing.tools;
    } else {
      // First attach with no flags — enable all by default
      enabledTools = { secretless: true, configguard: true, arp: true, hma: true, shield: true };
    }

    // 3. Collect trust hints from enabled tools
    const manifest = {
      version: '1',
      agent: { name: id.agentName, agentId: id.agentId, publicKey: id.publicKey, created: id.createdAt },
      tools: enabledTools,
      bridging: { autoSync: options.autoSync ?? true, lastSyncAt: null as string | null },
      registry: { contribute: false, gtin: false, sensorToken: null },
    };

    const { hints, details } = collectTrustHints(targetDir, manifest);

    if (!isJson) {
      if (options.tools) {
        process.stdout.write(bold('  Requested tools: ') + options.tools + '\n\n');
      }
      process.stdout.write(bold('  Tool Detection:') + '\n');

      // Show all tools (not just enabled ones) so user sees the full picture
      const allToolNames = [
        { key: 'secretless' as const, label: 'Secretless' },
        { key: 'configguard' as const, label: 'ConfigGuard' },
        { key: 'arp' as const, label: 'ARP' },
        { key: 'hma' as const, label: 'HMA' },
        { key: 'shield' as const, label: 'Shield' },
      ];
      for (const t of allToolNames) {
        const isEnabled = enabledTools[t.key];
        const detail = details.find(d => d.tool === t.label);
        let icon: string;
        let reason: string;
        if (!isEnabled) {
          icon = dim(' SKIP ');
          reason = 'not requested';
        } else if (detail?.active) {
          icon = green('ACTIVE');
          reason = detail.reason;
        } else {
          icon = yellow(' OFF  ');
          reason = detail?.reason ?? 'not detected';
        }
        const suffix = '';
        process.stdout.write(`    ${icon}  ${t.label.padEnd(14)} ${dim(reason)}${suffix}\n`);
      }
      process.stdout.write('\n');
    }

    // 4. Apply trust hints
    (aim as any).setTrustHints(hints);

    // 5. Calculate trust score BEFORE sync
    const trustBefore = aim.calculateTrust();

    // 6. Import events from enabled tools
    const bridgeResults = importAllToolEvents(aim, targetDir, enabledTools);

    // 7. Calculate trust score AFTER sync
    const trustAfter = aim.calculateTrust();

    // 8. Write manifest
    manifest.bridging.lastSyncAt = new Date().toISOString();
    writeManifest(targetDir, manifest);

    // 9. Log the attach event
    aim.logEvent({
      action: 'identity.attach',
      target: targetDir,
      result: 'allowed',
      plugin: 'opena2a-cli',
    });

    if (isJson) {
      process.stdout.write(JSON.stringify({
        agentId: id.agentId,
        name: id.agentName,
        tools: enabledTools,
        hints,
        bridgeResults: bridgeResults.total,
        trustBefore: { score: trustBefore.score, grade: trustBefore.grade },
        trustAfter: { score: trustAfter.score, grade: trustAfter.grade },
        manifestPath: path.join(targetDir, '.opena2a', 'agent.yaml'),
      }, null, 2) + '\n');
      return 0;
    }

    // 10. Display results
    if (bridgeResults.total.imported > 0) {
      process.stdout.write(bold('  Event Sync:') + '\n');
      const tools = ['shield', 'arp', 'hma', 'configguard', 'secretless'] as const;
      for (const t of tools) {
        const r = bridgeResults[t];
        if (r.imported > 0 || r.skipped > 0) {
          process.stdout.write(`    ${t.padEnd(14)} ${green(`+${r.imported}`)} imported${r.skipped > 0 ? dim(`, ${r.skipped} skipped`) : ''}\n`);
        }
      }
      process.stdout.write('\n');
    }

    process.stdout.write(bold('  Trust Score:') + '\n');
    const beforeColor = trustBefore.score >= 60 ? yellow : red;
    const afterColor = trustAfter.score >= 80 ? green : trustAfter.score >= 60 ? yellow : red;
    const delta = trustAfter.score - trustBefore.score;
    const deltaLabel = delta > 0 ? green(`+${delta}`) : delta < 0 ? red(`${delta}`) : dim('+0');

    process.stdout.write(`    ${beforeColor(String(trustBefore.score))} -> ${afterColor(bold(String(trustAfter.score)))} (${deltaLabel})\n`);
    process.stdout.write(`    Grade: ${afterColor(trustAfter.grade)}\n\n`);

    // Active hints
    const activeHintCount = Object.values(hints).filter(Boolean).length;
    const totalHintCount = Object.keys(hints).length;
    process.stdout.write(`  Trust factors active: ${green(String(activeHintCount))}/${totalHintCount}\n`);

    process.stdout.write(gray('-'.repeat(60)) + '\n');
    process.stdout.write(dim(`  Manifest: ${path.join(targetDir, '.opena2a', 'agent.yaml')}`) + '\n');

    // Suggestions for inactive tools
    const inactiveTools = details.filter(d => !d.active);
    if (inactiveTools.length > 0) {
      process.stdout.write('\n' + dim('  To improve your trust score:') + '\n');
      for (const t of inactiveTools) {
        const suggestion = getToolSuggestion(t.tool);
        if (suggestion) {
          process.stdout.write(dim(`    ${t.tool}: ${suggestion}`) + '\n');
        }
      }
    }

    return 0;
  } catch (err) {
    process.stderr.write(`Failed to attach: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

function getToolSuggestion(tool: string): string | null {
  switch (tool) {
    case 'Secretless': return 'npx secretless-ai init';
    case 'ConfigGuard': return 'opena2a guard sign';
    case 'ARP': return 'opena2a runtime --init';
    case 'HMA': return 'npx hackmyagent secure';
    case 'Shield': return 'opena2a shield init';
    default: return null;
  }
}

// ---------------------------------------------------------------------------
// detach -- remove cross-tool wiring
// ---------------------------------------------------------------------------

async function handleDetach(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const isJson = options.format === 'json';
  const targetDir = path.resolve(options.dir ?? process.cwd());

  try {
    const { readManifest, removeManifest } = await import('../identity/manifest.js');

    const manifest = readManifest(targetDir);
    if (!manifest) {
      if (isJson) {
        process.stdout.write(JSON.stringify({ detached: false, reason: 'no manifest found' }, null, 2) + '\n');
      } else {
        process.stderr.write('No identity attachment found in this directory.\n');
        process.stderr.write(dim('Run: opena2a identity attach') + '\n');
      }
      return 1;
    }

    // Log detach event before removing
    const aim = new mod.AIMCore({ agentName: manifest.agent.name });
    aim.logEvent({
      action: 'identity.detach',
      target: targetDir,
      result: 'allowed',
      plugin: 'opena2a-cli',
    });

    // Clear trust hints
    (aim as any).setTrustHints({});

    // Remove manifest
    removeManifest(targetDir);

    if (isJson) {
      process.stdout.write(JSON.stringify({ detached: true, agentId: manifest.agent.agentId }, null, 2) + '\n');
    } else {
      process.stdout.write(green('Identity detached') + '\n');
      process.stdout.write(`  Agent:     ${manifest.agent.agentId}\n`);
      process.stdout.write(`  Directory: ${dim(targetDir)}\n`);
      process.stdout.write(dim('\n  Identity, audit log, and tool configs are preserved.') + '\n');
      process.stdout.write(dim('  Only the cross-tool wiring was removed.') + '\n');
    }
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to detach: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

// ---------------------------------------------------------------------------
// sync -- re-sync events from enabled tools
// ---------------------------------------------------------------------------

async function handleSync(options: IdentityOptions): Promise<number> {
  const mod = await loadAimCore();
  if (!mod) return 1;

  const isJson = options.format === 'json';
  const targetDir = path.resolve(options.dir ?? process.cwd());

  try {
    const { readManifest, writeManifest } = await import('../identity/manifest.js');
    const { applyTrustHints } = await import('../identity/trust-collector.js');
    const { importAllToolEvents } = await import('../identity/bridges.js');

    const manifest = readManifest(targetDir);
    if (!manifest) {
      if (isJson) {
        process.stdout.write(JSON.stringify({ synced: false, reason: 'no manifest found' }, null, 2) + '\n');
      } else {
        process.stderr.write('No identity attachment found. Run: opena2a identity attach\n');
      }
      return 1;
    }

    const aim = new mod.AIMCore({ agentName: manifest.agent.name });

    // Refresh trust hints
    const { hints, score } = applyTrustHints(aim, targetDir, manifest);

    // Import new events
    const bridgeResults = importAllToolEvents(aim, targetDir, manifest.tools);

    // Update manifest sync timestamp
    manifest.bridging.lastSyncAt = new Date().toISOString();
    writeManifest(targetDir, manifest);

    if (isJson) {
      process.stdout.write(JSON.stringify({
        synced: true,
        imported: bridgeResults.total.imported,
        skipped: bridgeResults.total.skipped,
        trustScore: score.score,
        trustGrade: score.grade,
      }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(green('Sync complete') + '\n');
    process.stdout.write(`  Events imported: ${bridgeResults.total.imported}\n`);
    if (bridgeResults.total.skipped > 0) {
      process.stdout.write(`  Skipped (dedup): ${bridgeResults.total.skipped}\n`);
    }

    const scoreColor = score.score >= 80 ? green : score.score >= 60 ? yellow : red;
    process.stdout.write(`  Trust score:     ${scoreColor(bold(`${score.score}/100`))} (${scoreColor(score.grade)})\n`);

    const activeHints = Object.entries(hints).filter(([, v]) => v).map(([k]) => k);
    if (activeHints.length > 0) {
      process.stdout.write(`  Active factors:  ${activeHints.join(', ')}\n`);
    }
    return 0;
  } catch (err) {
    process.stderr.write(`Failed to sync: ${err instanceof Error ? err.message : String(err)}\n`);
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

/**
 * Parse a simple YAML capability policy file.
 *
 * Supports the format:
 *   version: "1"
 *   defaultAction: deny
 *   rules:
 *     - capability: "db:read"
 *       action: allow
 *     - capability: "net:*"
 *       action: deny
 *       plugins:
 *         - untrusted-plugin
 */
function parseSimpleYamlPolicy(content: string): Policy {
  const lines = content.split('\n');
  let version = '1';
  let defaultAction: 'allow' | 'deny' = 'deny';
  const rules: Array<{ capability: string; action: 'allow' | 'deny'; plugins?: string[] }> = [];

  let inRules = false;
  let currentRule: { capability?: string; action?: string; plugins?: string[] } | null = null;
  let inPlugins = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    // Top-level keys
    if (!line.startsWith(' ') && !line.startsWith('\t')) {
      inRules = false;
      inPlugins = false;
      if (currentRule?.capability && currentRule?.action) {
        rules.push(currentRule as { capability: string; action: 'allow' | 'deny'; plugins?: string[] });
        currentRule = null;
      }
    }

    const kvMatch = trimmed.match(/^(\w+):\s*(.*)$/);

    if (kvMatch && !inRules) {
      const [, key, val] = kvMatch;
      const cleanVal = val.replace(/^["']|["']$/g, '');
      if (key === 'version') version = cleanVal;
      if (key === 'defaultAction') defaultAction = cleanVal as 'allow' | 'deny';
      if (key === 'rules') inRules = true;
      continue;
    }

    if (inRules) {
      // New rule entry (starts with "- ")
      if (trimmed.startsWith('- ')) {
        if (currentRule?.capability && currentRule?.action) {
          rules.push(currentRule as { capability: string; action: 'allow' | 'deny'; plugins?: string[] });
        }
        currentRule = {};
        inPlugins = false;
        const inlineKv = trimmed.slice(2).match(/^(\w+):\s*(.*)$/);
        if (inlineKv) {
          const cleanVal = inlineKv[2].replace(/^["']|["']$/g, '');
          if (inlineKv[1] === 'capability') currentRule.capability = cleanVal;
          if (inlineKv[1] === 'action') currentRule.action = cleanVal;
        }
        continue;
      }

      // Rule properties
      if (currentRule && kvMatch) {
        const [, key, val] = kvMatch;
        const cleanVal = val.replace(/^["']|["']$/g, '');
        if (key === 'capability') currentRule.capability = cleanVal;
        if (key === 'action') currentRule.action = cleanVal;
        if (key === 'plugins') {
          inPlugins = true;
          currentRule.plugins = [];
        }
        continue;
      }

      // Plugin list items
      if (inPlugins && currentRule && trimmed.startsWith('- ')) {
        const pluginName = trimmed.slice(2).replace(/^["']|["']$/g, '');
        if (!currentRule.plugins) currentRule.plugins = [];
        currentRule.plugins.push(pluginName);
      }
    }
  }

  // Flush last rule
  if (currentRule?.capability && currentRule?.action) {
    rules.push(currentRule as { capability: string; action: 'allow' | 'deny'; plugins?: string[] });
  }

  return { version, defaultAction, rules };
}
