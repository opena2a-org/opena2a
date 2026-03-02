/**
 * opena2a shield -- Unified security orchestration.
 *
 * Subcommands:
 * - init:      Full environment scan, policy generation, shell hooks
 * - status:    Product availability, policy mode, integrity state
 * - log:       Query the tamper-evident event log
 * - selfcheck: Run integrity checks (alias: check)
 * - policy:    Show loaded policy summary
 * - evaluate:  Evaluate an action against the policy
 * - recover:   Exit lockdown mode
 * - report:    Generate a security posture report (stub)
 */

import type { EventSeverity } from '../shield/types.js';
import { bold, dim, gray, green, yellow, red, cyan } from '../util/colors.js';

// --- Types ---

export interface ShieldOptions {
  subcommand: string;
  dir?: string;
  agent?: string;
  count?: string;
  since?: string;
  severity?: string;
  source?: string;
  category?: string;
  verify?: boolean;
  reset?: boolean;
  forensic?: boolean;
  analyze?: boolean;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
}

// --- Core dispatcher ---

export async function shield(options: ShieldOptions): Promise<number> {
  switch (options.subcommand) {
    case 'init':
      return handleInit(options);
    case 'status':
      return handleStatus(options);
    case 'log':
      return handleLog(options);
    case 'selfcheck':
    case 'check':
      return handleSelfcheck(options);
    case 'policy':
      return handlePolicy(options);
    case 'evaluate':
      return handleEvaluate(options);
    case 'recover':
      return handleRecover(options);
    case 'report':
      return handleReport(options);
    default:
      process.stderr.write(red(`Unknown subcommand: ${options.subcommand}\n`));
      process.stderr.write('Usage: opena2a shield <init|status|log|selfcheck|policy|evaluate|recover|report>\n');
      return 1;
  }
}

// --- Subcommand handlers ---

async function handleInit(options: ShieldOptions): Promise<number> {
  const { shieldInit } = await import('../shield/init.js');
  const { exitCode } = await shieldInit({
    targetDir: options.dir,
    ci: options.ci,
    format: options.format,
    verbose: options.verbose,
  });
  return exitCode;
}

async function handleStatus(options: ShieldOptions): Promise<number> {
  const { getShieldStatus, formatStatus } = await import('../shield/status.js');
  const format = (options.format === 'json' ? 'json' : 'text') as 'text' | 'json';

  const status = getShieldStatus(options.dir);
  const output = formatStatus(status, format);
  process.stdout.write(output + '\n');

  return (status.integrityStatus === 'lockdown' || status.integrityStatus === 'compromised') ? 1 : 0;
}

async function handleLog(options: ShieldOptions): Promise<number> {
  const { readEvents } = await import('../shield/events.js');
  const isJson = options.format === 'json';

  const count = options.count ? parseInt(options.count, 10) : 20;
  const events = readEvents({
    count,
    source: options.source,
    severity: options.severity,
    agent: options.agent,
    since: options.since,
    category: options.category,
  });

  if (isJson) {
    process.stdout.write(JSON.stringify(events, null, 2) + '\n');
    return 0;
  }

  if (events.length === 0) {
    process.stdout.write(dim('No events found.\n'));
    return 0;
  }

  for (const event of events) {
    const ts = event.timestamp;
    const sev = colorSeverity(event.severity);
    const action = event.action;
    const target = event.target;
    const outcome = event.outcome;

    process.stdout.write(`[${ts}] [${sev}] ${action} -> ${target} (${outcome})\n`);
  }

  return 0;
}

async function handleSelfcheck(options: ShieldOptions): Promise<number> {
  const { runIntegrityChecks } = await import('../shield/integrity.js');
  const isJson = options.format === 'json';

  const shell = process.env.SHELL?.includes('zsh') ? 'zsh' as const
    : process.env.SHELL?.includes('bash') ? 'bash' as const
    : undefined;

  const state = runIntegrityChecks({ shell });

  if (isJson) {
    process.stdout.write(JSON.stringify(state, null, 2) + '\n');
  } else {
    process.stdout.write(bold('Shield Integrity Check\n'));
    process.stdout.write(gray('-'.repeat(50)) + '\n');

    for (const check of state.checks) {
      const icon = check.status === 'pass' ? green('PASS')
        : check.status === 'warn' ? yellow('WARN')
        : red('FAIL');
      process.stdout.write(`  ${icon}  ${check.name.padEnd(22)} ${dim(check.detail)}\n`);
    }

    process.stdout.write(gray('-'.repeat(50)) + '\n');
    const statusLabel = state.status === 'healthy' ? green(state.status.toUpperCase())
      : state.status === 'degraded' ? yellow(state.status.toUpperCase())
      : red(state.status.toUpperCase());
    process.stdout.write(`  Overall: ${statusLabel}\n`);
  }

  return (state.status === 'compromised' || state.status === 'lockdown') ? 1 : 0;
}

async function handlePolicy(options: ShieldOptions): Promise<number> {
  const { loadPolicy } = await import('../shield/policy.js');
  const isJson = options.format === 'json';

  const policy = loadPolicy(options.dir);

  if (!policy) {
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: 'No policy loaded' }, null, 2) + '\n');
    } else {
      process.stderr.write(yellow('No policy loaded. Run: opena2a shield init\n'));
    }
    return 1;
  }

  if (isJson) {
    process.stdout.write(JSON.stringify(policy, null, 2) + '\n');
    return 0;
  }

  process.stdout.write(bold('Shield Policy\n'));
  process.stdout.write(gray('-'.repeat(40)) + '\n');
  process.stdout.write(`  Mode: ${cyan(policy.mode)}\n`);
  process.stdout.write(`  Process deny:  ${policy.default.processes.deny.length} rules\n`);
  process.stdout.write(`  Process allow: ${policy.default.processes.allow.length} rules\n`);
  process.stdout.write(`  Cred deny:     ${policy.default.credentials.deny.length} rules\n`);
  process.stdout.write(`  Network allow: ${policy.default.network.allow.length} rules\n`);
  process.stdout.write(`  FS deny:       ${policy.default.filesystem.deny.length} rules\n`);
  process.stdout.write(`  MCP allow:     ${policy.default.mcpServers.allow.length} rules\n`);

  const agentCount = Object.keys(policy.agents).length;
  if (agentCount > 0) {
    process.stdout.write(`  Agent overrides: ${agentCount}\n`);
  }

  process.stdout.write(gray('-'.repeat(40)) + '\n');
  return 0;
}

async function handleEvaluate(options: ShieldOptions): Promise<number> {
  const { loadPolicy, evaluatePolicy } = await import('../shield/policy.js');
  const isJson = options.format === 'json';

  const policy = loadPolicy(options.dir);

  if (!policy) {
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: 'No policy loaded' }, null, 2) + '\n');
    } else {
      process.stderr.write(yellow('No policy loaded. Run: opena2a shield init\n'));
    }
    return 1;
  }

  // category and target come from remaining args, but Commander puts them
  // in the parent command's args. Fall back to options.category if available.
  const category = options.category ?? 'processes';
  const agent = options.agent ?? null;
  // target is not a named option -- use empty string as fallback
  const target = '';

  const decision = evaluatePolicy(policy, agent, category, target);

  if (isJson) {
    process.stdout.write(JSON.stringify(decision, null, 2) + '\n');
  } else {
    const outcomeLabel = decision.outcome === 'allowed' ? green('ALLOWED')
      : decision.outcome === 'blocked' ? red('BLOCKED')
      : yellow('MONITORED');
    process.stdout.write(`${outcomeLabel}  rule=${decision.rule}\n`);
  }

  return decision.outcome === 'blocked' ? 1 : 0;
}

async function handleRecover(options: ShieldOptions): Promise<number> {
  const { isLockdown, exitLockdown, getLockdownReason } = await import('../shield/integrity.js');
  const isJson = options.format === 'json';

  if (!isLockdown()) {
    if (isJson) {
      process.stdout.write(JSON.stringify({ status: 'not_in_lockdown' }, null, 2) + '\n');
    } else {
      process.stdout.write(green('System is not in lockdown.\n'));
    }
    return 0;
  }

  const reason = getLockdownReason();

  if (options.verify) {
    // Run integrity checks before recovering
    const { runIntegrityChecks } = await import('../shield/integrity.js');
    const shell = process.env.SHELL?.includes('zsh') ? 'zsh' as const
      : process.env.SHELL?.includes('bash') ? 'bash' as const
      : undefined;

    // Temporarily exit lockdown to run checks
    exitLockdown();
    const state = runIntegrityChecks({ shell });

    if (state.status === 'compromised') {
      // Re-enter lockdown if still compromised
      const { enterLockdown } = await import('../shield/integrity.js');
      enterLockdown(reason ?? 'Verification failed');

      if (isJson) {
        process.stdout.write(JSON.stringify({ status: 'verification_failed', state }, null, 2) + '\n');
      } else {
        process.stderr.write(red('Verification failed. System remains in lockdown.\n'));
        for (const check of state.checks) {
          if (check.status === 'fail') {
            process.stderr.write(`  ${red('FAIL')}  ${check.name}: ${check.detail}\n`);
          }
        }
      }
      return 1;
    }

    if (isJson) {
      process.stdout.write(JSON.stringify({ status: 'recovered', verified: true }, null, 2) + '\n');
    } else {
      process.stdout.write(green('Lockdown lifted after successful verification.\n'));
    }
    return 0;
  }

  // Force exit without verification
  exitLockdown();

  if (isJson) {
    process.stdout.write(JSON.stringify({ status: 'recovered', previousReason: reason }, null, 2) + '\n');
  } else {
    process.stdout.write(green('Lockdown lifted.\n'));
    if (reason) {
      process.stdout.write(dim(`Previous reason: ${reason}\n`));
    }
  }
  return 0;
}

async function handleReport(_options: ShieldOptions): Promise<number> {
  process.stderr.write(dim('Report generation is not yet implemented.\n'));
  return 0;
}

// --- Formatting helpers ---

function colorSeverity(severity: EventSeverity): string {
  switch (severity) {
    case 'info': return dim('INFO');
    case 'low': return gray('LOW');
    case 'medium': return yellow('MEDIUM');
    case 'high': return red('HIGH');
    case 'critical': return bold(red('CRITICAL'));
    default: return dim(String(severity));
  }
}
