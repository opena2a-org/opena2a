/**
 * opena2a shield -- Unified security orchestration.
 *
 * Subcommands:
 * - init:      Full environment scan, policy generation, shell hooks
 * - status:    Tool availability, policy mode, integrity state
 * - log:       Query the Shield event log
 * - selfcheck: Run integrity checks (alias: check)
 * - policy:    Show loaded policy summary
 * - evaluate:  Evaluate an action against the policy
 * - recover:   Exit lockdown mode
 * - report:    Generate a security posture report
 * - session:   Show current AI coding assistant session identity
 * - baseline:  View adaptive enforcement baselines for agents
 * - suggest:   LLM-powered policy suggestions from observed behavior
 * - explain:   LLM-powered anomaly explanations for events
 * - triage:    LLM-powered incident classification and response
 * - monitor:   Import ARP events and summarize runtime protection
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { EventSeverity, IntegrityState } from '../shield/types.js';
import type { EventVerificationStatus } from '../shield/events.js';
import { bold, dim, gray, green, yellow, red, cyan } from '../util/colors.js';
import { severityColor } from '../util/format.js';

// --- Types ---

export interface ShieldOptions {
  subcommand: string;
  args?: string[];
  dir?: string;
  agent?: string;
  count?: string;
  since?: string;
  severity?: string;
  source?: string;
  category?: string;
  /** `--action process.spawn` — the action to evaluate (evaluate only). */
  action?: string;
  /** `--target /usr/bin/curl` — the subject of that action (evaluate only). */
  target?: string;
  verify?: boolean;
  /** `--archive-log` — retire a broken event log and start a fresh chain. */
  archiveLog?: boolean;
  analyze?: boolean;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
  report?: string;
  shellHook?: boolean;
  aiTools?: boolean;
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
    case 'session':
      return handleSession(options);
    case 'baseline':
      return handleBaseline(options);
    case 'suggest':
      return handleSuggest(options);
    case 'explain':
      return handleExplain(options);
    case 'triage':
      return handleTriage(options);
    case 'monitor':
      return handleMonitor(options);
    default:
      process.stderr.write(red(`Unknown subcommand: ${options.subcommand}\n\n`));
      process.stderr.write('Usage: opena2a shield <subcommand>\n\n');
      process.stderr.write('Subcommands:\n');
      process.stderr.write('  init       Full environment scan, policy generation, shell hooks\n');
      process.stderr.write('  status     Tool availability, policy mode, integrity state\n');
      process.stderr.write('  log        Query the Shield event log\n');
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
      process.stderr.write('  monitor    Import ARP events and summarize runtime protection\n');
      return 1;
  }
}

// --- Subcommand handlers ---

/**
 * The directory `shield init` hardens: `--dir`, or the positional the way
 * every sibling command (`init`, `review`, `protect`, `scan`) takes it.
 * The positional used to be discarded, so `shield init <dir>` hardened the
 * current directory and reported success for a target it never touched
 * (#268). Returns an error message instead of guessing when the arguments
 * disagree or do not name a directory.
 */
export function resolveInitTarget(
  options: Pick<ShieldOptions, 'dir' | 'args'>,
): { targetDir?: string; error?: string } {
  const positional = options.args ?? [];
  if (positional.length > 1) {
    return {
      error: `shield init takes one directory, got ${positional.length}: ${positional.join(' ')}\n` +
        '  Fix: opena2a shield init <dir>',
    };
  }
  const [dirArg] = positional;
  if (dirArg !== undefined && options.dir !== undefined &&
      path.resolve(dirArg) !== path.resolve(options.dir)) {
    return {
      error: `shield init was given two different directories: ${dirArg} and --dir ${options.dir}\n` +
        '  Fix: pass one of them, e.g. opena2a shield init <dir>',
    };
  }
  const target = options.dir ?? dirArg;
  if (target === undefined) return {};
  const resolved = path.resolve(target);
  let isDir = false;
  try {
    isDir = fs.statSync(resolved).isDirectory();
  } catch {
    isDir = false;
  }
  if (!isDir) {
    return {
      error: `shield init: ${resolved} is not a directory\n` +
        '  Fix: opena2a shield init <existing-project-dir>',
    };
  }
  return { targetDir: resolved };
}

async function handleInit(options: ShieldOptions): Promise<number> {
  const { targetDir, error } = resolveInitTarget(options);
  if (error) {
    process.stderr.write(red(error) + '\n');
    return 1;
  }
  const { shieldInit } = await import('../shield/init.js');
  const { exitCode } = await shieldInit({
    targetDir,
    ci: options.ci,
    format: options.format,
    verbose: options.verbose,
    shellHook: options.shellHook,
    aiTools: options.aiTools,
  });
  return exitCode;
}

async function handleStatus(options: ShieldOptions): Promise<number> {
  const { getShieldStatus, formatStatus } = await import('../shield/status.js');
  const format = (options.format === 'json' ? 'json' : 'text') as 'text' | 'json';

  const status = getShieldStatus(options.dir);
  const output = formatStatus(status, format);
  process.stdout.write(output + '\n');

  // Status is informational: it exits 1 on the lockdown marker only. The
  // measured verdict decides `shield selfcheck`'s exit code, not this one.
  return status.integrityStatus === 'lockdown' ? 1 : 0;
}

async function handleLog(options: ShieldOptions): Promise<number> {
  const { readVerifiedEvents, eventVerificationStatus } = await import('../shield/events.js');
  const isJson = options.format === 'json';

  const count = options.count ? parseInt(options.count, 10) : 20;
  const verified = readVerifiedEvents({
    count,
    source: options.source,
    severity: options.severity,
    agent: options.agent,
    since: options.since,
    category: options.category,
  });
  const verification = eventVerificationStatus(verified);

  // The log is the forensic view: it keeps the newest `count` matching
  // events, as the unverified read returned them, and lists an event past a
  // chain break with that status instead of dropping it.
  const limit = count > 0 ? count : undefined;
  const rows = [
    ...verified.untrusted.map(event => ({ event, verified: false })),
    ...verified.events.map(event => ({ event, verified: true })),
  ].slice(0, limit);

  if (isJson) {
    process.stdout.write(JSON.stringify(rows.map(r => ({ ...r.event, verified: r.verified })), null, 2) + '\n');
    return 0;
  }

  writeChainBreakNotice(verification, 'marked UNVERIFIED where listed');

  if (rows.length === 0) {
    process.stdout.write(yellow('No events found.') + ' ' + dim('Generate events: opena2a shield init') + '\n');
    return 0;
  }

  for (const { event, verified: isVerified } of rows) {
    const ts = printableText(event.timestamp);
    const sev = colorSeverity(event.severity);
    const action = printableText(event.action);
    const target = printableText(event.target);
    const outcome = printableText(event.outcome);
    const marker = isVerified ? '' : ' ' + yellow('UNVERIFIED');

    process.stdout.write(`[${ts}] [${sev}] ${action} -> ${target} (${outcome})${marker}\n`);
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
  const { writeEvent } = await import('../shield/events.js');
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

  // Determine the command string from positional args.
  // Filter out what looks like a directory path (starts with / or ./ or contains path separators).
  const rawArgs = options.args ?? [];
  const commandArgs = rawArgs.filter(a => !a.startsWith('/') && !a.startsWith('./') && !a.startsWith('../'));
  const commandString = commandArgs.length > 0 ? commandArgs.join(' ') : null;

  // An explicit --action/--target is unambiguously a human (or a script)
  // asking for a verdict: the preexec hook never passes them. This is the
  // form src/shield/findings.ts prints as remediation, so it must report.
  const hasExplicitSubject = Boolean(options.action || options.target);

  // Otherwise hook mode is "a command was handed to us", keyed off the RAW
  // args: the installed preexec hook is `opena2a shield evaluate "$1"` and
  // always passes one. Keying off `commandString` instead would misread an
  // absolute-path command (`/usr/bin/ls`, dropped by the filter above) as a
  // direct invocation and print a verdict on every such hook run.
  const isHookInvocation = rawArgs.length > 0 && !hasExplicitSubject;

  const agent = options.agent ?? null;
  let category: string;
  let target: string;

  if (hasExplicitSubject) {
    // evaluatePolicy accepts either an action string ('process.spawn') or a
    // bare category ('processes') and maps it internally.
    category = options.action ?? options.category ?? 'processes';
    target = options.target ?? '';
  } else if (commandString) {
    // Shell hook mode: parse the command to extract the binary name (first word).
    // Handle pipes, subshells, and quoted strings by taking the first token.
    const trimmed = commandString.trim();
    const firstWord = trimmed.split(/[\s|;&]/)[0] ?? trimmed;
    category = 'processes';
    target = firstWord;
  } else {
    // Explicit category mode (used by direct API calls)
    category = options.category ?? 'processes';
    target = '';
  }

  const decision = evaluatePolicy(policy, agent, category, target);

  // Write enforcement events for non-allowed decisions
  if (decision.outcome === 'blocked') {
    writeEvent({
      source: 'shield',
      category: 'enforcement',
      severity: 'high',
      agent,
      sessionId: null,
      action: 'command.blocked',
      target: commandString ?? target,
      outcome: 'blocked',
      detail: { rule: decision.rule, mode: policy.mode },
      orgId: null,
      managed: false,
      agentId: null,
    });
    process.stderr.write(`[shield] blocked: ${commandString ?? target} (rule: ${decision.rule})\n`);
  } else if (decision.outcome === 'monitored') {
    writeEvent({
      source: 'shield',
      category: 'enforcement',
      severity: 'medium',
      agent,
      sessionId: null,
      action: 'command.monitored',
      target: commandString ?? target,
      outcome: 'monitored',
      detail: { rule: decision.rule, mode: policy.mode },
      orgId: null,
      managed: false,
      agentId: null,
    });
  }

  if (isJson) {
    process.stdout.write(JSON.stringify(decision, null, 2) + '\n');
  } else if (isHookInvocation) {
    // Hook mode: `evaluate` runs on EVERY interactive command, so an allowed
    // verdict must stay silent. Only the exception is worth a line.
    if (decision.outcome === 'monitored') {
      process.stdout.write(`${yellow('MONITORED')}  rule=${decision.rule}\n`);
    }
  } else {
    // Direct invocation: the user typed `shield evaluate` to be told the
    // verdict, and reporting it is the command's entire purpose. Silence here
    // was indistinguishable from a crash (#255).
    writeEvaluateVerdict(decision, category, target, agent);
  }

  return decision.outcome === 'blocked' ? 1 : 0;
}

/**
 * Render the verdict the --json path already returns: outcome, deciding rule,
 * agent, and the subject actually evaluated.
 *
 * The subject line is not decoration. `shield evaluate --action X --target Y`
 * is printed as remediation by src/shield/findings.ts, but neither flag is
 * registered on the command, so the target evaluated is the empty string.
 * Showing category/target lets a user see WHAT was judged rather than read a
 * confident verdict about nothing.
 */
function writeEvaluateVerdict(
  decision: { outcome: string; rule: string },
  category: string,
  target: string,
  agent: string | null,
): void {
  const label =
    decision.outcome === 'blocked'
      ? red('BLOCKED')
      : decision.outcome === 'monitored'
        ? yellow('MONITORED')
        : green('ALLOWED');

  process.stdout.write('\n');
  process.stdout.write(`  ${bold(label)}  ${dim(`rule ${decision.rule}`)}\n`);
  process.stdout.write(
    `  ${dim('Evaluated:')} ${category}${target ? ` -> ${target}` : dim(' (no target given)')}\n`,
  );
  process.stdout.write(`  ${dim('Agent:')} ${agent ?? dim('none')}\n`);

  // A default-allow is the state an operator most needs stated out loud: it
  // means nothing in the policy spoke to this action, not that it was vetted.
  if (decision.rule.endsWith(':no-match')) {
    process.stdout.write(
      `  ${dim('No policy rule matched. Allowing by default -- this action was not vetted.')}\n`,
    );
    process.stdout.write(
      `  ${dim('Review or tighten the policy:')} ${cyan('opena2a shield policy')}\n`,
    );
  }
  process.stdout.write('\n');
}

/** Longest read error `recover --archive-log` prints; the rest is cut. */
const MAX_READ_ERROR_CHARS = 300;

/**
 * A read error made safe to print: printableText on one trimmed line, cut at
 * MAX_READ_ERROR_CHARS characters.
 */
function printableReadError(message: string): string {
  const oneLine = printableText(message).trim();
  const chars = Array.from(oneLine);
  if (chars.length <= MAX_READ_ERROR_CHARS) return oneLine;
  const hidden = chars.length - MAX_READ_ERROR_CHARS;
  return `${chars.slice(0, MAX_READ_ERROR_CHARS).join('')}... (${hidden} more characters not shown)`;
}

/**
 * `shield recover --archive-log` -- retire a broken event log.
 *
 * SHIELD-INT-002 (broken hash chain) had no path to green: `selfcheck`
 * reports the config intact, `recover` reports "not in lockdown", and
 * `review` keeps raising the finding, so the only exit was deleting
 * `events.jsonl`, the Shield event log, by hand.
 *
 * The broken log is ARCHIVED, never deleted: it is the evidence of whatever
 * broke it. Its sha256 is recorded in the first event of the fresh chain, so
 * the new log carries a verifiable pointer back to the old one and the break
 * cannot be laundered by rotating it away.
 *
 * The chain check and the digest both read the log in fixed chunks. The check
 * keeps at most one event, the first one past the break, and the digest keeps
 * none, so a log of any size is checked and archived without being held whole.
 * A log that cannot be read is refused as unreadable, never as intact.
 */
async function handleArchiveLog(options: ShieldOptions): Promise<number> {
  const {
    getEventsPath,
    verifyEventLog,
    rotatedEventsPath,
    sha256File,
    writeEvent,
  } = await import('../shield/events.js');

  const isJson = options.format === 'json';
  const eventsPath = getEventsPath();

  const refuse = (status: string, message: string, extra: Record<string, unknown> = {}): number => {
    if (isJson) {
      process.stdout.write(JSON.stringify({ status, eventsPath, ...extra }, null, 2) + '\n');
    } else {
      process.stderr.write(red(message + '\n'));
    }
    return 1;
  };

  if (!fs.existsSync(eventsPath)) {
    return refuse('no_event_log', `No event log at ${eventsPath}. Nothing to archive.`);
  }

  // Counts only: the verdict and the anchor come from the counters, so the
  // chain is checked in fixed chunks and at most one event, the first one
  // past the break, is kept, whatever the size.
  let verification: ReturnType<typeof verifyEventLog>;
  try {
    verification = verifyEventLog(eventsPath, { countsOnly: true });
  } catch (err) {
    // A log that cannot be read is not known to be intact, and a log is
    // never archived without its chain being checked. The error reaches the
    // terminal in both output modes, so it is made printable first.
    const reason = printableReadError(err instanceof Error ? err.message : String(err));
    return refuse(
      'unreadable',
      'Event log could not be read, so its hash chain was not checked. Nothing archived.\n' +
      `  Reason:   ${reason}\n  Inspect:  opena2a shield selfcheck\n  Log:      ${eventsPath}`,
      { error: reason },
    );
  }
  const { chainBroken, brokenAt, untrustedCount } = verification;

  // Archiving an intact log would discard trustworthy history for nothing,
  // and would be a way to drop events on demand.
  if (!chainBroken) {
    return refuse(
      'chain_intact',
      'Event log hash chain is intact. Nothing to archive.\n' +
      `  Inspect:  opena2a shield log\n  Log:      ${eventsPath}`,
    );
  }

  // Hashed in fixed chunks: the log is never held whole, whatever its size.
  const archivedSha256 = sha256File(eventsPath);
  const archivedPath = rotatedEventsPath(eventsPath);

  fs.renameSync(eventsPath, archivedPath);

  // The fresh log is empty, so this event anchors to genesis and becomes the
  // first link of the new chain.
  const anchor = writeEvent({
    source: 'shield',
    // Deliberately not category 'integrity' + severity 'critical': that pair
    // classifies as SHIELD-INT-002, which would re-raise on the fresh chain
    // the very finding this command clears.
    category: 'log-archive',
    severity: 'high',
    agent: null,
    sessionId: null,
    action: 'shield.log-archived',
    target: archivedPath,
    outcome: 'monitored',
    detail: { archivedPath, archivedSha256, brokenAt, untrustedCount },
    orgId: null,
    managed: false,
    agentId: null,
  });

  if (isJson) {
    process.stdout.write(JSON.stringify({
      status: 'archived',
      archivedPath,
      archivedSha256,
      brokenAt,
      untrustedCount,
      eventsPath,
      anchorEventId: anchor.id,
    }, null, 2) + '\n');
    return 0;
  }

  process.stdout.write(green('Broken event log archived.\n'));
  process.stdout.write(`  ${dim('Archive:')} ${archivedPath}\n`);
  process.stdout.write(`  ${dim('sha256:')}  ${archivedSha256}\n`);
  process.stdout.write(
    `  ${dim('Excluded:')} ${untrustedCount} event(s) from index ${brokenAt}\n`,
  );
  process.stdout.write(`  ${dim('New log:')} ${eventsPath} ${dim('(fresh chain)')}\n`);
  process.stdout.write(dim('  Verify:  opena2a shield selfcheck\n'));
  return 0;
}

async function handleRecover(options: ShieldOptions): Promise<number> {
  const { isLockdown, exitLockdown, getLockdownReason } = await import('../shield/integrity.js');
  const isJson = options.format === 'json';

  // Before the lockdown gate on purpose: a broken hash chain does not put the
  // system into lockdown, so behind the gate this would be unreachable in the
  // exact situation it exists for.
  if (options.archiveLog) {
    return handleArchiveLog(options);
  }

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
    const { runIntegrityChecks } = await import('../shield/integrity.js');
    const shell = process.env.SHELL?.includes('zsh') ? 'zsh' as const
      : process.env.SHELL?.includes('bash') ? 'bash' as const
      : undefined;

    // Verify BEFORE recovering, which is what --verify promises (#228).
    // `ignoreLockdown` lets the checks run with the marker still in place, so
    // a compromised machine is never briefly unlocked and an interrupted
    // verification cannot strand it out of lockdown.
    //
    // A check that throws must stay locked AND stay actionable: `shield
    // status` cites this command as the single way out of lockdown, so an
    // unhandled stack trace here would leave the user with no cited path.
    let state: IntegrityState;
    try {
      state = runIntegrityChecks({ shell, ignoreLockdown: true });
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      if (isJson) {
        process.stdout.write(JSON.stringify({
          status: 'verification_error', detail, stillInLockdown: true,
        }, null, 2) + '\n');
      } else {
        process.stderr.write(red(`Verification could not complete: ${detail}\n`));
        process.stderr.write('System remains in lockdown.\n');
        process.stderr.write(dim('  Inspect:  opena2a shield selfcheck\n'));
        process.stderr.write(dim('  Unlock without verifying:  opena2a shield recover\n'));
      }
      return 1;
    }

    if (state.status === 'compromised') {
      // Still locked — nothing to re-enter, and the original reason survives.
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

    // No failing check — safe to lift the marker. `degraded` (warn-level
    // checks) still unlocks, as it always has: a missing shell rc file must
    // not strand someone in lockdown. But it is NOT "successful
    // verification", and saying so would paper over a warn on the
    // event log itself, so the warnings are named.
    exitLockdown();

    const warnings = state.checks.filter(c => c.status === 'warn');

    if (isJson) {
      process.stdout.write(JSON.stringify({
        status: 'recovered',
        verified: true,
        integrityStatus: state.status,
        warnings: warnings.map(c => ({ name: c.name, detail: c.detail })),
      }, null, 2) + '\n');
    } else if (warnings.length > 0) {
      process.stdout.write(yellow(
        `Lockdown lifted. Verification passed with ${warnings.length} warning(s):\n`,
      ));
      for (const c of warnings) {
        process.stdout.write(`  ${yellow('WARN')}  ${c.name}: ${c.detail}\n`);
      }
    } else {
      process.stdout.write(green('Lockdown lifted after successful verification.\n'));
    }
    return 0;
  }

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

// --- Report ---

async function handleReport(options: ShieldOptions): Promise<number> {
  const { chainBreakEvent, readVerifiedEvents } = await import('../shield/events.js');
  const isJson = options.format === 'json';

  const since = options.since ?? '7d';
  // Chain-verified read (#243), the same exclusion `review` applies (#204):
  // events at or after the first hash-chain break are untrusted, so they feed
  // none of the counts, findings, SARIF, HTML or trend snapshots below. The
  // break itself is surfaced once (SHIELD-INT-002) and the excluded count is
  // printed, so a report that lost part of its log never reads as a clean one.
  const verified = readVerifiedEvents({ since });
  const events = verified.events;
  const logIntegrity = {
    chainIntact: !verified.chainBroken,
    brokenAt: verified.brokenAt,
    excludedEvents: verified.untrustedCount,
    excludedInPeriod: verified.untrusted.length,
  };
  const writeIntegrityNote = (): void => {
    if (logIntegrity.chainIntact) return;
    process.stdout.write(red(
      `  Log integrity: hash chain broken at event index ${String(logIntegrity.brokenAt)}; ` +
      `${String(logIntegrity.excludedEvents)} event(s) at and after the break are excluded from this report\n`,
    ));
    process.stdout.write(dim('    Verify:  opena2a shield selfcheck\n'));
    process.stdout.write(dim('    Fix:     opena2a shield recover --archive-log\n'));
  };

  const total = events.length;
  const bySeverity: Record<string, number> = {};
  const bySource: Record<string, number> = {};
  const byAgent: Record<string, number> = {};
  const byAction: Record<string, number> = {};
  const byOutcome: Record<string, number> = {};

  for (const event of events) {
    bySeverity[event.severity] = (bySeverity[event.severity] ?? 0) + 1;
    bySource[event.source] = (bySource[event.source] ?? 0) + 1;
    byOutcome[event.outcome] = (byOutcome[event.outcome] ?? 0) + 1;
    const agentKey = event.agent ?? 'unknown';
    byAgent[agentKey] = (byAgent[agentKey] ?? 0) + 1;
    byAction[event.action] = (byAction[event.action] ?? 0) + 1;
  }

  const topN = (record: Record<string, number>, n: number): { name: string; count: number }[] =>
    Object.entries(record)
      .sort((a, b) => b[1] - a[1])
      .slice(0, n)
      .map(([name, count]) => ({ name, count }));

  const topAgents = topN(byAgent, 10);
  const topActions = topN(byAction, 10);

  // --- Classify events into findings ---
  const { classifyEvents, classifyViolation, frameworkTags } = await import('../shield/findings.js');
  const classifiedFindings = classifyEvents(
    verified.chainBroken ? [...events, chainBreakEvent(verified, 'report')] : events,
  );

  // --- SARIF output ---
  if (options.format === 'sarif') {
    const { toSarif } = await import('../shield/sarif.js');
    const { getVersion } = await import('../util/version.js');
    const sarif = toSarif(classifiedFindings, getVersion());
    const sarifJson = JSON.stringify(sarif, null, 2);
    if (options.report) {
      const reportPath = path.resolve(options.report);
      fs.writeFileSync(reportPath, sarifJson, 'utf-8');
      process.stdout.write(`SARIF report written to ${reportPath}\n`);
      writeIntegrityNote();
    } else {
      process.stdout.write(sarifJson + '\n');
    }
    return 0;
  }

  // --- HTML report output ---
  if (options.report) {
    const weeklyReport = await buildWeeklyReport(events, since, bySeverity, byOutcome, byAgent, topActions);

    // Enrich violations with finding data
    for (const v of weeklyReport.policyEvaluation.topViolations) {
      const finding = classifyViolation(v);
      if (finding) {
        v.findingId = finding.id;
        v.remediationCommand = finding.remediation;
        v.compliance = frameworkTags(finding);
      }
    }

    // Compute trend from snapshot history
    const trendData = await computeTrend(weeklyReport);
    if (trendData) {
      weeklyReport.posture.trend = trendData;
    }

    // Save snapshot for future trend comparisons
    await saveReportSnapshot(weeklyReport, classifiedFindings);

    let narrative: import('../shield/types.js').ReportNarrative | null = null;
    if (options.analyze) {
      const { generateNarrative } = await import('../shield/llm.js');
      narrative = await generateNarrative(weeklyReport);
    }
    const { generateShieldHtmlReport } = await import('../shield/report-html.js');
    const html = generateShieldHtmlReport(weeklyReport, narrative, classifiedFindings, trendData);
    const reportPath = path.resolve(options.report);
    fs.writeFileSync(reportPath, html, 'utf-8');
    process.stdout.write(`Report written to ${reportPath}\n`);
    writeIntegrityNote();
    return 0;
  }

  if (isJson) {
    const data: Record<string, unknown> = {
      periodSince: since,
      totalEvents: total,
      logIntegrity,
      bySeverity,
      bySource,
      byOutcome,
      topAgents,
      topActions,
    };

    if (options.analyze) {
      const narrative = await buildNarrative(events, since, bySeverity, byOutcome, byAgent, topActions);
      if (narrative) {
        data.narrative = narrative;
      }
    }

    process.stdout.write(JSON.stringify(data, null, 2) + '\n');
    return 0;
  }

  process.stdout.write(bold('Shield Security Report') + '\n');
  process.stdout.write(gray('-'.repeat(50)) + '\n');
  process.stdout.write(`  Period:       since ${cyan(since)}\n`);
  process.stdout.write(`  Total events: ${bold(String(total))}\n`);
  writeIntegrityNote();
  process.stdout.write('\n');

  process.stdout.write(bold('  Severity Breakdown') + '\n');
  const severityOrder: EventSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of severityOrder) {
    const count = bySeverity[sev];
    if (count === undefined || count === 0) continue;
    process.stdout.write(`    ${colorSeverity(sev).padEnd(20)} ${String(count)}\n`);
  }
  if (Object.keys(bySeverity).length === 0) {
    process.stdout.write(yellow('    (no events)\n'));
  }
  process.stdout.write('\n');

  process.stdout.write(bold('  Events by Source') + '\n');
  for (const { name, count } of topN(bySource, 10)) {
    process.stdout.write(`    ${name.padEnd(20)} ${String(count)}\n`);
  }
  if (Object.keys(bySource).length === 0) {
    process.stdout.write(yellow('    (no events)\n'));
  }
  process.stdout.write('\n');

  process.stdout.write(bold('  Top Agents') + '\n');
  for (const { name, count } of topAgents) {
    process.stdout.write(`    ${name.padEnd(20)} ${String(count)} events\n`);
  }
  if (topAgents.length === 0) {
    process.stdout.write(yellow('    (no events)\n'));
  }
  process.stdout.write('\n');

  process.stdout.write(bold('  Top Actions') + '\n');
  for (const { name, count } of topActions) {
    process.stdout.write(`    ${name.padEnd(30)} ${String(count)}\n`);
  }
  if (topActions.length === 0) {
    process.stdout.write(yellow('    (no events)\n'));
  }

  if (options.analyze) {
    process.stdout.write('\n');
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    process.stdout.write(bold('  AI Analysis') + '\n');

    const narrative = await buildNarrative(events, since, bySeverity, byOutcome, byAgent, topActions);
    if (narrative) {
      process.stdout.write('\n');
      process.stdout.write(`  ${bold('Summary')}\n`);
      process.stdout.write(`  ${narrative.summary}\n`);

      if (narrative.highlights.length > 0) {
        process.stdout.write('\n');
        process.stdout.write(`  ${green('Highlights')}\n`);
        for (const h of narrative.highlights) {
          process.stdout.write(`    - ${h}\n`);
        }
      }

      if (narrative.concerns.length > 0) {
        process.stdout.write('\n');
        process.stdout.write(`  ${yellow('Concerns')}\n`);
        for (const c of narrative.concerns) {
          process.stdout.write(`    - ${c}\n`);
        }
      }

      if (narrative.recommendations.length > 0) {
        process.stdout.write('\n');
        process.stdout.write(`  ${cyan('Recommendations')}\n`);
        for (const r of narrative.recommendations) {
          process.stdout.write(`    - ${r}\n`);
        }
      }
    } else {
      process.stdout.write(dim('  LLM analysis unavailable (no API key or backend configured).\n'));
    }
  }

  process.stdout.write(gray('-'.repeat(50)) + '\n');
  return 0;
}

// --- Snapshot Persistence for Trend Analysis ---

async function saveReportSnapshot(
  report: import('../shield/types.js').WeeklyReport,
  findings: import('../shield/findings.js').ClassifiedFinding[],
): Promise<void> {
  const { getShieldDir } = await import('../shield/events.js');
  const { SHIELD_SNAPSHOTS_FILE } = await import('../shield/types.js');

  const findingCounts: Record<string, number> = {};
  for (const f of findings) {
    const sev = f.finding.severity;
    findingCounts[sev] = (findingCounts[sev] ?? 0) + f.count;
  }

  const snapshot: import('../shield/types.js').ReportSnapshot = {
    timestamp: report.generatedAt,
    score: report.posture.score,
    grade: report.posture.grade,
    findingCounts,
    totalFindings: findings.reduce((sum, f) => sum + f.count, 0),
  };

  const dir = getShieldDir();
  const filePath = path.join(dir, SHIELD_SNAPSHOTS_FILE);
  fs.appendFileSync(filePath, JSON.stringify(snapshot) + '\n', 'utf-8');
}

async function loadPreviousSnapshot(): Promise<import('../shield/types.js').ReportSnapshot | null> {
  const { getShieldDir } = await import('../shield/events.js');
  const { SHIELD_SNAPSHOTS_FILE } = await import('../shield/types.js');

  const dir = getShieldDir();
  const filePath = path.join(dir, SHIELD_SNAPSHOTS_FILE);

  if (!fs.existsSync(filePath)) return null;

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }

  const lines = content.split('\n').filter(l => l.trim().length > 0);
  if (lines.length === 0) return null;

  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      return JSON.parse(lines[i]) as import('../shield/types.js').ReportSnapshot;
    } catch {
      continue;
    }
  }
  return null;
}

async function computeTrend(
  report: import('../shield/types.js').WeeklyReport,
): Promise<import('../shield/types.js').PostureTrend | null> {
  const previous = await loadPreviousSnapshot();
  if (!previous) return null;

  const delta = report.posture.score - previous.score;
  const periodMs = new Date(report.generatedAt).getTime() - new Date(previous.timestamp).getTime();
  const periodDays = Math.max(1, Math.round(periodMs / (24 * 60 * 60 * 1000)));

  let direction: 'improving' | 'declining' | 'stable';
  if (delta > 3) direction = 'improving';
  else if (delta < -3) direction = 'declining';
  else direction = 'stable';

  return {
    previousScore: previous.score,
    previousGrade: previous.grade,
    delta,
    direction,
    periodDays,
  };
}

/**
 * Build a WeeklyReport from aggregated event data.
 */
function extractCredProvider(event: import('../shield/types.js').ShieldEvent): string {
  const t = (event.target ?? '').toLowerCase();
  if (t.includes('anthropic')) return 'Anthropic';
  if (t.includes('openai')) return 'OpenAI';
  if (t.includes('github')) return 'GitHub';
  if (t.includes('aws') || t.includes('amazon')) return 'AWS';
  if (t.includes('azure')) return 'Azure';
  if (t.includes('gcp') || t.includes('google')) return 'Google Cloud';
  return event.source === 'secretless' ? 'Secretless' : 'Other';
}

async function buildWeeklyReport(
  events: import('../shield/types.js').ShieldEvent[],
  since: string,
  bySeverity: Record<string, number>,
  byOutcome: Record<string, number>,
  byAgent: Record<string, number>,
  topActions: { name: string; count: number }[],
): Promise<import('../shield/types.js').WeeklyReport> {
  const { computeARPStats } = await import('../shield/arp-bridge.js');
  const { hostname } = await import('node:os');

  const now = new Date();
  const sinceMatch = since.match(/^(\d+)([dwm])$/);
  let periodStart: Date;
  if (sinceMatch) {
    const amount = parseInt(sinceMatch[1], 10);
    const unit = sinceMatch[2];
    const msPerDay = 24 * 60 * 60 * 1000;
    const daysAgo = unit === 'd' ? amount : unit === 'w' ? amount * 7 : amount * 30;
    periodStart = new Date(now.getTime() - daysAgo * msPerDay);
  } else {
    const parsed = new Date(since);
    periodStart = isNaN(parsed.getTime()) ? new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000) : parsed;
  }

  const agentSummaries: Record<string, import('../shield/types.js').AgentActivitySummary> = {};
  const sessionIds = new Set<string>();

  for (const event of events) {
    const agentKey = event.agent ?? 'unknown';
    if (!agentSummaries[agentKey]) {
      agentSummaries[agentKey] = {
        sessions: 0,
        actions: 0,
        firstSeen: event.timestamp,
        lastSeen: event.timestamp,
        topActions: [],
      };
    }
    const summary = agentSummaries[agentKey];
    summary.actions += 1;
    if (event.timestamp < summary.firstSeen) summary.firstSeen = event.timestamp;
    if (event.timestamp > summary.lastSeen) summary.lastSeen = event.timestamp;
    if (event.sessionId) sessionIds.add(event.sessionId);
  }

  const agentActionCounts: Record<string, Record<string, number>> = {};
  for (const event of events) {
    const agentKey = event.agent ?? 'unknown';
    if (!agentActionCounts[agentKey]) agentActionCounts[agentKey] = {};
    agentActionCounts[agentKey][event.action] = (agentActionCounts[agentKey][event.action] ?? 0) + 1;
  }
  for (const [agent, actions] of Object.entries(agentActionCounts)) {
    if (agentSummaries[agent]) {
      agentSummaries[agent].topActions = Object.entries(actions)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([action, count]) => ({ action, count }));
    }
  }

  const agentSessions: Record<string, Set<string>> = {};
  for (const event of events) {
    const agentKey = event.agent ?? 'unknown';
    if (!agentSessions[agentKey]) agentSessions[agentKey] = new Set();
    if (event.sessionId) agentSessions[agentKey].add(event.sessionId);
  }
  for (const [agent, sessions] of Object.entries(agentSessions)) {
    if (agentSummaries[agent]) {
      agentSummaries[agent].sessions = sessions.size || 1;
    }
  }

  const violations: import('../shield/types.js').PolicyViolation[] = [];
  const violationMap: Record<string, { count: number; event: import('../shield/types.js').ShieldEvent }> = {};
  for (const event of events) {
    if (event.outcome === 'blocked' || event.severity === 'high' || event.severity === 'critical') {
      const key = `${event.action}:${event.target}:${event.agent ?? 'unknown'}`;
      if (!violationMap[key]) {
        violationMap[key] = { count: 0, event };
      }
      violationMap[key].count += 1;
    }
  }
  for (const [, { count, event }] of Object.entries(violationMap)) {
    violations.push({
      action: event.action,
      target: event.target,
      agent: event.agent ?? 'unknown',
      count,
      severity: event.severity,
      recommendation: event.outcome === 'blocked' ? 'Already blocked by policy' : 'Review and consider blocking',
    });
  }
  violations.sort((a, b) => b.count - a.count);

  let credAccessAttempts = 0;
  const credProviders: Record<string, number> = {};
  const credNames = new Set<string>();
  for (const event of events) {
    if (event.source === 'secretless' || (event.source !== 'shield' && event.category.includes('credential'))) {
      credAccessAttempts += 1;
      credNames.add(event.target);
      const provider = extractCredProvider(event);
      credProviders[provider] = (credProviders[provider] ?? 0) + 1;
    }
  }

  let packagesInstalled = 0;
  let advisoriesFound = 0;
  let blockedInstalls = 0;
  for (const event of events) {
    if (event.source === 'registry' || event.category.includes('supply-chain')) {
      packagesInstalled += 1;
      if (event.severity === 'high' || event.severity === 'critical') advisoriesFound += 1;
      if (event.outcome === 'blocked') blockedInstalls += 1;
    }
  }

  // Posture score: only count external threat events, not Shield's own diagnostic scans.
  // Shield events (posture-assessment, credential-finding, shield.init) are informational.
  const threatEvents = events.filter(e => e.source !== 'shield');
  const threatSeverity: Record<string, number> = {};
  for (const e of threatEvents) {
    threatSeverity[e.severity] = (threatSeverity[e.severity] ?? 0) + 1;
  }
  const criticalCount = threatSeverity['critical'] ?? 0;
  const highCount = threatSeverity['high'] ?? 0;
  const mediumCount = threatSeverity['medium'] ?? 0;
  const blockedCount = events.filter(e => e.source !== 'shield' && e.outcome === 'blocked').length;

  // From the verified events this report already holds, as `review` does:
  // an ARP event past a chain break never marks ARP active or raises the
  // enforcement and coverage factors.  Same window as the raw read it
  // replaces: source arp, the newest 10000 in the period.
  const arpStats = computeARPStats(events.filter(e => e.source === 'arp').slice(0, 10000));
  const hasRealActivity = threatEvents.length > 0;
  const arpIsActive = arpStats.totalEvents > 0;

  // Only count agents from non-shield events for coverage scoring
  const realAgentCount = new Set(
    events.filter(e => e.source !== 'shield' && e.agent).map(e => e.agent),
  ).size;

  // Weighted factor scoring: severity (50%), enforcement (25%), coverage (25%).
  // Severity uses capped penalties so a few events don't destroy the entire score.
  const severityPenalty = Math.min(60, criticalCount * 12 + highCount * 5 + mediumCount * 2);
  const severityScore = 100 - severityPenalty;

  // Enforcement: actively blocking threats is a strong positive signal.
  // Honest about gaps: no monitoring running = low score.
  const enforcementScore = blockedCount > 0
    ? Math.min(100, 60 + Math.min(40, blockedCount * 5))
    : hasRealActivity ? 30
    : arpIsActive ? 50
    : 20; // nothing running

  // Coverage: only real monitored agents count, not shield diagnostics.
  const coverageScore = realAgentCount >= 3 ? 80
    : realAgentCount >= 1 ? 60
    : arpIsActive ? 40
    : 20; // no runtime monitoring

  let score = Math.round(severityScore * 0.5 + enforcementScore * 0.25 + coverageScore * 0.25);
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? 'strong' : score >= 80 ? 'good' : score >= 70 ? 'moderate' : score >= 60 ? 'improving' : 'needs-attention';

  const report: import('../shield/types.js').WeeklyReport = {
    version: 1,
    generatedAt: now.toISOString(),
    periodStart: periodStart.toISOString(),
    periodEnd: now.toISOString(),
    hostname: hostname(),

    agentActivity: {
      totalSessions: sessionIds.size || (events.length > 0 ? 1 : 0),
      totalActions: events.length,
      byAgent: agentSummaries,
    },

    policyEvaluation: {
      monitored: events.filter(e => e.source !== 'shield' && e.outcome === 'monitored').length,
      wouldBlock: 0,
      blocked: blockedCount,
      topViolations: violations.slice(0, 5),
    },

    credentialExposure: {
      accessAttempts: credAccessAttempts,
      uniqueCredentials: credNames.size,
      byProvider: credProviders,
      recommendations: [],
    },

    supplyChain: {
      packagesInstalled,
      advisoriesFound,
      blockedInstalls,
      lowTrustPackages: [],
    },

    configIntegrity: await (async () => {
      try {
        const mod: any = await import('./guard.js');
        const fn = mod.verifyConfigIntegrity ?? mod.default?.verifyConfigIntegrity;
        if (fn) return fn();
        return { filesMonitored: 0, tamperedFiles: [] as string[], signatureStatus: 'unsigned' as const };
      } catch {
        return { filesMonitored: 0, tamperedFiles: [] as string[], signatureStatus: 'unsigned' as const };
      }
    })(),

    runtimeProtection: {
      arpActive: arpStats.totalEvents > 0,
      processesSpawned: arpStats.processEvents,
      networkConnections: arpStats.networkEvents,
      anomalies: arpStats.anomalies + arpStats.violations + arpStats.threats,
    },

    posture: {
      score,
      grade,
      factors: [
        { name: 'severity', score: severityScore, weight: 0.5, detail: threatEvents.length > 0 ? `${criticalCount} critical, ${highCount} high, ${mediumCount} medium` : 'no threat events' },
        { name: 'enforcement', score: enforcementScore, weight: 0.25, detail: blockedCount > 0 ? `${blockedCount} blocked` : hasRealActivity ? 'monitor-only mode' : arpIsActive ? 'ARP active, no threats' : 'no runtime monitoring' },
        { name: 'coverage', score: coverageScore, weight: 0.25, detail: realAgentCount > 0 ? `${realAgentCount} agent${realAgentCount !== 1 ? 's' : ''} monitored` : arpIsActive ? 'ARP active' : 'no runtime monitoring' },
      ],
      trend: null,
      comparative: null,
    },
  };

  return report;
}

/**
 * Build a WeeklyReport and call generateNarrative().
 * Returns the narrative or null if LLM is unavailable.
 */
async function buildNarrative(
  events: import('../shield/types.js').ShieldEvent[],
  since: string,
  bySeverity: Record<string, number>,
  byOutcome: Record<string, number>,
  byAgent: Record<string, number>,
  topActions: { name: string; count: number }[],
): Promise<import('../shield/types.js').ReportNarrative | null> {
  const { generateNarrative } = await import('../shield/llm.js');
  const report = await buildWeeklyReport(events, since, bySeverity, byOutcome, byAgent, topActions);
  return generateNarrative(report);
}

// --- Monitor ---

async function handleMonitor(options: ShieldOptions): Promise<number> {
  const { importARPEvents, getVerifiedARPStats } = await import('../shield/arp-bridge.js');
  const isJson = options.format === 'json';
  const targetDir = options.dir ? path.resolve(options.dir) : process.cwd();

  // Step 1: Import any existing ARP events into Shield's hash chain
  const result = importARPEvents(targetDir, options.agent);

  // Step 2: Get ARP stats from the verified events in Shield's unified log
  const { stats, unverifiedStats, verification } = getVerifiedARPStats(options.since ?? '7d');

  if (isJson) {
    process.stdout.write(JSON.stringify({
      import: result,
      stats,
      unverifiedStats,
      verification,
    }, null, 2) + '\n');
    return 0;
  }

  process.stdout.write(bold('Shield ARP Monitor') + '\n');
  process.stdout.write(gray('-'.repeat(50)) + '\n');

  // Import results
  if (result.total > 0) {
    process.stdout.write(bold('  Event Import') + '\n');
    if (result.imported > 0) {
      process.stdout.write(`    ${green(`${result.imported} new events`)} imported into Shield log\n`);
    }
    if (result.skipped > result.skippedUnverified) {
      process.stdout.write(`    ${dim(`${result.skipped - result.skippedUnverified} already imported`)}\n`);
    }
    if (result.skippedUnverified > 0) {
      process.stdout.write(
        `    ${yellow(`${result.skippedUnverified} recorded only past a chain break`)} ` +
        `${dim('(unverified); archive the broken log to import them into a fresh chain')}\n`,
      );
    }
    if (result.errors > 0) {
      process.stdout.write(`    ${yellow(`${result.errors} parse errors`)}\n`);
    }
    process.stdout.write('\n');
  } else {
    process.stdout.write(dim('  No ARP events found.') + '\n');
    process.stdout.write(dim('  Start ARP monitoring: opena2a runtime start') + '\n\n');
  }

  writeChainBreakNotice(verification, 'not counted', '  ');

  // Counts only: what the break holds back, so a broken chain never reads
  // as fewer detections without saying how many were left out.
  if (unverifiedStats.totalEvents > 0) {
    const counted = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;
    const held = [counted(unverifiedStats.totalEvents, 'ARP event', 'ARP events')];
    if (unverifiedStats.anomalies > 0) held.push(counted(unverifiedStats.anomalies, 'anomaly', 'anomalies'));
    if (unverifiedStats.violations > 0) held.push(counted(unverifiedStats.violations, 'violation', 'violations'));
    if (unverifiedStats.threats > 0) held.push(counted(unverifiedStats.threats, 'threat', 'threats'));
    process.stdout.write(bold('  Unverified, not counted') + '\n');
    process.stdout.write(`    ${yellow(held.join(', '))} ${dim('past the chain break in this period')}\n\n`);
  }

  // ARP stats from Shield's unified log
  if (stats.totalEvents > 0) {
    process.stdout.write(bold('  Runtime Protection Summary') + '\n');
    process.stdout.write(`    ${dim('Total events')}       ${stats.totalEvents}\n`);
    process.stdout.write(`    ${dim('Process events')}     ${stats.processEvents}\n`);
    process.stdout.write(`    ${dim('Network events')}     ${stats.networkEvents}\n`);
    process.stdout.write(`    ${dim('Filesystem events')}  ${stats.filesystemEvents}\n`);
    process.stdout.write(`    ${dim('Prompt events')}      ${stats.promptEvents}\n`);

    if (stats.anomalies > 0 || stats.violations > 0 || stats.threats > 0) {
      process.stdout.write('\n');
      process.stdout.write(bold('  Detections') + '\n');
      if (stats.anomalies > 0) {
        process.stdout.write(`    ${yellow(`${stats.anomalies} anomalies`)}\n`);
      }
      if (stats.violations > 0) {
        process.stdout.write(`    ${red(`${stats.violations} violations`)}\n`);
      }
      if (stats.threats > 0) {
        process.stdout.write(`    ${bold(red(`${stats.threats} threats`))}\n`);
      }
      if (stats.enforcements > 0) {
        process.stdout.write(`    ${cyan(`${stats.enforcements} enforcements`)}\n`);
      }
    } else {
      process.stdout.write(`    ${green('No anomalies or threats detected')}\n`);
    }
  }

  process.stdout.write(gray('-'.repeat(50)) + '\n');
  return 0;
}

// --- Session ---

async function handleSession(options: ShieldOptions): Promise<number> {
  const { identifySession, collectSignals } = await import('../shield/session.js');
  const isJson = options.format === 'json';

  const session = identifySession();

  if (!session) {
    if (isJson) {
      process.stdout.write(JSON.stringify({ detected: false }, null, 2) + '\n');
    } else {
      process.stdout.write(dim('No AI coding assistant session detected.\n'));
    }
    return 0;
  }

  const { isSessionExpired } = await import('../shield/session.js');
  const expired = isSessionExpired(session);

  if (isJson) {
    process.stdout.write(JSON.stringify({ detected: true, expired, ...session }, null, 2) + '\n');
    return 0;
  }

  process.stdout.write(bold('Shield Session\n'));
  process.stdout.write(gray('-'.repeat(40)) + '\n');
  process.stdout.write(`  Agent:       ${cyan(session.agent)}\n`);
  process.stdout.write(`  Confidence:  ${session.confidence.toFixed(2)}\n`);
  process.stdout.write(`  Session ID:  ${dim(session.sessionId)}\n`);
  process.stdout.write(`  Signals:     ${session.signals.length} detected\n`);
  process.stdout.write(`  Expired:     ${expired ? yellow('yes') : green('no')}\n`);
  process.stdout.write(`  Started:     ${dim(session.startedAt)}\n`);
  process.stdout.write(`  Last seen:   ${dim(session.lastSeenAt)}\n`);

  if (options.verbose) {
    const signals = collectSignals();
    process.stdout.write(gray('-'.repeat(40)) + '\n');
    process.stdout.write(bold('  Raw signals:\n'));
    for (const sig of signals) {
      process.stdout.write(`    ${dim(sig.type.padEnd(8))} ${sig.name.padEnd(24)} ${sig.value} ${dim(`(${sig.confidence.toFixed(2)})`)}\n`);
    }
  }

  process.stdout.write(gray('-'.repeat(40)) + '\n');
  return 0;
}

// --- Baseline ---

async function handleBaseline(options: ShieldOptions): Promise<number> {
  const { listBaselines, getBaseline, computeStability, checkPhaseTransition } =
    await import('../shield/baselines.js');
  const isJson = options.format === 'json';

  if (options.agent) {
    // Detailed view for a single agent
    const baseline = getBaseline(options.agent);
    const stability = computeStability(baseline);
    const transition = checkPhaseTransition(baseline);

    if (isJson) {
      process.stdout.write(JSON.stringify({
        ...baseline,
        stabilityScore: stability,
        transition,
      }, null, 2) + '\n');
      return 0;
    }

    process.stdout.write(bold('Agent Baseline') + '\n');
    process.stdout.write(gray('-'.repeat(50)) + '\n');
    process.stdout.write(`  Agent:          ${cyan(baseline.agent)}\n`);
    process.stdout.write(`  Phase:          ${phaseColor(baseline.phase)}\n`);
    process.stdout.write(`  Stability:      ${stabilityBar(stability)}\n`);
    process.stdout.write(`  Total actions:  ${String(baseline.totalActions)}\n`);
    process.stdout.write(`  Total sessions: ${String(baseline.totalSessions)}\n`);
    process.stdout.write(`  Observed since: ${dim(baseline.observationStart)}\n`);
    process.stdout.write(`  Last activity:  ${dim(baseline.observationEnd)}\n`);

    if (baseline.lastNewBehaviorAt) {
      process.stdout.write(`  Last new behavior: ${dim(baseline.lastNewBehaviorAt)}\n`);
    }

    process.stdout.write('\n');
    process.stdout.write(bold('  Observed Behavior') + '\n');

    const buckets: [string, Record<string, number>][] = [
      ['Processes', baseline.observed.processes],
      ['Credentials', baseline.observed.credentials],
      ['Filesystem', baseline.observed.filesystemPaths],
      ['Network', baseline.observed.networkHosts],
      ['MCP Servers', baseline.observed.mcpServers],
    ];

    for (const [label, entries] of buckets) {
      const keys = Object.keys(entries);
      if (keys.length === 0) continue;
      process.stdout.write(`    ${label} (${keys.length}):\n`);
      const sorted = Object.entries(entries).sort((a, b) => b[1] - a[1]);
      for (const [name, count] of sorted.slice(0, 10)) {
        process.stdout.write(`      ${name.padEnd(40)} ${dim(String(count) + 'x')}\n`);
      }
      if (sorted.length > 10) {
        process.stdout.write(dim(`      ... and ${sorted.length - 10} more\n`));
      }
    }

    process.stdout.write('\n');
    process.stdout.write(`  Transition: ${dim(transition.reason)}\n`);

    if (baseline.recommended) {
      process.stdout.write('\n');
      process.stdout.write(bold('  Recommended Policy') + '\n');
      if (baseline.recommended.processes?.allow?.length) {
        process.stdout.write(`    Allow processes: ${baseline.recommended.processes.allow.length}\n`);
      }
      if (baseline.recommended.credentials?.allow?.length) {
        process.stdout.write(`    Allow credentials: ${baseline.recommended.credentials.allow.length}\n`);
      }
      if (baseline.recommended.network?.allow?.length) {
        process.stdout.write(`    Allow network: ${baseline.recommended.network.allow.length}\n`);
      }
    }

    process.stdout.write(gray('-'.repeat(50)) + '\n');
    return 0;
  }

  // List all baselines
  const baselines = listBaselines();

  if (baselines.length === 0) {
    if (isJson) {
      process.stdout.write(JSON.stringify([], null, 2) + '\n');
    } else {
      process.stdout.write(dim('No baselines found. Shield will create baselines as agent activity is observed.\n'));
    }
    return 0;
  }

  if (isJson) {
    process.stdout.write(JSON.stringify(baselines, null, 2) + '\n');
    return 0;
  }

  process.stdout.write(bold('Agent Baselines') + '\n');
  process.stdout.write(gray('-'.repeat(70)) + '\n');
  process.stdout.write(
    `  ${'Agent'.padEnd(20)} ${'Phase'.padEnd(10)} ${'Stability'.padEnd(12)} ${'Actions'.padEnd(10)} Sessions\n`,
  );
  process.stdout.write(gray('-'.repeat(70)) + '\n');

  for (const bl of baselines) {
    process.stdout.write(
      `  ${bl.agent.padEnd(20)} ${phaseColor(bl.phase).padEnd(10 + colorPadding(bl.phase))} ` +
      `${bl.stabilityScore.toFixed(2).padEnd(12)} ` +
      `${String(bl.totalActions).padEnd(10)} ` +
      `${String(bl.totalSessions)}\n`,
    );
  }

  process.stdout.write(gray('-'.repeat(70)) + '\n');
  return 0;
}

function phaseColor(phase: string): string {
  switch (phase) {
    case 'learn': return cyan(phase);
    case 'suggest': return yellow(phase);
    case 'protect': return green(phase);
    default: return dim(phase);
  }
}

/** ANSI codes add invisible characters; compute extra length for padding. */
function colorPadding(phase: string): number {
  return phaseColor(phase).length - phase.length;
}

function stabilityBar(score: number): string {
  const filled = Math.round(score * 10);
  const empty = 10 - filled;
  const bar = '#'.repeat(filled) + '-'.repeat(empty);
  const label = (score * 100).toFixed(0) + '%';
  if (score >= 0.8) return green(`[${bar}] ${label}`);
  if (score >= 0.5) return yellow(`[${bar}] ${label}`);
  return dim(`[${bar}] ${label}`);
}

// --- LLM intelligence handlers ---

async function handleSuggest(options: ShieldOptions): Promise<number> {
  const { checkLlmAvailable, suggestPolicy } = await import('../shield/llm.js');
  const { readVerifiedEvents, eventVerificationStatus } = await import('../shield/events.js');
  const isJson = options.format === 'json';

  const { backend } = await checkLlmAvailable();
  if (backend === 'none') {
    process.stderr.write(yellow('LLM intelligence is not available.\n'));
    process.stderr.write('Enable it with: opena2a config llm on\n');
    return 1;
  }

  // Verified events only: an event past a chain break never shapes a policy.
  const verified = readVerifiedEvents({ count: 100, agent: options.agent });
  const verification = eventVerificationStatus(verified);
  const events = verified.events;

  if (events.length === 0) {
    if (isJson) {
      writeNoResultJson(verification.chainBroken ? 'no-verified-events' : 'no-events', verification);
      return 0;
    }
    if (verification.chainBroken) {
      process.stdout.write(yellow('No verified events found.') + '\n');
      writeChainBreakNotice(verification, 'left out of the suggestion');
      return 0;
    }
    process.stdout.write(yellow('No events found.') + ' ' + dim('Run shield init and use your tools to generate events.') + '\n');
    return 0;
  }

  const agentName = options.agent ?? events[0].agent ?? 'unknown';
  const sessionIds = new Set(events.map(e => e.sessionId).filter(Boolean));

  const processCounts: Record<string, number> = {};
  const credentialCounts: Record<string, number> = {};
  const filePathCounts: Record<string, number> = {};
  const networkHostCounts: Record<string, number> = {};

  for (const event of events) {
    if (event.category === 'process' || event.category === 'processes') {
      processCounts[event.target] = (processCounts[event.target] ?? 0) + 1;
    } else if (event.category === 'credential' || event.category === 'credentials') {
      credentialCounts[event.target] = (credentialCounts[event.target] ?? 0) + 1;
    } else if (event.category === 'filesystem') {
      filePathCounts[event.target] = (filePathCounts[event.target] ?? 0) + 1;
    } else if (event.category === 'network') {
      networkHostCounts[event.target] = (networkHostCounts[event.target] ?? 0) + 1;
    }
  }

  const toSorted = (counts: Record<string, number>) =>
    Object.entries(counts)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count);

  const toSortedPaths = (counts: Record<string, number>) =>
    Object.entries(counts)
      .map(([path, count]) => ({ path, count }))
      .sort((a, b) => b.count - a.count);

  const toSortedHosts = (counts: Record<string, number>) =>
    Object.entries(counts)
      .map(([host, count]) => ({ host, count }))
      .sort((a, b) => b.count - a.count);

  const suggestion = await suggestPolicy(agentName, {
    totalActions: events.length,
    totalSessions: sessionIds.size || 1,
    topProcesses: toSorted(processCounts),
    topCredentials: toSorted(credentialCounts),
    topFilePaths: toSortedPaths(filePathCounts),
    topNetworkHosts: toSortedHosts(networkHostCounts),
  });

  if (!suggestion) {
    if (isJson) {
      writeNoResultJson('llm-unavailable', verification);
      return 0;
    }
    writeChainBreakNotice(verification, 'left out of the suggestion');
    process.stdout.write(dim('LLM analysis unavailable. The backend may be unreachable.\n'));
    return 0;
  }

  if (isJson) {
    process.stdout.write(JSON.stringify({ ...suggestion, verification }, null, 2) + '\n');
    return 0;
  }

  writeChainBreakNotice(verification, 'left out of the suggestion');
  process.stdout.write(bold('Policy Suggestion') + dim(` (confidence: ${Math.round(suggestion.confidence * 100)}%)`) + '\n');
  process.stdout.write(gray('-'.repeat(50)) + '\n');
  process.stdout.write(dim(`Based on ${suggestion.basedOnActions} actions across ${suggestion.basedOnSessions} sessions for agent "${suggestion.agent}"\n\n`));

  if (suggestion.rules.processes) {
    if (suggestion.rules.processes.deny?.length) {
      process.stdout.write(red('  Deny processes:\n'));
      for (const proc of suggestion.rules.processes.deny) {
        process.stdout.write(`    - ${proc}\n`);
      }
    }
    if (suggestion.rules.processes.allow?.length) {
      process.stdout.write(green('  Allow processes:\n'));
      for (const proc of suggestion.rules.processes.allow) {
        process.stdout.write(`    + ${proc}\n`);
      }
    }
  }

  if (suggestion.rules.credentials?.deny?.length) {
    process.stdout.write(red('  Deny credentials:\n'));
    for (const cred of suggestion.rules.credentials.deny) {
      process.stdout.write(`    - ${cred}\n`);
    }
  }

  if (suggestion.rules.filesystem?.deny?.length) {
    process.stdout.write(red('  Deny filesystem:\n'));
    for (const p of suggestion.rules.filesystem.deny) {
      process.stdout.write(`    - ${p}\n`);
    }
  }

  if (suggestion.rules.network?.deny?.length) {
    process.stdout.write(red('  Deny network:\n'));
    for (const host of suggestion.rules.network.deny) {
      process.stdout.write(`    - ${host}\n`);
    }
  }

  process.stdout.write('\n' + dim('Reasoning: ') + suggestion.reasoning + '\n');
  return 0;
}

async function handleExplain(options: ShieldOptions): Promise<number> {
  const { checkLlmAvailable, explainAnomaly } = await import('../shield/llm.js');
  const { readVerifiedEvents, eventVerificationStatus } = await import('../shield/events.js');
  const isJson = options.format === 'json';

  const { backend } = await checkLlmAvailable();
  if (backend === 'none') {
    process.stderr.write(yellow('LLM intelligence is not available.\n'));
    process.stderr.write('Enable it with: opena2a config llm on\n');
    return 1;
  }

  const count = options.count ? parseInt(options.count, 10) : 1;
  const verified = readVerifiedEvents({
    count,
    severity: options.severity,
    agent: options.agent,
  });
  const verification = eventVerificationStatus(verified);

  // The newest `count` matching events, as the unverified read returned them.
  // Past a break the newest are the unverified tail, so they are listed with
  // that status rather than swapped for older verified events, and only the
  // verified ones are explained.
  const limit = count > 0 ? count : undefined;
  const rows = [
    ...verified.untrusted.map(event => ({ event, verified: false })),
    ...verified.events.map(event => ({ event, verified: true })),
  ].slice(0, limit);

  if (rows.length === 0) {
    if (isJson) {
      process.stdout.write('[]\n');
      return 0;
    }
    process.stdout.write(yellow('No events found matching the filters.') + ' ' + dim('Try: opena2a shield log --count 50') + '\n');
    return 0;
  }

  const agentName = options.agent ?? rows.find(r => r.verified)?.event.agent ?? 'unknown';
  const allAgentEvents = readVerifiedEvents({ count: 100, agent: agentName }).events;
  const actionCounts: Record<string, number> = {};
  for (const e of allAgentEvents) {
    const key = `${e.action} -> ${e.target}`;
    actionCounts[key] = (actionCounts[key] ?? 0) + 1;
  }
  const normalActions = Object.entries(actionCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([action]) => action);

  const seenActions = new Set<string>();
  const results: Array<{
    event: (typeof rows)[number]['event'];
    verified: boolean;
    explanation: Awaited<ReturnType<typeof explainAnomaly>>;
  }> = [];

  for (const { event, verified: isVerified } of rows) {
    if (!isVerified) {
      results.push({ event, verified: false, explanation: null });
      continue;
    }

    const actionKey = `${event.action}:${event.target}`;
    const isFirstOccurrence = !seenActions.has(actionKey);
    seenActions.add(actionKey);

    const explanation = await explainAnomaly(event, {
      agentName,
      normalActions,
      isFirstOccurrence,
    });

    results.push({ event, verified: true, explanation });
  }

  if (isJson) {
    process.stdout.write(JSON.stringify(results.map(r => ({
      event: r.event,
      verified: r.verified,
      explanation: r.explanation,
    })), null, 2) + '\n');
    return 0;
  }

  writeChainBreakNotice(verification, 'not explained');
  for (const { event, verified: isVerified, explanation } of results) {
    const sev = colorSeverity(event.severity);
    process.stdout.write(
      `[${printableText(event.timestamp)}] [${sev}] ${printableText(event.action)} -> ${printableText(event.target)}\n`,
    );

    if (!isVerified) {
      process.stdout.write(`  ${yellow('UNVERIFIED')} ${dim('Past the event chain break; not explained.')}\n\n`);
      continue;
    }

    if (!explanation) {
      process.stdout.write(dim('  Analysis unavailable.\n\n'));
      continue;
    }

    const explSev = colorSeverity(explanation.severity);
    process.stdout.write(`  Severity: ${explSev}\n`);
    process.stdout.write(`  ${explanation.explanation}\n`);

    if (explanation.riskFactors.length > 0) {
      process.stdout.write(dim('  Risk factors:\n'));
      for (const factor of explanation.riskFactors) {
        process.stdout.write(dim(`    - ${factor}\n`));
      }
    }

    const actionColor = explanation.suggestedAction === 'block' ? red
      : explanation.suggestedAction === 'investigate' ? yellow
      : dim;
    process.stdout.write(`  Recommended: ${actionColor(explanation.suggestedAction)}\n\n`);
  }

  return 0;
}

async function handleTriage(options: ShieldOptions): Promise<number> {
  const { checkLlmAvailable, triageIncident } = await import('../shield/llm.js');
  const { readVerifiedEvents, eventVerificationStatus } = await import('../shield/events.js');
  const { loadPolicy } = await import('../shield/policy.js');
  const isJson = options.format === 'json';

  const { backend } = await checkLlmAvailable();
  if (backend === 'none') {
    process.stderr.write(yellow('LLM intelligence is not available.\n'));
    process.stderr.write('Enable it with: opena2a config llm on\n');
    return 1;
  }

  const severity = options.severity ?? 'high';
  const count = options.count ? parseInt(options.count, 10) : 10;

  // Verified events only: an event past a chain break is never triaged.
  // `--severity` is a threshold: the default `high` triages critical too.
  const verified = readVerifiedEvents({
    minSeverity: severity,
    count,
    agent: options.agent,
  });
  const verification = eventVerificationStatus(verified);
  const events = verified.events;

  if (events.length === 0) {
    if (isJson) {
      writeNoResultJson(verification.chainBroken ? 'no-verified-events' : 'no-events', verification);
      return 0;
    }
    if (verification.chainBroken) {
      process.stdout.write(yellow(`No verified ${severity}+ severity events found.`) + '\n');
      writeChainBreakNotice(verification, 'left out of the triage');
      return 0;
    }
    process.stdout.write(yellow(`No ${severity}+ severity events found.`) + ' ' + dim('Lower the threshold: opena2a shield triage --severity low') + '\n');
    return 0;
  }

  const agentName = options.agent ?? events[0].agent ?? 'unknown';
  const policy = loadPolicy(options.dir);
  const policyMode = policy?.mode ?? 'monitor';

  const baselineEvents = readVerifiedEvents({ count: 100, agent: agentName }).events;
  const recentBaseline = [...new Set(
    baselineEvents.map(e => `${e.action} -> ${e.target}`)
  )].slice(0, 10);

  const triage = await triageIncident(events, {
    policyMode,
    agentName,
    recentBaseline,
  });

  if (!triage) {
    if (isJson) {
      writeNoResultJson('llm-unavailable', verification);
      return 0;
    }
    writeChainBreakNotice(verification, 'left out of the triage');
    process.stdout.write(dim('LLM analysis unavailable. The backend may be unreachable.\n'));
    return 0;
  }

  if (isJson) {
    process.stdout.write(JSON.stringify({ ...triage, verification }, null, 2) + '\n');
    return 0;
  }

  writeChainBreakNotice(verification, 'left out of the triage');

  const classColor = triage.classification === 'confirmed-threat' ? red
    : triage.classification === 'suspicious' ? yellow
    : dim;

  process.stdout.write(bold('Incident Triage') + '\n');
  process.stdout.write(gray('-'.repeat(50)) + '\n');
  process.stdout.write(`  Classification: ${classColor(triage.classification)}\n`);
  process.stdout.write(`  Severity:       ${colorSeverity(triage.severity)}\n`);
  process.stdout.write(`  Events:         ${triage.eventIds.length}\n`);
  process.stdout.write(`  Explanation:    ${triage.explanation}\n`);

  if (triage.responseSteps.length > 0) {
    process.stdout.write('\n' + bold('  Recommended actions:\n'));
    for (let i = 0; i < triage.responseSteps.length; i++) {
      process.stdout.write(`    ${i + 1}. ${triage.responseSteps[i]}\n`);
    }
  }

  process.stdout.write(gray('-'.repeat(50)) + '\n');
  return 0;
}

// --- Formatting helpers ---

/**
 * The `--format json` output of suggest and triage when there is no result
 * to print: why (`no-events`, `no-verified-events` or `llm-unavailable`)
 * and the log's verification status, so the output stays JSON and still
 * carries that status.
 */
function writeNoResultJson(status: string, verification: EventVerificationStatus): void {
  process.stdout.write(JSON.stringify({ status, verification }, null, 2) + '\n');
}

/**
 * Printed by a feature that read events through the chain-verified reader
 * when the chain is broken: where it breaks, what the feature did with the
 * events from there on, and the commands to inspect it and start a fresh
 * chain.  Prints nothing for an intact chain.
 */
function writeChainBreakNotice(
  verification: EventVerificationStatus,
  effect: string,
  indent = '',
): void {
  if (!verification.chainBroken) return;
  const n = verification.untrustedCount;
  const subject = n === 1 ? 'The event from there on is' : `The ${n} events from there on are`;
  process.stdout.write(indent + yellow(
    `Event chain breaks at event ${(verification.brokenAt as number) + 1}. ` +
    `${subject} unverified and ${effect}.`,
  ) + '\n');
  process.stdout.write(indent + dim('  Inspect:     opena2a shield selfcheck') + '\n');
  process.stdout.write(indent + dim('  Fresh chain: opena2a shield recover --archive-log') + '\n\n');
}

/**
 * Text read from the event log or an error, made safe to print: line breaks
 * and other whitespace become spaces (the value stays on its one line and
 * cannot forge the lines printed after it), and control and format
 * characters are removed (no escape sequence reaches the terminal, so a
 * value cannot hide the text printed after it, such as an UNVERIFIED
 * marker).  A value that is not a string is printed as its JSON text.
 */
function printableText(value: unknown): string {
  const text = typeof value === 'string' ? value : (JSON.stringify(value) ?? String(value));
  return text
    .replace(/[^\S ]+/g, ' ')
    .replace(/[\p{Cc}\p{Cf}]/gu, '');
}

/**
 * A severity label.  An event line is data, so its severity may be any JSON
 * value; one that is not a string is printed as its JSON text, and never
 * stops the listing.
 */
function colorSeverity(severity: unknown): string {
  const label = printableText(severity ?? 'unknown');
  return severityColor(label)(label.toUpperCase());
}
