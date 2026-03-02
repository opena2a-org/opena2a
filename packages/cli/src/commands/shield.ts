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
 * - report:    Generate a security posture report
 * - session:   Show current AI coding assistant session identity
 * - suggest:   LLM-powered policy suggestions from observed behavior
 * - explain:   LLM-powered anomaly explanations for events
 * - triage:    LLM-powered incident classification and response
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
    case 'session':
      return handleSession(options);
    case 'suggest':
      return handleSuggest(options);
    case 'explain':
      return handleExplain(options);
    case 'triage':
      return handleTriage(options);
    default:
      process.stderr.write(red(`Unknown subcommand: ${options.subcommand}\n`));
      process.stderr.write('Usage: opena2a shield <init|status|log|selfcheck|policy|evaluate|recover|report|session|suggest|explain|triage>\n');
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

  const category = options.category ?? 'processes';
  const agent = options.agent ?? null;
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
    const { runIntegrityChecks } = await import('../shield/integrity.js');
    const shell = process.env.SHELL?.includes('zsh') ? 'zsh' as const
      : process.env.SHELL?.includes('bash') ? 'bash' as const
      : undefined;

    exitLockdown();
    const state = runIntegrityChecks({ shell });

    if (state.status === 'compromised') {
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
  const { readEvents } = await import('../shield/events.js');
  const isJson = options.format === 'json';

  const since = options.since ?? '7d';
  const events = readEvents({ since });

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

  if (isJson) {
    const data: Record<string, unknown> = {
      periodSince: since,
      totalEvents: total,
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
  process.stdout.write('\n');

  process.stdout.write(bold('  Severity Breakdown') + '\n');
  const severityOrder: EventSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of severityOrder) {
    const count = bySeverity[sev];
    if (count === undefined || count === 0) continue;
    process.stdout.write(`    ${colorSeverity(sev).padEnd(20)} ${String(count)}\n`);
  }
  if (Object.keys(bySeverity).length === 0) {
    process.stdout.write(dim('    (none)\n'));
  }
  process.stdout.write('\n');

  process.stdout.write(bold('  Events by Source') + '\n');
  for (const { name, count } of topN(bySource, 10)) {
    process.stdout.write(`    ${name.padEnd(20)} ${String(count)}\n`);
  }
  if (Object.keys(bySource).length === 0) {
    process.stdout.write(dim('    (none)\n'));
  }
  process.stdout.write('\n');

  process.stdout.write(bold('  Top Agents') + '\n');
  for (const { name, count } of topAgents) {
    process.stdout.write(`    ${name.padEnd(20)} ${String(count)} events\n`);
  }
  if (topAgents.length === 0) {
    process.stdout.write(dim('    (none)\n'));
  }
  process.stdout.write('\n');

  process.stdout.write(bold('  Top Actions') + '\n');
  for (const { name, count } of topActions) {
    process.stdout.write(`    ${name.padEnd(30)} ${String(count)}\n`);
  }
  if (topActions.length === 0) {
    process.stdout.write(dim('    (none)\n'));
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

/**
 * Build a WeeklyReport from aggregated event data and call generateNarrative().
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
    if (event.source === 'secretless' || event.category.includes('credential')) {
      credAccessAttempts += 1;
      credNames.add(event.target);
      credProviders[event.source] = (credProviders[event.source] ?? 0) + 1;
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

  const criticalCount = bySeverity['critical'] ?? 0;
  const highCount = bySeverity['high'] ?? 0;
  const mediumCount = bySeverity['medium'] ?? 0;
  const blockedCount = byOutcome['blocked'] ?? 0;
  let score = 100;
  score -= criticalCount * 15;
  score -= highCount * 8;
  score -= mediumCount * 3;
  score += blockedCount * 2;
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';

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
      monitored: byOutcome['monitored'] ?? 0,
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

    configIntegrity: {
      filesMonitored: 0,
      tamperedFiles: [],
      signatureStatus: 'unsigned',
    },

    runtimeProtection: {
      arpActive: false,
      processesSpawned: 0,
      networkConnections: 0,
      anomalies: 0,
    },

    posture: {
      score,
      grade,
      factors: [
        { name: 'severity', score: Math.max(0, 100 - criticalCount * 15 - highCount * 8), weight: 0.4, detail: `${criticalCount} critical, ${highCount} high` },
        { name: 'enforcement', score: blockedCount > 0 ? 80 : 50, weight: 0.3, detail: `${blockedCount} blocked` },
        { name: 'coverage', score: Object.keys(byAgent).length > 0 ? 70 : 30, weight: 0.3, detail: `${Object.keys(byAgent).length} agents monitored` },
      ],
      trend: null,
      comparative: null,
    },
  };

  return generateNarrative(report);
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

// --- LLM intelligence handlers ---

async function handleSuggest(options: ShieldOptions): Promise<number> {
  const { checkLlmAvailable, suggestPolicy } = await import('../shield/llm.js');
  const { readEvents } = await import('../shield/events.js');
  const isJson = options.format === 'json';

  const { backend } = await checkLlmAvailable();
  if (backend === 'none') {
    process.stderr.write(yellow('LLM intelligence is not available.\n'));
    process.stderr.write('Enable it with: opena2a config llm on\n');
    return 1;
  }

  const events = readEvents({ count: 100, agent: options.agent });

  if (events.length === 0) {
    process.stdout.write(dim('No events found. Run shield init and use your tools to generate events.\n'));
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
    process.stdout.write(dim('LLM analysis unavailable. The backend may be unreachable.\n'));
    return 0;
  }

  if (isJson) {
    process.stdout.write(JSON.stringify(suggestion, null, 2) + '\n');
    return 0;
  }

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
  const { readEvents } = await import('../shield/events.js');
  const isJson = options.format === 'json';

  const { backend } = await checkLlmAvailable();
  if (backend === 'none') {
    process.stderr.write(yellow('LLM intelligence is not available.\n'));
    process.stderr.write('Enable it with: opena2a config llm on\n');
    return 1;
  }

  const count = options.count ? parseInt(options.count, 10) : 1;
  const events = readEvents({
    count,
    severity: options.severity,
    agent: options.agent,
  });

  if (events.length === 0) {
    process.stdout.write(dim('No events found matching the filters.\n'));
    return 0;
  }

  const agentName = options.agent ?? events[0].agent ?? 'unknown';
  const allAgentEvents = readEvents({ count: 100, agent: agentName });
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
  const results: Array<{ event: typeof events[0]; explanation: Awaited<ReturnType<typeof explainAnomaly>> }> = [];

  for (const event of events) {
    const actionKey = `${event.action}:${event.target}`;
    const isFirstOccurrence = !seenActions.has(actionKey);
    seenActions.add(actionKey);

    const explanation = await explainAnomaly(event, {
      agentName,
      normalActions,
      isFirstOccurrence,
    });

    results.push({ event, explanation });
  }

  if (isJson) {
    process.stdout.write(JSON.stringify(results.map(r => ({
      event: r.event,
      explanation: r.explanation,
    })), null, 2) + '\n');
    return 0;
  }

  for (const { event, explanation } of results) {
    const sev = colorSeverity(event.severity);
    process.stdout.write(`[${event.timestamp}] [${sev}] ${event.action} -> ${event.target}\n`);

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
  const { readEvents } = await import('../shield/events.js');
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

  const events = readEvents({
    severity,
    count,
    agent: options.agent,
  });

  if (events.length === 0) {
    process.stdout.write(dim(`No ${severity}+ severity events found.\n`));
    return 0;
  }

  const agentName = options.agent ?? events[0].agent ?? 'unknown';
  const policy = loadPolicy(options.dir);
  const policyMode = policy?.mode ?? 'monitor';

  const baselineEvents = readEvents({ count: 100, agent: agentName });
  const recentBaseline = [...new Set(
    baselineEvents.map(e => `${e.action} -> ${e.target}`)
  )].slice(0, 10);

  const triage = await triageIncident(events, {
    policyMode,
    agentName,
    recentBaseline,
  });

  if (!triage) {
    process.stdout.write(dim('LLM analysis unavailable. The backend may be unreachable.\n'));
    return 0;
  }

  if (isJson) {
    process.stdout.write(JSON.stringify(triage, null, 2) + '\n');
    return 0;
  }

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
