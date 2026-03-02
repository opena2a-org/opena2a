import type { ShieldOptions, ShieldSubcommand } from '../shield/types.js';

export async function shield(options: ShieldOptions): Promise<number> {
  const subcommand = options.subcommand as ShieldSubcommand;

  switch (subcommand) {
    case 'init':
      return shieldInit(options);
    case 'status':
      return shieldStatus(options);
    case 'log':
      return shieldLog(options);
    case 'evaluate':
      return shieldEvaluate(options);
    case 'selfcheck':
      return shieldSelfCheck(options);
    case 'recover':
      return shieldRecover(options);
    default:
      process.stderr.write(`Unknown shield subcommand: ${subcommand}\n`);
      process.stderr.write('Available: init, status, log, evaluate, selfcheck, recover\n');
      return 1;
  }
}

async function shieldInit(options: ShieldOptions): Promise<number> {
  const { shieldInit: runInit } = await import('../shield/init.js');
  const { exitCode } = await runInit({
    targetDir: options.targetDir,
    ci: options.ci,
    format: options.format,
    verbose: options.verbose,
  });
  return exitCode;
}

async function shieldStatus(options: ShieldOptions): Promise<number> {
  const { getShieldStatus, formatStatus } = await import('../shield/status.js');
  const status = getShieldStatus(options.targetDir);
  const format = (options.format as 'text' | 'json') ?? 'text';
  process.stdout.write(formatStatus(status, format) + '\n');

  // Append LLM intelligence stats if available
  if (format === 'text') {
    try {
      const { getCacheStats } = await import('../shield/llm.js');
      const stats = getCacheStats();
      if (stats.totalEntries > 0) {
        process.stdout.write('\nLLM Intelligence:\n');
        process.stdout.write(`  Cache entries: ${stats.validEntries}/${stats.totalEntries} (valid/total)\n`);
        process.stdout.write(`  Tokens used: ${stats.totalInputTokens} in / ${stats.totalOutputTokens} out\n`);
        process.stdout.write(`  Estimated cost: $${stats.estimatedCostUsd.toFixed(4)}\n`);
      }
    } catch {
      // LLM module not available, skip
    }
  }

  return 0;
}

async function shieldLog(options: ShieldOptions): Promise<number> {
  const { readEvents } = await import('../shield/events.js');
  const events = readEvents({
    count: options.count ?? 50,
    source: options.source,
    severity: options.severity,
    agent: options.agent,
    since: options.since,
    category: options.category,
  });

  if (options.format === 'json') {
    if (options.analyze) {
      const { explainAnomaly } = await import('../shield/llm.js');
      const allEvents = readEvents({ count: 200 });
      const normalActions = [...new Set(
        allEvents.filter(e => e.severity === 'info').map(e => e.action)
      )].slice(0, 20);

      const analyzed = [];
      for (const e of events) {
        const item: Record<string, unknown> = { ...e };
        if (e.severity === 'high' || e.severity === 'critical') {
          const seenActions = new Set(allEvents.map(ev => `${ev.action}:${ev.target}`));
          const explanation = await explainAnomaly(e, {
            agentName: e.agent ?? 'unknown',
            normalActions,
            isFirstOccurrence: !seenActions.has(`${e.action}:${e.target}`),
          });
          if (explanation) item.analysis = explanation;
        }
        analyzed.push(item);
      }
      process.stdout.write(JSON.stringify(analyzed, null, 2) + '\n');
    } else {
      process.stdout.write(JSON.stringify(events, null, 2) + '\n');
    }
    return 0;
  }

  if (events.length === 0) {
    process.stdout.write('No events found.\n');
    process.stdout.write('Shield logs agent activity after initialization.\n');
    process.stdout.write('Run: opena2a shield init\n');
    return 0;
  }

  process.stdout.write(`Shield Audit Log (${events.length} events)\n\n`);
  process.stdout.write(
    'Time'.padEnd(20) +
    'Source'.padEnd(14) +
    'Agent'.padEnd(14) +
    'Action'.padEnd(22) +
    'Target'.padEnd(30) +
    'Outcome\n'
  );

  for (const e of events) {
    const time = e.timestamp.slice(0, 19).replace('T', ' ');
    const source = (e.source ?? '').padEnd(14);
    const agent = (e.agent ?? '--').padEnd(14);
    const action = (e.action ?? '').padEnd(22);
    const target = (e.target ?? '').slice(0, 29).padEnd(30);
    const outcome = e.outcome ?? '';
    process.stdout.write(`${time} ${source}${agent}${action}${target}${outcome}\n`);
  }

  // With --analyze, append LLM insights for high-severity events
  if (options.analyze) {
    const highSeverity = events.filter(e => e.severity === 'high' || e.severity === 'critical');
    if (highSeverity.length > 0) {
      const { explainAnomaly } = await import('../shield/llm.js');
      const allEvents = readEvents({ count: 200 });
      const normalActions = [...new Set(
        allEvents.filter(e => e.severity === 'info').map(e => e.action)
      )].slice(0, 20);

      process.stdout.write('\n--- LLM Analysis ---\n\n');

      for (const e of highSeverity.slice(0, 5)) {
        const seenActions = new Set(allEvents.map(ev => `${ev.action}:${ev.target}`));
        const explanation = await explainAnomaly(e, {
          agentName: e.agent ?? 'unknown',
          normalActions,
          isFirstOccurrence: !seenActions.has(`${e.action}:${e.target}`),
        });
        if (explanation) {
          process.stdout.write(`[${explanation.severity.toUpperCase()}] ${e.action} -> ${e.target}\n`);
          process.stdout.write(`  ${explanation.explanation}\n`);
          if (explanation.riskFactors.length > 0) {
            process.stdout.write(`  Risk factors: ${explanation.riskFactors.join(', ')}\n`);
          }
          process.stdout.write(`  Suggested: ${explanation.suggestedAction}\n\n`);
        }
      }
    }
  }

  return 0;
}

async function shieldEvaluate(options: ShieldOptions): Promise<number> {
  const { loadPolicy, loadPolicyCache, evaluatePolicy, savePolicyCache } = await import('../shield/policy.js');
  const { writeEvent } = await import('../shield/events.js');
  const { identifySession } = await import('../shield/session.js');

  // Load policy (cache-first for performance)
  let policy = loadPolicyCache();
  if (!policy) {
    policy = loadPolicy(options.targetDir);
    if (policy) savePolicyCache(policy);
  }
  if (!policy) {
    // No policy = allow everything, don't log
    return 0;
  }

  // Detect agent session
  const session = identifySession();
  if (!session) {
    // Not running inside an AI agent -- skip
    return 0;
  }

  // The target command comes from remaining args or stdin
  const target = options.targetDir ?? '';
  if (!target) return 0;

  // Evaluate
  const decision = evaluatePolicy(policy, session.agent, 'process.spawn', target);

  // Log the event
  writeEvent({
    source: 'shield',
    category: 'process.spawn',
    severity: decision.outcome === 'blocked' ? 'high' : 'info',
    agent: session.agent,
    sessionId: session.sessionId,
    action: 'process.spawn',
    target,
    outcome: decision.outcome,
    detail: { rule: decision.rule },
    orgId: null,
    managed: false,
    agentId: null,
  });

  if (options.format === 'json') {
    process.stdout.write(JSON.stringify(decision) + '\n');
  }

  return decision.allowed ? 0 : 1;
}

async function shieldSelfCheck(options: ShieldOptions): Promise<number> {
  const { runIntegrityChecks, isLockdown, getLockdownReason } = await import('../shield/integrity.js');

  if (isLockdown()) {
    const reason = getLockdownReason();
    process.stderr.write('SHIELD LOCKDOWN\n\n');
    if (reason) process.stderr.write(`Reason: ${reason}\n`);
    process.stderr.write('\nRun: opena2a shield recover --verify\n');
    return 1;
  }

  const shell = process.env.SHELL?.includes('zsh') ? 'zsh' as const
    : process.env.SHELL?.includes('bash') ? 'bash' as const
    : undefined;

  const state = runIntegrityChecks({ shell });

  if (options.format === 'json') {
    process.stdout.write(JSON.stringify(state, null, 2) + '\n');
    return state.status === 'healthy' ? 0 : 1;
  }

  process.stdout.write('Shield Self-Check\n\n');
  for (const check of state.checks) {
    const icon = check.status === 'pass' ? 'PASS' : check.status === 'warn' ? 'WARN' : 'FAIL';
    process.stdout.write(`  ${icon.padEnd(6)} ${check.name.padEnd(24)} ${check.detail}\n`);
  }
  process.stdout.write(`\nIntegrity: ${state.status.toUpperCase()}\n`);

  if (state.status === 'compromised') {
    process.stderr.write('\nShield has detected integrity issues.\n');
    process.stderr.write('Run: opena2a shield recover --verify\n');
  }

  return state.status === 'healthy' ? 0 : 1;
}

async function shieldRecover(options: ShieldOptions): Promise<number> {
  const {
    runIntegrityChecks,
    isLockdown,
    exitLockdown,
    recordPolicyHash,
    getExpectedHookContent,
  } = await import('../shield/integrity.js');
  const { getShieldDir } = await import('../shield/events.js');
  const { join } = await import('node:path');
  const { existsSync, writeFileSync, readFileSync } = await import('node:fs');
  const { homedir } = await import('node:os');
  const { SHIELD_POLICY_FILE } = await import('../shield/types.js');

  if (options.verify) {
    // Re-run integrity checks; if all pass, exit lockdown
    const shell = process.env.SHELL?.includes('zsh') ? 'zsh' as const
      : process.env.SHELL?.includes('bash') ? 'bash' as const
      : undefined;

    const state = runIntegrityChecks({ shell });
    const hasFail = state.checks.some(c => c.status === 'fail');

    if (!hasFail) {
      exitLockdown();
      process.stdout.write('All integrity checks passed. Lockdown cleared.\n');
      return 0;
    } else {
      process.stderr.write('Integrity checks still failing:\n');
      for (const c of state.checks.filter(c => c.status === 'fail')) {
        process.stderr.write(`  FAIL: ${c.name} -- ${c.detail}\n`);
      }
      return 1;
    }
  }

  if (options.reset) {
    const shieldDir = getShieldDir();

    // Re-sign policy
    const policyPath = join(shieldDir, SHIELD_POLICY_FILE);
    if (existsSync(policyPath)) {
      recordPolicyHash(policyPath);
      process.stdout.write('Policy hash re-recorded.\n');
    }

    // Reinstall shell hooks
    const shell = process.env.SHELL?.includes('zsh') ? 'zsh' as const
      : process.env.SHELL?.includes('bash') ? 'bash' as const
      : null;

    if (shell) {
      const rcFile = shell === 'zsh'
        ? join(homedir(), '.zshrc')
        : join(homedir(), '.bashrc');
      let content = '';
      try { content = readFileSync(rcFile, 'utf-8'); } catch { /* ok */ }
      // Remove old hook block
      const startMarker = '# >>> opena2a shield hook >>>';
      const endMarker = '# <<< opena2a shield hook <<<';
      const startIdx = content.indexOf(startMarker);
      const endIdx = content.indexOf(endMarker);
      if (startIdx !== -1 && endIdx !== -1) {
        content = content.slice(0, startIdx) + content.slice(endIdx + endMarker.length);
      }
      // Add fresh hook
      const hookContent = getExpectedHookContent(shell);
      writeFileSync(rcFile, content.trimEnd() + '\n\n' + hookContent + '\n', { mode: 0o600 });
      process.stdout.write(`Shell hooks reinstalled in ~/.${shell}rc\n`);
    }

    exitLockdown();
    process.stdout.write('Recovery complete. Lockdown cleared.\n');
    return 0;
  }

  if (options.forensic) {
    process.stderr.write('Forensic export not yet implemented.\n');
    process.stderr.write('Manually collect: ~/.opena2a/shield/events.jsonl, policy.yaml, lockdown\n');
    return 1;
  }

  process.stderr.write('Usage: opena2a shield recover --verify|--reset|--forensic\n');
  return 1;
}

// Expose internals for testing
export const _internals = {
  shieldInit,
  shieldStatus,
  shieldLog,
  shieldEvaluate,
  shieldSelfCheck,
  shieldRecover,
};
