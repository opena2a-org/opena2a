import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { execFileSync } from 'node:child_process';
import type { ShieldStatus, ToolStatus, PolicyMode, IntegrityStatus } from './types.js';
import { SHIELD_POLICY_FILE, SHIELD_EVENTS_FILE, SHIELD_REPORTS_DIR } from './types.js';

function getShieldDir(): string {
  return join(homedir(), '.opena2a', 'shield');
}

/** Run a binary with args without shell interpretation (safe from injection). */
function tryExecFile(binary: string, args: string[]): string | null {
  try {
    return execFileSync(binary, args, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch {
    return null;
  }
}

/** Resolve a binary via which, returning the path or null. */
function whichBinary(name: string): string | null {
  try {
    return execFileSync('which', [name], { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch {
    return null;
  }
}

function detectTool(name: string): ToolStatus {
  switch (name) {
    case 'Secretless': {
      const version = whichBinary('secretless-ai') ? tryExecFile('secretless-ai', ['--version']) : null;
      const configExists = existsSync(join(process.cwd(), '.secretless.json')) ||
        existsSync(join(homedir(), '.secretless', 'config.json'));
      return {
        name: 'Secretless',
        installed: version !== null,
        active: configExists,
        version,
        keyMetric: configExists ? 'configured' : 'not configured',
      };
    }

    case 'AIM Core': {
      const dataDir = join(homedir(), '.opena2a', 'aim-core');
      const hasIdentity = existsSync(join(dataDir, 'identity.json')) ||
        existsSync(join(dataDir, 'keypair.json'));
      return {
        name: 'AIM Core (Identity)',
        installed: hasIdentity,
        active: hasIdentity,
        version: null,
        keyMetric: hasIdentity ? 'Ed25519 identity active' : 'no local identity',
      };
    }

    case 'ARP': {
      const configExists = existsSync(join(process.cwd(), '.arp.yaml')) ||
        existsSync(join(process.cwd(), 'arp.yaml'));
      const eventsPath = join(process.cwd(), '.opena2a', 'arp', 'events.jsonl');
      const hasEvents = existsSync(eventsPath);
      return {
        name: 'Runtime Guard (ARP)',
        installed: configExists,
        active: hasEvents,
        version: null,
        keyMetric: hasEvents ? 'monitoring' : configExists ? 'configured' : 'not configured',
      };
    }

    case 'Browser Guard': {
      const configPaths = [
        join(homedir(), '.config', 'opena2a', 'browser-guard.json'),
        join(homedir(), '.opena2a', 'browser-guard.json'),
      ];
      const found = configPaths.some(p => existsSync(p));
      return {
        name: 'Browser Guard',
        installed: found,
        active: found,
        version: null,
        keyMetric: found ? 'active' : 'not installed',
      };
    }

    case 'HMA': {
      // Prefer workspace version over stale global binary
      let version: string | null = null;
      try {
        // resolve from CLI's own location (not cwd) to find workspace hackmyagent
        const entryPath = require.resolve('hackmyagent', { paths: [__dirname, process.cwd()] });
        let dir = entryPath;
        for (let i = 0; i < 10; i++) {
          dir = join(dir, '..');
          const pkgPath = join(dir, 'package.json');
          if (existsSync(pkgPath)) {
            const hmaPkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
            if (hmaPkg.name === 'hackmyagent') {
              version = hmaPkg.version ?? null;
              break;
            }
          }
        }
      } catch {
        // Fall back to global binary
        version = whichBinary('hackmyagent') ? tryExecFile('hackmyagent', ['--version']) : null;
      }
      return {
        name: 'HackMyAgent',
        installed: version !== null,
        active: version !== null,
        version,
        keyMetric: version ? `v${version}` : 'not installed',
      };
    }

    case 'Registry': {
      // Registry is typically a remote service; check if CLI supports it
      const hasRegistry = whichBinary('opena2a') !== null;
      return {
        name: 'Registry',
        installed: hasRegistry !== null,
        active: false,
        version: null,
        keyMetric: hasRegistry ? 'available' : 'not available',
      };
    }

    case 'ConfigGuard': {
      const sigFile = join(process.cwd(), '.opena2a', 'guard', 'signatures.json');
      let fileCount = 0;
      if (existsSync(sigFile)) {
        try {
          const store = JSON.parse(readFileSync(sigFile, 'utf-8'));
          fileCount = Array.isArray(store.signatures) ? store.signatures.length : 0;
        } catch { /* ok */ }
      }
      return {
        name: 'ConfigGuard',
        installed: true, // Built into CLI
        active: fileCount > 0,
        version: null,
        keyMetric: fileCount > 0 ? `${fileCount} files signed` : 'no signatures',
      };
    }

    default:
      return { name, installed: false, active: false, version: null, keyMetric: 'unknown' };
  }
}

export function getShieldStatus(targetDir?: string): ShieldStatus {
  const shieldDir = getShieldDir();
  const tools: ToolStatus[] = [
    detectTool('Secretless'),
    detectTool('AIM Core'),
    detectTool('ARP'),
    detectTool('Browser Guard'),
    detectTool('HMA'),
    detectTool('Registry'),
    detectTool('ConfigGuard'),
  ];

  // Policy status
  const policyPath = join(shieldDir, SHIELD_POLICY_FILE);
  let policyLoaded = false;
  let policyMode: PolicyMode | null = null;

  if (existsSync(policyPath)) {
    policyLoaded = true;
    try {
      const raw = readFileSync(policyPath, 'utf-8');
      const policy = JSON.parse(raw);
      policyMode = policy.mode ?? 'adaptive';
    } catch {
      policyMode = null;
    }
  }

  // Shell integration
  const shell = process.env.SHELL?.includes('zsh') ? 'zsh'
    : process.env.SHELL?.includes('bash') ? 'bash'
    : null;

  let shellIntegration = false;
  if (shell) {
    const rcFile = shell === 'zsh'
      ? join(homedir(), '.zshrc')
      : join(homedir(), '.bashrc');
    try {
      const content = readFileSync(rcFile, 'utf-8');
      shellIntegration = content.includes('opena2a_shield_preexec') ||
        content.includes('opena2a_shield_debug');
    } catch { /* ok */ }
  }

  // Integrity status
  let integrityStatus: IntegrityStatus = 'healthy';
  const lockdownPath = join(shieldDir, 'lockdown');
  if (existsSync(lockdownPath)) {
    integrityStatus = 'lockdown';
  }

  // Last report
  let lastReportScore: number | null = null;
  let lastReportDate: string | null = null;
  const reportsDir = join(shieldDir, SHIELD_REPORTS_DIR);
  if (existsSync(reportsDir)) {
    try {
      const files = readdirSync(reportsDir)
        .filter(f => f.endsWith('.json'))
        .sort()
        .reverse();
      if (files.length > 0) {
        const latestReport = JSON.parse(readFileSync(join(reportsDir, files[0]), 'utf-8'));
        lastReportScore = latestReport.posture?.score ?? null;
        lastReportDate = latestReport.generatedAt ?? null;
      }
    } catch { /* ok */ }
  }

  return {
    timestamp: new Date().toISOString(),
    tools,
    policyLoaded,
    policyMode,
    shellIntegration,
    integrityStatus,
    lastReportScore,
    lastReportDate,
  };
}

export function formatStatus(status: ShieldStatus, format: 'text' | 'json'): string {
  if (format === 'json') {
    return JSON.stringify(status, null, 2);
  }

  const lines: string[] = [];
  lines.push('Shield Status\n');

  // Tools table
  lines.push('Tools:');
  for (const p of status.tools) {
    const state = p.active ? 'ACTIVE' : p.installed ? 'INSTALLED' : '  --  ';
    lines.push(`  ${state.padEnd(10)} ${p.name.padEnd(22)} ${p.keyMetric}`);
  }
  lines.push('');

  // Policy
  if (status.policyLoaded) {
    lines.push(`Policy: loaded (${status.policyMode ?? 'unknown'} mode)`);
  } else {
    lines.push('Policy: not loaded (run: opena2a shield init)');
  }

  // Shell integration
  lines.push(`Shell integration: ${status.shellIntegration ? 'active' : 'inactive'}`);

  // Integrity
  lines.push(`Integrity: ${status.integrityStatus.toUpperCase()}`);

  // Last report
  if (status.lastReportScore !== null) {
    lines.push(`Last report: ${status.lastReportScore}/100 (${status.lastReportDate ?? 'unknown'})`);
  }

  // Recommendations
  const recs: string[] = [];
  if (!status.policyLoaded) recs.push('Run: opena2a shield init');
  if (!status.shellIntegration) recs.push('Shell hooks not installed. Re-run: opena2a shield init');
  if (status.integrityStatus === 'lockdown') recs.push('LOCKDOWN active. Run: opena2a shield recover --verify');
  if (status.integrityStatus === 'compromised') recs.push('Integrity issues detected. Run: opena2a shield selfcheck');

  const inactiveTools = status.tools.filter(p => !p.active && p.name !== 'Registry');
  if (inactiveTools.length > 0) {
    recs.push(`Inactive tools: ${inactiveTools.map(p => p.name).join(', ')}`);
  }

  if (recs.length > 0) {
    lines.push('');
    lines.push('Recommendations:');
    for (const r of recs) {
      lines.push(`  - ${r}`);
    }
  }

  return lines.join('\n');
}
