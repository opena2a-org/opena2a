import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { execSync } from 'node:child_process';
import type { ShieldStatus, ProductStatus, PolicyMode, IntegrityStatus } from './types.js';
import { SHIELD_POLICY_FILE, SHIELD_EVENTS_FILE, SHIELD_REPORTS_DIR } from './types.js';

function getShieldDir(): string {
  return join(homedir(), '.opena2a', 'shield');
}

function tryExec(cmd: string): string | null {
  try {
    return execSync(cmd, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
  } catch {
    return null;
  }
}

function detectProduct(name: string): ProductStatus {
  switch (name) {
    case 'Secretless': {
      const version = tryExec('npx secretless-ai --version 2>/dev/null');
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
      const version = tryExec('npx hackmyagent --version 2>/dev/null');
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
      const hasRegistry = tryExec('npx opena2a registry --help 2>/dev/null');
      return {
        name: 'Registry',
        installed: hasRegistry !== null,
        active: false,
        version: null,
        keyMetric: hasRegistry ? 'available' : 'not available',
      };
    }

    case 'ConfigGuard': {
      const sigDir = join(process.cwd(), '.opena2a', 'signatures');
      const hasSigs = existsSync(sigDir);
      let fileCount = 0;
      if (hasSigs) {
        try { fileCount = readdirSync(sigDir).length; } catch { /* ok */ }
      }
      return {
        name: 'ConfigGuard',
        installed: true, // Built into CLI
        active: hasSigs && fileCount > 0,
        version: null,
        keyMetric: hasSigs ? `${fileCount} files signed` : 'no signatures',
      };
    }

    default:
      return { name, installed: false, active: false, version: null, keyMetric: 'unknown' };
  }
}

export function getShieldStatus(targetDir?: string): ShieldStatus {
  const shieldDir = getShieldDir();
  const products: ProductStatus[] = [
    detectProduct('Secretless'),
    detectProduct('ARP'),
    detectProduct('Browser Guard'),
    detectProduct('HMA'),
    detectProduct('Registry'),
    detectProduct('ConfigGuard'),
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
    products,
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

  // Products table
  lines.push('Products:');
  for (const p of status.products) {
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

  const inactiveProducts = status.products.filter(p => !p.active && p.name !== 'Registry');
  if (inactiveProducts.length > 0) {
    recs.push(`Inactive products: ${inactiveProducts.map(p => p.name).join(', ')}`);
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
