/**
 * opena2a runtime -- ARP (Agent Runtime Protection) wrapper.
 *
 * Subcommands:
 * - start:  Start ARP monitoring (dynamic import of hackmyagent/arp)
 * - status: Show protection status, monitors, budget
 * - tail:   Read last N events from .opena2a/arp/events.jsonl
 * - init:   Auto-generate arp.yaml from detected project type
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { bold, green, yellow, red, dim, gray, cyan } from '../util/colors.js';
import { severityColor } from '../util/format.js';
import { detectProject } from '../util/detect.js';

// --- Types ---

export interface RuntimeOptions {
  subcommand: 'start' | 'status' | 'tail' | 'init';
  configPath?: string;
  count?: number;
  targetDir?: string;
  ci?: boolean;
  format?: 'text' | 'json';
  verbose?: boolean;
  force?: boolean;
}

interface RuntimeStatus {
  running: boolean;
  monitors: string[];
  interceptors: string[];
  eventCount: number;
  configFile: string | null;
}

// --- Core ---

export async function runtime(options: RuntimeOptions): Promise<number> {
  const targetDir = path.resolve(options.targetDir ?? process.cwd());

  switch (options.subcommand) {
    case 'start':
      return runtimeStart(targetDir, options);
    case 'status':
      return runtimeStatus(targetDir, options);
    case 'tail':
      return runtimeTail(targetDir, options);
    case 'init':
      return runtimeInit(targetDir, options);
    default:
      process.stderr.write(red(`Unknown subcommand: ${options.subcommand}\n`));
      process.stderr.write('Usage: opena2a runtime <start|status|tail|init>\n');
      return 1;
  }
}

// --- Start ---

async function runtimeStart(targetDir: string, options: RuntimeOptions): Promise<number> {
  const isJson = options.format === 'json';

  // Check for ARP installation
  let arp: any;
  try {
    arp = await (Function('return import("hackmyagent/arp")')() as Promise<any>);
  } catch {
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: 'hackmyagent not installed' }, null, 2) + '\n');
    } else {
      process.stderr.write(red('hackmyagent is not installed.\n'));
      process.stderr.write('\nInstall it:\n');
      process.stderr.write(dim('  npm install -g hackmyagent\n'));
      process.stderr.write('\nOr generate config first:\n');
      process.stderr.write(dim('  opena2a runtime init\n'));
    }
    return 1;
  }

  // Find config file
  const configPath = options.configPath ?? findConfigFile(targetDir);
  if (!configPath) {
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: 'No ARP config found. Run: opena2a runtime init' }, null, 2) + '\n');
    } else {
      process.stderr.write(yellow('No ARP configuration found.\n'));
      process.stderr.write(dim('Generate one: opena2a runtime init\n'));
    }
    return 1;
  }

  if (!isJson) {
    process.stdout.write(bold('Starting ARP monitoring...') + '\n');
    process.stdout.write(dim(`Config: ${configPath}\n`));
  }

  // Start ARP
  try {
    const mod = 'default' in arp ? arp.default : arp;

    // AgentRuntimeProtection is a class — instantiate it with the config path
    const ARPClass = mod.AgentRuntimeProtection ?? arp.AgentRuntimeProtection;
    if (!ARPClass) {
      process.stderr.write(red('ARP module does not export AgentRuntimeProtection class.\n'));
      return 1;
    }

    const instance = new ARPClass(configPath);
    await instance.start();

    const status = instance.getStatus();
    const monitorCount = status.monitors?.length ?? 0;

    if (isJson) {
      process.stdout.write(JSON.stringify({
        running: true,
        monitors: status.monitors,
        budget: status.budget,
      }, null, 2) + '\n');
    } else {
      process.stdout.write(green(`ARP monitoring active.`) + ` ${monitorCount} monitors running.\n`);
      for (const m of (status.monitors ?? [])) {
        process.stdout.write(dim(`  - ${m.type}: ${m.running ? 'running' : 'stopped'}\n`));
      }
      process.stdout.write('\n' + dim('Press Ctrl+C to stop monitoring.\n'));
    }

    // Keep the process alive until interrupted
    await new Promise<void>((resolve) => {
      const shutdown = async () => {
        if (!isJson) {
          process.stdout.write('\n' + dim('Stopping ARP monitoring...\n'));
        }
        await instance.stop();
        if (!isJson) {
          process.stdout.write(green('ARP monitoring stopped.\n'));
        }
        resolve();
      };
      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);
    });
    return 0;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: msg }, null, 2) + '\n');
    } else {
      process.stderr.write(red(`Failed to start ARP: ${msg}\n`));
    }
    return 1;
  }
}

// --- Status ---

async function runtimeStatus(targetDir: string, options: RuntimeOptions): Promise<number> {
  const isJson = options.format === 'json';
  const configPath = findConfigFile(targetDir);
  const eventsPath = path.join(targetDir, '.opena2a/arp/events.jsonl');
  const eventCount = countEvents(eventsPath);

  const monitors: string[] = [];
  const interceptors: string[] = [];

  // Read config to determine active monitors
  if (configPath) {
    try {
      const raw = fs.readFileSync(configPath, 'utf-8');

      if (configPath.endsWith('.json')) {
        // Parse JSON config
        const cfg = JSON.parse(raw);
        if (cfg.monitors?.process?.enabled !== false) monitors.push('process');
        if (cfg.monitors?.network?.enabled !== false) monitors.push('network');
        if (cfg.monitors?.filesystem?.enabled !== false) monitors.push('filesystem');
        if (cfg.aiLayer?.prompt) interceptors.push('prompt');
        if (cfg.aiLayer?.['mcp-protocol'] || cfg.aiLayer?.mcp) interceptors.push('mcp-protocol');
        if (cfg.aiLayer?.['a2a-protocol'] || cfg.aiLayer?.a2a) interceptors.push('a2a-protocol');
      } else {
        // YAML: parse section-aware to avoid false positives from unrelated "enabled: true"
        const lines = raw.split('\n');
        let currentSection = '';
        let currentSubSection = '';
        for (const line of lines) {
          const trimmed = line.trimStart();
          const indent = line.length - trimmed.length;

          if (indent === 0 && trimmed.endsWith(':')) {
            currentSection = trimmed.slice(0, -1);
            currentSubSection = '';
          } else if (indent <= 2 && trimmed.includes(':')) {
            currentSubSection = trimmed.split(':')[0].trim();
          }

          if (currentSection === 'monitors' && trimmed.includes('enabled: true')) {
            if (currentSubSection === 'process' || trimmed.startsWith('process:')) monitors.push('process');
            if (currentSubSection === 'network' || trimmed.startsWith('network:')) monitors.push('network');
            if (currentSubSection === 'filesystem' || trimmed.startsWith('filesystem:')) monitors.push('filesystem');
          }

          if (currentSection === 'aiLayer') {
            if (currentSubSection === 'prompt' && (trimmed === 'prompt: true' || trimmed.includes('enabled: true'))) interceptors.push('prompt');
            if ((currentSubSection === 'mcp-protocol' || currentSubSection === 'mcp') && (trimmed.includes(': true') || trimmed.includes('enabled: true'))) interceptors.push('mcp-protocol');
            if ((currentSubSection === 'a2a-protocol' || currentSubSection === 'a2a') && (trimmed.includes(': true') || trimmed.includes('enabled: true'))) interceptors.push('a2a-protocol');
          }
        }

        // Deduplicate in case of inline YAML like { enabled: true }
        const dedupMonitors = [...new Set(monitors)];
        const dedupInterceptors = [...new Set(interceptors)];
        monitors.length = 0;
        interceptors.length = 0;
        monitors.push(...dedupMonitors);
        interceptors.push(...dedupInterceptors);
      }
    } catch {
      // Config unreadable
    }
  }

  // Check if ARP is actively running by looking for recent events (within last 30s)
  let running = false;
  if (eventCount > 0) {
    try {
      const content = fs.readFileSync(eventsPath, 'utf-8');
      const lastLine = content.trim().split('\n').pop();
      if (lastLine) {
        const lastEvent = JSON.parse(lastLine);
        const lastTime = new Date(lastEvent.timestamp).getTime();
        running = Date.now() - lastTime < 30_000;
      }
    } catch { /* ok */ }
  }

  const status: RuntimeStatus = {
    running,
    monitors,
    interceptors,
    eventCount,
    configFile: configPath,
  };

  if (isJson) {
    process.stdout.write(JSON.stringify(status, null, 2) + '\n');
  } else {
    process.stdout.write(bold('ARP Runtime Status') + '\n');
    process.stdout.write(gray('-'.repeat(40)) + '\n');
    process.stdout.write(`  ${dim('Config')}         ${configPath ?? yellow('not found')}\n`);
    process.stdout.write(`  ${dim('Monitors')}       ${monitors.length > 0 ? monitors.join(', ') : dim('none configured')}\n`);
    process.stdout.write(`  ${dim('Interceptors')}   ${interceptors.length > 0 ? interceptors.join(', ') : dim('none configured')}\n`);
    process.stdout.write(`  ${dim('Events')}         ${eventCount}\n`);
    process.stdout.write(gray('-'.repeat(40)) + '\n');
  }

  return 0;
}

// --- Tail ---

async function runtimeTail(targetDir: string, options: RuntimeOptions): Promise<number> {
  const isJson = options.format === 'json';
  const eventsPath = path.join(targetDir, '.opena2a/arp/events.jsonl');
  const count = options.count ?? 20;

  if (!fs.existsSync(eventsPath)) {
    if (isJson) {
      process.stdout.write(JSON.stringify({ events: [], error: 'No events file found' }, null, 2) + '\n');
    } else {
      process.stdout.write(yellow('No events found.') + ' ' + dim('Start monitoring: opena2a runtime start') + '\n');
    }
    return 0;
  }

  const content = fs.readFileSync(eventsPath, 'utf-8');
  const lines = content.trim().split('\n').filter(Boolean);
  const lastN = lines.slice(-count);

  if (isJson) {
    const events = lastN.map(line => {
      try { return JSON.parse(line); } catch { return { raw: line }; }
    });
    process.stdout.write(JSON.stringify({ events, total: lines.length }, null, 2) + '\n');
  } else {
    process.stdout.write(bold(`Last ${Math.min(count, lastN.length)} events`) + dim(` (${lines.length} total)`) + '\n');
    process.stdout.write(gray('-'.repeat(60)) + '\n');
    for (const line of lastN) {
      try {
        const event = JSON.parse(line);
        const ts = event.timestamp ? dim(event.timestamp.slice(11, 19)) + ' ' : '';
        const sev = event.severity ?? 'info';
        const severity = severityColor(sev)(sev);
        process.stdout.write(`  ${ts}${severity.padEnd(16)} ${event.message ?? event.type ?? line}\n`);
      } catch {
        process.stdout.write(`  ${dim(line)}\n`);
      }
    }
    process.stdout.write(gray('-'.repeat(60)) + '\n');
  }

  return 0;
}

// --- Init ---

async function runtimeInit(targetDir: string, options: RuntimeOptions): Promise<number> {
  const isJson = options.format === 'json';
  const project = detectProject(targetDir);
  const configPath = path.join(targetDir, 'arp.yaml');

  if (fs.existsSync(configPath) && !options.force) {
    if (isJson) {
      process.stdout.write(JSON.stringify({ exists: true, path: configPath }, null, 2) + '\n');
    } else {
      process.stdout.write(yellow(`Config already exists: ${configPath}\n`));
      process.stdout.write(dim('Use --force to overwrite.\n'));
    }
    return 0;
  }

  const agentName = project.name ?? path.basename(targetDir);
  const hasMcp = project.hasMcp;

  const config = [
    `agentName: ${agentName}`,
    'monitors:',
    '  process: { enabled: true, intervalMs: 5000 }',
    '  network: { enabled: true, intervalMs: 10000 }',
    '  filesystem: { enabled: true }',
    'interceptors:',
    '  process: true',
    '  network: true',
    '  filesystem: true',
    'aiLayer:',
    '  prompt: true',
    hasMcp ? '  mcp-protocol: true' : '  mcp-protocol: false',
    '  a2a-protocol: true',
    '',
  ].join('\n');

  fs.writeFileSync(configPath, config, 'utf-8');

  if (isJson) {
    process.stdout.write(JSON.stringify({ created: true, path: configPath, agentName }, null, 2) + '\n');
  } else {
    process.stdout.write(green(`Created ARP config: ${configPath}\n`));
    process.stdout.write(dim(`Agent name: ${agentName}\n`));
    if (hasMcp) {
      process.stdout.write(dim('MCP protocol monitoring enabled.\n'));
    }
    process.stdout.write('\nStart monitoring:\n');
    process.stdout.write(dim('  opena2a runtime start\n'));
  }

  return 0;
}

// --- Silent init (for shield init integration) ---

/**
 * Initialize ARP config without any stdout output. Returns what was created.
 * Used by shield init to silently create ARP config as part of the init flow.
 */
export async function runtimeInitSilent(targetDir: string): Promise<{ created: boolean; path: string; agentName?: string }> {
  const project = detectProject(targetDir);
  const configPath = path.join(targetDir, 'arp.yaml');

  if (fs.existsSync(configPath)) {
    return { created: false, path: configPath };
  }

  const agentName = project.name ?? path.basename(targetDir);
  const hasMcp = project.hasMcp;

  const config = [
    `agentName: ${agentName}`,
    'monitors:',
    '  process: { enabled: true, intervalMs: 5000 }',
    '  network: { enabled: true, intervalMs: 10000 }',
    '  filesystem: { enabled: true }',
    'interceptors:',
    '  process: true',
    '  network: true',
    '  filesystem: true',
    'aiLayer:',
    '  prompt: true',
    hasMcp ? '  mcp-protocol: true' : '  mcp-protocol: false',
    '  a2a-protocol: true',
    '',
  ].join('\n');

  fs.writeFileSync(configPath, config, 'utf-8');

  return { created: true, path: configPath, agentName };
}

// --- Helpers ---

function findConfigFile(dir: string): string | null {
  const candidates = ['arp.yaml', 'arp.yml', 'arp.json'];
  for (const name of candidates) {
    const fullPath = path.join(dir, name);
    if (fs.existsSync(fullPath)) return fullPath;
  }
  return null;
}

function countEvents(eventsPath: string): number {
  if (!fs.existsSync(eventsPath)) return 0;
  try {
    const content = fs.readFileSync(eventsPath, 'utf-8');
    return content.trim().split('\n').filter(Boolean).length;
  } catch {
    return 0;
  }
}

// --- Testable internals ---

export const _internals = {
  findConfigFile,
  countEvents,
};
