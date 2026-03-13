/**
 * Agent Manifest — .opena2a/agent.yaml
 *
 * Persists the identity attachment configuration so that subsequent
 * commands know which tools are wired and how to collect trust hints.
 */

import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AgentManifest {
  version: string;
  agent: {
    name: string;
    agentId: string;
    publicKey: string;
    created: string;
  };
  tools: {
    secretless: boolean;
    configguard: boolean;
    arp: boolean;
    hma: boolean;
    shield: boolean;
  };
  bridging: {
    autoSync: boolean;
    lastSyncAt: string | null;
  };
  registry: {
    shareIntel: boolean;
  };
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

export function readManifest(targetDir: string): AgentManifest | null {
  const manifestPath = join(targetDir, '.opena2a', 'agent.yaml');
  if (!existsSync(manifestPath)) return null;

  try {
    const content = readFileSync(manifestPath, 'utf-8');
    return parseManifestYaml(content);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

export function writeManifest(targetDir: string, manifest: AgentManifest): void {
  const opena2aDir = join(targetDir, '.opena2a');
  if (!existsSync(opena2aDir)) {
    mkdirSync(opena2aDir, { recursive: true });
  }

  const yaml = serializeManifestYaml(manifest);
  writeFileSync(join(opena2aDir, 'agent.yaml'), yaml, { encoding: 'utf-8', mode: 0o600 });
}

// ---------------------------------------------------------------------------
// Remove
// ---------------------------------------------------------------------------

export function removeManifest(targetDir: string): boolean {
  const manifestPath = join(targetDir, '.opena2a', 'agent.yaml');
  if (!existsSync(manifestPath)) return false;

  unlinkSync(manifestPath);
  return true;
}

// ---------------------------------------------------------------------------
// YAML serialization (no dependency)
// ---------------------------------------------------------------------------

function serializeManifestYaml(m: AgentManifest): string {
  const lines: string[] = [
    `version: "${m.version}"`,
    '',
    'agent:',
    `  name: "${m.agent.name}"`,
    `  agentId: "${m.agent.agentId}"`,
    `  publicKey: "${m.agent.publicKey}"`,
    `  created: "${m.agent.created}"`,
    '',
    'tools:',
    `  secretless: ${m.tools.secretless}`,
    `  configguard: ${m.tools.configguard}`,
    `  arp: ${m.tools.arp}`,
    `  hma: ${m.tools.hma}`,
    `  shield: ${m.tools.shield}`,
    '',
    'bridging:',
    `  autoSync: ${m.bridging.autoSync}`,
    `  lastSyncAt: ${m.bridging.lastSyncAt ? `"${m.bridging.lastSyncAt}"` : 'null'}`,
    '',
    'registry:',
    `  shareIntel: ${m.registry.shareIntel}`,
    '',
  ];
  return lines.join('\n');
}

function parseManifestYaml(content: string): AgentManifest {
  const lines = content.split('\n');
  const flat: Record<string, string> = {};
  let section = '';

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    // Top-level section header (no indent)
    if (!line.startsWith(' ') && !line.startsWith('\t') && trimmed.endsWith(':') && !trimmed.includes(': ')) {
      section = trimmed.slice(0, -1);
      continue;
    }

    const kvMatch = trimmed.match(/^(\w+):\s*(.+)$/);
    if (kvMatch) {
      const key = section ? `${section}.${kvMatch[1]}` : kvMatch[1];
      flat[key] = kvMatch[2].replace(/^["']|["']$/g, '');
    }
  }

  return {
    version: flat['version'] ?? '1',
    agent: {
      name: flat['agent.name'] ?? 'default',
      agentId: flat['agent.agentId'] ?? '',
      publicKey: flat['agent.publicKey'] ?? '',
      created: flat['agent.created'] ?? new Date().toISOString(),
    },
    tools: {
      secretless: flat['tools.secretless'] === 'true',
      configguard: flat['tools.configguard'] === 'true',
      arp: flat['tools.arp'] === 'true',
      hma: flat['tools.hma'] === 'true',
      shield: flat['tools.shield'] === 'true',
    },
    bridging: {
      autoSync: flat['bridging.autoSync'] === 'true',
      lastSyncAt: flat['bridging.lastSyncAt'] === 'null' ? null : (flat['bridging.lastSyncAt'] ?? null),
    },
    registry: {
      shareIntel: flat['registry.shareIntel'] === 'true',
    },
  };
}
