/**
 * Trust Hints Collector
 *
 * Scans installed tool state on disk and derives TrustHints for aim-core.
 * Each tool's presence and activity maps to a specific trust factor.
 * Only enabled tools contribute hints — respects opt-in choices.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

import type { AgentManifest } from './manifest.js';

// ---------------------------------------------------------------------------
// TrustHints interface (mirrors aim-core's TrustHints)
// ---------------------------------------------------------------------------

export interface TrustHints {
  secretsManaged?: boolean;
  configSigned?: boolean;
  skillsVerified?: boolean;
  networkControlled?: boolean;
  heartbeatMonitored?: boolean;
  runtimeProtected?: boolean;
  sessionsProtected?: boolean;
  promptsGuarded?: boolean;
  daemonHardened?: boolean;
  dlpEnabled?: boolean;
}

export interface CollectionResult {
  hints: TrustHints;
  details: Array<{ tool: string; hint: string; active: boolean; reason: string }>;
}

// ---------------------------------------------------------------------------
// Individual tool detectors
// ---------------------------------------------------------------------------

function detectSecretless(targetDir: string): { active: boolean; reason: string } {
  const projectConfig = join(targetDir, '.secretless.json');
  const globalConfig = join(homedir(), '.secretless', 'config.json');

  if (existsSync(projectConfig)) {
    return { active: true, reason: `Project config: ${projectConfig}` };
  }
  if (existsSync(globalConfig)) {
    return { active: true, reason: `Global config: ${globalConfig}` };
  }
  return { active: false, reason: 'No Secretless config found' };
}

function detectConfigGuard(targetDir: string): { active: boolean; reason: string; fileCount: number } {
  const sigFile = join(targetDir, '.opena2a', 'guard', 'signatures.json');
  if (!existsSync(sigFile)) {
    return { active: false, reason: 'No signature store found', fileCount: 0 };
  }

  try {
    const store = JSON.parse(readFileSync(sigFile, 'utf-8'));
    const count = Array.isArray(store.signatures) ? store.signatures.length : 0;
    if (count > 0) {
      return { active: true, reason: `${count} files signed`, fileCount: count };
    }
    return { active: false, reason: 'Signature store empty', fileCount: 0 };
  } catch {
    return { active: false, reason: 'Failed to read signature store', fileCount: 0 };
  }
}

function detectARP(targetDir: string): { active: boolean; reason: string } {
  const configPaths = [
    join(targetDir, '.arp.yaml'),
    join(targetDir, 'arp.yaml'),
  ];
  const eventsPath = join(targetDir, '.opena2a', 'arp', 'events.jsonl');

  const hasConfig = configPaths.some(p => existsSync(p));
  const hasEvents = existsSync(eventsPath);

  if (hasEvents) {
    return { active: true, reason: 'ARP is actively monitoring' };
  }
  if (hasConfig) {
    return { active: true, reason: 'ARP configured (no events yet)' };
  }
  return { active: false, reason: 'No ARP config found' };
}

function detectHMA(targetDir: string): { active: boolean; reason: string } {
  // Check for governance files that HMA creates/verifies
  const governancePaths = [
    join(targetDir, 'SOUL.md'),
    join(targetDir, 'SKILL.md'),
    join(targetDir, '.opena2a', 'hma'),
  ];

  for (const p of governancePaths) {
    if (existsSync(p)) {
      return { active: true, reason: `Governance file: ${p}` };
    }
  }
  return { active: false, reason: 'No HMA governance files found' };
}

function detectShield(): { active: boolean; reason: string; shellHook: boolean } {
  const shieldDir = join(homedir(), '.opena2a', 'shield');
  const configFile = join(shieldDir, 'config.json');
  const eventsFile = join(shieldDir, 'events.jsonl');

  if (!existsSync(shieldDir)) {
    return { active: false, reason: 'Shield not initialized', shellHook: false };
  }

  let shellHook = false;
  if (existsSync(configFile)) {
    try {
      const config = JSON.parse(readFileSync(configFile, 'utf-8'));
      shellHook = config?.shellIntegration?.enabled === true;
    } catch { /* ok */ }
  }

  const hasEvents = existsSync(eventsFile);
  if (hasEvents) {
    return { active: true, reason: 'Shield active with events', shellHook };
  }
  return { active: true, reason: 'Shield initialized', shellHook };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Collect trust hints by scanning which tools are active.
 * Only checks tools that are enabled in the manifest (opt-in).
 */
export function collectTrustHints(targetDir: string, manifest?: AgentManifest | null): CollectionResult {
  const hints: TrustHints = {};
  const details: CollectionResult['details'] = [];

  // If no manifest, check all tools (used during initial attach)
  const enabledTools = manifest?.tools ?? {
    secretless: true,
    configguard: true,
    arp: true,
    hma: true,
    shield: true,
  };

  // Secretless -> secretsManaged
  if (enabledTools.secretless) {
    const result = detectSecretless(targetDir);
    hints.secretsManaged = result.active;
    details.push({ tool: 'Secretless', hint: 'secretsManaged', active: result.active, reason: result.reason });
  }

  // ConfigGuard -> configSigned
  if (enabledTools.configguard) {
    const result = detectConfigGuard(targetDir);
    hints.configSigned = result.active;
    details.push({ tool: 'ConfigGuard', hint: 'configSigned', active: result.active, reason: result.reason });
  }

  // ARP -> networkControlled + runtimeProtected
  if (enabledTools.arp) {
    const result = detectARP(targetDir);
    hints.networkControlled = result.active;
    hints.runtimeProtected = result.active;
    details.push({ tool: 'ARP', hint: 'networkControlled + runtimeProtected', active: result.active, reason: result.reason });
  }

  // HMA -> skillsVerified + promptsGuarded
  if (enabledTools.hma) {
    const result = detectHMA(targetDir);
    hints.skillsVerified = result.active;
    hints.promptsGuarded = result.active;
    details.push({ tool: 'HMA', hint: 'skillsVerified + promptsGuarded', active: result.active, reason: result.reason });
  }

  // Shield -> sessionsProtected + daemonHardened
  if (enabledTools.shield) {
    const result = detectShield();
    hints.sessionsProtected = result.active;
    hints.daemonHardened = result.shellHook;
    details.push({ tool: 'Shield', hint: 'sessionsProtected + daemonHardened', active: result.active, reason: result.reason });
  }

  return { hints, details };
}

/**
 * Apply collected hints to an AIMCore instance and return the updated trust score.
 */
export function applyTrustHints(
  aim: any,
  targetDir: string,
  manifest?: AgentManifest | null,
): { hints: TrustHints; details: CollectionResult['details']; score: any } {
  const { hints, details } = collectTrustHints(targetDir, manifest);
  aim.setTrustHints(hints);
  const score = aim.calculateTrust();
  return { hints, details, score };
}
