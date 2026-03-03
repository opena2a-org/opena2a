/**
 * Guard policy: signing requirements and heartbeat disable on tamper.
 *
 * Loads policy from `.opena2a/guard/policy.json`, checks compliance
 * against the signature store, and manages the heartbeat-disabled marker.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { bold, green, yellow, red, dim, gray } from '../util/colors.js';

// --- Types ---

export interface GuardPolicy {
  version: 1;
  requiredFiles: string[];
  blockOnUnsigned: boolean;
  disableHeartbeatOnTamper: boolean;
  autoRemediate: boolean;
}

export interface PolicyComplianceResult {
  compliant: boolean;
  requiredSigned: number;
  requiredUnsigned: string[];
  requiredTampered: string[];
  requiredMissing: string[];
}

interface HeartbeatStatus {
  disabled: boolean;
  reason?: string;
  disabledAt?: string;
}

// --- Constants ---

const GUARD_DIR = '.opena2a/guard';
const POLICY_FILE = 'policy.json';
const HEARTBEAT_DISABLED_FILE = 'heartbeat-disabled';
const SIGNATURES_FILE = 'signatures.json';

const DEFAULT_CONFIG_FILES = [
  'mcp.json', '.mcp.json', '.claude/settings.json',
  'package.json', 'package-lock.json',
  'arp.yaml', 'arp.yml', 'arp.json',
  'openclaw.json', '.openclaw/config.json',
  '.opena2a.yaml', '.opena2a.json',
  'tsconfig.json', 'go.mod', 'go.sum',
  'pyproject.toml', 'requirements.txt',
  'Dockerfile', 'docker-compose.yml',
];

// --- Event emission ---

async function emitEvent(
  category: string, action: string, target: string,
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical',
  outcome: 'allowed' | 'blocked' | 'monitored',
  detail: Record<string, unknown>,
): Promise<void> {
  try {
    const { writeEvent } = await import('../shield/events.js');
    writeEvent({
      source: 'configguard', category, severity,
      agent: null, sessionId: null, action, target, outcome, detail,
      orgId: null, managed: false, agentId: null,
    });
  } catch {
    // Shield module not available
  }
}

// --- Policy loading ---

export function loadGuardPolicy(targetDir: string): GuardPolicy | null {
  const policyPath = path.join(targetDir, GUARD_DIR, POLICY_FILE);
  if (!fs.existsSync(policyPath)) return null;
  try { return JSON.parse(fs.readFileSync(policyPath, 'utf-8')) as GuardPolicy; } catch { return null; }
}

export function saveGuardPolicy(targetDir: string, policy: GuardPolicy): void {
  const dir = path.join(targetDir, GUARD_DIR);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, POLICY_FILE), JSON.stringify(policy, null, 2) + '\n', 'utf-8');
}

// --- Default policy generation ---

export function generateDefaultPolicy(targetDir: string): GuardPolicy {
  const detected = DEFAULT_CONFIG_FILES.filter(f => fs.existsSync(path.join(targetDir, f)));
  return {
    version: 1,
    requiredFiles: detected,
    blockOnUnsigned: true,
    disableHeartbeatOnTamper: true,
    autoRemediate: false,
  };
}

// --- Compliance checking ---

export function checkPolicyCompliance(targetDir: string, policy: GuardPolicy): PolicyComplianceResult {
  const storePath = path.join(targetDir, GUARD_DIR, SIGNATURES_FILE);
  let signatures: Array<{ filePath: string; hash: string }> = [];
  try {
    const store = JSON.parse(fs.readFileSync(storePath, 'utf-8'));
    signatures = store.signatures ?? [];
  } catch { /* no store */ }

  const sigMap = new Map(signatures.map(s => [s.filePath, s.hash]));
  const requiredUnsigned: string[] = [];
  const requiredTampered: string[] = [];
  const requiredMissing: string[] = [];
  let requiredSigned = 0;

  for (const file of policy.requiredFiles) {
    const fullPath = path.join(targetDir, file);
    const storedHash = sigMap.get(file);

    if (!storedHash) { requiredUnsigned.push(file); continue; }
    if (!fs.existsSync(fullPath)) { requiredMissing.push(file); continue; }

    const content = fs.readFileSync(fullPath);
    const currentHash = 'sha256:' + createHash('sha256').update(content).digest('hex');
    if (currentHash === storedHash) { requiredSigned++; }
    else { requiredTampered.push(file); }
  }

  const compliant = requiredUnsigned.length === 0 && requiredTampered.length === 0 && requiredMissing.length === 0;
  return { compliant, requiredSigned, requiredUnsigned, requiredTampered, requiredMissing };
}

// --- Heartbeat management ---

export function disableHeartbeat(targetDir: string, reason: string): void {
  const dir = path.join(targetDir, GUARD_DIR);
  fs.mkdirSync(dir, { recursive: true });
  const marker = { disabled: true, reason, disabledAt: new Date().toISOString() };
  fs.writeFileSync(path.join(dir, HEARTBEAT_DISABLED_FILE), JSON.stringify(marker, null, 2) + '\n', 'utf-8');
}

export function isHeartbeatDisabled(targetDir: string): HeartbeatStatus {
  const markerPath = path.join(targetDir, GUARD_DIR, HEARTBEAT_DISABLED_FILE);
  if (!fs.existsSync(markerPath)) return { disabled: false };
  try {
    const data = JSON.parse(fs.readFileSync(markerPath, 'utf-8'));
    return { disabled: true, reason: data.reason, disabledAt: data.disabledAt };
  } catch { return { disabled: false }; }
}

export function enableHeartbeat(targetDir: string): void {
  const markerPath = path.join(targetDir, GUARD_DIR, HEARTBEAT_DISABLED_FILE);
  if (fs.existsSync(markerPath)) fs.unlinkSync(markerPath);
}

// --- Guard policy subcommand handler ---

export async function guardPolicy(targetDir: string, action: string, options: { format?: 'text' | 'json' }): Promise<number> {
  const isJson = options.format === 'json';

  switch (action) {
    case 'init': {
      const policy = generateDefaultPolicy(targetDir);
      saveGuardPolicy(targetDir, policy);

      await emitEvent('policy.created', 'guard.policy.init', targetDir, 'info', 'allowed', {
        requiredFiles: policy.requiredFiles, blockOnUnsigned: policy.blockOnUnsigned, disableHeartbeatOnTamper: policy.disableHeartbeatOnTamper,
      });

      if (isJson) { process.stdout.write(JSON.stringify(policy, null, 2) + '\n'); }
      else {
        process.stdout.write(green('Guard policy initialized.\n'));
        process.stdout.write(dim(`  Required files: ${policy.requiredFiles.length}\n`));
        for (const f of policy.requiredFiles) { process.stdout.write(dim(`    ${f}\n`)); }
        process.stdout.write(dim(`  Block on unsigned: ${policy.blockOnUnsigned}\n`));
        process.stdout.write(dim(`  Disable heartbeat on tamper: ${policy.disableHeartbeatOnTamper}\n`));
        process.stdout.write(dim(`  Policy file: ${GUARD_DIR}/${POLICY_FILE}\n`));
      }
      return 0;
    }

    case 'show': {
      const policy = loadGuardPolicy(targetDir);
      if (!policy) {
        if (isJson) { process.stdout.write(JSON.stringify({ error: 'No guard policy found. Run: opena2a guard policy init' }, null, 2) + '\n'); }
        else { process.stdout.write(yellow('No guard policy found. Run: opena2a guard policy init\n')); }
        return 1;
      }

      if (isJson) { process.stdout.write(JSON.stringify(policy, null, 2) + '\n'); }
      else {
        process.stdout.write(bold('Guard Policy') + '\n');
        process.stdout.write(gray('-'.repeat(40)) + '\n');
        process.stdout.write(`  Block on unsigned:           ${policy.blockOnUnsigned ? green('yes') : dim('no')}\n`);
        process.stdout.write(`  Disable heartbeat on tamper: ${policy.disableHeartbeatOnTamper ? green('yes') : dim('no')}\n`);
        process.stdout.write(`  Auto-remediate:              ${policy.autoRemediate ? green('yes') : dim('no')}\n`);
        process.stdout.write(`  Required files (${policy.requiredFiles.length}):\n`);
        for (const f of policy.requiredFiles) { process.stdout.write(dim(`    ${f}\n`)); }
        const hb = isHeartbeatDisabled(targetDir);
        if (hb.disabled) { process.stdout.write(red(`  Heartbeat: DISABLED (${hb.reason})\n`)); }
        else { process.stdout.write(green('  Heartbeat: active\n')); }
        process.stdout.write(gray('-'.repeat(40)) + '\n');
      }
      return 0;
    }

    default:
      if (isJson) { process.stdout.write(JSON.stringify({ error: `Unknown policy action: ${action}` }, null, 2) + '\n'); }
      else {
        process.stderr.write(red(`Unknown policy action: ${action}\n`));
        process.stderr.write('Usage: opena2a guard policy <init|show>\n');
      }
      return 1;
  }
}

// --- Testable internals ---

export const _internals = {
  loadGuardPolicy, saveGuardPolicy, generateDefaultPolicy, checkPolicyCompliance,
  disableHeartbeat, isHeartbeatDisabled, enableHeartbeat, guardPolicy, emitEvent,
  GUARD_DIR, POLICY_FILE, HEARTBEAT_DISABLED_FILE, SIGNATURES_FILE,
  DEFAULT_CONFIG_FILES,
};
