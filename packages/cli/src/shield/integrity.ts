// Shield: Self-Healing Security
// Integrity verification, lockdown mode, and recovery for the Shield system.

import { createHash } from 'node:crypto';
import {
  existsSync,
  readFileSync,
  writeFileSync,
  unlinkSync,
  mkdirSync,
} from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

import type { IntegrityCheck, IntegrityState, IntegrityStatus } from './types.js';
import { SHIELD_POLICY_FILE } from './types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getShieldDir(): string {
  return join(homedir(), '.opena2a', 'shield');
}

// ---------------------------------------------------------------------------
// File hashing
// ---------------------------------------------------------------------------

/**
 * Compute a SHA-256 hex digest of a file's contents.
 * Returns an empty string if the file does not exist.
 */
export function computeFileHash(filePath: string): string {
  if (!existsSync(filePath)) {
    return '';
  }
  const contents = readFileSync(filePath);
  return createHash('sha256').update(contents).digest('hex');
}

// ---------------------------------------------------------------------------
// Policy hash recording & verification
// ---------------------------------------------------------------------------

/**
 * Compute the hash of a policy file and persist it to
 * `~/.opena2a/shield/policy-hash.json` with restricted permissions.
 */
export function recordPolicyHash(policyPath: string): void {
  const hash = computeFileHash(policyPath);
  const shieldDir = getShieldDir();

  if (!existsSync(shieldDir)) {
    mkdirSync(shieldDir, { recursive: true, mode: 0o700 });
  }

  const record = {
    hash,
    recordedAt: new Date().toISOString(),
  };

  const hashFile = join(shieldDir, 'policy-hash.json');
  writeFileSync(hashFile, JSON.stringify(record, null, 2), {
    encoding: 'utf-8',
    mode: 0o600,
  });
}

/**
 * Compare the current policy file hash against the previously recorded hash.
 *
 * Returns `{ valid: true }` when:
 *   - No policy file exists (nothing to verify)
 *   - No recorded hash exists (policy was never recorded)
 *   - The current hash matches the recorded hash
 *
 * Returns `{ valid: false, detail }` when the hashes diverge (tampered).
 */
export function verifyPolicyIntegrity(
  policyPath?: string,
): { valid: boolean; detail: string } {
  const resolvedPath = policyPath ?? join(getShieldDir(), SHIELD_POLICY_FILE);

  if (!existsSync(resolvedPath)) {
    return { valid: true, detail: 'No policy file found; nothing to verify.' };
  }

  const hashFile = join(getShieldDir(), 'policy-hash.json');

  if (!existsSync(hashFile)) {
    return {
      valid: true,
      detail: 'No recorded policy hash; skipping verification.',
    };
  }

  let recorded: { hash: string; recordedAt: string };
  try {
    recorded = JSON.parse(readFileSync(hashFile, 'utf-8'));
  } catch {
    return {
      valid: false,
      detail: 'Failed to parse policy-hash.json; file may be corrupted.',
    };
  }

  const currentHash = computeFileHash(resolvedPath);

  if (currentHash === recorded.hash) {
    return { valid: true, detail: 'Policy hash matches recorded value.' };
  }

  return {
    valid: false,
    detail: `Policy file has been modified since ${recorded.recordedAt}. Expected hash ${recorded.hash}, got ${currentHash}.`,
  };
}

// ---------------------------------------------------------------------------
// Shell hook content & verification
// ---------------------------------------------------------------------------

const HOOK_START_MARKER = '# >>> opena2a shield hook >>>';
const HOOK_END_MARKER = '# <<< opena2a shield hook <<<';

/**
 * Return the canonical shell hook content for the given shell.
 */
export function getExpectedHookContent(shell: 'zsh' | 'bash'): string {
  if (shell === 'zsh') {
    return [
      HOOK_START_MARKER,
      'opena2a_shield_preexec() {',
      '  opena2a shield evaluate "$1"',
      '}',
      'autoload -Uz add-zsh-hook',
      'add-zsh-hook preexec opena2a_shield_preexec',
      HOOK_END_MARKER,
    ].join('\n');
  }

  // bash
  return [
    HOOK_START_MARKER,
    'opena2a_shield_debug() {',
    '  opena2a shield evaluate "$BASH_COMMAND"',
    '}',
    "trap 'opena2a_shield_debug' DEBUG",
    HOOK_END_MARKER,
  ].join('\n');
}

/**
 * Verify that the shell hook installed in the user's rc file matches the
 * expected content.
 */
export function verifyShellHookIntegrity(
  shell?: 'zsh' | 'bash',
): IntegrityCheck {
  const now = new Date().toISOString();
  const resolvedShell = shell ?? 'zsh';
  const rcFile =
    resolvedShell === 'zsh'
      ? join(homedir(), '.zshrc')
      : join(homedir(), '.bashrc');

  if (!existsSync(rcFile)) {
    return {
      name: 'shell-hook',
      status: 'warn',
      detail: `RC file ${rcFile} does not exist.`,
      checkedAt: now,
    };
  }

  const rcContent = readFileSync(rcFile, 'utf-8');

  const startIdx = rcContent.indexOf(HOOK_START_MARKER);
  const endIdx = rcContent.indexOf(HOOK_END_MARKER);

  if (startIdx === -1 || endIdx === -1) {
    return {
      name: 'shell-hook',
      status: 'warn',
      detail: 'Shield hook markers not found in rc file. Hook may not be installed.',
      checkedAt: now,
    };
  }

  const installedBlock = rcContent
    .slice(startIdx, endIdx + HOOK_END_MARKER.length)
    .trim();
  const expected = getExpectedHookContent(resolvedShell).trim();

  if (installedBlock === expected) {
    return {
      name: 'shell-hook',
      status: 'pass',
      detail: 'Shell hook matches expected content.',
      checkedAt: now,
    };
  }

  return {
    name: 'shell-hook',
    status: 'fail',
    detail:
      'Installed shell hook does not match expected content. The hook may have been tampered with.',
    checkedAt: now,
  };
}

// ---------------------------------------------------------------------------
// Process integrity
// ---------------------------------------------------------------------------

/**
 * Basic check that the current Node.js process has not been tampered with.
 * Validates that `process.execPath` exists and looks like a valid node binary.
 */
export function verifyProcessIntegrity(): IntegrityCheck {
  const now = new Date().toISOString();
  const execPath = process.execPath;

  if (!existsSync(execPath)) {
    return {
      name: 'process',
      status: 'fail',
      detail: `Node executable not found at ${execPath}.`,
      checkedAt: now,
    };
  }

  // A minimal heuristic: the binary name should contain "node".
  const binaryName = execPath.split('/').pop() ?? '';
  if (!binaryName.toLowerCase().includes('node')) {
    return {
      name: 'process',
      status: 'warn',
      detail: `Executable name "${binaryName}" does not appear to be a standard node binary.`,
      checkedAt: now,
    };
  }

  return {
    name: 'process',
    status: 'pass',
    detail: `Process running from ${execPath}.`,
    checkedAt: now,
  };
}

// ---------------------------------------------------------------------------
// Event chain integrity
// ---------------------------------------------------------------------------

/**
 * Verify the integrity of the event chain by checking that each event's
 * prevHash correctly references the preceding event's eventHash.
 */
function verifyEventChainIntegrity(): IntegrityCheck {
  const now = new Date().toISOString();
  const eventsFile = join(getShieldDir(), 'events.jsonl');

  if (!existsSync(eventsFile)) {
    return {
      name: 'event-chain',
      status: 'pass',
      detail: 'No events file found; chain is trivially valid.',
      checkedAt: now,
    };
  }

  let lines: string[];
  try {
    const raw = readFileSync(eventsFile, 'utf-8').trim();
    if (raw.length === 0) {
      return {
        name: 'event-chain',
        status: 'pass',
        detail: 'Events file is empty; chain is trivially valid.',
        checkedAt: now,
      };
    }
    lines = raw.split('\n');
  } catch {
    return {
      name: 'event-chain',
      status: 'fail',
      detail: 'Failed to read events file.',
      checkedAt: now,
    };
  }

  let previousHash = '';

  for (let i = 0; i < lines.length; i++) {
    let event: { prevHash?: string; eventHash?: string };
    try {
      event = JSON.parse(lines[i]);
    } catch {
      return {
        name: 'event-chain',
        status: 'fail',
        detail: `Malformed JSON at event line ${i + 1}.`,
        checkedAt: now,
      };
    }

    if (typeof event.prevHash !== 'string' || typeof event.eventHash !== 'string') {
      return {
        name: 'event-chain',
        status: 'fail',
        detail: `Event at line ${i + 1} is missing prevHash or eventHash.`,
        checkedAt: now,
      };
    }

    if (event.prevHash !== previousHash) {
      return {
        name: 'event-chain',
        status: 'fail',
        detail: `Chain broken at event line ${i + 1}: expected prevHash "${previousHash}", got "${event.prevHash}".`,
        checkedAt: now,
      };
    }

    previousHash = event.eventHash;
  }

  return {
    name: 'event-chain',
    status: 'pass',
    detail: `Event chain valid across ${lines.length} events.`,
    checkedAt: now,
  };
}

// ---------------------------------------------------------------------------
// Lockdown management
// ---------------------------------------------------------------------------

const LOCKDOWN_FILE = 'lockdown';

/**
 * Check whether the system is currently in lockdown mode.
 */
export function isLockdown(): boolean {
  return existsSync(join(getShieldDir(), LOCKDOWN_FILE));
}

/**
 * Enter lockdown mode by writing a lockdown marker file.
 */
export function enterLockdown(reason: string): void {
  const shieldDir = getShieldDir();

  if (!existsSync(shieldDir)) {
    mkdirSync(shieldDir, { recursive: true, mode: 0o700 });
  }

  const record = {
    reason,
    timestamp: new Date().toISOString(),
    enteredBy: 'selfcheck',
  };

  writeFileSync(
    join(shieldDir, LOCKDOWN_FILE),
    JSON.stringify(record, null, 2),
    { encoding: 'utf-8', mode: 0o600 },
  );
}

/**
 * Exit lockdown mode by removing the lockdown marker file.
 */
export function exitLockdown(): void {
  const lockdownPath = join(getShieldDir(), LOCKDOWN_FILE);
  if (existsSync(lockdownPath)) {
    unlinkSync(lockdownPath);
  }
}

/**
 * Read and return the reason the system entered lockdown, or null if not in
 * lockdown.
 */
export function getLockdownReason(): string | null {
  const lockdownPath = join(getShieldDir(), LOCKDOWN_FILE);

  if (!existsSync(lockdownPath)) {
    return null;
  }

  try {
    const data = JSON.parse(readFileSync(lockdownPath, 'utf-8'));
    return (data.reason as string) ?? null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Comprehensive integrity checks
// ---------------------------------------------------------------------------

/**
 * Run all integrity checks and produce an overall IntegrityState.
 *
 * Checks performed:
 *   1. Policy file integrity (hash comparison)
 *   2. Shell hook integrity (content comparison)
 *   3. Event chain integrity (hash chain validation)
 *   4. Process integrity (node binary verification)
 *
 * Status logic:
 *   - All pass   -> healthy
 *   - Any warn   -> degraded
 *   - Any fail   -> compromised
 *   - In lockdown -> lockdown (overrides all)
 */
export function runIntegrityChecks(options: {
  shell?: 'zsh' | 'bash';
}): IntegrityState {
  const now = new Date().toISOString();

  // If already in lockdown, short-circuit with lockdown status.
  if (isLockdown()) {
    const reason = getLockdownReason() ?? 'Unknown reason';
    return {
      status: 'lockdown',
      checks: [
        {
          name: 'lockdown',
          status: 'fail',
          detail: `System is in lockdown: ${reason}`,
          checkedAt: now,
        },
      ],
      lastVerified: now,
      chainHash: '',
    };
  }

  // 1. Policy integrity
  const policyResult = verifyPolicyIntegrity();
  const policyCheck: IntegrityCheck = {
    name: 'policy',
    status: policyResult.valid ? 'pass' : 'fail',
    detail: policyResult.detail,
    checkedAt: now,
  };

  // 2. Shell hook integrity
  const shellHookCheck = verifyShellHookIntegrity(options.shell);

  // 3. Event chain integrity
  const eventChainCheck = verifyEventChainIntegrity();

  // 4. Process integrity
  const processCheck = verifyProcessIntegrity();

  const checks: IntegrityCheck[] = [
    policyCheck,
    shellHookCheck,
    eventChainCheck,
    processCheck,
  ];

  // Derive overall status.
  let status: IntegrityStatus = 'healthy';

  const hasWarn = checks.some((c) => c.status === 'warn');
  const hasFail = checks.some((c) => c.status === 'fail');

  if (hasFail) {
    status = 'compromised';
  } else if (hasWarn) {
    status = 'degraded';
  }

  // Compute a chain hash from the concatenation of all check details.
  const chainInput = checks.map((c) => `${c.name}:${c.status}:${c.detail}`).join('|');
  const chainHash = createHash('sha256').update(chainInput).digest('hex');

  return {
    status,
    checks,
    lastVerified: now,
    chainHash,
  };
}
