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
import { verifyAllArtifacts } from './signing.js';
import { verifyEventLog, type EventLogVerification } from './events.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getShieldDir(): string {
  return join(homedir(), '.opena2a', 'shield');
}

/** Quote a value for a POSIX shell, so a cited command runs as printed. */
function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** The command a failing check tells the user to run next, and what it is for. */
export interface NextStep {
  label: string;
  command: string;
}

/**
 * Build a failing check. A FAIL with no next step is a dead end, so the step
 * is required here and every failing check is built here.
 *
 * The step must leave the evidence of the failure in place: it reads, or (in
 * lockdown) verifies before it unlocks. It is never `shield init`, which
 * re-records the policy hash and re-signs the artifacts, so the failing rows
 * turn green without anyone having looked at what changed.
 */
function failCheck(
  name: string,
  detail: string,
  step: NextStep,
  checkedAt: string,
): IntegrityCheck {
  const sentence = /[.!?]$/.test(detail) ? detail : `${detail}.`;
  return {
    name,
    status: 'fail',
    detail: `${sentence} ${step.label}: ${step.command}`,
    nextStep: step.command,
    checkedAt,
  };
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
 * Returns `{ valid: false, detail, nextStep }` when the hashes diverge
 * (tampered) or the recorded hash cannot be read.
 */
export function verifyPolicyIntegrity(
  policyPath?: string,
):
  | { valid: true; detail: string }
  | { valid: false; detail: string; nextStep: NextStep } {
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
      nextStep: { label: 'Inspect the record', command: `cat ${shellQuote(hashFile)}` },
    };
  }

  const currentHash = computeFileHash(resolvedPath);

  if (currentHash === recorded.hash) {
    return { valid: true, detail: 'Policy hash matches recorded value.' };
  }

  return {
    valid: false,
    detail: `Policy file has been modified since ${recorded.recordedAt}. Expected hash ${recorded.hash}, got ${currentHash}.`,
    nextStep: {
      label: 'Review the policy as it is now',
      command: `cat ${shellQuote(resolvedPath)}`,
    },
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
      '  if ! opena2a shield evaluate "$1" 2>/dev/null; then',
      '    return 1',
      '  fi',
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
    '  if ! opena2a shield evaluate "$BASH_COMMAND" 2>/dev/null; then',
    '    return 1',
    '  fi',
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
      status: 'pass',
      detail: 'Shell hook not installed (opt-in via: opena2a shield init --shell-hook).',
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

  return failCheck(
    'shell-hook',
    'Installed shell hook does not match expected content. The hook may have been tampered with.',
    {
      label: 'Review the installed hook',
      command: `sed -n ${shellQuote(`/${HOOK_START_MARKER}/,/${HOOK_END_MARKER}/p`)} ${shellQuote(rcFile)}`,
    },
    now,
  );
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
    return failCheck(
      'process',
      `Node executable not found at ${execPath}.`,
      { label: 'Find the node binary a new shell would run', command: 'command -v node' },
      now,
    );
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
 * Verify the event chain with the same reader and verifier `opena2a review`
 * uses (verifyEventLog, behind readVerifiedEvents), so selfcheck and review
 * agree on whether the log is intact and where it breaks (issue #244).
 * Unreadable lines are skipped exactly as review skips them: a torn trailing
 * write is recovered by the writer and does not break the chain, while a
 * line damaged between two events still breaks it through the next event's
 * prevHash.  The log is read once in fixed chunks, so a log of any size gets
 * a verdict.
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

  let verified: EventLogVerification;
  try {
    verified = verifyEventLog(eventsFile, { countsOnly: true });
  } catch {
    return failCheck(
      'event-chain',
      'Failed to read events file.',
      { label: 'Check its type and permissions', command: `ls -ld ${shellQuote(eventsFile)}` },
      now,
    );
  }

  const total = verified.trustedCount + verified.untrustedCount;
  const skipped = verified.unreadableLines;
  if (total + skipped === 0) {
    return {
      name: 'event-chain',
      status: 'pass',
      detail: 'Events file is empty; chain is trivially valid.',
      checkedAt: now,
    };
  }
  const skippedNote = skipped > 0
    ? ` ${skipped} unreadable ${skipped === 1 ? 'line was' : 'lines were'} skipped, as review skips them.`
    : '';

  if (verified.chainBroken) {
    const excluded = verified.untrustedCount;
    return {
      name: 'event-chain',
      status: 'warn',
      detail:
        `Event chain breaks at event ${(verified.brokenAt as number) + 1} of ${total}. ` +
        `opena2a review reports the break as SHIELD-INT-002 and excludes the ` +
        `${excluded} ${excluded === 1 ? 'event' : 'events'} from there on. ` +
        `A break comes from an edit to the log or from an older CLI version writing concurrently. ` +
        `To start a fresh chain: opena2a shield recover --archive-log.${skippedNote}`,
      checkedAt: now,
    };
  }

  return {
    name: 'event-chain',
    status: 'pass',
    detail: `Event chain valid across ${total} events.${skippedNote}`,
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
  /**
   * Run the full check battery even while the lockdown marker is present,
   * instead of short-circuiting to `lockdown` status.
   *
   * Only `shield recover --verify` sets this. It has to decide whether it is
   * safe to leave lockdown, and it must make that decision WITHOUT leaving
   * lockdown first (issue #228) — otherwise a compromised machine is briefly
   * unlocked, and anything that ends the process during the window leaves it
   * unlocked for good. Every other caller wants the short-circuit: while the
   * marker is present, "in lockdown" is the answer.
   */
  ignoreLockdown?: boolean;
}): IntegrityState {
  const now = new Date().toISOString();

  // If already in lockdown, short-circuit with lockdown status.
  if (!options.ignoreLockdown && isLockdown()) {
    const reason = getLockdownReason() ?? 'Unknown reason';
    return {
      status: 'lockdown',
      checks: [
        // recover --verify runs every check with the marker still in place
        // and lifts it only when none fails (#228).
        failCheck(
          'lockdown',
          `System is in lockdown: ${reason}`,
          { label: 'Verify before unlocking', command: 'opena2a shield recover --verify' },
          now,
        ),
      ],
      lastVerified: now,
      chainHash: '',
    };
  }

  // 1. Policy integrity
  const policyResult = verifyPolicyIntegrity();
  const policyCheck: IntegrityCheck = policyResult.valid
    ? { name: 'policy', status: 'pass', detail: policyResult.detail, checkedAt: now }
    : failCheck('policy', policyResult.detail, policyResult.nextStep, now);

  // 2. Shell hook integrity
  const shellHookCheck = verifyShellHookIntegrity(options.shell);

  // 3. Event chain integrity
  const eventChainCheck = verifyEventChainIntegrity();

  // 4. Process integrity
  const processCheck = verifyProcessIntegrity();

  // 5. Artifact signatures
  const artifactResult = verifyAllArtifacts();
  const artifactCheck: IntegrityCheck = artifactResult.valid
    ? { name: 'artifact-signatures', status: 'pass', detail: artifactResult.detail, checkedAt: now }
    : failCheck(
      'artifact-signatures',
      artifactResult.detail,
      {
        label: 'See when each signed file last changed',
        command: `ls -l ${shellQuote(getShieldDir())}`,
      },
      now,
    );

  const checks: IntegrityCheck[] = [
    policyCheck,
    shellHookCheck,
    eventChainCheck,
    processCheck,
    artifactCheck,
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
