/**
 * Shield session identification.
 *
 * Uses multiple environment signals (env vars, process tree, TTY) to
 * determine which AI coding assistant is driving the current terminal
 * session.  Signal confidences are combined probabilistically and a
 * deterministic session ID is derived so the same physical session
 * always maps to the same identifier.
 */

import { createHash } from 'node:crypto';

import type {
  SessionIdentity,
  SessionSignal,
  SessionSignalType,
} from './types.js';

import { SESSION_TIMEOUT_MS } from './types.js';

// ---------------------------------------------------------------------------
// Signal collection
// ---------------------------------------------------------------------------

/**
 * Gather all available session signals from environment variables,
 * the process tree, and TTY information.
 *
 * Each signal carries a name, a raw string value, and a confidence
 * weight indicating how strongly that signal implies a particular
 * AI coding assistant is active.
 */
export function collectSignals(): SessionSignal[] {
  const signals: SessionSignal[] = [];

  // -- Environment variable signals --

  const termProgram = process.env['TERM_PROGRAM'];
  if (termProgram) {
    signals.push({
      type: 'env' as SessionSignalType,
      name: 'TERM_PROGRAM',
      value: termProgram,
      confidence: termProgram.toLowerCase() === 'claude' ? 0.9 : 0.3,
    });
  }

  const claudeCode = process.env['CLAUDE_CODE'];
  if (claudeCode) {
    signals.push({
      type: 'env' as SessionSignalType,
      name: 'CLAUDE_CODE',
      value: claudeCode,
      confidence: 0.95,
    });
  }

  const cursor = process.env['CURSOR'];
  if (cursor) {
    signals.push({
      type: 'env' as SessionSignalType,
      name: 'CURSOR',
      value: cursor,
      confidence: 0.9,
    });
  }

  const termVersion = process.env['TERM_PROGRAM_VERSION'];
  if (termVersion) {
    signals.push({
      type: 'env' as SessionSignalType,
      name: 'TERM_PROGRAM_VERSION',
      value: termVersion,
      confidence: 0.3,
    });
  }

  const sshTty = process.env['SSH_TTY'];
  if (sshTty) {
    signals.push({
      type: 'tty' as SessionSignalType,
      name: 'SSH_TTY',
      value: sshTty,
      confidence: 0.2,
    });
  }

  // -- Process tree signals --

  const ppid = process.ppid;
  if (ppid > 0) {
    signals.push({
      type: 'pid' as SessionSignalType,
      name: 'PPID',
      value: String(ppid),
      confidence: 0.4,
    });
  }

  // -- VS Code / Copilot signals --

  const vscodePid = process.env['VSCODE_PID'];
  if (vscodePid) {
    signals.push({
      type: 'env' as SessionSignalType,
      name: 'VSCODE_PID',
      value: vscodePid,
      confidence: 0.7,
    });
  }

  // -- X11 terminal detection --

  const windowId = process.env['WINDOWID'];
  if (windowId) {
    signals.push({
      type: 'tty' as SessionSignalType,
      name: 'WINDOWID',
      value: windowId,
      confidence: 0.1,
    });
  }

  return signals;
}

// ---------------------------------------------------------------------------
// Agent detection
// ---------------------------------------------------------------------------

/** Agent detection rules ordered by priority (highest first). */
interface AgentRule {
  agent: string;
  /** Return true if one or more signals match this agent. */
  match: (signals: SessionSignal[]) => boolean;
  /** Return the subset of signals that contributed to the match. */
  relevant: (signals: SessionSignal[]) => SessionSignal[];
}

const AGENT_RULES: AgentRule[] = [
  {
    agent: 'claude-code',
    match: (s) =>
      s.some(
        (sig) =>
          sig.name === 'CLAUDE_CODE' ||
          (sig.name === 'TERM_PROGRAM' && sig.value.toLowerCase() === 'claude'),
      ),
    relevant: (s) =>
      s.filter(
        (sig) =>
          sig.name === 'CLAUDE_CODE' ||
          (sig.name === 'TERM_PROGRAM' && sig.value.toLowerCase() === 'claude') ||
          sig.name === 'TERM_PROGRAM_VERSION',
      ),
  },
  {
    agent: 'cursor',
    match: (s) => s.some((sig) => sig.name === 'CURSOR'),
    relevant: (s) =>
      s.filter(
        (sig) => sig.name === 'CURSOR' || sig.name === 'TERM_PROGRAM_VERSION',
      ),
  },
  {
    agent: 'copilot',
    match: (s) => s.some((sig) => sig.name === 'VSCODE_PID'),
    relevant: (s) =>
      s.filter(
        (sig) => sig.name === 'VSCODE_PID' || sig.name === 'TERM_PROGRAM_VERSION',
      ),
  },
  {
    agent: 'aider',
    match: (s) =>
      s.some(
        (sig) =>
          sig.name === 'TERM_PROGRAM' && sig.value.toLowerCase() === 'aider',
      ),
    relevant: (s) =>
      s.filter(
        (sig) =>
          (sig.name === 'TERM_PROGRAM' && sig.value.toLowerCase() === 'aider') ||
          sig.name === 'TERM_PROGRAM_VERSION',
      ),
  },
  {
    agent: 'unknown',
    match: () => true,
    relevant: (s) => s,
  },
];

/**
 * Combine individual signal confidences into an aggregate confidence
 * using the probabilistic union formula:
 *
 *   P(at_least_one) = 1 - product(1 - c_i)
 *
 * This means two weak signals together produce a stronger combined
 * confidence than either alone, without exceeding 1.0.
 */
function combineConfidences(signals: SessionSignal[]): number {
  if (signals.length === 0) return 0;
  const complement = signals.reduce((acc, sig) => acc * (1 - sig.confidence), 1);
  return 1 - complement;
}

/**
 * Determine which AI coding assistant is active based on the
 * collected signals.
 *
 * Rules are evaluated in priority order: claude-code, cursor, copilot,
 * aider, unknown.  The first rule whose `match` predicate succeeds
 * wins.  If the combined confidence of matching signals falls below
 * 0.3, null is returned -- the session is likely not driven by any
 * known AI agent.
 */
export function detectAgent(
  signals: SessionSignal[],
): { agent: string; confidence: number } | null {
  for (const rule of AGENT_RULES) {
    if (!rule.match(signals)) continue;

    const relevant = rule.relevant(signals);
    const confidence = combineConfidences(relevant);

    // Below 0.3 we cannot confidently claim an AI agent is active.
    if (confidence < 0.3) return null;

    return { agent: rule.agent, confidence };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Session ID computation
// ---------------------------------------------------------------------------

/**
 * Generate a deterministic session ID from the agent name and the
 * stable signal values collected during detection.
 *
 * Format: `{agent}-{hash12}` where hash12 is the first 12 hex
 * characters of the SHA-256 digest of the sorted signal values
 * concatenated with the agent name.
 *
 * Sorting ensures the same set of signals always produces the same
 * hash regardless of collection order.
 */
export function computeSessionId(agent: string, signals: SessionSignal[]): string {
  const parts = signals
    .map((sig) => `${sig.name}=${sig.value}`)
    .sort();

  const payload = `${agent}:${parts.join(',')}`;
  const hash = createHash('sha256').update(payload).digest('hex');
  const hash12 = hash.slice(0, 12);

  return `${agent}-${hash12}`;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Main entry point for session identification.
 *
 * Collects environment signals, detects the active AI agent, computes
 * a deterministic session ID, and returns a complete SessionIdentity.
 *
 * Returns null when no AI coding assistant is detected with sufficient
 * confidence.
 */
export function identifySession(): SessionIdentity | null {
  const signals = collectSignals();
  const detection = detectAgent(signals);

  if (!detection) return null;

  const { agent, confidence } = detection;
  const sessionId = computeSessionId(agent, signals);
  const now = new Date().toISOString();

  return {
    sessionId,
    agent,
    confidence,
    signals,
    startedAt: now,
    lastSeenAt: now,
  };
}

/**
 * Check whether a session has exceeded the inactivity timeout.
 *
 * A session is considered expired if the elapsed time since
 * `lastSeenAt` exceeds SESSION_TIMEOUT_MS (30 minutes).
 */
export function isSessionExpired(session: SessionIdentity): boolean {
  const lastSeen = new Date(session.lastSeenAt).getTime();
  const elapsed = Date.now() - lastSeen;
  return elapsed > SESSION_TIMEOUT_MS;
}
