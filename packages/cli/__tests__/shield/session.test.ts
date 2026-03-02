import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  collectSignals,
  detectAgent,
  computeSessionId,
  identifySession,
  isSessionExpired,
} from '../../src/shield/session.js';
import type { SessionSignal, SessionIdentity } from '../../src/shield/types.js';
import { SESSION_TIMEOUT_MS } from '../../src/shield/types.js';

let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  savedEnv = { ...process.env };
  // Clear AI-related env vars to get a clean state
  delete process.env.CLAUDE_CODE;
  delete process.env.CURSOR;
  delete process.env.VSCODE_PID;
  delete process.env.TERM_PROGRAM;
  delete process.env.TERM_PROGRAM_VERSION;
  delete process.env.SSH_TTY;
  delete process.env.WINDOWID;
});

afterEach(() => {
  process.env = savedEnv;
});

// ---------------------------------------------------------------------------
// collectSignals
// ---------------------------------------------------------------------------

describe('collectSignals', () => {
  it('returns array with PPID signal when no env vars are set', () => {
    const signals = collectSignals();
    const ppidSignal = signals.find((s) => s.name === 'PPID');
    expect(ppidSignal).toBeDefined();
    expect(ppidSignal!.type).toBe('pid');
    expect(Number(ppidSignal!.value)).toBeGreaterThan(0);
    expect(ppidSignal!.confidence).toBe(0.4);
  });

  it('includes CLAUDE_CODE signal with confidence 0.95 when env var is set', () => {
    process.env.CLAUDE_CODE = '1';
    const signals = collectSignals();
    const sig = signals.find((s) => s.name === 'CLAUDE_CODE');
    expect(sig).toBeDefined();
    expect(sig!.value).toBe('1');
    expect(sig!.confidence).toBe(0.95);
    expect(sig!.type).toBe('env');
  });

  it('includes TERM_PROGRAM signal with confidence 0.9 when set to "claude"', () => {
    process.env.TERM_PROGRAM = 'claude';
    const signals = collectSignals();
    const sig = signals.find((s) => s.name === 'TERM_PROGRAM');
    expect(sig).toBeDefined();
    expect(sig!.value).toBe('claude');
    expect(sig!.confidence).toBe(0.9);
  });

  it('includes CURSOR signal with confidence 0.9 when env var is set', () => {
    process.env.CURSOR = '1';
    const signals = collectSignals();
    const sig = signals.find((s) => s.name === 'CURSOR');
    expect(sig).toBeDefined();
    expect(sig!.value).toBe('1');
    expect(sig!.confidence).toBe(0.9);
    expect(sig!.type).toBe('env');
  });
});

// ---------------------------------------------------------------------------
// detectAgent
// ---------------------------------------------------------------------------

describe('detectAgent', () => {
  it('returns claude-code with confidence >= 0.9 for CLAUDE_CODE signal', () => {
    const signals: SessionSignal[] = [
      { type: 'env', name: 'CLAUDE_CODE', value: '1', confidence: 0.95 },
    ];
    const result = detectAgent(signals);
    expect(result).not.toBeNull();
    expect(result!.agent).toBe('claude-code');
    expect(result!.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('returns cursor with confidence >= 0.9 for CURSOR signal', () => {
    const signals: SessionSignal[] = [
      { type: 'env', name: 'CURSOR', value: '1', confidence: 0.9 },
    ];
    const result = detectAgent(signals);
    expect(result).not.toBeNull();
    expect(result!.agent).toBe('cursor');
    expect(result!.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it('returns copilot with confidence >= 0.7 for VSCODE_PID signal', () => {
    const signals: SessionSignal[] = [
      { type: 'env', name: 'VSCODE_PID', value: '12345', confidence: 0.7 },
    ];
    const result = detectAgent(signals);
    expect(result).not.toBeNull();
    expect(result!.agent).toBe('copilot');
    expect(result!.confidence).toBeGreaterThanOrEqual(0.7);
  });

  it('returns null for an empty signals array', () => {
    const result = detectAgent([]);
    expect(result).toBeNull();
  });

  it('returns unknown with confidence 0.4 for only a PPID signal', () => {
    const signals: SessionSignal[] = [
      { type: 'pid', name: 'PPID', value: '999', confidence: 0.4 },
    ];
    const result = detectAgent(signals);
    expect(result).not.toBeNull();
    expect(result!.agent).toBe('unknown');
    expect(result!.confidence).toBe(0.4);
  });
});

// ---------------------------------------------------------------------------
// detectAgent priority
// ---------------------------------------------------------------------------

describe('detectAgent priority', () => {
  it('prefers claude-code over cursor when both signals are present', () => {
    const signals: SessionSignal[] = [
      { type: 'env', name: 'CLAUDE_CODE', value: '1', confidence: 0.95 },
      { type: 'env', name: 'CURSOR', value: '1', confidence: 0.9 },
    ];
    const result = detectAgent(signals);
    expect(result).not.toBeNull();
    expect(result!.agent).toBe('claude-code');
  });
});

// ---------------------------------------------------------------------------
// computeSessionId
// ---------------------------------------------------------------------------

describe('computeSessionId', () => {
  const sampleSignals: SessionSignal[] = [
    { type: 'env', name: 'CLAUDE_CODE', value: '1', confidence: 0.95 },
    { type: 'pid', name: 'PPID', value: '42', confidence: 0.4 },
  ];

  it('returns format {agent}-{12hexchars}', () => {
    const id = computeSessionId('claude-code', sampleSignals);
    const pattern = /^claude-code-[0-9a-f]{12}$/;
    expect(id).toMatch(pattern);
  });

  it('is deterministic -- same inputs produce same ID', () => {
    const id1 = computeSessionId('claude-code', sampleSignals);
    const id2 = computeSessionId('claude-code', sampleSignals);
    expect(id1).toBe(id2);
  });

  it('produces different IDs for different inputs', () => {
    const id1 = computeSessionId('claude-code', sampleSignals);

    const otherSignals: SessionSignal[] = [
      { type: 'env', name: 'CURSOR', value: '1', confidence: 0.9 },
      { type: 'pid', name: 'PPID', value: '99', confidence: 0.4 },
    ];
    const id2 = computeSessionId('cursor', otherSignals);

    expect(id1).not.toBe(id2);
  });
});

// ---------------------------------------------------------------------------
// identifySession
// ---------------------------------------------------------------------------

describe('identifySession', () => {
  it('returns SessionIdentity with agent="claude-code" when CLAUDE_CODE is set', () => {
    process.env.CLAUDE_CODE = '1';
    const session = identifySession();
    expect(session).not.toBeNull();
    expect(session!.agent).toBe('claude-code');
  });

  it('returns null when no relevant env vars are set', () => {
    // With cleaned env, only PPID signal is present (confidence 0.4).
    // detectAgent returns {agent:'unknown', confidence:0.4} which is above 0.3,
    // so identifySession would return a session. However, on some CI/test
    // environments additional env vars may be absent. To guarantee null,
    // we need confidence below 0.3.  We mock process.ppid to 0 to remove
    // the PPID signal entirely, leaving an empty signals array.
    const origPpid = process.ppid;
    Object.defineProperty(process, 'ppid', { value: 0, writable: true, configurable: true });
    try {
      const session = identifySession();
      expect(session).toBeNull();
    } finally {
      Object.defineProperty(process, 'ppid', { value: origPpid, writable: true, configurable: true });
    }
  });

  it('returned identity has sessionId, startedAt, lastSeenAt, and signals array', () => {
    process.env.CLAUDE_CODE = '1';
    const session = identifySession();
    expect(session).not.toBeNull();
    expect(session!.sessionId).toEqual(expect.any(String));
    expect(session!.startedAt).toEqual(expect.any(String));
    expect(session!.lastSeenAt).toEqual(expect.any(String));
    expect(Array.isArray(session!.signals)).toBe(true);
    expect(session!.signals.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// isSessionExpired
// ---------------------------------------------------------------------------

describe('isSessionExpired', () => {
  function makeSession(lastSeenAt: string): SessionIdentity {
    return {
      sessionId: 'test-abc123def456',
      agent: 'claude-code',
      confidence: 0.95,
      signals: [],
      startedAt: lastSeenAt,
      lastSeenAt,
    };
  }

  it('returns false for a session with lastSeenAt = now', () => {
    const session = makeSession(new Date().toISOString());
    expect(isSessionExpired(session)).toBe(false);
  });

  it('returns true for a session with lastSeenAt 31 minutes ago', () => {
    const thirtyOneMinutesAgo = new Date(Date.now() - 31 * 60 * 1000).toISOString();
    const session = makeSession(thirtyOneMinutesAgo);
    expect(isSessionExpired(session)).toBe(true);
  });

  it('returns false for a session just under the timeout threshold', () => {
    const justUnder = new Date(Date.now() - (SESSION_TIMEOUT_MS - 1000)).toISOString();
    const session = makeSession(justUnder);
    expect(isSessionExpired(session)).toBe(false);
  });
});
