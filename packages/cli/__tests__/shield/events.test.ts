import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

// ---------------------------------------------------------------------------
// Mock node:os so that homedir() returns our temp directory.
// ---------------------------------------------------------------------------

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => _mockHomeDir,
  };
});

// Import after mocks so the modules pick up the mocked homedir.
const { writeEvent, verifyEventChain, GENESIS_HASH, getShieldDir } =
  await import('../../src/shield/events.js');

const { runIntegrityChecks } = await import('../../src/shield/integrity.js');

// ---------------------------------------------------------------------------
// Temp directory setup
// ---------------------------------------------------------------------------

let tempDir: string;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-events-test-'));
  _mockHomeDir = tempDir;
});

afterEach(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Helper: minimal event partial (all fields except generated ones)
// ---------------------------------------------------------------------------

function makePartial(overrides: Record<string, unknown> = {}) {
  return {
    source: 'shield' as const,
    category: 'test',
    severity: 'info' as const,
    agent: null,
    sessionId: null,
    action: 'test-action',
    target: 'test-target',
    outcome: 'allowed' as const,
    detail: {},
    orgId: null,
    managed: false,
    agentId: null,
    ...overrides,
  };
}

// ===========================================================================
// 1. Genesis event passes chain verification
// ===========================================================================

describe('genesis event chain verification', () => {
  it('single genesis event passes verifyEventChain', () => {
    getShieldDir(); // ensure directory exists
    const event = writeEvent(makePartial());

    // The first event should reference the genesis hash
    expect(event.prevHash).toBe(GENESIS_HASH);

    const result = verifyEventChain([event]);
    expect(result.valid).toBe(true);
    expect(result.brokenAt).toBeNull();
  });

  it('GENESIS_HASH is a valid SHA-256 hex string', () => {
    expect(GENESIS_HASH).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ===========================================================================
// 2. Multi-event chain passes
// ===========================================================================

describe('multi-event chain verification', () => {
  it('three-event chain passes verifyEventChain', () => {
    getShieldDir();

    const e1 = writeEvent(makePartial({ action: 'first' }));
    const e2 = writeEvent(makePartial({ action: 'second' }));
    const e3 = writeEvent(makePartial({ action: 'third' }));

    // Verify chaining: each event's prevHash links to previous eventHash
    expect(e1.prevHash).toBe(GENESIS_HASH);
    expect(e2.prevHash).toBe(e1.eventHash);
    expect(e3.prevHash).toBe(e2.eventHash);

    const result = verifyEventChain([e1, e2, e3]);
    expect(result.valid).toBe(true);
    expect(result.brokenAt).toBeNull();
  });
});

// ===========================================================================
// 3. Tampered prevHash is detected
// ===========================================================================

describe('tampered chain detection', () => {
  it('detects tampered prevHash', () => {
    getShieldDir();

    const e1 = writeEvent(makePartial({ action: 'first' }));
    const e2 = writeEvent(makePartial({ action: 'second' }));

    // Tamper with e2's prevHash
    const tampered = { ...e2, prevHash: 'deadbeef'.repeat(8) };

    const result = verifyEventChain([e1, tampered]);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
  });

  it('detects tampered eventHash', () => {
    getShieldDir();

    const e1 = writeEvent(makePartial({ action: 'first' }));

    // Tamper with e1's eventHash
    const tampered = { ...e1, eventHash: 'deadbeef'.repeat(8) };

    const result = verifyEventChain([tampered]);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(0);
  });
});

// ===========================================================================
// 4. Empty file is trivially valid
// ===========================================================================

describe('empty event list', () => {
  it('empty array passes verifyEventChain', () => {
    const result = verifyEventChain([]);
    expect(result.valid).toBe(true);
    expect(result.brokenAt).toBeNull();
  });
});

// ===========================================================================
// 5. Integration: selfcheck passes after writing a genesis event
// ===========================================================================

describe('selfcheck integration', () => {
  it('runIntegrityChecks event-chain check passes after writing events', () => {
    getShieldDir();

    // Write a genesis event
    writeEvent(makePartial({ action: 'init' }));

    // Run the full integrity check suite
    const state = runIntegrityChecks({ shell: 'zsh' });

    // Find the event-chain check
    const eventChainCheck = state.checks.find((c) => c.name === 'event-chain');
    expect(eventChainCheck).toBeDefined();
    expect(eventChainCheck!.status).toBe('pass');
    expect(eventChainCheck!.detail).toContain('valid');
  });

  it('runIntegrityChecks event-chain passes with multiple events', () => {
    getShieldDir();

    writeEvent(makePartial({ action: 'first' }));
    writeEvent(makePartial({ action: 'second' }));
    writeEvent(makePartial({ action: 'third' }));

    const state = runIntegrityChecks({ shell: 'zsh' });

    const eventChainCheck = state.checks.find((c) => c.name === 'event-chain');
    expect(eventChainCheck).toBeDefined();
    expect(eventChainCheck!.status).toBe('pass');
    expect(eventChainCheck!.detail).toContain('3 events');
  });

  it('runIntegrityChecks event-chain detects tampered events file', () => {
    const shieldDir = getShieldDir();

    writeEvent(makePartial({ action: 'legit' }));

    // Tamper with the events file: overwrite prevHash in the stored JSON
    const eventsPath = path.join(shieldDir, 'events.jsonl');
    const content = fs.readFileSync(eventsPath, 'utf-8');
    const tampered = content.replace(GENESIS_HASH, 'deadbeef'.repeat(8));
    fs.writeFileSync(eventsPath, tampered);

    const state = runIntegrityChecks({ shell: 'zsh' });

    const eventChainCheck = state.checks.find((c) => c.name === 'event-chain');
    expect(eventChainCheck).toBeDefined();
    expect(eventChainCheck!.status).toBe('warn');
  });
});
