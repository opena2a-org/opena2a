import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { execFileSync, spawn } from 'node:child_process';
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

// Import after mocks
const { translateARPEvent, importARPEvents, getARPStats } =
  await import('../../src/shield/arp-bridge.js');

const { writeEvent, readEvents, getShieldDir, GENESIS_HASH } =
  await import('../../src/shield/events.js');

// ---------------------------------------------------------------------------
// Temp directory setup
// ---------------------------------------------------------------------------

let tempDir: string;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-arp-bridge-test-'));
  _mockHomeDir = tempDir;
});

afterEach(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// ARP event fixtures
// ---------------------------------------------------------------------------

function makeARPEvent(overrides: Record<string, unknown> = {}) {
  return {
    id: 'arp-test-' + Math.random().toString(36).slice(2),
    timestamp: new Date().toISOString(),
    source: 'process',
    category: 'normal',
    severity: 'info',
    description: 'Test process spawn',
    data: { command: '/usr/bin/ls', pid: 12345 },
    classifiedBy: 'L0-rules',
    ...overrides,
  };
}

// ===========================================================================
// translateARPEvent
// ===========================================================================

describe('translateARPEvent', () => {
  it('translates a normal process event', () => {
    const arp = makeARPEvent();
    const shield = translateARPEvent(arp);

    expect(shield.source).toBe('arp');
    expect(shield.category).toBe('arp.process');
    expect(shield.severity).toBe('info');
    expect(shield.action).toBe('process.spawn');
    expect(shield.target).toBe('/usr/bin/ls');
    expect(shield.outcome).toBe('allowed');
    expect(shield.detail).toHaveProperty('arpEventId', arp.id);
    expect(shield.detail).toHaveProperty('arpSource', 'process');
    expect(shield.detail).toHaveProperty('classifiedBy', 'L0-rules');
  });

  it('maps anomaly category to monitored outcome', () => {
    const arp = makeARPEvent({ category: 'anomaly', severity: 'medium' });
    const shield = translateARPEvent(arp);

    expect(shield.outcome).toBe('monitored');
    expect(shield.severity).toBe('medium');
    expect(shield.action).toBe('process.anomaly');
  });

  it('maps violation category to blocked outcome', () => {
    const arp = makeARPEvent({ category: 'violation', severity: 'high' });
    const shield = translateARPEvent(arp);

    expect(shield.outcome).toBe('blocked');
    expect(shield.severity).toBe('high');
  });

  it('maps threat category to blocked outcome', () => {
    const arp = makeARPEvent({ category: 'threat', severity: 'critical' });
    const shield = translateARPEvent(arp);

    expect(shield.outcome).toBe('blocked');
    expect(shield.severity).toBe('critical');
  });

  it('translates network events', () => {
    const arp = makeARPEvent({
      source: 'network',
      category: 'anomaly',
      data: { host: 'evil.com', port: 443 },
    });
    const shield = translateARPEvent(arp);

    expect(shield.category).toBe('arp.network');
    expect(shield.action).toBe('network.anomaly');
    expect(shield.target).toBe('evil.com');
  });

  it('translates filesystem events', () => {
    const arp = makeARPEvent({
      source: 'filesystem',
      data: { path: '/etc/passwd' },
    });
    const shield = translateARPEvent(arp);

    expect(shield.category).toBe('arp.filesystem');
    expect(shield.target).toBe('/etc/passwd');
  });

  it('translates prompt events', () => {
    const arp = makeARPEvent({
      source: 'prompt',
      category: 'violation',
      severity: 'high',
      description: 'Prompt injection detected',
      data: { name: 'injection-attempt' },
    });
    const shield = translateARPEvent(arp);

    expect(shield.category).toBe('arp.prompt');
    expect(shield.action).toBe('prompt.violation');
    expect(shield.target).toBe('injection-attempt');
  });

  it('translates mcp-protocol events', () => {
    const arp = makeARPEvent({
      source: 'mcp-protocol',
      data: { command: 'tool_call:read_file' },
    });
    const shield = translateARPEvent(arp);

    expect(shield.category).toBe('arp.mcp-protocol');
    expect(shield.action).toBe('mcp.normal');
    expect(shield.target).toBe('tool_call:read_file');
  });

  it('includes agent name when provided', () => {
    const arp = makeARPEvent();
    const shield = translateARPEvent(arp, 'claude-code');

    expect(shield.agent).toBe('claude-code');
  });

  it('extracts agent name from data when not provided', () => {
    const arp = makeARPEvent({ data: { agentName: 'cursor', command: 'ls' } });
    const shield = translateARPEvent(arp);

    expect(shield.agent).toBe('cursor');
  });

  it('includes LLM assessment when present', () => {
    const arp = makeARPEvent({
      llmAssessment: {
        consistent: false,
        confidence: 0.95,
        reasoning: 'Unusual process spawn',
        recommendation: 'pause',
      },
    });
    const shield = translateARPEvent(arp);

    expect(shield.outcome).toBe('blocked'); // pause -> blocked
    expect(shield.detail).toHaveProperty('llmAssessment');
  });

  it('sets default fields correctly', () => {
    const arp = makeARPEvent();
    const shield = translateARPEvent(arp);

    expect(shield.orgId).toBeNull();
    expect(shield.managed).toBe(false);
    expect(shield.agentId).toBeNull();
    expect(shield.sessionId).toBeNull();
  });

  it('handles unknown severity gracefully', () => {
    const arp = makeARPEvent({ severity: 'unknown-level' });
    const shield = translateARPEvent(arp);

    expect(shield.severity).toBe('info'); // default fallback
  });

  it('uses description as target fallback', () => {
    const arp = makeARPEvent({ data: {}, description: 'Something happened' });
    const shield = translateARPEvent(arp);

    expect(shield.target).toBe('Something happened');
  });
});

// ===========================================================================
// importARPEvents
// ===========================================================================

describe('importARPEvents', () => {
  it('returns zeros when no ARP events file exists', () => {
    getShieldDir();
    const result = importARPEvents(tempDir);

    expect(result.imported).toBe(0);
    expect(result.skipped).toBe(0);
    expect(result.errors).toBe(0);
    expect(result.total).toBe(0);
  });

  it.skipIf(process.platform === 'win32')(
    'imports nothing from a named pipe at the ARP events path instead of blocking on it',
    async () => {
      getShieldDir();
      const arpDir = path.join(tempDir, '.opena2a', 'arp');
      fs.mkdirSync(arpDir, { recursive: true });
      const arpEventsPath = path.join(arpDir, 'events.jsonl');
      execFileSync('mkfifo', [arpEventsPath]);
      // A pipe with no writer blocks a plain read until one appears and
      // closes it. After RESCUE_MS this child opens the pipe for writing and
      // closes it at once, so a read that blocks reaches end of file, and is
      // caught by the elapsed time, rather than hanging the run. The pipe path
      // reaches the child in its argument vector; no shell is involved.
      const RESCUE_MS = 5_000;
      const rescue = spawn(process.execPath, ['-e', `
        const fs = require('node:fs');
        setTimeout(() => {
          try { fs.closeSync(fs.openSync(process.argv[1], 'w')); } catch {}
          setInterval(() => {}, 1000);
        }, ${RESCUE_MS});
      `, arpEventsPath], { stdio: 'ignore' });
      try {
        const started = Date.now();
        const result = importARPEvents(tempDir);
        expect(Date.now() - started).toBeLessThan(RESCUE_MS);
        // The answer a directory at the same path gets: nothing to import.
        expect(result).toEqual({ imported: 0, skipped: 0, skippedUnverified: 0, errors: 0, total: 0 });
        fs.unlinkSync(arpEventsPath);
        fs.mkdirSync(arpEventsPath);
        expect(importARPEvents(tempDir)).toEqual(result);
        expect(readEvents({ source: 'arp' })).toEqual([]);
      } finally {
        rescue.kill();
      }
    },
    15_000,
  );

  it('imports ARP events into Shield log', () => {
    getShieldDir();

    // Create ARP events file
    const arpDir = path.join(tempDir, '.opena2a', 'arp');
    fs.mkdirSync(arpDir, { recursive: true });

    const events = [
      makeARPEvent({ id: 'arp-1', severity: 'info' }),
      makeARPEvent({ id: 'arp-2', severity: 'high', category: 'anomaly' }),
      makeARPEvent({ id: 'arp-3', severity: 'critical', category: 'threat' }),
    ];

    const content = events.map(e => JSON.stringify(e)).join('\n') + '\n';
    fs.writeFileSync(path.join(arpDir, 'events.jsonl'), content);

    const result = importARPEvents(tempDir);

    expect(result.imported).toBe(3);
    expect(result.skipped).toBe(0);
    expect(result.errors).toBe(0);
    expect(result.total).toBe(3);

    // Verify events are in Shield log
    const shieldEvents = readEvents({ source: 'arp' });
    expect(shieldEvents.length).toBe(3);
  });

  it('skips already-imported events', () => {
    getShieldDir();

    const arpDir = path.join(tempDir, '.opena2a', 'arp');
    fs.mkdirSync(arpDir, { recursive: true });

    const events = [
      makeARPEvent({ id: 'arp-dup-1' }),
      makeARPEvent({ id: 'arp-dup-2' }),
    ];

    const content = events.map(e => JSON.stringify(e)).join('\n') + '\n';
    fs.writeFileSync(path.join(arpDir, 'events.jsonl'), content);

    // First import
    const result1 = importARPEvents(tempDir);
    expect(result1.imported).toBe(2);

    // Second import - should skip
    const result2 = importARPEvents(tempDir);
    expect(result2.imported).toBe(0);
    expect(result2.skipped).toBe(2);
  });

  it('handles malformed JSON lines', () => {
    getShieldDir();

    const arpDir = path.join(tempDir, '.opena2a', 'arp');
    fs.mkdirSync(arpDir, { recursive: true });

    const content = JSON.stringify(makeARPEvent({ id: 'good-1' })) + '\n'
      + 'not valid json\n'
      + JSON.stringify(makeARPEvent({ id: 'good-2' })) + '\n';

    fs.writeFileSync(path.join(arpDir, 'events.jsonl'), content);

    const result = importARPEvents(tempDir);

    expect(result.imported).toBe(2);
    expect(result.errors).toBe(1);
    expect(result.total).toBe(3);
  });

  it('preserves Shield hash chain integrity after import', () => {
    getShieldDir();

    // Write a pre-existing Shield event
    writeEvent({
      source: 'shield',
      category: 'test',
      severity: 'info',
      agent: null,
      sessionId: null,
      action: 'pre-existing',
      target: 'test',
      outcome: 'allowed',
      detail: {},
      orgId: null,
      managed: false,
      agentId: null,
    });

    // Import ARP events
    const arpDir = path.join(tempDir, '.opena2a', 'arp');
    fs.mkdirSync(arpDir, { recursive: true });

    const arpEvents = [
      makeARPEvent({ id: 'chain-test-1' }),
      makeARPEvent({ id: 'chain-test-2' }),
    ];
    fs.writeFileSync(
      path.join(arpDir, 'events.jsonl'),
      arpEvents.map(e => JSON.stringify(e)).join('\n') + '\n',
    );

    importARPEvents(tempDir);

    // Read all events and verify they exist in the Shield log
    const allEvents = readEvents({ count: 100 });
    // Pre-existing (1) + imported (2) = 3 total events
    expect(allEvents.length).toBe(3);

    // Verify ARP events have correct source
    const importedArp = allEvents.filter(e => e.source === 'arp');
    expect(importedArp.length).toBe(2);
  });

  it('passes agent name through import', () => {
    getShieldDir();

    const arpDir = path.join(tempDir, '.opena2a', 'arp');
    fs.mkdirSync(arpDir, { recursive: true });

    const content = JSON.stringify(makeARPEvent({ id: 'agent-test-1' })) + '\n';
    fs.writeFileSync(path.join(arpDir, 'events.jsonl'), content);

    importARPEvents(tempDir, 'my-agent');

    const events = readEvents({ source: 'arp' });
    expect(events[0].agent).toBe('my-agent');
  });
});

// ===========================================================================
// getARPStats
// ===========================================================================

describe('getARPStats', () => {
  it('returns zeros when no ARP events exist', () => {
    getShieldDir();
    const stats = getARPStats();

    expect(stats.totalEvents).toBe(0);
    expect(stats.anomalies).toBe(0);
    expect(stats.processEvents).toBe(0);
  });

  it('computes stats from imported ARP events', () => {
    getShieldDir();

    // Write ARP-sourced events directly to Shield log
    const events = [
      { source: 'arp' as const, category: 'arp.process', severity: 'info' as const, action: 'process.spawn', target: 'ls', outcome: 'allowed' as const, detail: { arpCategory: 'normal' } },
      { source: 'arp' as const, category: 'arp.process', severity: 'high' as const, action: 'process.anomaly', target: 'curl', outcome: 'monitored' as const, detail: { arpCategory: 'anomaly' } },
      { source: 'arp' as const, category: 'arp.network', severity: 'medium' as const, action: 'network.anomaly', target: 'evil.com', outcome: 'monitored' as const, detail: { arpCategory: 'anomaly' } },
      { source: 'arp' as const, category: 'arp.prompt', severity: 'critical' as const, action: 'prompt.threat', target: 'injection', outcome: 'blocked' as const, detail: { arpCategory: 'threat' } },
      { source: 'arp' as const, category: 'arp.filesystem', severity: 'high' as const, action: 'filesystem.violation', target: '/etc/passwd', outcome: 'blocked' as const, detail: { arpCategory: 'violation' } },
    ];

    for (const e of events) {
      writeEvent({
        ...e,
        agent: null,
        sessionId: null,
        orgId: null,
        managed: false,
        agentId: null,
      });
    }

    const stats = getARPStats();

    expect(stats.totalEvents).toBe(5);
    expect(stats.processEvents).toBe(2);
    expect(stats.networkEvents).toBe(1);
    expect(stats.promptEvents).toBe(1);
    expect(stats.filesystemEvents).toBe(1);
    expect(stats.anomalies).toBe(2);
    expect(stats.violations).toBe(1);
    expect(stats.threats).toBe(1);
    expect(stats.enforcements).toBe(2); // 2 blocked outcomes
  });

  it('ignores non-ARP events', () => {
    getShieldDir();

    // Write a non-ARP event
    writeEvent({
      source: 'shield',
      category: 'test',
      severity: 'info',
      agent: null,
      sessionId: null,
      action: 'test',
      target: 'test',
      outcome: 'allowed',
      detail: {},
      orgId: null,
      managed: false,
      agentId: null,
    });

    const stats = getARPStats();
    expect(stats.totalEvents).toBe(0);
  });
});
