import { describe, it, expect } from 'vitest';
import type { ShieldEvent, PolicyViolation } from '../../src/shield/types.js';
import {
  FINDING_CATALOG,
  classifyEvent,
  classifyEvents,
  classifyViolation,
  getRemediation,
} from '../../src/shield/findings.js';

// ---------------------------------------------------------------------------
// Helper: build a minimal ShieldEvent
// ---------------------------------------------------------------------------

function makeEvent(overrides: Partial<ShieldEvent> = {}): ShieldEvent {
  return {
    id: 'test-id',
    timestamp: '2026-03-01T00:00:00.000Z',
    version: 1,
    source: 'shield',
    category: 'test',
    severity: 'info',
    agent: null,
    sessionId: null,
    action: 'test-action',
    target: 'test-target',
    outcome: 'allowed',
    detail: {},
    prevHash: 'abc',
    eventHash: 'def',
    orgId: null,
    managed: false,
    agentId: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// FINDING_CATALOG
// ---------------------------------------------------------------------------

describe('FINDING_CATALOG', () => {
  it('contains 15 finding definitions', () => {
    expect(Object.keys(FINDING_CATALOG).length).toBe(15);
  });

  it('all findings have required fields', () => {
    for (const [id, def] of Object.entries(FINDING_CATALOG)) {
      expect(def.id).toBe(id);
      expect(def.title).toBeTruthy();
      expect(def.severity).toBeTruthy();
      expect(def.category).toBeTruthy();
      expect(def.owaspAgentic).toMatch(/^ASI\d+$/);
      expect(def.mitreAtlas).toMatch(/^AML\.T\d+$/);
      expect(def.remediation).toBeTruthy();
      expect(def.description).toBeTruthy();
    }
  });

  it('finding IDs follow SHIELD-{CAT}-{NUM} pattern', () => {
    for (const id of Object.keys(FINDING_CATALOG)) {
      expect(id).toMatch(/^SHIELD-[A-Z]+-\d{3}$/);
    }
  });
});

// ---------------------------------------------------------------------------
// classifyEvent
// ---------------------------------------------------------------------------

describe('classifyEvent', () => {
  it('classifies secretless Anthropic credential as SHIELD-CRED-001', () => {
    const event = makeEvent({
      source: 'secretless',
      target: 'anthropic-key-file',
      action: 'credential-scan',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-CRED-001');
    expect(finding?.severity).toBe('critical');
  });

  it('classifies secretless OpenAI credential as SHIELD-CRED-002', () => {
    const event = makeEvent({
      source: 'secretless',
      target: 'openai-api-key',
      action: 'credential-scan',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-CRED-002');
  });

  it('classifies secretless GitHub credential as SHIELD-CRED-003', () => {
    const event = makeEvent({
      source: 'secretless',
      target: 'github-token',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-CRED-003');
  });

  it('classifies generic secretless event as SHIELD-CRED-004', () => {
    const event = makeEvent({
      source: 'secretless',
      target: 'some-api-key',
      action: 'found',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-CRED-004');
  });

  it('classifies credential-finding category as CRED', () => {
    // Real credential findings come from secretless, not shield
    const event = makeEvent({
      source: 'secretless',
      category: 'credential-finding',
      target: 'openai-key',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-CRED-002');
  });

  it('classifies configguard tamper as SHIELD-INT-001', () => {
    const event = makeEvent({
      source: 'configguard',
      action: 'tamper-detected',
      severity: 'critical',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-INT-001');
  });

  it('classifies configguard unsigned as SHIELD-INT-003', () => {
    const event = makeEvent({
      source: 'configguard',
      action: 'unsigned',
      category: 'config-unsigned',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-INT-003');
  });

  it('classifies ARP process.spawn as SHIELD-PROC-001', () => {
    const event = makeEvent({
      source: 'arp',
      category: 'process.spawn',
      severity: 'high',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-PROC-001');
  });

  it('classifies ARP network event as SHIELD-PROC-002', () => {
    const event = makeEvent({
      source: 'arp',
      category: 'network.connect',
      severity: 'medium',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-PROC-002');
  });

  it('classifies ARP behavioral anomaly as SHIELD-BAS-001', () => {
    const event = makeEvent({
      source: 'arp',
      category: 'behavioral-anomaly',
      severity: 'medium',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-BAS-001');
  });

  it('classifies registry high-severity as SHIELD-SUP-001', () => {
    const event = makeEvent({
      source: 'registry',
      severity: 'high',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-SUP-001');
  });

  it('classifies registry medium-severity as SHIELD-SUP-002', () => {
    const event = makeEvent({
      source: 'registry',
      severity: 'medium',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-SUP-002');
  });

  it('classifies blocked outcome as SHIELD-POL-002', () => {
    const event = makeEvent({
      source: 'arp',
      category: 'policy',
      outcome: 'blocked',
      severity: 'high',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-POL-002');
  });

  it('classifies monitored high-severity as SHIELD-POL-003', () => {
    const event = makeEvent({
      source: 'arp',
      category: 'policy',
      outcome: 'monitored',
      severity: 'high',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-POL-003');
  });

  it('returns null for shield diagnostic events', () => {
    const event = makeEvent({
      source: 'shield',
      category: 'posture-assessment',
      severity: 'info',
    });
    expect(classifyEvent(event)).toBeNull();
  });

  it('returns null for benign allowed events', () => {
    const event = makeEvent({
      outcome: 'allowed',
      severity: 'info',
    });
    expect(classifyEvent(event)).toBeNull();
  });

  it('returns null for shield.posture diagnostic events', () => {
    const event = makeEvent({
      source: 'shield',
      category: 'shield.posture',
      severity: 'info',
      outcome: 'monitored',
    });
    expect(classifyEvent(event)).toBeNull();
  });

  it('returns null for shield.credential diagnostic events', () => {
    const event = makeEvent({
      source: 'shield',
      category: 'shield.credential',
      severity: 'medium',
      outcome: 'monitored',
    });
    expect(classifyEvent(event)).toBeNull();
  });

  it('returns null for shield enforcement events', () => {
    const event = makeEvent({
      source: 'shield',
      category: 'policy-evaluation',
      severity: 'high',
      outcome: 'blocked',
    });
    expect(classifyEvent(event)).toBeNull();
  });

  it('still classifies shield integrity failures as SHIELD-INT-002', () => {
    const event = makeEvent({
      source: 'shield',
      category: 'integrity',
      severity: 'critical',
    });
    const finding = classifyEvent(event);
    expect(finding?.id).toBe('SHIELD-INT-002');
  });
});

// ---------------------------------------------------------------------------
// classifyEvents
// ---------------------------------------------------------------------------

describe('classifyEvents', () => {
  it('deduplicates findings by ID', () => {
    const events = [
      makeEvent({ source: 'secretless', target: 'anthropic-key', timestamp: '2026-03-01T01:00:00Z' }),
      makeEvent({ source: 'secretless', target: 'anthropic-key2', timestamp: '2026-03-01T02:00:00Z' }),
    ];
    const classified = classifyEvents(events);
    const cred001 = classified.find(c => c.finding.id === 'SHIELD-CRED-001');
    expect(cred001).toBeDefined();
    expect(cred001!.count).toBe(2);
    expect(cred001!.firstSeen).toBe('2026-03-01T01:00:00Z');
    expect(cred001!.lastSeen).toBe('2026-03-01T02:00:00Z');
  });

  it('sorts by severity (critical first), then by count', () => {
    const events = [
      makeEvent({ source: 'secretless', target: 'anthropic-key' }),       // CRED-001 critical
      makeEvent({ source: 'arp', category: 'process.spawn' }),            // PROC-001 high
      makeEvent({ source: 'arp', category: 'network.connect' }),          // PROC-002 medium
      makeEvent({ source: 'arp', category: 'network.connect' }),          // PROC-002 medium (dup)
    ];
    const classified = classifyEvents(events);
    expect(classified[0].finding.id).toBe('SHIELD-CRED-001');   // critical
    expect(classified[1].finding.id).toBe('SHIELD-PROC-001');   // high
    expect(classified[2].finding.id).toBe('SHIELD-PROC-002');   // medium, count 2
  });

  it('limits examples to 3', () => {
    const events = Array.from({ length: 5 }, (_, i) =>
      makeEvent({ source: 'secretless', target: `anthropic-key-${i}`, timestamp: `2026-03-0${i + 1}T00:00:00Z` }),
    );
    const classified = classifyEvents(events);
    expect(classified[0].examples.length).toBe(3);
    expect(classified[0].count).toBe(5);
  });

  it('returns empty array for empty events', () => {
    expect(classifyEvents([])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// classifyViolation
// ---------------------------------------------------------------------------

describe('classifyViolation', () => {
  function makeViolation(overrides: Partial<PolicyViolation> = {}): PolicyViolation {
    return {
      action: 'test-action',
      target: 'test-target',
      agent: 'claude-code',
      count: 1,
      severity: 'high',
      recommendation: 'Review and consider blocking',
      ...overrides,
    };
  }

  it('classifies credential-related violations', () => {
    const v = makeViolation({ action: 'credential.access', target: 'anthropic-api' });
    const finding = classifyViolation(v);
    expect(finding?.id).toBe('SHIELD-CRED-001');
  });

  it('classifies process violations', () => {
    const v = makeViolation({ action: 'process.spawn', target: '/usr/bin/curl' });
    const finding = classifyViolation(v);
    expect(finding?.id).toBe('SHIELD-PROC-001');
  });

  it('classifies network violations', () => {
    const v = makeViolation({ action: 'network.connect', target: 'evil.com' });
    const finding = classifyViolation(v);
    expect(finding?.id).toBe('SHIELD-PROC-002');
  });

  it('classifies config violations', () => {
    const v = makeViolation({ action: 'config.tamper', target: '.env' });
    const finding = classifyViolation(v);
    expect(finding?.id).toBe('SHIELD-INT-001');
  });

  it('defaults to POL-002 for high-severity unknowns', () => {
    const v = makeViolation({ action: 'unknown', severity: 'high' });
    const finding = classifyViolation(v);
    expect(finding?.id).toBe('SHIELD-POL-002');
  });

  it('defaults to POL-003 for medium-severity unknowns', () => {
    const v = makeViolation({ action: 'unknown', severity: 'medium' });
    const finding = classifyViolation(v);
    expect(finding?.id).toBe('SHIELD-POL-003');
  });
});

// ---------------------------------------------------------------------------
// getRemediation
// ---------------------------------------------------------------------------

describe('getRemediation', () => {
  it('returns remediation for known finding', () => {
    const cmd = getRemediation('SHIELD-CRED-001');
    expect(cmd).toContain('opena2a protect');
  });

  it('returns default for unknown finding', () => {
    const cmd = getRemediation('SHIELD-UNKNOWN-999');
    expect(cmd).toBe('opena2a shield selfcheck');
  });
});
