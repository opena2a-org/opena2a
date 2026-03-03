import { describe, it, expect } from 'vitest';
import type { ShieldEvent } from '../../src/shield/types.js';
import { classifyEvents } from '../../src/shield/findings.js';
import { toSarif } from '../../src/shield/sarif.js';
import type { SarifLog } from '../../src/shield/sarif.js';

// ---------------------------------------------------------------------------
// Helper
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
// toSarif
// ---------------------------------------------------------------------------

describe('toSarif', () => {
  it('produces valid SARIF 2.1.0 structure', () => {
    const events = [
      makeEvent({ source: 'secretless', target: 'anthropic-key' }),
      makeEvent({ source: 'arp', category: 'process.spawn', severity: 'high' }),
    ];
    const findings = classifyEvents(events);
    const sarif = toSarif(findings, '0.1.2');

    expect(sarif.$schema).toContain('sarif-schema-2.1.0');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);

    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe('OpenA2A Shield');
    expect(run.tool.driver.version).toBe('0.1.2');
    expect(run.tool.driver.informationUri).toBe('https://opena2a.org');
  });

  it('creates one rule per unique finding ID', () => {
    const events = [
      makeEvent({ source: 'secretless', target: 'anthropic-key-1' }),
      makeEvent({ source: 'secretless', target: 'anthropic-key-2' }),
    ];
    const findings = classifyEvents(events);
    const sarif = toSarif(findings, '0.1.2');

    // Both events map to SHIELD-CRED-001, so only 1 rule
    const rules = sarif.runs[0].tool.driver.rules;
    expect(rules.length).toBe(1);
    expect(rules[0].id).toBe('SHIELD-CRED-001');
  });

  it('creates one result per classified finding', () => {
    const events = [
      makeEvent({ source: 'secretless', target: 'anthropic-key' }),
      makeEvent({ source: 'arp', category: 'process.spawn', severity: 'high' }),
      makeEvent({ source: 'arp', category: 'network.connect', severity: 'medium' }),
    ];
    const findings = classifyEvents(events);
    const sarif = toSarif(findings, '0.1.2');

    expect(sarif.runs[0].results.length).toBe(3);
  });

  it('maps severity to correct SARIF level', () => {
    const events = [
      makeEvent({ source: 'secretless', target: 'anthropic-key' }),       // critical -> error
      makeEvent({ source: 'arp', category: 'network.connect', severity: 'medium' }), // medium -> warning
    ];
    const findings = classifyEvents(events);
    const sarif = toSarif(findings, '0.1.2');

    const results = sarif.runs[0].results;
    const critResult = results.find(r => r.ruleId === 'SHIELD-CRED-001');
    const medResult = results.find(r => r.ruleId === 'SHIELD-PROC-002');
    expect(critResult?.level).toBe('error');
    expect(medResult?.level).toBe('warning');
  });

  it('includes OWASP and MITRE tags in rule properties', () => {
    const events = [
      makeEvent({ source: 'secretless', target: 'anthropic-key' }),
    ];
    const findings = classifyEvents(events);
    const sarif = toSarif(findings, '0.1.2');

    const rule = sarif.runs[0].tool.driver.rules[0];
    expect(rule.properties.tags).toContain('ASI04');
    expect(rule.properties.tags).toContain('AML.T0025');
  });

  it('includes security-severity score', () => {
    const events = [
      makeEvent({ source: 'secretless', target: 'anthropic-key' }),
    ];
    const findings = classifyEvents(events);
    const sarif = toSarif(findings, '0.1.2');

    const rule = sarif.runs[0].tool.driver.rules[0];
    expect(rule.properties['security-severity']).toBe('9.5');
  });

  it('includes locations for file-path targets', () => {
    const events = [
      makeEvent({ source: 'secretless', target: '/src/config.ts' }),
    ];
    const findings = classifyEvents(events);
    const sarif = toSarif(findings, '0.1.2');

    const result = sarif.runs[0].results[0];
    expect(result.locations).toBeDefined();
    expect(result.locations![0].physicalLocation.artifactLocation.uri).toBe('/src/config.ts');
  });

  it('omits locations for non-file targets', () => {
    const events = [
      makeEvent({ source: 'secretless', target: 'anthropic-key', category: 'credential-finding' }),
    ];
    const findings = classifyEvents(events);
    const sarif = toSarif(findings, '0.1.2');

    const result = sarif.runs[0].results[0];
    expect(result.locations).toBeUndefined();
  });

  it('includes help text with remediation', () => {
    const events = [
      makeEvent({ source: 'secretless', target: 'anthropic-key' }),
    ];
    const findings = classifyEvents(events);
    const sarif = toSarif(findings, '0.1.2');

    const rule = sarif.runs[0].tool.driver.rules[0];
    expect(rule.help.text).toContain('opena2a protect');
  });

  it('handles empty findings', () => {
    const sarif = toSarif([], '0.1.2');
    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
  });

  it('produces valid JSON', () => {
    const events = [
      makeEvent({ source: 'secretless', target: 'anthropic-key' }),
      makeEvent({ source: 'configguard', action: 'tamper-detected', severity: 'critical' }),
    ];
    const findings = classifyEvents(events);
    const sarif = toSarif(findings, '0.1.2');

    // Should not throw
    const json = JSON.stringify(sarif, null, 2);
    const parsed = JSON.parse(json) as SarifLog;
    expect(parsed.version).toBe('2.1.0');
  });
});
