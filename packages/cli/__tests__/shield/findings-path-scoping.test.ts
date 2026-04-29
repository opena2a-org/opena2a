import { describe, it, expect } from 'vitest';
import path from 'node:path';

import type { ShieldEvent, ShieldEventSource } from '../../src/shield/types.js';
import {
  classifyEvents,
  filterEventsToTarget,
} from '../../src/shield/findings.js';

function makeEvent(overrides: Partial<ShieldEvent> = {}): ShieldEvent {
  const base: ShieldEvent = {
    id: 'test-id',
    timestamp: '2026-03-01T00:00:00.000Z',
    version: 1,
    source: 'configguard',
    category: 'config.tampered',
    severity: 'critical',
    agent: null,
    sessionId: null,
    action: 'guard.verify',
    target: '/Users/foo/projectA',
    outcome: 'blocked',
    detail: {},
    prevHash: 'abc',
    eventHash: 'def',
    orgId: null,
    managed: false,
    agentId: null,
  };
  return { ...base, ...overrides };
}

describe('filterEventsToTarget — configguard scoping', () => {
  it('drops absolute-path configguard events outside the scan target', () => {
    const events = [
      makeEvent({ target: '/Users/foo/projectA' }),
      makeEvent({ target: '/Users/foo/projectB' }),
      makeEvent({ target: '/tmp/other' }),
    ];
    const filtered = filterEventsToTarget(events, '/Users/foo/projectA');
    expect(filtered).toHaveLength(1);
    expect(filtered[0]!.target).toBe('/Users/foo/projectA');
  });

  it('keeps configguard events whose path is nested under the scan target', () => {
    const events = [
      makeEvent({ target: '/Users/foo/projectA/.env' }),
      makeEvent({ target: '/Users/foo/projectA/sub/dir/config.yaml' }),
    ];
    const filtered = filterEventsToTarget(events, '/Users/foo/projectA');
    expect(filtered).toHaveLength(2);
  });

  it('keeps configguard events whose path equals the scan target exactly', () => {
    const events = [makeEvent({ target: '/Users/foo/projectA' })];
    const filtered = filterEventsToTarget(events, '/Users/foo/projectA');
    expect(filtered).toHaveLength(1);
  });

  it('does not match by lexical prefix (projectA vs project)', () => {
    const events = [
      makeEvent({ target: '/Users/foo/projectA' }),
      makeEvent({ target: '/Users/foo/projectAlpha/config' }),
    ];
    const filtered = filterEventsToTarget(events, '/Users/foo/project');
    expect(filtered).toHaveLength(0);
  });

  it('does not drop a child whose name happens to begin with "..bytes" (unusual but valid)', () => {
    // path.relative('/Users/foo', '/Users/foo/..badname') === '..badname'.
    // The check must use ('..' + sep) so it doesn't false-trip on names
    // that merely start with two dots without being parent traversal.
    const events = [makeEvent({ target: '/Users/foo/..badname' })];
    const filtered = filterEventsToTarget(events, '/Users/foo');
    expect(filtered).toHaveLength(1);
  });

  it('keeps configguard events whose target is empty or relative (guard watch case)', () => {
    // guard.ts:493,522 emits target: sig.filePath (relative, e.g. "package.json").
    // We can't reliably scope these without writer-side changes, so they
    // pass through. Documented as residual in the helper docstring.
    const events = [
      makeEvent({ target: '' }),
      makeEvent({ target: 'package.json' }),
      makeEvent({ target: '.opena2a/config.yaml' }),
    ];
    const filtered = filterEventsToTarget(events, '/Users/foo/projectA');
    expect(filtered).toHaveLength(3);
  });

  it('normalizes the scan target so trailing slashes and . segments do not change the result', () => {
    const events = [makeEvent({ target: '/Users/foo/projectA/.env' })];
    expect(filterEventsToTarget(events, '/Users/foo/projectA/').length).toBe(1);
    expect(filterEventsToTarget(events, '/Users/foo/projectA/./').length).toBe(1);
    expect(filterEventsToTarget(events, '/Users/foo/projectA/sub/..').length).toBe(1);
  });

  it('handles a relative scan target by resolving against cwd', () => {
    const events = [
      makeEvent({ target: path.resolve('.') }),
      makeEvent({ target: '/some/other/place' }),
    ];
    const filtered = filterEventsToTarget(events, '.');
    expect(filtered).toHaveLength(1);
    expect(filtered[0]!.target).toBe(path.resolve('.'));
  });

  it('issue #109 reproducer: empty scan dir surfaces 0 cross-target tamper events', () => {
    const events: ShieldEvent[] = Array.from({ length: 288 }, (_, i) =>
      makeEvent({
        id: `evt-${i}`,
        target: '/Users/foo/projectA',
        action: 'guard.verify',
        outcome: 'blocked',
      }),
    );
    const filtered = filterEventsToTarget(events, '/tmp/empty-test-dir');
    expect(filtered).toHaveLength(0);
  });
});

describe('filterEventsToTarget — non-configguard sources are NOT scoped', () => {
  // Critical safety property: only configguard events use `target` as the
  // scope indicator. Other sources use `target` for the affected entity
  // (binary, package, action, finding id), which has nothing to do with
  // whether the event is in scope. Filtering them by path would suppress
  // legitimate findings — e.g. a malicious agent shelling out to
  // /usr/bin/curl from inside the scan target.
  const otherSources: ShieldEventSource[] = [
    'arp', 'registry', 'secretless', 'shield', 'browser-guard', 'hma',
  ];

  for (const source of otherSources) {
    it(`passes through ${source} events even when target is an absolute system path outside the scan dir`, () => {
      const events = [
        makeEvent({ source, target: '/usr/bin/curl' }),
        makeEvent({ source, target: '/etc/passwd' }),
        makeEvent({ source, target: '/var/log/system.log' }),
      ];
      const filtered = filterEventsToTarget(events, '/Users/foo/projectA');
      expect(filtered).toHaveLength(3);
    });

    it(`passes through ${source} events with non-path targets`, () => {
      const events = [
        makeEvent({ source, target: 'left-pad' }),
        makeEvent({ source, target: 'https://evil.example.com' }),
        makeEvent({ source, target: 'pid:12345' }),
        makeEvent({ source, target: '' }),
      ];
      const filtered = filterEventsToTarget(events, '/Users/foo/projectA');
      expect(filtered).toHaveLength(4);
    });
  }
});

describe('filterEventsToTarget — heterogeneous stream + classification integration', () => {
  it('mixed stream: drops only out-of-scope configguard events; preserves the rest', () => {
    const events: ShieldEvent[] = [
      // Out-of-scope configguard tamper from another project — should be dropped
      makeEvent({ id: 'cg-out-1', target: '/Users/foo/projectB' }),
      makeEvent({ id: 'cg-out-2', target: '/tmp/random' }),
      // In-scope configguard tamper — should survive
      makeEvent({ id: 'cg-in-1', target: '/Users/foo/projectA' }),
      // ARP event with absolute system binary path — should survive (not configguard)
      makeEvent({ id: 'arp-1', source: 'arp', category: 'process.spawn', target: '/usr/bin/curl' }),
      // Registry event for a package — should survive
      makeEvent({ id: 'reg-1', source: 'registry', category: 'supply-chain.advisory', target: 'left-pad' }),
      // Secretless credential finding — should survive
      makeEvent({ id: 'sec-1', source: 'secretless', category: 'credential-finding', target: 'anthropic' }),
    ];
    const filtered = filterEventsToTarget(events, '/Users/foo/projectA');
    const survivedIds = filtered.map(e => e.id).sort();
    expect(survivedIds).toEqual(['arp-1', 'cg-in-1', 'reg-1', 'sec-1']);
  });

  it('positive integration: in-scope ConfigGuard tamper still classifies to SHIELD-INT-001', () => {
    const events: ShieldEvent[] = [
      makeEvent({
        id: 'in-scope-tamper',
        source: 'configguard',
        target: '/Users/foo/projectA',
        outcome: 'blocked',
      }),
      // Drown the in-scope event in cross-project noise to prove it survives.
      ...Array.from({ length: 100 }, (_, i) => makeEvent({
        id: `noise-${i}`, target: '/Users/foo/projectB',
      })),
    ];
    const filtered = filterEventsToTarget(events, '/Users/foo/projectA');
    const classified = classifyEvents(filtered);
    const shieldInt001 = classified.find(c => c.finding.id === 'SHIELD-INT-001');
    expect(shieldInt001).toBeDefined();
    expect(shieldInt001!.count).toBe(1);
  });

  it('positive integration: ARP process-spawn surfaces as SHIELD-PROC-001 even with system-binary target', () => {
    // Regression guard for the adversarial-review H1 finding: an earlier
    // version of this filter dropped ARP events whose target was an
    // absolute path (e.g. /usr/bin/curl), suppressing real attacks.
    const events: ShieldEvent[] = [
      makeEvent({
        id: 'arp-curl',
        source: 'arp',
        category: 'process.spawn',
        severity: 'high',
        target: '/usr/bin/curl',
        outcome: 'blocked',
      }),
    ];
    const filtered = filterEventsToTarget(events, '/Users/foo/projectA');
    const classified = classifyEvents(filtered);
    const shieldProc = classified.find(c => c.finding.id === 'SHIELD-PROC-001');
    expect(shieldProc).toBeDefined();
    expect(shieldProc!.count).toBe(1);
  });
});
