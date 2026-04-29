import { describe, it, expect } from 'vitest';
import path from 'node:path';

import type { ShieldEvent } from '../../src/shield/types.js';
import { filterEventsToTarget } from '../../src/shield/findings.js';

function makeEvent(overrides: Partial<ShieldEvent> = {}): ShieldEvent {
  return {
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
    ...overrides,
  };
}

describe('filterEventsToTarget', () => {
  it('drops absolute-path events outside the scan target', () => {
    const events = [
      makeEvent({ target: '/Users/foo/projectA' }),
      makeEvent({ target: '/Users/foo/projectB' }),
      makeEvent({ target: '/tmp/other' }),
    ];
    const filtered = filterEventsToTarget(events, '/Users/foo/projectA');
    expect(filtered).toHaveLength(1);
    expect(filtered[0]!.target).toBe('/Users/foo/projectA');
  });

  it('keeps events whose path is nested under the scan target', () => {
    const events = [
      makeEvent({ target: '/Users/foo/projectA/.env' }),
      makeEvent({ target: '/Users/foo/projectA/sub/dir/config.yaml' }),
    ];
    const filtered = filterEventsToTarget(events, '/Users/foo/projectA');
    expect(filtered).toHaveLength(2);
  });

  it('keeps events whose path equals the scan target exactly', () => {
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

  it('keeps events whose target is empty or non-path (URLs, package names, action ids)', () => {
    const events = [
      makeEvent({ source: 'arp', target: '' }),
      makeEvent({ source: 'arp', target: 'curl' }),
      makeEvent({ source: 'registry', target: 'left-pad' }),
      makeEvent({ source: 'arp', target: 'https://malicious.example.com' }),
      makeEvent({ source: 'shield', target: 'shield.posture' }),
    ];
    const filtered = filterEventsToTarget(events, '/Users/foo/projectA');
    expect(filtered).toHaveLength(5);
  });

  it('normalizes the scan target so trailing slashes and . segments do not change the result', () => {
    const events = [
      makeEvent({ target: '/Users/foo/projectA/.env' }),
    ];
    expect(filterEventsToTarget(events, '/Users/foo/projectA/').length).toBe(1);
    expect(filterEventsToTarget(events, '/Users/foo/projectA/./').length).toBe(1);
    expect(filterEventsToTarget(events, '/Users/foo/projectA/sub/..').length).toBe(1);
  });

  it('returns an empty array when no events match', () => {
    const events = [makeEvent({ target: '/Users/foo/projectB' })];
    expect(filterEventsToTarget(events, '/tmp/empty')).toEqual([]);
  });

  it('returns the input unchanged when every event is in scope', () => {
    const events = [
      makeEvent({ target: '/Users/foo/projectA' }),
      makeEvent({ target: '/Users/foo/projectA/.env' }),
    ];
    const filtered = filterEventsToTarget(events, '/Users/foo/projectA');
    expect(filtered).toHaveLength(2);
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

  it('issue #109 sub-item 1 reproducer: empty test dir surfaces 0 cross-target tamper events', () => {
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
