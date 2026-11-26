/**
 * The hackmyagent spawns in index.ts and router.ts fall back to `npx
 * hackmyagent` when hackmyagent cannot start. Node reports a program that
 * cannot start with 'error' and then 'close' with a negative errno (-2 for
 * ENOENT). That close must not settle the call: the status is the npx
 * fallback's, or 1 when npx cannot start either — never -2 (exit 254).
 *
 * The mocked spawn emits events in the order Node does for a missing program.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';

/** What each spawned program does: start and exit with a status, or fail to start. */
const outcome: Record<string, number | 'missing'> = {};

vi.mock('node:child_process', () => ({
  spawn: vi.fn((bin: string) => {
    const child = new EventEmitter();
    const result = outcome[bin] ?? 'missing';
    setTimeout(() => {
      if (result === 'missing') {
        const err = Object.assign(new Error(`spawn ${bin} ENOENT`), { code: 'ENOENT', errno: -2 });
        child.emit('error', err);
        child.emit('close', -2, null);
      } else {
        // npx runs for longer than the failed start takes to report close.
        setTimeout(() => child.emit('close', result, null), 20);
      }
    }, 0);
    return child;
  }),
  execFileSync: vi.fn(() => {
    throw Object.assign(new Error('not found'), { code: 'ENOENT' });
  }),
}));

const { spawnHmaCheckFromRouter } = await import('../../src/router.js');
const { spawnHmaCheck, spawnHackmyagent } = await import('../../src/index.js');

const SITES: Array<[string, () => Promise<number>]> = [
  ['index.ts spawnHmaCheck', () => spawnHmaCheck('express', [], {})],
  ['index.ts spawnHackmyagent', () => spawnHackmyagent(['scan-soul', '--explain'])],
  ['router.ts spawnHmaCheckFromRouter', () => spawnHmaCheckFromRouter('express', [], {})],
];

let stderrSpy: ReturnType<typeof vi.spyOn> | undefined;

beforeEach(() => {
  for (const key of Object.keys(outcome)) delete outcome[key];
  stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation((() => true) as typeof process.stderr.write);
});

afterEach(() => {
  stderrSpy?.mockRestore();
});

describe('hackmyagent not on PATH: the status is the npx fallback\'s', () => {
  for (const [name, run] of SITES) {
    it(`${name} returns the npx fallback's status`, async () => {
      outcome.npx = 7;
      expect(await run()).toBe(7);
    });

    it(`${name} returns 0 when the npx fallback succeeds`, async () => {
      outcome.npx = 0;
      expect(await run()).toBe(0);
    });

    it(`${name} returns 1 when neither hackmyagent nor npx can start`, async () => {
      expect(await run()).toBe(1);
    });

    it(`${name} returns hackmyagent's own status when it starts`, async () => {
      outcome.hackmyagent = 3;
      outcome.npx = 7;
      expect(await run()).toBe(3);
    });
  }
});
