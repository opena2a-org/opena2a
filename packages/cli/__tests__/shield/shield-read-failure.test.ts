/**
 * An unreadable event log is UNKNOWN, and unknown is not intact.
 *
 * `runShieldPhase` wraps `readVerifiedEvents` in a try/catch. That catch used
 * to fall back to `chainBroken: false` with zero events, which reports an
 * unreadable log as a clean one -- the same fail-open shape the chain
 * verification exists to close, one layer up.
 *
 * The branch is unreachable in production today: `readAllEvents` swallows its
 * own I/O errors and `verifyEventChain` is total over JSON-derived input. That
 * is precisely why it needs a test. An unreachable branch is where a wrong
 * default survives unnoticed -- a mutation of that line cannot be killed by any
 * test that only drives the phase through real logs, so the mutation score of
 * the surrounding work said nothing about it either way.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

const throwing = vi.hoisted(() => ({ shouldThrow: false }));

vi.mock('../../src/shield/events.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/shield/events.js')>();
  return {
    ...actual,
    readVerifiedEvents: (...args: Parameters<typeof actual.readVerifiedEvents>) => {
      if (throwing.shouldThrow) throw new Error('event log unreadable');
      return actual.readVerifiedEvents(...args);
    },
  };
});

let targetDir: string;

beforeEach(() => {
  throwing.shouldThrow = false;
  targetDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-read-failure-'));
});

afterEach(() => {
  throwing.shouldThrow = false;
  fs.rmSync(targetDir, { recursive: true, force: true });
});

describe('runShieldPhase when the event log cannot be read', () => {
  it('reports the chain as broken, not intact', async () => {
    const { runShieldPhase } = await import('../../src/commands/review.js');

    throwing.shouldThrow = true;
    const data = runShieldPhase(targetDir);

    expect(data.chainBroken).toBe(true);
    expect(data.eventCount).toBe(0);
  });

  it('does not score better than a readable log with the same zero events', async () => {
    const { runShieldPhase } = await import('../../src/commands/review.js');

    throwing.shouldThrow = false;
    const readable = runShieldPhase(targetDir);

    throwing.shouldThrow = true;
    const unreadable = runShieldPhase(targetDir);

    // The whole point: failing to read must never be the cheaper outcome.
    expect(unreadable.shieldPostureScore).toBeLessThanOrEqual(readable.shieldPostureScore);
  });
});
