/**
 * Concurrent `writeEvent` must not fork the hash chain (#231).
 *
 * `writeEvent` reads the last line for its prevHash and then appends.  Before
 * the event lock, two processes that interleaved inside that window appended
 * two events claiming the same predecessor: `verifyEventChain` reported
 * `{valid:false, brokenAt:1}` on a log written entirely by legitimate,
 * non-malicious callers.  Measured on this tree at N=8: 5/5 runs forked.
 *
 * Since `review` now excludes every event at or after the first break and
 * raises a critical finding, that fork is a false critical on a clean
 * project.  This test is the regression barrier for the lock that closes it.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { verifyEventChain } from '../../src/shield/events.js';
import { MAX_EVENTS_FILE_SIZE } from '../../src/shield/types.js';
import {
  STALE_MS,
  TIMEOUT_MS,
  getEventLockPath,
  withEventLock,
} from '../../src/shield/lock.js';

const CHILD = path.resolve(__dirname, 'fixtures', 'concurrent-write-child.ts');

/** The child is TypeScript, so it runs under the workspace's own tsx. */
function resolveTsx(): string {
  const candidates = [
    path.resolve(__dirname, '..', '..', 'node_modules', '.bin', 'tsx'),
    path.resolve(__dirname, '..', '..', '..', '..', 'node_modules', '.bin', 'tsx'),
  ];
  const found = candidates.find(p => fs.existsSync(p));
  if (!found) {
    throw new Error(`tsx not found; looked in:\n${candidates.join('\n')}`);
  }
  return found;
}

const tempHomes: string[] = [];

function makeHome(): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'shield-concurrent-'));
  tempHomes.push(home);
  return home;
}

afterEach(() => {
  while (tempHomes.length > 0) {
    fs.rmSync(tempHomes.pop()!, { recursive: true, force: true });
  }
});

/** Far enough ahead that the slowest interpreter start still lands before it. */
const START_DELAY_MS = 1_500;

function spawnChild(home: string, startAt: number, index: number): Promise<void> {
  const tsx = resolveTsx();
  return new Promise<void>((resolve, reject) => {
    const child = spawn(tsx, [CHILD, String(startAt), String(index)], {
      env: { ...process.env, HOME: home },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', chunk => { stderr += String(chunk); });
    child.on('error', reject);
    child.on('exit', code => {
      if (code === 0) resolve();
      else reject(new Error(`child ${index} exited ${code}: ${stderr}`));
    });
  });
}

function runChildren(home: string, count: number): Promise<void[]> {
  const startAt = Date.now() + START_DELAY_MS;
  return Promise.all(
    Array.from({ length: count }, (_unused, index) => spawnChild(home, startAt, index)),
  );
}

/** Block this thread until `deadline`, the way `writeEvent` waits for a lock. */
function sleepUntil(deadline: number): void {
  const remaining = deadline - Date.now();
  if (remaining > 0) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, remaining);
}

function readLog(home: string): { lines: string[]; shieldDir: string } {
  const shieldDir = path.join(home, '.opena2a', 'shield');
  const logPath = path.join(shieldDir, 'events.jsonl');
  const raw = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf-8') : '';
  return { lines: raw.split('\n').filter(l => l.trim().length > 0), shieldDir };
}

describe('concurrent writeEvent (#231)', () => {
  // Defaults are the PR-gate configuration and must not change: 8 writers, two
  // rounds. The env overrides exist so the dispatchable stress job in
  // concurrency-stress.yml can drive the SAME test at higher writer counts and
  // more rounds, rather than forking a second copy that can drift from this one.
  const N = Number(process.env.SHIELD_CONCURRENT_WRITERS ?? 8);
  const ROUNDS = Number(process.env.SHIELD_CONCURRENT_ROUNDS ?? 2);

  if (!Number.isInteger(N) || N < 1 || !Number.isInteger(ROUNDS) || ROUNDS < 1) {
    // A typo'd override must not silently reduce coverage to nothing. Without
    // this, SHIELD_CONCURRENT_WRITERS=eight yields NaN, the loop body never
    // runs, and the job reports success having tested zero writers — the same
    // shape as a gate that passes because it measured nothing.
    throw new Error(
      `Invalid concurrency override: SHIELD_CONCURRENT_WRITERS=${process.env.SHIELD_CONCURRENT_WRITERS}, ` +
      `SHIELD_CONCURRENT_ROUNDS=${process.env.SHIELD_CONCURRENT_ROUNDS}. Both must be positive integers.`,
    );
  }

  // Two rounds: one clean round can hide a lock that only mostly works.
  for (const round of Array.from({ length: ROUNDS }, (_, i) => i + 1)) {
    it(`keeps the chain intact across ${N} concurrent writer processes (round ${round})`, async () => {
      const home = makeHome();
      await runChildren(home, N);

      const { lines, shieldDir } = readLog(home);

      // No write may be lost: the lock serialises writers, it does not drop them.
      expect(lines.length).toBe(N);

      const events = lines.map(line => JSON.parse(line));
      expect(verifyEventChain(events)).toEqual({ valid: true, brokenAt: null });

      // Every child is represented exactly once.
      const targets = events.map(e => e.target).sort();
      expect(targets).toEqual(
        Array.from({ length: N }, (_u, i) => `child-${i}`).sort(),
      );

      // A lock left on disk blocks every later writer for STALE_MS.
      const leftover = fs.readdirSync(shieldDir).filter(f => f.endsWith('.lock'));
      expect(leftover).toEqual([]);
    }, 60_000);
  }

  it('rotates an oversized log only while holding the lock', async () => {
    // Rotation renames events.jsonl out from under anyone who has already
    // read their prevHash from it, so it belongs inside the same critical
    // section as the append rather than in front of it.
    const home = makeHome();
    const shieldDir = path.join(home, '.opena2a', 'shield');
    fs.mkdirSync(shieldDir, { recursive: true });
    const logPath = path.join(shieldDir, 'events.jsonl');
    // Sparse: the size is what rotation reads, and 10MB of real bytes is a
    // pointless write.
    fs.writeFileSync(logPath, '');
    fs.truncateSync(logPath, MAX_EVENTS_FILE_SIZE + 1);

    const startAt = Date.now() + START_DELAY_MS;
    const child = spawnChild(home, startAt, 0);

    // Hold the lock across the instant the child tries to write, and look at
    // the log from inside the critical section.
    let sizeWhileHeld = -1;
    withEventLock(getEventLockPath(logPath), () => {
      sleepUntil(startAt + 400);
      sizeWhileHeld = fs.existsSync(logPath) ? fs.statSync(logPath).size : -1;
    });

    await child;

    // The child must not have rotated while we held the lock.
    expect(sizeWhileHeld).toBe(MAX_EVENTS_FILE_SIZE + 1);

    // Once released, it rotates once and appends to the fresh file.
    const rotated = fs.readdirSync(shieldDir).filter(f => /^events-.+\.jsonl$/.test(f));
    expect(rotated.length).toBe(1);

    const { lines } = readLog(home);
    expect(lines.length).toBe(1);
    expect(verifyEventChain(lines.map(l => JSON.parse(l)))).toEqual({
      valid: true,
      brokenAt: null,
    });
  }, 60_000);
});

describe('event lock', () => {
  it('times out later than it declares a lock stale', () => {
    // If TIMEOUT_MS <= STALE_MS a waiter always gives up before the age rule
    // can fire, so an abandoned lock is never taken over and every writer
    // fails open forever.
    expect(TIMEOUT_MS).toBeGreaterThan(STALE_MS);
  });

  it('derives the lock path from the events path', () => {
    expect(getEventLockPath('/tmp/x/shield/events.jsonl')).toBe('/tmp/x/shield/events.lock');
  });

  it('releases the lock when the critical section throws', () => {
    const home = makeHome();
    const lockPath = path.join(home, 'events.lock');

    expect(() => withEventLock(lockPath, () => { throw new Error('boom'); })).toThrow('boom');
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  it('takes over a lock whose recorded pid is dead on this host', () => {
    const home = makeHome();
    const lockPath = path.join(home, 'events.lock');
    // pid 2^22 is above the default pid_max on macOS and Linux, so it cannot
    // be a live process here.
    fs.writeFileSync(
      lockPath,
      JSON.stringify({ pid: 4_194_304, host: os.hostname(), at: Date.now() }),
    );

    const startedAt = Date.now();
    const ran = withEventLock(lockPath, () => 'ok');

    expect(ran).toBe('ok');
    // Taken over on the pid rule, not by waiting out STALE_MS.
    expect(Date.now() - startedAt).toBeLessThan(STALE_MS);
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  it('takes over a lock older than STALE_MS whose holder is unidentifiable', () => {
    const home = makeHome();
    const lockPath = path.join(home, 'events.lock');
    fs.writeFileSync(lockPath, 'not json');
    const old = Date.now() - (STALE_MS + 1_000);
    fs.utimesSync(lockPath, old / 1000, old / 1000);

    expect(withEventLock(lockPath, () => 'ok')).toBe('ok');
    expect(fs.existsSync(lockPath)).toBe(false);
  });

  it('waits out a live holder, then takes over on the age rule', () => {
    const home = makeHome();
    const lockPath = path.join(home, 'events.lock');
    // Held by this process, so the pid rule cannot fire and only age can.
    fs.writeFileSync(
      lockPath,
      JSON.stringify({ pid: process.pid, host: os.hostname(), at: Date.now() }),
    );

    // Same code path as production, scaled down; the production constants are
    // covered by the invariant assertion above.
    const timing = { staleMs: 120, timeoutMs: 600 };
    const startedAt = Date.now();
    expect(withEventLock(lockPath, () => 'ok', timing)).toBe('ok');
    const waited = Date.now() - startedAt;

    // The holder's window is respected...
    expect(waited).toBeGreaterThanOrEqual(timing.staleMs);
    // ...and the takeover happens before the waiter gives up, which is the
    // whole point of timeoutMs > staleMs. With the inequality reversed the
    // waiter fails open here instead of acquiring.
    expect(waited).toBeLessThan(timing.timeoutMs);
    expect(fs.existsSync(lockPath)).toBe(false);
  }, 30_000);

  it('does not release a lock that was taken over while it was held', () => {
    const home = makeHome();
    const lockPath = path.join(home, 'events.lock');

    withEventLock(lockPath, () => {
      // Our critical section outlived staleMs and someone else took over.
      fs.writeFileSync(
        lockPath,
        JSON.stringify({ pid: process.pid + 1, host: os.hostname(), at: Date.now() }),
      );
    });

    // Releasing unconditionally here would unlock the new holder's section.
    expect(fs.existsSync(lockPath)).toBe(true);
    expect(JSON.parse(fs.readFileSync(lockPath, 'utf-8')).pid).toBe(process.pid + 1);
  });

  it('fails open with an attributable diagnostic when the lock cannot be created', () => {
    // Shield directory gone: the lock cannot be created at all.  Losing a
    // security event is worse than a forked chain, so the write proceeds --
    // but it must say so.
    const lockPath = path.join(makeHome(), 'missing-dir', 'events.lock');

    const warnings = captureStderr(() => {
      expect(withEventLock(lockPath, () => 'ok')).toBe('ok');
    });

    expect(warnings).toContain('lock-timeout');
    expect(warnings).toContain(lockPath);
  });

  it('fails open on a genuine timeout, naming the holder it waited on', () => {
    if (typeof process.getuid === 'function' && process.getuid() === 0) return; // root ignores mode bits

    const home = makeHome();
    const lockPath = path.join(home, 'events.lock');
    // Stale by age, but in a directory that forbids unlinking it, so the
    // takeover fails and the waiter runs out the clock.
    const timing = { staleMs: 60, timeoutMs: 300 };
    const holderPid = 4_194_304;
    fs.writeFileSync(
      lockPath,
      JSON.stringify({ pid: holderPid, host: 'some-other-host', at: Date.now() - 5_000 }),
    );
    fs.chmodSync(home, 0o500);

    let warnings = '';
    const startedAt = Date.now();
    try {
      warnings = captureStderr(() => {
        expect(withEventLock(lockPath, () => 'ok', timing)).toBe('ok');
      });
    } finally {
      fs.chmodSync(home, 0o700);
    }

    expect(Date.now() - startedAt).toBeGreaterThanOrEqual(timing.timeoutMs);
    expect(warnings).toContain('lock-timeout (timeout)');
    expect(warnings).toContain(String(holderPid));
    // A waiter that never acquired must not delete the holder's lock.
    expect(fs.existsSync(lockPath)).toBe(true);
  }, 30_000);
});

function captureStderr(fn: () => void): string {
  const chunks: string[] = [];
  const real = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: unknown) => {
    chunks.push(String(chunk));
    return true;
  }) as typeof process.stderr.write;
  try {
    fn();
  } finally {
    process.stderr.write = real;
  }
  return chunks.join('');
}
