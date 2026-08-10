/**
 * Cross-process advisory lock for the Shield event log.
 *
 * `writeEvent` is read-last-line -> compute prevHash -> append.  Without a
 * lock, two processes that interleave inside that sequence read the same
 * prevHash and append two events claiming the same predecessor: the chain
 * forks, permanently.  Nothing malicious is required -- a shell preexec hook
 * firing while `opena2a` runs, a git hook racing a CI step, or two terminals
 * is enough.  Since the log is now hash-chain verified on read, such a fork
 * is no longer cosmetic: every event after it is excluded as untrusted.
 *
 * The lock is a lockfile created with `O_EXCL`, which is atomic on local
 * filesystems.  It is NOT reliable on NFS, where the exclusive-create
 * guarantee depends on server and client implementation; on a network-mounted
 * home directory this degrades to the age-based stale rule below, which
 * bounds the damage rather than preventing it.
 *
 * `writeEvent` is synchronous and is called from synchronous paths, so the
 * wait has to be synchronous too.  `Atomics.wait` on a `SharedArrayBuffer`
 * parks the thread for a bounded interval without a busy loop; `setTimeout`
 * is unavailable and spinning would burn the CPU it is waiting on.
 */

import { hostname } from 'node:os';
import { readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';

/**
 * A lock older than this is treated as abandoned.  Covers the case where the
 * holder died without running its `finally` (SIGKILL, power loss) on a host
 * where the pid check cannot help -- a foreign host, or a recycled pid.
 */
export const STALE_MS = 5_000;

/**
 * How long a waiter blocks before giving up and writing anyway.
 *
 * MUST exceed STALE_MS: the age rule has to be reachable while a caller is
 * still waiting, otherwise an abandoned lock outlives every waiter and the
 * log stops accepting events until someone deletes the file by hand.
 */
export const TIMEOUT_MS = 6_000;

/** Interval between acquisition attempts. */
const RETRY_MS = 15;

/** Backing store for the synchronous sleep.  Never written; only waited on. */
const SLEEP_SLOT = new Int32Array(new SharedArrayBuffer(4));

/** Block this thread for `ms`, without a busy loop. */
function sleepSync(ms: number): void {
  // Value 0 always matches, so this always waits out the full timeout.
  Atomics.wait(SLEEP_SLOT, 0, 0, ms);
}

interface LockRecord {
  pid: number;
  host: string;
  at: number;
}

/**
 * Timing overrides.  Production callers use the module constants; tests
 * exercise the same code paths at millisecond scale instead of parking a
 * suite for STALE_MS + TIMEOUT_MS of real time.
 */
export interface EventLockOptions {
  staleMs?: number;
  timeoutMs?: number;
}

/** `.../events.jsonl` -> `.../events.lock` */
export function getEventLockPath(eventsPath: string): string {
  return eventsPath.replace(/\.jsonl$/, '') + '.lock';
}

function readLock(lockPath: string): LockRecord | null {
  try {
    const parsed: unknown = JSON.parse(readFileSync(lockPath, 'utf-8'));
    if (parsed === null || typeof parsed !== 'object') return null;
    const record = parsed as Partial<LockRecord>;
    if (typeof record.pid !== 'number' || typeof record.host !== 'string') return null;
    return { pid: record.pid, host: record.host, at: typeof record.at === 'number' ? record.at : 0 };
  } catch {
    // Missing, truncated, or written by a process that died mid-write.
    return null;
  }
}

/** Age of the lock file on disk, or Infinity when it cannot be stat'd. */
function lockAgeMs(lockPath: string): number {
  try {
    return Date.now() - statSync(lockPath).mtimeMs;
  } catch {
    return Infinity;
  }
}

/**
 * True when the lock may be taken over: the recorded pid is gone on this
 * host, or the lock is older than STALE_MS.
 *
 * The pid check only applies to locks recorded by this host -- a pid from
 * another machine says nothing about a local process, so those fall through
 * to the age rule.
 */
function isStale(lockPath: string, record: LockRecord | null, staleMs: number): boolean {
  if (record === null) {
    // Unreadable content: only the age rule can speak to it.  A lock being
    // written right now is milliseconds old and is left alone.
    return lockAgeMs(lockPath) > staleMs;
  }

  if (record.host === hostname() && !processAlive(record.pid)) return true;

  // Prefer the recorded acquisition time; fall back to the file's mtime when
  // the record predates that field or carries a nonsense value.
  const age = record.at > 0 ? Date.now() - record.at : lockAgeMs(lockPath);
  return age > staleMs;
}

function processAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM means the process exists but belongs to another user.
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/**
 * Run `fn` while holding the event-log lock.
 *
 * On genuine timeout the lock is NOT acquired and `fn` still runs: losing a
 * security event is worse than a forked chain, and losing it silently is
 * worse than either, so the fallback is announced on stderr with the holder
 * named.  The lock is released in `finally`, and only if it is still ours --
 * a lock we already lost to a stale takeover belongs to its new holder.
 */
export function withEventLock<T>(
  lockPath: string,
  fn: () => T,
  options: EventLockOptions = {},
): T {
  const self: LockRecord = { pid: process.pid, host: hostname(), at: Date.now() };
  const acquired = acquire(lockPath, self, options);

  try {
    return fn();
  } finally {
    if (acquired) release(lockPath, self);
  }
}

function acquire(lockPath: string, self: LockRecord, options: EventLockOptions): boolean {
  const staleMs = options.staleMs ?? STALE_MS;
  const timeoutMs = options.timeoutMs ?? TIMEOUT_MS;
  const retryMs = Math.max(1, Math.min(RETRY_MS, Math.floor(staleMs / 4)));
  const startedAt = Date.now();
  const deadline = startedAt + timeoutMs;

  for (;;) {
    self.at = Date.now();
    try {
      writeFileSync(lockPath, JSON.stringify(self), { flag: 'wx', mode: 0o600 });
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') {
        // An unwritable shield directory is not a lock conflict.  Report it
        // the same way a timeout is reported and let the caller write: the
        // append itself will fail loudly if the directory is truly broken.
        warnLockFailure(lockPath, null, Date.now() - startedAt,
          (err as NodeJS.ErrnoException).code ?? 'unknown');
        return false;
      }

      const holder = readLock(lockPath);

      if (isStale(lockPath, holder, staleMs)) {
        // Remove and retry.  Two processes may both reach this point; the
        // exclusive create on the next pass decides which one wins.
        try {
          rmSync(lockPath, { force: true });
        } catch {
          // Someone else already removed it; the retry settles ownership.
        }
      }

      if (Date.now() >= deadline) {
        warnLockFailure(lockPath, holder, Date.now() - startedAt, 'timeout');
        return false;
      }

      // Sleep on every pass, including after a takeover: a lock we cannot
      // remove would otherwise spin this thread hot until the deadline.
      sleepSync(retryMs);
    }
  }
}

function release(lockPath: string, self: LockRecord): void {
  const holder = readLock(lockPath);
  if (holder !== null && (holder.pid !== self.pid || holder.host !== self.host)) {
    // Taken over while we held it (we ran longer than STALE_MS).  Deleting
    // it now would unlock the new holder's critical section.
    return;
  }
  try {
    rmSync(lockPath, { force: true });
  } catch {
    // Already gone.
  }
}

/**
 * Announce a fail-open write.  Attributable on purpose: without the holder's
 * pid and host, a forked chain days later has no explanation.
 */
function warnLockFailure(
  lockPath: string,
  holder: LockRecord | null,
  waitedMs: number,
  reason: string,
): void {
  const held = holder ? `pid ${holder.pid} on ${holder.host}` : 'unknown holder';
  process.stderr.write(
    `shield: lock-timeout (${reason}) after ${waitedMs}ms waiting on ${lockPath} ` +
    `(held by ${held}); writing the event without the lock -- the hash chain may fork.\n`,
  );
}
