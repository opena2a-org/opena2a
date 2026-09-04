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
import {
  appendFileSync,
  mkdirSync,
  readFileSync,
  rmSync,
  rmdirSync,
  statSync,
  writeFileSync,
} from 'node:fs';

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

// ---------------------------------------------------------------------------
// Fork trace instrument (OPA-01).
//
// The event lock has produced forked chains under contention that none of the
// refuted hypotheses explain.  This channel records every operation the lock
// performs against the lock file -- exclusive create, record read, and both
// removals -- tagged with the file's identity (dev+ino) as seen immediately
// before the operation, so a trace read after a fork shows which process
// removed or created which incarnation of the lock file, in which order.
//
// Off unless OPENA2A_SHIELD_LOCK_TRACE holds the trace file path.  With the
// variable unset nothing below runs: no file is written and no output is
// emitted, and the lock's behaviour is untouched either way -- the wrappers
// perform exactly the syscalls the untraced code performed, in the same order.
// ---------------------------------------------------------------------------

/** Environment variable holding the trace file path; tracing is off without it. */
export const LOCK_TRACE_ENV = 'OPENA2A_SHIELD_LOCK_TRACE';

function traceTarget(): string | null {
  const p = process.env[LOCK_TRACE_ENV];
  return p === undefined || p === '' ? null : p;
}

/** dev+ino of the lock path immediately before an operation, or 'absent'. */
function statForTrace(lockPath: string): { dev: number | 'absent'; ino: number | 'absent' } {
  try {
    const s = statSync(lockPath);
    return { dev: s.dev, ino: s.ino };
  } catch {
    return { dev: 'absent', ino: 'absent' };
  }
}

/**
 * Append one trace line under a cross-process mutex, carrying a sequence
 * number that is a strictly increasing total order over every process that
 * appends to the same trace file.
 *
 * The number is assigned at the event from a counter file, not from a clock:
 * two hosts' clocks (and even one host's `process.hrtime` across processes)
 * order nothing.  Assignment and append share one critical section, so line
 * order in the file and sequence order are the same order.  The mutex is a
 * `mkdir` spinlock -- atomic on the same class of filesystems as the lock's
 * own O_EXCL create, and deliberately NOT the event lock itself, which is the
 * subject under observation.
 */
function appendTraceLine(
  target: string,
  op: string,
  before: { dev: number | 'absent'; ino: number | 'absent' },
  outcome: string,
): void {
  const mutexDir = target + '.seqlock';
  const seqFile = target + '.seq';
  let stealAt = Date.now() + 10_000;
  for (;;) {
    try {
      mkdirSync(mutexDir);
      break;
    } catch {
      if (Date.now() > stealAt) {
        // A holder died between mkdir and rmdir.  The instrument must not
        // deadlock the suite it observes; steal and retry.
        try { rmdirSync(mutexDir); } catch { /* already stolen */ }
        stealAt = Date.now() + 10_000;
      }
      sleepSync(1);
    }
  }
  try {
    let seq = 0;
    try {
      seq = Number(readFileSync(seqFile, 'utf-8'));
      if (!Number.isFinite(seq)) seq = 0;
    } catch {
      // First line: counter starts at zero.
    }
    seq += 1;
    writeFileSync(seqFile, String(seq));
    appendFileSync(
      target,
      JSON.stringify({
        seq,
        op,
        dev: before.dev,
        ino: before.ino,
        outcome,
        pid: process.pid,
        host: hostname(),
      }) + '\n',
    );
  } finally {
    try { rmdirSync(mutexDir); } catch { /* nothing to release */ }
  }
}

/** The exclusive create at the heart of the lock, traced when enabled. */
function exclusiveCreate(lockPath: string, payload: string): void {
  const target = traceTarget();
  if (target === null) {
    writeFileSync(lockPath, payload, { flag: 'wx', mode: 0o600 });
    return;
  }
  const before = statForTrace(lockPath);
  try {
    writeFileSync(lockPath, payload, { flag: 'wx', mode: 0o600 });
  } catch (err) {
    appendTraceLine(target, 'create', before, (err as NodeJS.ErrnoException).code ?? 'unknown');
    throw err;
  }
  appendTraceLine(target, 'create', before, 'created');
}

/**
 * Both `rmSync` sites, traced when enabled.  `site` names which one.
 *
 * With `force: true` the call itself cannot distinguish "removed a file" from
 * "nothing was there", so the outcome is read off the stat taken immediately
 * before: a path present before a successful call was removed by it or by a
 * racing process inside the same instant -- exactly the ambiguity the dev+ino
 * pair exists to resolve across lines.
 */
function tracedRmSync(lockPath: string, site: 'rm-stale' | 'rm-release'): void {
  const target = traceTarget();
  if (target === null) {
    rmSync(lockPath, { force: true });
    return;
  }
  const before = statForTrace(lockPath);
  try {
    rmSync(lockPath, { force: true });
  } catch (err) {
    appendTraceLine(target, site, before, (err as NodeJS.ErrnoException).code ?? 'unknown');
    throw err;
  }
  appendTraceLine(target, site, before, before.dev === 'absent' ? 'enoent' : 'removed');
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
  const target = traceTarget();
  const before = target === null ? null : statForTrace(lockPath);
  let record: LockRecord | null = null;
  try {
    const parsed: unknown = JSON.parse(readFileSync(lockPath, 'utf-8'));
    if (parsed !== null && typeof parsed === 'object') {
      const partial = parsed as Partial<LockRecord>;
      if (typeof partial.pid === 'number' && typeof partial.host === 'string') {
        record = {
          pid: partial.pid,
          host: partial.host,
          at: typeof partial.at === 'number' ? partial.at : 0,
        };
      }
    }
  } catch {
    // Missing, truncated, or written by a process that died mid-write.
  }
  if (target !== null && before !== null) {
    appendTraceLine(
      target, 'read', before,
      record === null ? 'null' : `pid=${record.pid} host=${record.host} at=${record.at}`,
    );
  }
  return record;
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
      exclusiveCreate(lockPath, JSON.stringify(self));
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
          tracedRmSync(lockPath, 'rm-stale');
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
    tracedRmSync(lockPath, 'rm-release');
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
