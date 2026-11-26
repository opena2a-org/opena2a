/**
 * The witness a running ARP monitor leaves, and how status reads it.
 *
 * `opena2a runtime start` writes `.opena2a/arp/monitor.pid` (its own pid)
 * once ARP has started, and removes it when it stops. Status reports a
 * monitor only when that file names a process that is alive. An events file
 * alone is a record of the past: it stays behind after the monitor exits.
 */
import { closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, readSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

export const ARP_DIR = join('.opena2a', 'arp');
export const ARP_EVENTS_FILE = join(ARP_DIR, 'events.jsonl');
export const ARP_MONITOR_PID_FILE = join(ARP_DIR, 'monitor.pid');

interface MonitorWitness {
  pid: number;
  startedAt: string;
}

/** Record this process as the running monitor for `targetDir`. Returns the witness path. */
export function writeMonitorWitness(targetDir: string, pid: number = process.pid): string {
  const file = join(targetDir, ARP_MONITOR_PID_FILE);
  mkdirSync(dirname(file), { recursive: true });
  const witness: MonitorWitness = { pid, startedAt: new Date().toISOString() };
  writeFileSync(file, JSON.stringify(witness) + '\n', { mode: 0o644 });
  return file;
}

/** Remove the witness, only if it still names `pid` (another monitor may have replaced it). */
export function removeMonitorWitness(targetDir: string, pid: number = process.pid): void {
  const file = join(targetDir, ARP_MONITOR_PID_FILE);
  if (readWitnessPid(file) === pid) {
    try { rmSync(file, { force: true }); } catch { /* best effort */ }
  }
}

function readWitnessPid(file: string): number | null {
  let raw: string;
  try {
    raw = readFileSync(file, 'utf-8').trim();
  } catch {
    return null;
  }
  let pid: unknown;
  try {
    const parsed: unknown = JSON.parse(raw);
    pid = typeof parsed === 'number' ? parsed
      : typeof parsed === 'object' && parsed !== null ? (parsed as { pid?: unknown }).pid
      : null;
  } catch {
    pid = /^\d+$/.test(raw) ? Number(raw) : null;
  }
  // pid 0 and negative pids address process groups, never a single monitor.
  return typeof pid === 'number' && Number.isInteger(pid) && pid > 0 ? pid : null;
}

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM: the process exists but belongs to another user.
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/** The pid of a live ARP monitor for `targetDir`, or null when none is running. */
export function liveMonitorPid(targetDir: string): number | null {
  const pid = readWitnessPid(join(targetDir, ARP_MONITOR_PID_FILE));
  return pid !== null && processAlive(pid) ? pid : null;
}

const TAIL_BYTES = 64 * 1024;

/**
 * When the last event in an ARP events file was recorded: the last line's
 * `timestamp` (or `ts`/`time`), else the file's modification time. Null when
 * the file cannot be read.
 */
export function lastEventTime(eventsPath: string): Date | null {
  let fd: number;
  try {
    fd = openSync(eventsPath, 'r');
  } catch {
    return null;
  }
  try {
    const size = fstatSync(fd).size;
    const length = Math.min(size, TAIL_BYTES);
    const buf = Buffer.alloc(length);
    readSync(fd, buf, 0, length, size - length);
    const lines = buf.toString('utf-8').split('\n').map(l => l.trim()).filter(Boolean);
    const last = lines[lines.length - 1];
    if (last) {
      try {
        const event: unknown = JSON.parse(last);
        if (typeof event === 'object' && event !== null) {
          const e = event as Record<string, unknown>;
          for (const key of ['timestamp', 'ts', 'time']) {
            const v = e[key];
            if (typeof v === 'string' || typeof v === 'number') {
              const t = new Date(v);
              if (!Number.isNaN(t.getTime())) return t;
            }
          }
        }
      } catch { /* fall through to mtime */ }
    }
  } catch {
    /* fall through to mtime */
  } finally {
    closeSync(fd);
  }
  try {
    return existsSync(eventsPath) ? statSync(eventsPath).mtime : null;
  } catch {
    return null;
  }
}

/** A short age such as `42s`, `5m`, `3h`, `12d` or `6y`. */
export function formatAge(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h`;
  const d = Math.floor(h / 24);
  if (d < 365) return `${d}d`;
  return `${Math.floor(d / 365)}y`;
}
