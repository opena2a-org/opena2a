import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { ContributionEvent, ContributionBatch } from './types.js';
import { getContributorToken } from './contributor.js';

const QUEUE_PATH = join(homedir(), '.opena2a', 'contribute-queue.json');
const FLUSH_THRESHOLD = 10;
const MAX_QUEUE_SIZE = 100;

export const DEFAULT_REGISTRY_URL = 'https://api.oa2a.org';

/**
 * One queued event and the Registry it is meant for. The queue file is
 * shared by every tool on the machine, and tools point at different
 * Registries, so an event carries its own destination: a flush sends only
 * the events recorded for the Registry it submits to. The `registry` field
 * is stripped before an event leaves the machine.
 */
interface QueuedEvent extends ContributionEvent {
  registry: string;
}

interface QueueFile {
  events: QueuedEvent[];
  lastFlushAttempt?: string;
}

/** The form a Registry URL is recorded and compared in. */
export function normalizeRegistryUrl(registryUrl?: string): string {
  return (registryUrl || DEFAULT_REGISTRY_URL).replace(/\/+$/, '');
}

function strip(entry: QueuedEvent): ContributionEvent {
  const event: Partial<QueuedEvent> = { ...entry };
  delete event.registry;
  return event as ContributionEvent;
}

/** Queue an event for `registryUrl` (the default Registry when omitted). */
export function queueEvent(event: ContributionEvent, registryUrl?: string): void {
  const queue = loadQueue();
  queue.events.push({ ...event, registry: normalizeRegistryUrl(registryUrl) });

  if (queue.events.length > MAX_QUEUE_SIZE) {
    queue.events = queue.events.slice(-MAX_QUEUE_SIZE);
  }

  saveQueue(queue);
}

/**
 * The queued events. With `registryUrl`, only those recorded for that
 * Registry; without it, every queued event.
 */
export function getQueuedEvents(registryUrl?: string): ContributionEvent[] {
  const events = loadQueue().events;
  if (registryUrl === undefined) return events.map(strip);
  const registry = normalizeRegistryUrl(registryUrl);
  return events.filter((e) => e.registry === registry).map(strip);
}

/**
 * Clear the queue. With `registryUrl`, only the events recorded for that
 * Registry are removed; without it, the whole queue.
 */
export function clearQueue(registryUrl?: string): void {
  if (registryUrl === undefined) {
    saveQueue({ events: [] });
    return;
  }
  const registry = normalizeRegistryUrl(registryUrl);
  const queue = loadQueue();
  queue.events = queue.events.filter((e) => e.registry !== registry);
  saveQueue(queue);
}

/**
 * Remove the given events (as sent to `registryUrl`) from the queue, leaving
 * anything queued since the batch was built and every other Registry's events.
 */
export function removeSentEvents(sent: ContributionEvent[], registryUrl?: string): void {
  const registry = normalizeRegistryUrl(registryUrl);
  const pending = new Map<string, number>();
  for (const event of sent) {
    const key = JSON.stringify(event);
    pending.set(key, (pending.get(key) ?? 0) + 1);
  }
  const queue = loadQueue();
  queue.events = queue.events.filter((entry) => {
    if (entry.registry !== registry) return true;
    const key = JSON.stringify(strip(entry));
    const left = pending.get(key) ?? 0;
    if (left === 0) return true;
    pending.set(key, left - 1);
    return false;
  });
  saveQueue(queue);
}

/** Whether the events queued for `registryUrl` have reached the flush threshold. */
export function shouldFlush(registryUrl?: string): boolean {
  return getQueuedEvents(normalizeRegistryUrl(registryUrl)).length >= FLUSH_THRESHOLD;
}

/**
 * Build a batch of the events queued for `registryUrl` (the default Registry
 * when omitted); `null` when none are queued for it.
 */
export function buildBatch(registryUrl?: string): ContributionBatch | null {
  const events = getQueuedEvents(normalizeRegistryUrl(registryUrl));
  if (events.length === 0) return null;

  return {
    contributorToken: getContributorToken(),
    events,
    submittedAt: new Date().toISOString(),
  };
}

/**
 * Read the queue. Events with no recorded Registry were queued by an older
 * version that did not record one: their destination is unknown, so they are
 * dropped rather than sent to whichever Registry flushes next.
 */
function loadQueue(): QueueFile {
  if (!existsSync(QUEUE_PATH)) return { events: [] };
  try {
    const parsed = JSON.parse(readFileSync(QUEUE_PATH, 'utf-8')) as { events?: unknown };
    const events = Array.isArray(parsed.events) ? parsed.events : [];
    return {
      events: events.filter(
        (e): e is QueuedEvent =>
          typeof e === 'object' && e !== null && typeof (e as QueuedEvent).registry === 'string' &&
          (e as QueuedEvent).registry !== '',
      ),
    };
  } catch {
    return { events: [] };
  }
}

function saveQueue(queue: QueueFile): void {
  const dir = join(homedir(), '.opena2a');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(QUEUE_PATH, JSON.stringify(queue), { mode: 0o600 });
}
