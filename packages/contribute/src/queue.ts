import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { ContributionEvent, ContributionBatch } from './types.js';
import { getContributorToken } from './contributor.js';

const QUEUE_PATH = join(homedir(), '.opena2a', 'contribute-queue.json');
const FLUSH_THRESHOLD = 10;
const MAX_QUEUE_SIZE = 100;

interface QueueFile {
  events: ContributionEvent[];
  lastFlushAttempt?: string;
}

export function queueEvent(event: ContributionEvent): void {
  const queue = loadQueue();
  queue.events.push(event);

  if (queue.events.length > MAX_QUEUE_SIZE) {
    queue.events = queue.events.slice(-MAX_QUEUE_SIZE);
  }

  saveQueue(queue);
}

export function getQueuedEvents(): ContributionEvent[] {
  return loadQueue().events;
}

export function clearQueue(): void {
  saveQueue({ events: [] });
}

export function shouldFlush(): boolean {
  const queue = loadQueue();
  return queue.events.length >= FLUSH_THRESHOLD;
}

export function buildBatch(): ContributionBatch | null {
  const events = getQueuedEvents();
  if (events.length === 0) return null;

  return {
    contributorToken: getContributorToken(),
    events,
    submittedAt: new Date().toISOString(),
  };
}

function loadQueue(): QueueFile {
  if (!existsSync(QUEUE_PATH)) return { events: [] };
  try {
    return JSON.parse(readFileSync(QUEUE_PATH, 'utf-8'));
  } catch {
    return { events: [] };
  }
}

function saveQueue(queue: QueueFile): void {
  const dir = join(homedir(), '.opena2a');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(QUEUE_PATH, JSON.stringify(queue), { mode: 0o600 });
}
