/**
 * ConfigGuard Snapshots -- timestamped snapshots of signature state for rollback.
 *
 * Stores snapshots in .opena2a/guard/snapshots/ as ISO-timestamped JSON files.
 * Supports create, list, restore, and automatic pruning at 20 snapshots.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

// --- Types ---

export interface SnapshotInfo {
  id: string;
  createdAt: string;
  fileCount: number;
  path: string;
}

export interface SnapshotResult {
  id: string;
  path: string;
  fileCount: number;
}

export interface RestoreResult {
  restored: boolean;
  fileCount: number;
  previousId: string | null;
}

// --- Constants ---

const STORE_DIR = '.opena2a/guard';
const STORE_FILE = 'signatures.json';
const SNAPSHOTS_DIR = '.opena2a/guard/snapshots';
const MAX_SNAPSHOTS = 20;

// --- Core ---

function createSnapshot(targetDir: string): SnapshotResult {
  const storePath = path.join(targetDir, STORE_DIR, STORE_FILE);
  if (!fs.existsSync(storePath)) {
    throw new Error('No signature store found. Run: opena2a guard sign');
  }

  const storeContent = fs.readFileSync(storePath, 'utf-8');
  const store = JSON.parse(storeContent);

  const now = new Date();
  const id = now.toISOString().replace(/:/g, '-').replace(/\.\d+Z$/, 'Z');
  const snapshotsDir = path.join(targetDir, SNAPSHOTS_DIR);
  fs.mkdirSync(snapshotsDir, { recursive: true });

  const snapshotPath = path.join(snapshotsDir, `${id}.json`);
  fs.writeFileSync(snapshotPath, storeContent, 'utf-8');

  pruneSnapshots(snapshotsDir);

  return {
    id,
    path: snapshotPath,
    fileCount: store.signatures?.length ?? 0,
  };
}

function listSnapshots(targetDir: string): SnapshotInfo[] {
  const snapshotsDir = path.join(targetDir, SNAPSHOTS_DIR);
  if (!fs.existsSync(snapshotsDir)) return [];

  const entries = fs.readdirSync(snapshotsDir).filter(f => f.endsWith('.json'));
  const snapshots: SnapshotInfo[] = [];

  for (const entry of entries) {
    const fullPath = path.join(snapshotsDir, entry);
    try {
      const content = fs.readFileSync(fullPath, 'utf-8');
      const store = JSON.parse(content);
      const id = entry.replace(/\.json$/, '');
      // Reconstruct ISO date from ID: 2026-03-03T01-12-55Z -> 2026-03-03T01:12:55.000Z
      const createdAt = id.replace(/-(?=\d{2}-\d{2}Z)/g, ':').replace(/-(?=\d{2}Z)/g, ':').replace(/Z$/, '.000Z');
      snapshots.push({
        id,
        createdAt,
        fileCount: store.signatures?.length ?? 0,
        path: fullPath,
      });
    } catch {
      // Skip corrupt snapshot files
    }
  }

  // Sort newest first
  snapshots.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  return snapshots;
}

function restoreSnapshot(targetDir: string, snapshotId: string): RestoreResult {
  const snapshotsDir = path.join(targetDir, SNAPSHOTS_DIR);
  const snapshotPath = path.join(snapshotsDir, `${snapshotId}.json`);

  if (!fs.existsSync(snapshotPath)) {
    throw new Error(`Snapshot not found: ${snapshotId}`);
  }

  const storePath = path.join(targetDir, STORE_DIR, STORE_FILE);

  // Track previous snapshot ID if there is an existing store
  let previousId: string | null = null;
  if (fs.existsSync(storePath)) {
    try {
      // Create a safety snapshot of current state before restoring
      const safetyResult = createSnapshot(targetDir);
      previousId = safetyResult.id;
    } catch {
      // No current store to snapshot -- that is fine
    }
  }

  const snapshotContent = fs.readFileSync(snapshotPath, 'utf-8');
  const store = JSON.parse(snapshotContent);

  fs.mkdirSync(path.join(targetDir, STORE_DIR), { recursive: true });
  fs.writeFileSync(storePath, snapshotContent, 'utf-8');

  return {
    restored: true,
    fileCount: store.signatures?.length ?? 0,
    previousId,
  };
}

// --- Pruning ---

function pruneSnapshots(snapshotsDir: string): void {
  const entries = fs.readdirSync(snapshotsDir)
    .filter(f => f.endsWith('.json'))
    .sort();

  if (entries.length <= MAX_SNAPSHOTS) return;

  const toRemove = entries.slice(0, entries.length - MAX_SNAPSHOTS);
  for (const entry of toRemove) {
    try {
      fs.unlinkSync(path.join(snapshotsDir, entry));
    } catch {
      // Best-effort pruning
    }
  }
}

// --- CLI entry points (called from guard.ts switch) ---

export async function guardResign(targetDir: string, options: { format?: string }): Promise<number> {
  const isJson = options.format === 'json';
  try {
    const snap = createSnapshot(targetDir);
    if (!isJson) process.stdout.write(`Snapshot created: ${snap.id}\n`);
  } catch { /* no existing store */ }
  if (isJson) { process.stdout.write(JSON.stringify({ action: 'resign', snapshot: true }, null, 2) + '\n'); }
  else { process.stdout.write('Re-sign by running: opena2a guard sign\n'); }
  return 0;
}

export async function guardSnapshot(targetDir: string, options: { format?: string; args?: string[] }): Promise<number> {
  const isJson = options.format === 'json';
  const action = options.args?.[0] ?? 'list';
  if (action === 'create') {
    try {
      const result = createSnapshot(targetDir);
      if (isJson) { process.stdout.write(JSON.stringify(result, null, 2) + '\n'); }
      else { process.stdout.write(`Snapshot created: ${result.id} (${result.fileCount} files)\n`); }
      return 0;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (isJson) { process.stdout.write(JSON.stringify({ error: msg }, null, 2) + '\n'); }
      else { process.stderr.write(`Error: ${msg}\n`); }
      return 1;
    }
  }
  if (action === 'list') {
    const snapshots = listSnapshots(targetDir);
    if (isJson) { process.stdout.write(JSON.stringify(snapshots, null, 2) + '\n'); }
    else if (snapshots.length === 0) { process.stdout.write('No snapshots found.\n'); }
    else { for (const s of snapshots) { process.stdout.write(`  ${s.id}  (${s.fileCount} files)\n`); } }
    return 0;
  }
  if (action === 'restore') {
    const id = options.args?.[1];
    if (!id) { process.stderr.write('Usage: opena2a guard snapshot restore <id>\n'); return 1; }
    try {
      const result = restoreSnapshot(targetDir, id);
      if (isJson) { process.stdout.write(JSON.stringify(result, null, 2) + '\n'); }
      else { process.stdout.write(`Restored snapshot: ${id} (${result.fileCount} files)\n`); }
      return 0;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`Error: ${msg}\n`);
      return 1;
    }
  }
  process.stderr.write(`Unknown snapshot action: ${action}\n`);
  return 1;
}

// --- Testable internals ---

export const _internals = {
  createSnapshot, listSnapshots, restoreSnapshot, pruneSnapshots,
  guardResign, guardSnapshot,
  STORE_DIR, STORE_FILE, SNAPSHOTS_DIR, MAX_SNAPSHOTS,
};
