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
    throw new Error(`Snapshot not found: ${snapshotId}. List available: opena2a guard snapshot list`);
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

interface ResignOptions {
  format?: string;
  ci?: boolean;
  verbose?: boolean;
}

export async function guardResign(targetDir: string, options: ResignOptions): Promise<number> {
  const isJson = options.format === 'json';
  const isCi = options.ci ?? false;

  // Load store
  const storePath = path.join(targetDir, STORE_DIR, STORE_FILE);
  if (!fs.existsSync(storePath)) {
    if (isJson) { process.stdout.write(JSON.stringify({ error: 'No signature store found. Run: opena2a guard sign' }, null, 2) + '\n'); }
    else { process.stderr.write('No signature store found. Run: opena2a guard sign\n'); }
    return 1;
  }

  const store = JSON.parse(fs.readFileSync(storePath, 'utf-8'));
  const { createHash } = await import('node:crypto');
  const os = await import('node:os');

  // Find tampered files
  interface TamperedEntry { filePath: string; sizeChange: number; sigIndex: number; }
  const tampered: TamperedEntry[] = [];
  for (let i = 0; i < store.signatures.length; i++) {
    const sig = store.signatures[i];
    const fullPath = path.join(targetDir, sig.filePath);
    if (!fs.existsSync(fullPath)) continue;
    const content = fs.readFileSync(fullPath);
    const currentHash = 'sha256:' + createHash('sha256').update(content).digest('hex');
    if (currentHash !== sig.hash) {
      tampered.push({ filePath: sig.filePath, sizeChange: content.length - sig.fileSize, sigIndex: i });
    }
  }

  if (tampered.length === 0) {
    if (isJson) { process.stdout.write(JSON.stringify({ resigned: 0, files: [] }, null, 2) + '\n'); }
    else { process.stdout.write('All signed files are up to date. Nothing to re-sign.\n'); }
    return 0;
  }

  // Show changes
  if (!isJson) {
    process.stdout.write(`Found ${tampered.length} modified file${tampered.length === 1 ? '' : 's'}:\n`);
    for (const entry of tampered) {
      const sign = entry.sizeChange > 0 ? '+' : '';
      const sizeInfo = entry.sizeChange !== 0 ? ` (${sign}${entry.sizeChange}b)` : '';
      process.stdout.write(`  CHANGED ${entry.filePath}${sizeInfo}\n`);
    }
  }

  // Confirm in interactive mode
  if (!isCi && !isJson) {
    const confirmed = await confirmAction();
    if (!confirmed) {
      process.stdout.write('Re-sign cancelled.\n');
      return 1;
    }
  }

  // Create safety snapshot before re-signing
  try {
    const snapshot = createSnapshot(targetDir);
    if (!isJson) { process.stdout.write(`Safety snapshot created: ${snapshot.id}\n`); }
  } catch {
    // Snapshot creation failed -- proceed anyway
  }

  // Re-sign only the changed files
  const now = new Date().toISOString();
  const signedBy = os.userInfo().username + '@opena2a-cli';
  for (const entry of tampered) {
    const fullPath = path.join(targetDir, entry.filePath);
    const content = fs.readFileSync(fullPath);
    const hash = 'sha256:' + createHash('sha256').update(content).digest('hex');
    const stat = fs.statSync(fullPath);
    store.signatures[entry.sigIndex].hash = hash;
    store.signatures[entry.sigIndex].signedAt = now;
    store.signatures[entry.sigIndex].signedBy = signedBy;
    store.signatures[entry.sigIndex].fileSize = stat.size;
  }
  store.updatedAt = now;

  // Write updated store
  fs.mkdirSync(path.join(targetDir, STORE_DIR), { recursive: true });
  fs.writeFileSync(storePath, JSON.stringify(store, null, 2) + '\n', 'utf-8');

  // Emit shield event
  try {
    const { writeEvent } = await import('../shield/events.js');
    writeEvent({
      source: 'configguard', category: 'config.resigned', severity: 'info',
      agent: null, sessionId: null, action: 'guard.resign', target: targetDir,
      outcome: 'allowed', detail: { fileCount: tampered.length, files: tampered.map(t => t.filePath) },
      orgId: null, managed: false, agentId: null,
    });
  } catch { /* Shield module not available */ }

  if (isJson) {
    process.stdout.write(JSON.stringify({ resigned: tampered.length, files: tampered.map(t => t.filePath) }, null, 2) + '\n');
  } else {
    process.stdout.write(`Re-signed ${tampered.length} file${tampered.length === 1 ? '' : 's'}.\n`);
  }
  return 0;
}

function confirmAction(): Promise<boolean> {
  return new Promise((resolve) => {
    process.stdout.write('\nConfirm re-sign? [y/N] ');
    const { createInterface } = require('node:readline') as typeof import('node:readline');
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: false });
    rl.once('line', (answer: string) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y' || answer.trim().toLowerCase() === 'yes');
    });
    rl.once('close', () => resolve(false));
  });
}

interface SnapshotOptions {
  format?: string;
  args?: string[];
  verbose?: boolean;
}

export async function guardSnapshot(targetDir: string, options: SnapshotOptions): Promise<number> {
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
    if (isJson) { process.stdout.write(JSON.stringify({ snapshots }, null, 2) + '\n'); }
    else if (snapshots.length === 0) { process.stdout.write('No snapshots found. Create one: opena2a guard snapshot create\n'); }
    else {
      for (const s of snapshots) { process.stdout.write(`  ${s.id}  (${s.fileCount} files)\n`); }
      process.stdout.write(`Total: ${snapshots.length} snapshot${snapshots.length === 1 ? '' : 's'}\n`);
    }
    return 0;
  }

  if (action === 'restore') {
    const id = options.args?.[1];
    if (!id) {
      if (isJson) { process.stdout.write(JSON.stringify({ error: 'Snapshot ID required. Usage: opena2a guard snapshot restore <id>' }, null, 2) + '\n'); }
      else { process.stderr.write('Snapshot ID required. List available: opena2a guard snapshot list\n'); }
      return 1;
    }
    try {
      const result = restoreSnapshot(targetDir, id);
      if (isJson) { process.stdout.write(JSON.stringify(result, null, 2) + '\n'); }
      else {
        process.stdout.write(`Restored snapshot: ${id} (${result.fileCount} files)\n`);
        if (result.previousId) { process.stdout.write(`Previous state saved as: ${result.previousId}\n`); }
      }
      return 0;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (isJson) { process.stdout.write(JSON.stringify({ error: msg }, null, 2) + '\n'); }
      else { process.stderr.write(`Error: ${msg}\n`); }
      return 1;
    }
  }

  process.stderr.write(`Unknown snapshot action: ${action}\nUsage: opena2a guard snapshot <create|list|restore> [id]\n`);
  return 1;
}

// --- Testable internals ---

export const _internals = {
  createSnapshot, listSnapshots, restoreSnapshot, pruneSnapshots,
  guardResign, guardSnapshot, confirmAction,
  STORE_DIR, STORE_FILE, SNAPSHOTS_DIR, MAX_SNAPSHOTS,
};
