import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';

export interface ScanEntry {
  timestamp: string;
  command: string;
  target: string;
  findings: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  duration: number;
  contributed: boolean;
}

export interface ScanHistory {
  version: 1;
  entries: ScanEntry[];
}

const MAX_ENTRIES = 100;

function getHistoryPath(): string {
  return join(homedir(), '.opena2a', 'history.json');
}

export function loadScanHistory(): ScanHistory {
  const historyPath = getHistoryPath();
  try {
    const raw = readFileSync(historyPath, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return { version: 1, entries: [] };
  }
}

export function appendScanEntry(entry: ScanEntry): void {
  const history = loadScanHistory();
  history.entries.push(entry);

  // Keep only the most recent entries
  if (history.entries.length > MAX_ENTRIES) {
    history.entries = history.entries.slice(-MAX_ENTRIES);
  }

  const historyPath = getHistoryPath();
  const historyDir = dirname(historyPath);

  if (!existsSync(historyDir)) {
    mkdirSync(historyDir, { recursive: true, mode: 0o700 });
  }

  writeFileSync(historyPath, JSON.stringify(history, null, 2) + '\n', {
    mode: 0o600,
  });
}

export function getLastScan(): ScanEntry | null {
  const history = loadScanHistory();
  return history.entries.length > 0
    ? history.entries[history.entries.length - 1]
    : null;
}

export function getRecentScans(count: number = 10): ScanEntry[] {
  const history = loadScanHistory();
  return history.entries.slice(-count);
}
