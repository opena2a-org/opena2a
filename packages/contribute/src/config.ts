/**
 * Minimal config reader for the contribute package.
 * Reads ~/.opena2a/config.json without depending on @opena2a/shared,
 * keeping this package zero-dependency and small (~2KB).
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const CONFIG_PATH = join(homedir(), '.opena2a', 'config.json');

interface MinimalConfig {
  contribute?: { enabled?: boolean };
}

/**
 * Returns true if the user has opted into community contributions.
 * Default: false. Reads from ~/.opena2a/config.json.
 */
export function isContributeEnabled(): boolean {
  if (!existsSync(CONFIG_PATH)) return false;
  try {
    const raw: MinimalConfig = JSON.parse(readFileSync(CONFIG_PATH, 'utf-8'));
    return raw.contribute?.enabled === true;
  } catch {
    return false;
  }
}
