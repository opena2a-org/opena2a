import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The `name` field of `package.json` in `dir`, or null when there is no
 * package.json, it cannot be read or parsed, or it names no package.
 * `opena2a publish` with no argument checks the package it is run in.
 */
export function readLocalPackageName(dir: string = process.cwd()): string | null {
  try {
    const pkg: unknown = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf-8'));
    if (pkg && typeof pkg === 'object' && !Array.isArray(pkg)) {
      const name = (pkg as { name?: unknown }).name;
      if (typeof name === 'string' && name.trim() !== '') return name.trim();
    }
  } catch { /* no readable package.json */ }
  return null;
}
