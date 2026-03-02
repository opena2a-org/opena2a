import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

let cached: string | null = null;

/**
 * Read the CLI version from package.json. Result is cached after first call.
 */
export function getVersion(): string {
  if (cached) return cached;
  try {
    // From dist/util/ or src/util/, walk up to the package root
    const pkgPath = resolve(__dirname, '..', '..', 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    cached = pkg.version ?? '0.0.0';
  } catch {
    cached = '0.0.0';
  }
  return cached!;
}
