/**
 * HackMyAgent check counts, read from the engine itself.
 *
 * Help text, the guided wizard, the natural-language fallback and `init`
 * quote how many checks `opena2a scan secure` runs. That number used to be a
 * literal here (209), and the README carried another (204), while the engine
 * reported `310 static` in a scan. Reading HMA's own `getCheckCounts()` keeps
 * every quote equal to what a scan prints; the README is held to the same
 * number by `__tests__/util/hma-checks.test.ts`.
 *
 * `getCheckCounts()` lives in `hardening/taxonomy.js`, which HMA does not list
 * in its package `exports`, so the module is resolved by path from the
 * package's main entry. It is a self-contained file with no imports, so
 * loading it does not pull in the scanner.
 */

import { dirname, join } from 'node:path';

export interface HmaCheckCounts {
  /** Every check in the taxonomy, static and semantic. */
  total: number;
  /** Static rule checks: the number a scan reports as `N static`. */
  static: number;
  /** NanoMind semantic (AST) checks. */
  semantic: number;
  totalCategories: number;
  staticCategories: number;
}

let cached: HmaCheckCounts | null | undefined;

function isCounts(value: unknown): value is HmaCheckCounts {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return ['total', 'static', 'semantic', 'totalCategories', 'staticCategories']
    .every(k => typeof v[k] === 'number' && Number.isInteger(v[k]) && (v[k] as number) >= 0)
    && (v.static as number) > 0;
}

/**
 * The installed engine's check counts, or null when HackMyAgent cannot be
 * loaded or does not expose them. Read once per process.
 */
export function hmaCheckCounts(): HmaCheckCounts | null {
  if (cached !== undefined) return cached;
  cached = null;
  try {
    const entry = require.resolve('hackmyagent', { paths: [__dirname] });
    const taxonomy = require(join(dirname(entry), 'hardening', 'taxonomy.js')) as {
      getCheckCounts?: () => unknown;
    };
    if (typeof taxonomy.getCheckCounts === 'function') {
      const counts = taxonomy.getCheckCounts();
      if (isCounts(counts)) cached = counts;
    }
  } catch {
    // HackMyAgent missing or laid out differently: callers drop the number.
  }
  return cached;
}

/**
 * The number of checks `opena2a scan secure` runs, as the engine reports it
 * in a scan (`N static`), or null when it cannot be read.
 */
export function hmaCheckCount(): number | null {
  return hmaCheckCounts()?.static ?? null;
}

/**
 * `"<count> <noun>"`, or just `"<noun>"` when the count cannot be read, so
 * copy never shows a number the engine did not report.
 */
export function hmaChecksPhrase(noun = 'checks'): string {
  const count = hmaCheckCount();
  return count === null ? noun : `${count} ${noun}`;
}
