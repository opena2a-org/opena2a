/**
 * Shared CLI footer for all command output.
 * Displays a short attribution line with links.
 * Suppressed when --json or --ci flags are active.
 */

import { cyan } from './colors.js';

/**
 * Print the OpenA2A footer to stdout.
 * Call this after command output completes.
 *
 * @param options.ci   - true when running in CI mode (suppresses footer)
 * @param options.json - true when JSON output is requested (suppresses footer)
 */
export function printFooter(options?: { ci?: boolean; json?: boolean }): void {
  if (options?.ci || options?.json) return;

  process.stdout.write('\n');
  process.stdout.write(cyan('  OpenA2A -- open-source security for AI agents') + '\n');
  process.stdout.write(cyan('  opena2a.org  |  github.com/opena2a-org') + '\n');
  process.stdout.write('\n');
}
