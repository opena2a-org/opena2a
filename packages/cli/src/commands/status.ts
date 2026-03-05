/**
 * opena2a status -- Show security status of the current project.
 *
 * Aggregates: Shield status (tools, policy, integrity),
 * ConfigGuard (signed files), and identity status.
 */

import { getShieldStatus, formatStatus } from '../shield/status.js';
import { getVersion } from '../util/version.js';

export interface StatusOptions {
  targetDir?: string;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
}

export async function status(options: StatusOptions): Promise<number> {
  const dir = options.targetDir ?? process.cwd();

  // Change to target directory so shield status detects project-local files
  const originalCwd = process.cwd();
  try {
    process.chdir(dir);
  } catch {
    process.stderr.write(`Cannot access directory: ${dir}\n`);
    return 1;
  }

  try {
    const shieldStatus = getShieldStatus(dir);

    if (options.format === 'json') {
      const report = {
        version: getVersion(),
        directory: dir,
        ...shieldStatus,
      };
      process.stdout.write(JSON.stringify(report, null, 2) + '\n');
      return 0;
    }

    // Text output
    const lines: string[] = [];
    lines.push(`OpenA2A Security Status  (${dir})`);
    lines.push('');
    lines.push(formatStatus(shieldStatus, 'text'));
    lines.push('');

    process.stdout.write(lines.join('\n') + '\n');
    return 0;
  } finally {
    process.chdir(originalCwd);
  }
}
