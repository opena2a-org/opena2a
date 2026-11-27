import { join, sep } from 'node:path';
import { homedir } from 'node:os';
import { getUserConfigDir } from '@opena2a/shared';

/**
 * The aim-core data directory: `<OpenA2A user home>/aim-core`, which is
 * `$OPENA2A_HOME/aim-core` when OPENA2A_HOME is set and `~/.opena2a/aim-core`
 * otherwise — the same default aim-core itself uses. Resolved on every call
 * so a change to OPENA2A_HOME after import is honoured.
 */
export function getAimCoreDir(): string {
  return join(getUserConfigDir(), 'aim-core');
}

/**
 * The aim-core data directory for display: a path under the home directory
 * is shown with `~`, and the result ends in a path separator.
 */
export function displayAimCoreDir(): string {
  const dir = getAimCoreDir();
  const home = homedir();
  if (dir === home) return `~${sep}`;
  if (dir.startsWith(home + sep)) {
    return `~${dir.slice(home.length)}${sep}`;
  }
  return `${dir}${sep}`;
}
