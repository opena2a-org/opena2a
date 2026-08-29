import { getVersion } from './version.js';

/**
 * The `signedBy` label written into guard, snapshot and shield signature stores.
 * A constant tool identity: stores are committed to public repositories, so the
 * label must never carry the operating-system username of whoever ran the command.
 */
export function signedByLabel(): string {
  return `opena2a-cli/${getVersion()}`;
}
