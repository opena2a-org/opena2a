import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { homedir, hostname, userInfo } from 'node:os';

const SALT_PATH = join(homedir(), '.opena2a', 'contributor-salt');

/**
 * Returns a stable contributor token: a SHA-256 of the hostname, the user name
 * and a random salt stored on this machine. It cannot be recomputed without the
 * salt, and the raw inputs do not leave the machine.
 */
export function getContributorToken(): string {
  let salt: string;
  if (existsSync(SALT_PATH)) {
    salt = readFileSync(SALT_PATH, 'utf-8').trim();
  } else {
    salt = randomBytes(32).toString('hex');
    const dir = join(homedir(), '.opena2a');
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(SALT_PATH, salt, { mode: 0o600 });
  }

  const input = `${hostname()}|${userInfo().username}|${salt}`;
  return createHash('sha256').update(input).digest('hex');
}
