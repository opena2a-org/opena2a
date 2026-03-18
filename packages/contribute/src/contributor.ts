import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { homedir, hostname, userInfo } from 'node:os';

const SALT_PATH = join(homedir(), '.opena2a', 'contributor-salt');

/**
 * Returns a stable anonymous contributor token derived from a locally-stored
 * random salt combined with machine identifiers. The token is a SHA-256 hex
 * digest -- no PII leaves the machine.
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
