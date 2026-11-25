import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { homedir, hostname, userInfo } from 'node:os';

// Resolved on each call, not at import, so the salt follows the HOME the
// caller runs under.
function saltDir(): string {
  return join(homedir(), '.opena2a');
}

function saltPath(): string {
  return join(saltDir(), 'contributor-salt');
}

function tokenFromSalt(salt: string): string {
  const input = `${hostname()}|${userInfo().username}|${salt}`;
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Returns a stable contributor token: a SHA-256 of the hostname, the user name
 * and a random salt stored on this machine. It cannot be recomputed without the
 * salt, and the raw inputs do not leave the machine.
 *
 * Creates the salt on first use. Callers that only report the token, such as
 * `telemetry status`, use `peekContributorToken` instead.
 */
export function getContributorToken(): string {
  const path = saltPath();
  let salt: string;
  if (existsSync(path)) {
    salt = readFileSync(path, 'utf-8').trim();
  } else {
    salt = randomBytes(32).toString('hex');
    const dir = saltDir();
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(path, salt, { mode: 0o600 });
  }
  return tokenFromSalt(salt);
}

/**
 * The token `getContributorToken` would return, or null when this machine has
 * no salt yet. Read-only: it never creates the salt or its directory.
 */
export function peekContributorToken(): string | null {
  const path = saltPath();
  if (!existsSync(path)) return null;
  return tokenFromSalt(readFileSync(path, 'utf-8').trim());
}
