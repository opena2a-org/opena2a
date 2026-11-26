/**
 * The contributor token and the salt it is derived from.
 *
 * `getContributorToken` from @opena2a/contribute creates
 * ~/.opena2a/contributor-salt when it is missing, so a status command that
 * called it wrote a file in a fresh HOME. `opena2a telemetry status`, `on` and
 * `off` call `peekContributorToken`, which reads the same salt, derives the
 * same token and returns null when there is no salt yet. The salt is created
 * only by `ensureContributorSalt`, which the contribution path calls after the
 * contribution opt-in check, when a scan is first contributed.
 *
 * The salt path, its format and the hash match the @opena2a/contribute
 * release this CLI depends on; __tests__/util/contributor-token.test.ts holds
 * them equal.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { homedir, hostname, userInfo } from 'node:os';

export function contributorSaltPath(): string {
  return join(homedir(), '.opena2a', 'contributor-salt');
}

function tokenFromSalt(salt: string): string {
  return createHash('sha256').update(`${hostname()}|${userInfo().username}|${salt}`).digest('hex');
}

export function peekContributorToken(): string | null {
  const saltPath = contributorSaltPath();
  if (!existsSync(saltPath)) return null;
  return tokenFromSalt(readFileSync(saltPath, 'utf-8').trim());
}

/**
 * Creates the contributor salt when it is missing, the way @opena2a/contribute
 * does, and returns the token. Call it only once contribution is known to be
 * enabled: nothing else may create the salt.
 */
export function ensureContributorSalt(): string {
  const existing = peekContributorToken();
  if (existing !== null) return existing;
  const saltPath = contributorSaltPath();
  const salt = randomBytes(32).toString('hex');
  mkdirSync(dirname(saltPath), { recursive: true });
  // 'wx' leaves a salt another process wrote in the meantime as it is.
  try {
    writeFileSync(saltPath, salt, { mode: 0o600, flag: 'wx' });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
    return peekContributorToken() as string;
  }
  return tokenFromSalt(salt);
}
