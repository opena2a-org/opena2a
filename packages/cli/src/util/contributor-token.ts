/**
 * The contributor token `opena2a telemetry status` prints, read without
 * creating anything.
 *
 * `getContributorToken` from @opena2a/contribute creates
 * ~/.opena2a/contributor-salt when it is missing, so a status command that
 * called it wrote a file in a fresh HOME. This reads the same salt, derives
 * the same token and returns null when there is no salt yet: the salt is
 * created only when a scan is first contributed.
 *
 * The salt path and the hash match the @opena2a/contribute release this CLI
 * depends on; __tests__/util/contributor-token.test.ts holds the two equal.
 */
import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { homedir, hostname, userInfo } from 'node:os';

export function contributorSaltPath(): string {
  return join(homedir(), '.opena2a', 'contributor-salt');
}

export function peekContributorToken(): string | null {
  const saltPath = contributorSaltPath();
  if (!existsSync(saltPath)) return null;
  const salt = readFileSync(saltPath, 'utf-8').trim();
  return createHash('sha256').update(`${hostname()}|${userInfo().username}|${salt}`).digest('hex');
}
