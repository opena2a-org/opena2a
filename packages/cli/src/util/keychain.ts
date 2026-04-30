/**
 * OS keychain integration for opena2a-cli auth tokens.
 *
 * Primary storage path for OAuth access + refresh tokens. Falls back to a
 * 0600-mode JSON file (see ../util/auth.ts) when the keychain is unavailable
 * (Docker, headless CI, locked keychain, missing libsecret, etc.).
 *
 * Why shell out to `security` / `secret-tool` instead of using a native
 * binding: same approach as @opena2a secretless-ai's keychain backends. No
 * native deps, no compile step on `npx` install, identical attack surface
 * (the `security` binary is signed by Apple). execFileSync prevents shell
 * injection.
 *
 * Service name: "opena2a-cli". Visible in macOS Passwords.app as
 * "opena2a-cli: <serverUrl>". Account = `${serverUrl}:${kind}` where kind is
 * "access" or "refresh".
 *
 * Known limitation (macOS): `security add-generic-password -w <value>` passes
 * the secret via argv, briefly observable via `ps -ww` during the exec
 * window (~50ms per call). Linux `secret-tool` reads from stdin and is not
 * affected. The argv-exposure window is the same threat surface every
 * shell-out keychain tool faces (gh, pass, aws-vault, secretless-ai). Proper
 * fix requires a NAPI binding — tracked in
 * todo/2026-04-30-cli-auth-keychain-storage-P1.md. Net effect over plaintext
 * file storage: 30-90 days of at-rest exposure replaced with ~50ms windows
 * per login/refresh, observable only by a same-user attacker actively polling
 * `ps -ww`. Strictly better against the dominant attack vectors (file
 * backups, supply-chain readers, accidental commits).
 *
 * Listing keychain entries (used by logout to clear orphans from prior
 * sessions or server-switches): see `listAccounts()` on each backend.
 */

import { execFileSync } from 'node:child_process';

export const KEYCHAIN_SERVICE = 'opena2a-cli';

export type TokenKind = 'access' | 'refresh';

export interface KeychainBackend {
  /** Display name, e.g. "macOS Keychain", "GNOME Keyring (libsecret)". */
  readonly name: string;
  /** True when this OS / environment can talk to a real keychain. */
  isAvailable(): boolean;
  setSecret(serverUrl: string, kind: TokenKind, value: string): void;
  getSecret(serverUrl: string, kind: TokenKind): string | null;
  deleteSecret(serverUrl: string, kind: TokenKind): boolean;
  /**
   * Enumerate every `${serverUrl}:${kind}` account this backend stored under
   * KEYCHAIN_SERVICE. Used by logout to clear orphan entries left behind by
   * prior sessions or server-switches (user logged into cloud, then into
   * self-hosted without logging out first — the cloud refresh token would
   * otherwise persist indefinitely). Best-effort: returns [] when
   * enumeration is not supported on this platform.
   */
  listAccounts(): string[];
}

/**
 * Reject server URLs that contain control characters, leading hyphens, or
 * are excessively long before using them as keychain account names.
 *
 * Defense-in-depth: execFileSync already prevents shell-level injection
 * because no shell is involved, but a serverUrl starting with `-` could be
 * misinterpreted by future arg-parsing changes in `security` / `secret-tool`,
 * and embedded NUL / LF / CR in the account string would either truncate
 * (NUL on libsecret) or split the account string across lines on
 * enumeration, which lets an attacker who can write the metadata file create
 * keychain entries with names that don't round-trip on lookup.
 */
export function validateServerUrl(serverUrl: string): void {
  if (typeof serverUrl !== 'string' || serverUrl.length === 0) {
    throw new Error('keychain: serverUrl must be a non-empty string');
  }
  if (serverUrl.length > 512) {
    throw new Error('keychain: serverUrl exceeds 512 characters');
  }
  if (serverUrl.startsWith('-')) {
    throw new Error('keychain: serverUrl must not start with a hyphen');
  }
  if (/[\x00-\x1f\x7f]/.test(serverUrl)) {
    throw new Error('keychain: serverUrl contains control characters');
  }
}

function accountFor(serverUrl: string, kind: TokenKind): string {
  validateServerUrl(serverUrl);
  return `${serverUrl}:${kind}`;
}

/* macOS: shell out to `security`. */
class MacOSKeychain implements KeychainBackend {
  readonly name = 'macOS Keychain';

  isAvailable(): boolean {
    try {
      execFileSync('security', ['default-keychain'], { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }

  setSecret(serverUrl: string, kind: TokenKind, value: string): void {
    const account = accountFor(serverUrl, kind);
    // Delete existing entry (security add-generic-password fails on dup unless -U).
    try {
      execFileSync('security', [
        'delete-generic-password',
        '-s', KEYCHAIN_SERVICE,
        '-a', account,
      ], { stdio: 'pipe' });
    } catch {
      // No existing entry — fine.
    }
    execFileSync('security', [
      'add-generic-password',
      '-s', KEYCHAIN_SERVICE,
      '-a', account,
      '-l', `opena2a-cli: ${serverUrl} (${kind})`,
      '-w', value,
    ], { stdio: 'pipe' });
  }

  getSecret(serverUrl: string, kind: TokenKind): string | null {
    try {
      const out = execFileSync('security', [
        'find-generic-password',
        '-s', KEYCHAIN_SERVICE,
        '-a', accountFor(serverUrl, kind),
        '-w',
      ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' });
      return out.trimEnd();
    } catch {
      return null;
    }
  }

  deleteSecret(serverUrl: string, kind: TokenKind): boolean {
    try {
      execFileSync('security', [
        'delete-generic-password',
        '-s', KEYCHAIN_SERVICE,
        '-a', accountFor(serverUrl, kind),
      ], { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }

  listAccounts(): string[] {
    // `security dump-keychain` prints every entry; we filter for our service.
    // Heavy but reliable; logout is not on a hot path and only runs once per
    // user-initiated logout. Each entry block contains lines like:
    //   "svce"<blob>="opena2a-cli"
    //   "acct"<blob>="https://aim.oa2a.org:access"
    let dump: string;
    try {
      dump = execFileSync('security', ['dump-keychain'], {
        stdio: ['pipe', 'pipe', 'pipe'],
        encoding: 'utf-8',
        // dump-keychain output can be large on busy keychains; cap to ~10MB
        maxBuffer: 10 * 1024 * 1024,
      });
    } catch {
      return [];
    }
    const accounts: string[] = [];
    const blocks = dump.split(/\nkeychain:/);
    for (const block of blocks) {
      if (!block.includes(`"svce"<blob>="${KEYCHAIN_SERVICE}"`)) continue;
      const acctMatch = block.match(/"acct"<blob>="([^"\n]*)"/);
      if (acctMatch) accounts.push(acctMatch[1]);
    }
    return accounts;
  }
}

/* Linux: shell out to `secret-tool` (libsecret). */
class LinuxKeychain implements KeychainBackend {
  readonly name = 'Secret Service (libsecret)';

  isAvailable(): boolean {
    try {
      // `secret-tool --version` returns 0 when binary is present AND the
      // backing service is reachable enough to respond. On headless boxes
      // without DBus, the binary may be present but `lookup` fails — we
      // catch that on first store/lookup call below.
      execFileSync('secret-tool', ['--version'], { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }

  setSecret(serverUrl: string, kind: TokenKind, value: string): void {
    // `secret-tool store` reads the secret from stdin (no value-on-cmdline).
    execFileSync('secret-tool', [
      'store',
      '--label', `opena2a-cli: ${serverUrl} (${kind})`,
      'service', KEYCHAIN_SERVICE,
      'account', accountFor(serverUrl, kind),
    ], { input: value, stdio: ['pipe', 'pipe', 'pipe'] });
  }

  getSecret(serverUrl: string, kind: TokenKind): string | null {
    try {
      const out = execFileSync('secret-tool', [
        'lookup',
        'service', KEYCHAIN_SERVICE,
        'account', accountFor(serverUrl, kind),
      ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' });
      // `secret-tool lookup` prints the secret with no trailing newline by
      // default, but trim defensively in case libsecret changes.
      const trimmed = out.replace(/\n$/, '');
      return trimmed.length > 0 ? trimmed : null;
    } catch {
      return null;
    }
  }

  deleteSecret(serverUrl: string, kind: TokenKind): boolean {
    try {
      execFileSync('secret-tool', [
        'clear',
        'service', KEYCHAIN_SERVICE,
        'account', accountFor(serverUrl, kind),
      ], { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }

  listAccounts(): string[] {
    // `secret-tool search --all` writes matched attribute sets to stdout.
    // Each match prints one set of `[attribute] = [value]` lines; we extract
    // the `account` attribute. `--unlock` not used so a locked keyring just
    // returns []. Best-effort.
    let out: string;
    try {
      out = execFileSync('secret-tool', [
        'search', '--all',
        'service', KEYCHAIN_SERVICE,
      ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' });
    } catch {
      return [];
    }
    const accounts: string[] = [];
    for (const line of out.split('\n')) {
      const m = line.match(/^attribute\.account = (.+)$/);
      if (m) accounts.push(m[1]);
    }
    return accounts;
  }
}

/* Stub for unsupported platforms. */
class NullKeychain implements KeychainBackend {
  readonly name = 'No keychain (file fallback)';
  isAvailable(): boolean { return false; }
  setSecret(): void { throw new Error('keychain not available on this platform'); }
  getSecret(): string | null { return null; }
  deleteSecret(): boolean { return false; }
  listAccounts(): string[] { return []; }
}

let cached: KeychainBackend | null = null;

/**
 * Returns the keychain backend for this OS. Caches the result for the
 * process lifetime — `isAvailable()` does I/O so we don't want to re-run it
 * on every load/save call.
 *
 * Test override: `OPENA2A_AUTH_FORCE_FILE=1` returns the null backend so
 * tests don't write into the real keychain.
 */
export function getKeychain(): KeychainBackend {
  if (cached) return cached;
  if (process.env.OPENA2A_AUTH_FORCE_FILE === '1') {
    cached = new NullKeychain();
    return cached;
  }
  switch (process.platform) {
    case 'darwin':
      cached = new MacOSKeychain();
      break;
    case 'linux':
      cached = new LinuxKeychain();
      break;
    default:
      // Windows + others fall back to file-mode for now. cmdkey support is
      // tracked separately (todo/2026-04-30-cli-auth-keychain-storage-P1.md).
      cached = new NullKeychain();
  }
  return cached;
}

/** Reset the cache (test-only). */
export function _resetKeychainForTests(): void {
  cached = null;
}
