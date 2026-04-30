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
}

function accountFor(serverUrl: string, kind: TokenKind): string {
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
}

/* Stub for unsupported platforms. */
class NullKeychain implements KeychainBackend {
  readonly name = 'No keychain (file fallback)';
  isAvailable(): boolean { return false; }
  setSecret(): void { throw new Error('keychain not available on this platform'); }
  getSecret(): string | null { return null; }
  deleteSecret(): boolean { return false; }
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
