/**
 * Auth credential storage for browser-based (OAuth device flow) authentication.
 *
 * Tokens are stored in the OS keychain (macOS Keychain / Linux Secret
 * Service via libsecret). When the keychain is unavailable (Windows,
 * headless CI, locked DBus, etc.), tokens fall back to ~/.opena2a/auth.json
 * with mode 0600.
 *
 * The metadata file at ~/.opena2a/auth.json always exists when the user is
 * authenticated. It carries serverUrl, expiresAt, authenticatedAt, tokenType,
 * and a `tokenStorage: 'keychain' | 'file'` discriminator. When tokenStorage
 * is 'keychain', the file does NOT contain the token strings — they live in
 * the OS keychain only.
 *
 * Pre-keychain users are migrated transparently on first loadAuth() after
 * upgrade. The legacy file shape (tokens inline, no `tokenStorage` field) is
 * detected and rewritten.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { getKeychain } from './keychain.js';

const AUTH_DIR = join(homedir(), '.opena2a');

export interface AuthCredentials {
  serverUrl: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: string;   // ISO 8601 timestamp when access token expires
  tokenType: string;
  authenticatedAt: string;
}

/** Where the tokens for a given auth blob actually live. */
export type TokenStorage = 'keychain' | 'file';

/** What the JSON file on disk looks like. Tokens are absent when stored in keychain. */
interface AuthFile {
  serverUrl: string;
  expiresAt: string;
  tokenType: string;
  authenticatedAt: string;
  tokenStorage: TokenStorage;
  // Only present when tokenStorage === 'file' (or when reading a legacy file
  // pre-migration). Never written to disk when tokenStorage === 'keychain'.
  accessToken?: string;
  refreshToken?: string;
}

export function authConfigPath(): string {
  return join(AUTH_DIR, 'auth.json');
}

/** Public read API. Returns the full credentials regardless of storage location. */
export function loadAuth(): AuthCredentials | null {
  const p = authConfigPath();
  if (!existsSync(p)) return null;

  let parsed: AuthFile;
  try {
    parsed = JSON.parse(readFileSync(p, 'utf-8')) as AuthFile;
  } catch {
    return null;
  }

  // Legacy file (pre-keychain): tokens inline, no tokenStorage discriminator.
  // Migrate transparently — write tokens to keychain if available, rewrite
  // file without inline tokens. Idempotent.
  if (!parsed.tokenStorage) {
    if (typeof parsed.accessToken !== 'string' || typeof parsed.refreshToken !== 'string') {
      return null;
    }
    return migrateLegacy({
      serverUrl: parsed.serverUrl,
      accessToken: parsed.accessToken,
      refreshToken: parsed.refreshToken,
      expiresAt: parsed.expiresAt,
      tokenType: parsed.tokenType,
      authenticatedAt: parsed.authenticatedAt,
    });
  }

  if (parsed.tokenStorage === 'keychain') {
    const kc = getKeychain();
    const accessToken = kc.getSecret(parsed.serverUrl, 'access');
    const refreshToken = kc.getSecret(parsed.serverUrl, 'refresh');
    if (!accessToken || !refreshToken) {
      // Keychain entry vanished (user wiped it manually, ran keychain reset,
      // etc.). Treat as not authenticated; caller will prompt re-login.
      return null;
    }
    return {
      serverUrl: parsed.serverUrl,
      accessToken,
      refreshToken,
      expiresAt: parsed.expiresAt,
      tokenType: parsed.tokenType,
      authenticatedAt: parsed.authenticatedAt,
    };
  }

  // tokenStorage === 'file' — tokens are in the file alongside metadata.
  if (typeof parsed.accessToken !== 'string' || typeof parsed.refreshToken !== 'string') {
    return null;
  }
  return {
    serverUrl: parsed.serverUrl,
    accessToken: parsed.accessToken,
    refreshToken: parsed.refreshToken,
    expiresAt: parsed.expiresAt,
    tokenType: parsed.tokenType,
    authenticatedAt: parsed.authenticatedAt,
  };
}

/**
 * Save auth credentials. Tries keychain first; falls back to file with a
 * stderr warning if the keychain is unavailable. Returns the storage location
 * actually used so callers (login.ts) can tell the user where their tokens
 * landed.
 */
export function saveAuth(creds: AuthCredentials): TokenStorage {
  if (!existsSync(AUTH_DIR)) {
    mkdirSync(AUTH_DIR, { recursive: true });
  }

  // Was the previous on-disk file already known to be on file-fallback? If
  // so, don't re-print the "keychain unavailable" warning on repeat saves
  // (e.g. token refresh inside identity.ts:tryRefreshAuth would otherwise
  // spam stderr every hour).
  let previousStorage: TokenStorage | null = null;
  const filePath = authConfigPath();
  if (existsSync(filePath)) {
    try {
      const prev = JSON.parse(readFileSync(filePath, 'utf-8')) as Partial<AuthFile>;
      if (prev.tokenStorage === 'keychain' || prev.tokenStorage === 'file') {
        previousStorage = prev.tokenStorage;
      }
    } catch { /* malformed — treat as first save */ }
  }

  const kc = getKeychain();
  let storage: TokenStorage = 'file';
  if (kc.isAvailable()) {
    try {
      kc.setSecret(creds.serverUrl, 'access', creds.accessToken);
      kc.setSecret(creds.serverUrl, 'refresh', creds.refreshToken);
      storage = 'keychain';
    } catch (err) {
      // Keychain reachable but write failed (locked keychain, permission
      // prompt denied, etc.). Fall back to file with a warning.
      process.stderr.write(`Warning: keychain write failed (${err instanceof Error ? err.message : String(err)}). Falling back to ~/.opena2a/auth.json (mode 0600).\n`);
      storage = 'file';
    }
  } else if (
    process.env.OPENA2A_AUTH_FORCE_FILE !== '1' &&
    previousStorage !== 'file'
  ) {
    // Only warn the first time we land on file-fallback. Repeat saves on a
    // box that's already known to be keychain-less stay silent.
    process.stderr.write(`Warning: ${kc.name} unavailable. Storing tokens in ~/.opena2a/auth.json (mode 0600). Re-run "opena2a logout" + "opena2a login" from a session with keychain access to upgrade.\n`);
  }

  const file: AuthFile = storage === 'keychain'
    ? {
        serverUrl: creds.serverUrl,
        expiresAt: creds.expiresAt,
        tokenType: creds.tokenType,
        authenticatedAt: creds.authenticatedAt,
        tokenStorage: 'keychain',
      }
    : {
        serverUrl: creds.serverUrl,
        expiresAt: creds.expiresAt,
        tokenType: creds.tokenType,
        authenticatedAt: creds.authenticatedAt,
        tokenStorage: 'file',
        accessToken: creds.accessToken,
        refreshToken: creds.refreshToken,
      };
  writeFileSync(authConfigPath(), JSON.stringify(file, null, 2), { encoding: 'utf-8', mode: 0o600 });
  return storage;
}

/**
 * Remove auth credentials from BOTH keychain and file.
 * Returns true if anything was removed.
 */
export function removeAuth(): boolean {
  const p = authConfigPath();
  let removed = false;

  // Read file first so we know which serverUrl to clear from keychain.
  let serverUrl: string | null = null;
  if (existsSync(p)) {
    try {
      const parsed = JSON.parse(readFileSync(p, 'utf-8')) as AuthFile;
      serverUrl = parsed.serverUrl ?? null;
    } catch {
      // Malformed file — fine, just delete it.
    }
  }

  if (serverUrl) {
    const kc = getKeychain();
    if (kc.isAvailable()) {
      // Best-effort; deleteSecret returns false when the entry is absent.
      if (kc.deleteSecret(serverUrl, 'access')) removed = true;
      if (kc.deleteSecret(serverUrl, 'refresh')) removed = true;
    }
  }

  if (existsSync(p)) {
    unlinkSync(p);
    removed = true;
  }

  return removed;
}

export function isAuthValid(creds: AuthCredentials): boolean {
  // Check if access token has expired (with 60-second buffer)
  const expiresAt = new Date(creds.expiresAt).getTime();
  return Date.now() < expiresAt - 60_000;
}

/**
 * Migrate a pre-keychain file in-place to the new shape. Idempotent — re-
 * running on a partially-migrated file is safe.
 */
function migrateLegacy(creds: AuthCredentials): AuthCredentials {
  const storage = saveAuth(creds);
  if (storage === 'keychain') {
    process.stderr.write('Note: tokens migrated to OS keychain. ~/.opena2a/auth.json now holds metadata only.\n');
  }
  return creds;
}
