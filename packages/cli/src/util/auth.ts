/**
 * Auth credential storage for browser-based (OAuth device flow) authentication.
 *
 * Credentials are stored in ~/.opena2a/auth.json, separate from the agent-level
 * ServerConfig (which stores per-agent registration data in
 * ~/.opena2a/aim-core/identities/server.json).
 *
 * File permissions are set to 0o600 (owner read/write only).
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const AUTH_DIR = join(homedir(), '.opena2a');

export interface AuthCredentials {
  serverUrl: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: string;   // ISO 8601 timestamp when access token expires
  tokenType: string;
  authenticatedAt: string;
}

export function authConfigPath(): string {
  return join(AUTH_DIR, 'auth.json');
}

export function loadAuth(): AuthCredentials | null {
  const p = authConfigPath();
  if (!existsSync(p)) return null;
  try {
    const creds = JSON.parse(readFileSync(p, 'utf-8')) as AuthCredentials;
    return creds;
  } catch {
    return null;
  }
}

export function saveAuth(creds: AuthCredentials): void {
  if (!existsSync(AUTH_DIR)) {
    mkdirSync(AUTH_DIR, { recursive: true });
  }
  writeFileSync(authConfigPath(), JSON.stringify(creds, null, 2), { encoding: 'utf-8', mode: 0o600 });
}

export function removeAuth(): boolean {
  const p = authConfigPath();
  if (!existsSync(p)) return false;
  unlinkSync(p);
  return true;
}

export function isAuthValid(creds: AuthCredentials): boolean {
  // Check if access token has expired (with 60-second buffer)
  const expiresAt = new Date(creds.expiresAt).getTime();
  return Date.now() < expiresAt - 60_000;
}
