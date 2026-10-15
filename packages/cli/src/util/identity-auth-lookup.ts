/**
 * What `opena2a identity` signs in to an AIM server with: the token, API key
 * and agent ID stored for that server, looked up by the server's origin.
 *
 * Two stores hold them. The login `opena2a login` writes holds a token for
 * one server; the agent connection `identity connect`, `identity create` and
 * `opena2a setup` write holds an agent ID, and an API key or a token, for one
 * server. Each value is returned only for the origin (scheme, host and port)
 * of the server it was stored for, so a request to one server never carries
 * what was stored for another.
 */

import { AimClient, loadServerConfig } from './aim-client.js';
import { loadAuth, saveAuth, isAuthValid } from './auth.js';
import { resolveServerUrl } from './server-url.js';

export interface ServerSignIn {
  token?: string;
  apiKey?: string;
  agentId?: string;
}

/** The origin of a server URL or --server value, or undefined when it is not an http(s) URL. */
export function serverOrigin(serverUrl: string): string | undefined {
  try {
    const url = new URL(resolveServerUrl(serverUrl));
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.origin : undefined;
  } catch {
    return undefined;
  }
}

function sameOrigin(a: string | undefined, b: string): boolean {
  if (!a) return false;
  const origin = serverOrigin(a);
  return origin !== undefined && origin === serverOrigin(b);
}

/** A key typed with --api-key, and the --server value typed with it, if any. */
export interface TypedApiKey {
  apiKey?: string;
  apiKeyServer?: string;
}

/**
 * The token, API key and agent ID stored for the origin of `serverUrl`. Each
 * is absent when nothing was stored for that origin. A login that has not
 * expired gives the token before a token kept with the agent connection,
 * which is a copy that is not refreshed. A key typed with --api-key replaces
 * the stored key for the server typed with it, or, typed without --server,
 * for the server the command sends to.
 */
export function authFor(serverUrl: string, typed: TypedApiKey = {}): ServerSignIn {
  const found: ServerSignIn = {};
  const login = loadAuth();
  if (login && isAuthValid(login) && sameOrigin(login.serverUrl, serverUrl)) {
    found.token = login.accessToken;
  }
  const connection = loadServerConfig();
  if (connection && sameOrigin(connection.serverUrl, serverUrl)) {
    found.token ??= connection.accessToken || undefined;
    found.apiKey = connection.apiKey || undefined;
    found.agentId = connection.agentId || undefined;
  }
  if (typed.apiKey && (!typed.apiKeyServer || sameOrigin(typed.apiKeyServer, serverUrl))) {
    found.apiKey = typed.apiKey;
  }
  return found;
}

/** The server of the login, when it has not expired. */
export function loginServerUrl(): string | undefined {
  const login = loadAuth();
  return login && isAuthValid(login) ? login.serverUrl : undefined;
}

/** The server identity commands act on without --server: the agent connection's, else the login's. */
export function storedServerUrl(): string | undefined {
  return loadServerConfig()?.serverUrl || loginServerUrl();
}

/**
 * Refresh an expired login with its refresh token, at the server that issued
 * it. If the access token is still valid, this is a no-op. If refresh
 * succeeds, the new tokens are saved to ~/.opena2a/auth.json.
 * Returns true if the login is now valid (was valid or refreshed), false otherwise.
 */
export async function refreshExpiredLogin(): Promise<boolean> {
  const auth = loadAuth();
  if (!auth) return false;

  // Token still valid -- nothing to do
  if (isAuthValid(auth)) return true;

  // Token expired -- attempt refresh if we have a refresh token
  if (!auth.refreshToken) return false;

  try {
    const client = new AimClient(auth.serverUrl);
    const refreshed = await client.refreshAccessToken(auth.refreshToken);
    // Save the new credentials
    const expiresAt = new Date(Date.now() + (refreshed.expiresIn ?? 7200) * 1000).toISOString();
    saveAuth({
      serverUrl: auth.serverUrl,
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken ?? auth.refreshToken,
      expiresAt,
      tokenType: refreshed.tokenType ?? 'Bearer',
      authenticatedAt: new Date().toISOString(),
    });
    return true;
  } catch {
    // Refresh failed -- caller should prompt for re-login
    return false;
  }
}
