/**
 * Login / Logout / Whoami commands
 *
 * Implements OAuth 2.0 Device Authorization Grant (RFC 8628) for
 * browser-based authentication against an AIM server.
 *
 * Credentials are stored in ~/.opena2a/auth.json with 0600 permissions.
 */

import { resolveServerUrl } from '../util/server-url.js';
import { AimClient, AimServerError } from '../util/aim-client.js';
import { loadAuth, saveAuth, removeAuth, isAuthValid, type AuthCredentials } from '../util/auth.js';

export interface LoginOptions {
  server?: string;
  ci?: boolean;
  format?: string;
  json?: boolean;
}

export async function login(options: LoginOptions): Promise<number> {
  const isJson = options.json || options.format === 'json';

  // Determine server URL
  const serverInput = (options.server ?? 'cloud').trim();
  if (!serverInput) {
    if (isJson) {
      console.log(JSON.stringify({ error: 'invalid_server', message: 'Server URL is required.' }));
    } else {
      console.error('Server URL is required. Use --server <url> or omit for aim.oa2a.org.');
    }
    return 1;
  }
  const serverUrl = resolveServerUrl(serverInput);

  // Check if already authenticated
  const existing = loadAuth();
  if (existing && existing.serverUrl === serverUrl && isAuthValid(existing)) {
    if (isJson) {
      console.log(JSON.stringify({ status: 'already_authenticated', serverUrl }));
    } else {
      console.log(`Already authenticated to ${serverUrl}`);
      console.log('Run "opena2a logout" first to re-authenticate.');
    }
    return 0;
  }

  const client = new AimClient(serverUrl);

  // Step 1: Check server health
  try {
    await client.health();
  } catch {
    if (isJson) {
      console.log(JSON.stringify({ error: 'server_unreachable', serverUrl }));
    } else {
      console.error(`Cannot reach AIM server at ${serverUrl}`);
      if (serverUrl.includes('localhost') || serverUrl.includes('127.0.0.1')) {
        console.error('Is the AIM server running? Start it with: docker compose up');
      } else {
        console.error('Check your network connection and try again.');
      }
    }
    return 1;
  }

  // Step 2: Request device code
  let deviceCode;
  try {
    deviceCode = await client.requestDeviceCode('opena2a-cli');
  } catch (err) {
    if (isJson) {
      console.log(JSON.stringify({ error: 'device_code_failed', message: String(err) }));
    } else {
      console.error('Failed to initiate login:', err instanceof Error ? err.message : String(err));
    }
    return 1;
  }

  // Step 3: Display instructions and open browser
  if (isJson) {
    console.log(JSON.stringify({
      status: 'awaiting_approval',
      userCode: deviceCode.userCode,
      verificationUri: deviceCode.verificationUri,
      verificationUriComplete: deviceCode.verificationUriComplete,
      expiresIn: deviceCode.expiresIn,
    }));
  } else {
    console.log('');
    console.log('  To authenticate, open this URL in your browser:');
    console.log('');
    console.log(`    ${deviceCode.verificationUriComplete}`);
    console.log('');
    console.log(`  And enter this code: ${deviceCode.userCode}`);
    console.log('');
    console.log('  Waiting for authentication...');
  }

  // Try to open browser automatically (non-blocking, best-effort)
  if (!options.ci) {
    openBrowser(deviceCode.verificationUriComplete);
  }

  // Step 4: Poll for token
  const interval = (deviceCode.interval || 5) * 1000;
  const deadline = Date.now() + deviceCode.expiresIn * 1000;

  while (Date.now() < deadline) {
    await sleep(interval);

    try {
      const token = await client.pollDeviceToken(deviceCode.deviceCode);

      // Success -- save credentials
      const expiresAt = new Date(Date.now() + token.expiresIn * 1000).toISOString();
      saveAuth({
        serverUrl,
        accessToken: token.accessToken,
        refreshToken: token.refreshToken,
        expiresAt,
        tokenType: token.tokenType,
        authenticatedAt: new Date().toISOString(),
      });

      if (isJson) {
        console.log(JSON.stringify({ status: 'authenticated', serverUrl }));
      } else {
        console.log('');
        console.log(`  Authenticated to ${serverUrl}`);
        console.log('  Credentials saved to ~/.opena2a/auth.json');
        console.log('');
        console.log('  You can now use server commands without --api-key:');
        console.log('    opena2a identity list --server cloud');
        console.log('    opena2a identity create --name my-agent --server cloud');
      }
      return 0;
    } catch (err) {
      if (err instanceof AimServerError) {
        const oauthError = (err as any).oauthError;
        if (oauthError === 'authorization_pending') {
          continue; // Keep polling
        }
        if (oauthError === 'slow_down') {
          await sleep(5000); // Extra delay as requested by server
          continue;
        }
        if (oauthError === 'expired_token') {
          if (isJson) {
            console.log(JSON.stringify({ error: 'expired', message: 'Login session expired. Run "opena2a login" again.' }));
          } else {
            console.error('Login session expired. Run "opena2a login" again.');
          }
          return 1;
        }
        if (oauthError === 'access_denied') {
          if (isJson) {
            console.log(JSON.stringify({ error: 'denied', message: 'Login was denied.' }));
          } else {
            console.error('Login was denied.');
          }
          return 1;
        }
      }
      // Unexpected error
      if (isJson) {
        console.log(JSON.stringify({ error: 'poll_failed', message: String(err) }));
      } else {
        console.error('Authentication failed:', err instanceof Error ? err.message : String(err));
      }
      return 1;
    }
  }

  // Timeout
  if (isJson) {
    console.log(JSON.stringify({ error: 'timeout', message: 'Login timed out.' }));
  } else {
    console.error('Login timed out. Run "opena2a login" again.');
  }
  return 1;
}

export async function logout(options: { format?: string; json?: boolean }): Promise<number> {
  const isJson = options.json || options.format === 'json';
  const removed = removeAuth();

  if (isJson) {
    console.log(JSON.stringify({ status: removed ? 'logged_out' : 'not_authenticated' }));
  } else if (removed) {
    console.log('Logged out. Credentials removed from ~/.opena2a/auth.json');
  } else {
    console.log('Not currently authenticated.');
  }
  return 0;
}

export async function whoami(options: { format?: string; json?: boolean }): Promise<number> {
  const isJson = options.json || options.format === 'json';
  const auth = loadAuth();

  if (!auth) {
    if (isJson) {
      console.log(JSON.stringify({ authenticated: false }));
    } else {
      console.log('Not authenticated. Run "opena2a login" to authenticate.');
    }
    return 0;
  }

  const valid = isAuthValid(auth);

  if (isJson) {
    console.log(JSON.stringify({
      authenticated: valid,
      tokenExpired: !valid,
      serverUrl: auth.serverUrl,
      authenticatedAt: auth.authenticatedAt,
      expiresAt: auth.expiresAt,
    }));
  } else {
    console.log(`Server:    ${auth.serverUrl}`);
    console.log(`Status:    ${valid ? 'Authenticated' : 'Token expired'}`);
    console.log(`Since:     ${auth.authenticatedAt}`);
    console.log(`Expires:   ${auth.expiresAt}`);
    if (!valid) {
      console.log('');
      console.log('Token has expired. Run "opena2a login" to re-authenticate.');
    }
  }
  return 0;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function openBrowser(url: string): void {
  const { exec } = require('node:child_process');
  const cmd = process.platform === 'darwin' ? 'open'
    : process.platform === 'win32' ? 'start'
    : 'xdg-open';
  exec(`${cmd} "${url}"`, () => {}); // Ignore errors, best-effort
}
