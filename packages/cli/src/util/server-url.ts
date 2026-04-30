/**
 * Resolve a user-provided --server value into a full URL.
 *
 * Shortcuts:
 *   "cloud"             -> https://aim.oa2a.org
 *   "aim.opena2a.org"   -> https://api.aim.opena2a.org
 *   "localhost:8080"    -> http://localhost:8080
 *   "http://..." / "https://..." -> used as-is
 */
export function resolveServerUrl(input: string): string {
  const trimmed = input.trim();

  // Shorthand for AIM Cloud (Phase 7 backend)
  if (trimmed === 'cloud') {
    return 'https://aim.oa2a.org';
  }

  // Already a full URL -- use as-is
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    return trimmed.replace(/\/+$/, '');
  }

  // Bare community hostnames route to the community API
  if (trimmed === 'aim.opena2a.org' || trimmed.startsWith('aim.opena2a.org/')) {
    return 'https://api.aim.opena2a.org';
  }
  if (trimmed === 'api.aim.opena2a.org' || trimmed.startsWith('api.aim.opena2a.org/')) {
    return `https://${trimmed}`.replace(/\/+$/, '');
  }

  // localhost / 127.0.0.1 / [::1] -- default to http
  if (/^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/.test(trimmed)) {
    return `http://${trimmed}`.replace(/\/+$/, '');
  }

  // Any other hostname -- default to https
  return `https://${trimmed}`.replace(/\/+$/, '');
}

/**
 * Map an AIM API/server URL to the user-facing frontend host (where the
 * dashboard renders). Backend = oa2a.org, frontend = opena2a.org. Printing the
 * backend host as a "Dashboard:" link sends users to the API health endpoint
 * instead of the UI.
 *
 *   https://aim.oa2a.org             -> https://aim.opena2a.org
 *   https://api.aim.opena2a.org      -> https://aim.opena2a.org
 *   http://localhost:8080            -> http://localhost:8080  (self-hosted: same host serves both)
 *   https://aim.example.internal     -> https://aim.example.internal (self-hosted: same host)
 */
export function resolveDashboardUrl(serverUrl: string): string {
  const trimmed = serverUrl.trim().replace(/\/+$/, '');

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    // Caller passed something that isn't parseable; return it untouched so
    // callers don't crash on unexpected config.
    return trimmed;
  }

  // AIM Cloud backend -> AIM Cloud frontend
  if (url.host === 'aim.oa2a.org') {
    return 'https://aim.opena2a.org';
  }

  // Community API host -> community frontend (drop the api. prefix)
  if (url.host === 'api.aim.opena2a.org') {
    return 'https://aim.opena2a.org';
  }

  // Self-hosted (localhost or custom hostname): same host serves API + UI.
  // Strip any path so the caller can append its own.
  return `${url.protocol}//${url.host}`;
}
