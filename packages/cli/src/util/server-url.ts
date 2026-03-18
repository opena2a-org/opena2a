/**
 * Resolve a user-provided --server value into a full URL.
 *
 * Shortcuts:
 *   "cloud"             → https://aim.opena2a.org
 *   "aim.opena2a.org"   → https://aim.opena2a.org
 *   "localhost:8080"    → http://localhost:8080
 *   "http://..." / "https://..." → used as-is
 *   "cloud"             -> https://aim.opena2a.org
 *   "aim.opena2a.org"   -> https://aim.opena2a.org
 *   "localhost:8080"    -> http://localhost:8080
 *   "http://..." / "https://..." -> used as-is
 */
export function resolveServerUrl(input: string): string {
  const trimmed = input.trim();

  // Shorthand for the hosted AIM service (API endpoint, not the dashboard)
  if (trimmed === 'cloud') {
    return 'https://api.aim.opena2a.org';
  }

  // Already a full URL — use as-is
  // Already a full URL -- use as-is
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    // Strip trailing slash for consistency
    return trimmed.replace(/\/+$/, '');
  }

  // Bare hostname that matches the cloud service — route to API endpoint
  if (trimmed === 'aim.opena2a.org' || trimmed.startsWith('aim.opena2a.org/')) {
    return 'https://api.aim.opena2a.org';
  }
  if (trimmed === 'api.aim.opena2a.org' || trimmed.startsWith('api.aim.opena2a.org/')) {
    return `https://${trimmed}`.replace(/\/+$/, '');
  }

  // localhost / 127.0.0.1 / [::1] → default to http
  // localhost / 127.0.0.1 / [::1] -- default to http
  if (/^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/.test(trimmed)) {
    return `http://${trimmed}`.replace(/\/+$/, '');
  }

  // Any other hostname — default to https
  // Any other hostname -- default to https
  return `https://${trimmed}`.replace(/\/+$/, '');
}
