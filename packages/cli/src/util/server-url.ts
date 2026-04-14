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
