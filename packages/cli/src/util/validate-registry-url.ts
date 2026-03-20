/**
 * Registry URL validation -- enforces HTTPS for all registry URLs
 * except localhost (for local development).
 *
 * OA2A-001: Prevents MITM attacks by rejecting plain HTTP registry URLs.
 */

/**
 * Validates that a registry URL uses HTTPS.
 * Allows http://localhost and http://127.0.0.1 for local development.
 *
 * @param url  The registry URL to validate
 * @throws Error if the URL uses plain HTTP (non-localhost)
 */
export function validateRegistryUrl(url: string): void {
  if (!url) return;

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid registry URL: ${url}`);
  }

  const isLocalhost =
    parsed.hostname === 'localhost' ||
    parsed.hostname === '127.0.0.1' ||
    parsed.hostname === '::1';

  if (parsed.protocol === 'http:' && !isLocalhost) {
    throw new Error(
      `Registry URL must use HTTPS: ${url}\n` +
      'Plain HTTP is only allowed for localhost development.\n' +
      'Use https:// or http://localhost for local testing.',
    );
  }
}
