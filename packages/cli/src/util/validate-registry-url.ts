/**
 * Registry URL validation -- enforces HTTPS for all registry URLs
 * except localhost (for local development).
 *
 * OA2A-001: Prevents MITM attacks by rejecting plain HTTP registry URLs.
 */

/**
 * The refusal `validateRegistryUrl` throws. `kind` says why and `url` holds
 * the refused value as it was given, so a caller that names the URL in its
 * own output can name it from the parsed URL instead of from the message,
 * which repeats the value whole, a user name and password included. The
 * message is the same as before for every caller that prints it.
 */
export class RegistryUrlRefusal extends Error {
  readonly kind: 'not-a-url' | 'plain-http';
  readonly url: string;

  constructor(message: string, kind: 'not-a-url' | 'plain-http', url: string) {
    super(message);
    this.kind = kind;
    this.url = url;
  }
}

/**
 * Validates that a registry URL uses HTTPS.
 * Allows http://localhost and http://127.0.0.1 for local development.
 *
 * @param url  The registry URL to validate
 * @throws RegistryUrlRefusal if the URL does not parse or uses plain HTTP (non-localhost)
 */
export function validateRegistryUrl(url: string): void {
  if (!url) return;

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new RegistryUrlRefusal(`Invalid registry URL: ${url}`, 'not-a-url', url);
  }

  const isLocalhost =
    parsed.hostname === 'localhost' ||
    parsed.hostname === '127.0.0.1' ||
    parsed.hostname === '::1';

  if (parsed.protocol === 'http:' && !isLocalhost) {
    throw new RegistryUrlRefusal(
      `Registry URL must use HTTPS: ${url}\n` +
      'Plain HTTP is only allowed for localhost development.\n' +
      'Use https:// or http://localhost for local testing.',
      'plain-http',
      url,
    );
  }
}
