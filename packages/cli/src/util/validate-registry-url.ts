/**
 * Registry URL validation -- enforces HTTPS for all registry URLs
 * except localhost (for local development).
 *
 * OA2A-001: Prevents MITM attacks by rejecting plain HTTP registry URLs.
 */

/**
 * The refusal `validateRegistryUrl` throws. `kind` says why and `url` holds
 * the refused value as it was given, so a caller that names the URL in its
 * own output can build that name from the parsed URL. The message never
 * holds the URL's user name or password: it names the URL with them cleared,
 * or does not name it when that cannot be done safely.
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
 * The parsed URL as a refusal names it: with its user name and password
 * cleared. A `/`, `?`, `#` or `\` in a password ends the host part early, so
 * the parser reads the user name as the host and the rest of the password
 * as a port and a path; an `@` left after the host shows that, and then the
 * URL is not named at all.
 */
function shownUrl(parsed: URL): string | null {
  if (`${parsed.pathname}${parsed.search}${parsed.hash}`.includes('@')) return null;
  const shown = new URL(parsed.href);
  shown.username = '';
  shown.password = '';
  return shown.href;
}

/**
 * Validates that a registry URL uses HTTPS.
 * Allows http://localhost, http://127.0.0.1 and http://[::1] for local development.
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
    // A value that does not parse has no user name or password to clear; it
    // is named only when it holds no `@` that could set one off.
    const message = url.includes('@')
      ? 'Invalid registry URL (the value is not shown because it may hold a user name or password).'
      : `Invalid registry URL: ${url}`;
    throw new RegistryUrlRefusal(message, 'not-a-url', url);
  }

  // WHATWG URL keeps the brackets on an IPv6 hostname: http://[::1]:8080 has
  // hostname '[::1]', never '::1'.
  const isLocalhost =
    parsed.hostname === 'localhost' ||
    parsed.hostname === '127.0.0.1' ||
    parsed.hostname === '[::1]' ||
    parsed.hostname === '::1';

  if (parsed.protocol === 'http:' && !isLocalhost) {
    const shown = shownUrl(parsed);
    throw new RegistryUrlRefusal(
      (shown ? `Registry URL must use HTTPS: ${shown}\n` : 'Registry URL must use HTTPS.\n') +
      'Plain HTTP is only allowed for localhost development.\n' +
      'Use https:// or http://localhost for local testing.',
      'plain-http',
      url,
    );
  }
}
