/**
 * Trust badge snippet for `opena2a trust` and `opena2a claim`.
 *
 * The badge URLs come from the Registry's lookup response. The CLI never
 * builds one itself: the badge is keyed by package and source on the Registry
 * side, and a URL derived from profileUrl pointed at a host that does not
 * serve badges.
 */

import type { TrustLookupResponse } from '../commands/atp-types.js';

function httpUrl(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}

/**
 * Markdown badge for a README, or null when the lookup response does not
 * carry both a badge image URL and a badge link URL.
 */
export function trustBadgeMarkdown(
  data: Pick<TrustLookupResponse, 'badgeImageUrl' | 'badgeLinkUrl'>,
): string | null {
  const image = httpUrl(data.badgeImageUrl);
  const link = httpUrl(data.badgeLinkUrl);
  if (!image || !link) return null;
  return `[![Trust](${image})](${link})`;
}
