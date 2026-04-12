import { describe, it, expect } from 'vitest';
import {
  isStaleRegistryUrl,
  STALE_REGISTRY_HOSTS,
  CANONICAL_REGISTRY_URL,
} from './user-config.js';

describe('isStaleRegistryUrl', () => {
  it('returns true for each documented stale host', () => {
    for (const host of STALE_REGISTRY_HOSTS) {
      expect(isStaleRegistryUrl(host)).toBe(true);
    }
  });

  it('returns true for stale host with trailing slash', () => {
    expect(isStaleRegistryUrl('https://registry.opena2a.org/')).toBe(true);
  });

  it('returns true for stale host with path suffix', () => {
    expect(isStaleRegistryUrl('https://registry.opena2a.org/api/v1/trust')).toBe(true);
  });

  it('returns true for stale host regardless of case', () => {
    expect(isStaleRegistryUrl('HTTPS://REGISTRY.OPENA2A.ORG')).toBe(true);
  });

  it('returns false for the current canonical URL', () => {
    expect(isStaleRegistryUrl(CANONICAL_REGISTRY_URL)).toBe(false);
  });

  it('returns false for a third-party URL that happens to share a suffix', () => {
    expect(isStaleRegistryUrl('https://not-registry.opena2a.org')).toBe(false);
  });

  it('returns false for empty or undefined input', () => {
    expect(isStaleRegistryUrl('')).toBe(false);
    expect(isStaleRegistryUrl('   ')).toBe(false);
    expect(isStaleRegistryUrl(undefined)).toBe(false);
    expect(isStaleRegistryUrl(null)).toBe(false);
  });

  it('returns false for a user-provided self-hosted registry', () => {
    expect(isStaleRegistryUrl('https://my-internal-registry.example.com')).toBe(false);
  });
});
