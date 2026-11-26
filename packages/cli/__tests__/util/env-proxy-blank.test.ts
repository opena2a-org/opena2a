/**
 * A proxy variable that holds only whitespace counts as unset: no proxy is
 * used for its scheme and no empty proxy is named in a failure.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import { envProxyFor, resetEnvProxy, routeThroughEnvProxy } from '../../src/util/env-proxy.js';
import { AimClient, AimServerError } from '../../src/util/aim-client.js';

describe('a whitespace-only proxy variable', () => {
  afterEach(() => {
    resetEnvProxy();
    vi.unstubAllEnvs();
  });

  it('is treated as unset by envProxyFor', () => {
    expect(envProxyFor('https://aim.example.com', { HTTPS_PROXY: ' ' })).toBeNull();
    expect(envProxyFor('https://aim.example.com', { HTTPS_PROXY: ' \t\n' })).toBeNull();
    expect(envProxyFor('http://aim.example.com', { HTTP_PROXY: '  ' })).toBeNull();
    expect(routeThroughEnvProxy('https://aim.example.com', { HTTPS_PROXY: ' ' })).toBeNull();
  });

  it('gives way to the other spelling of the variable when that one names a proxy', () => {
    expect(envProxyFor('https://aim.example.com', { https_proxy: ' ', HTTPS_PROXY: 'http://upper:2' }))
      .toEqual({ url: 'http://upper:2', variable: 'HTTPS_PROXY' });
  });

  it('names no proxy when an AIM request fails', async () => {
    for (const name of ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'no_proxy', 'NO_PROXY']) vi.stubEnv(name, '');
    vi.stubEnv('HTTPS_PROXY', ' ');
    const client = new AimClient('https://aim.scratch.invalid', { timeoutMs: 5000 });
    const err = await client.health().then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(AimServerError);
    expect((err as AimServerError).proxyRoute).toBeUndefined();
    expect((err as AimServerError).message).not.toMatch(/proxy/i);
  });
});
