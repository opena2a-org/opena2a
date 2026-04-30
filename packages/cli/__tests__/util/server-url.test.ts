import { describe, it, expect } from 'vitest';
import { resolveServerUrl, resolveDashboardUrl } from '../../src/util/server-url.js';

describe('resolveServerUrl', () => {
  it('resolves "cloud" to https://aim.oa2a.org', () => {
    expect(resolveServerUrl('cloud')).toBe('https://aim.oa2a.org');
  });

  it('resolves bare "aim.opena2a.org" to the community API', () => {
    expect(resolveServerUrl('aim.opena2a.org')).toBe('https://api.aim.opena2a.org');
  });

  it('resolves "aim.opena2a.org/" with trailing slash', () => {
    expect(resolveServerUrl('aim.opena2a.org/')).toBe('https://api.aim.opena2a.org');
  });

  it('resolves "api.aim.opena2a.org" literal as-is', () => {
    expect(resolveServerUrl('api.aim.opena2a.org')).toBe('https://api.aim.opena2a.org');
  });

  it('passes through full https:// URLs as-is', () => {
    expect(resolveServerUrl('https://my-server.example.com')).toBe('https://my-server.example.com');
  });

  it('passes through full http:// URLs as-is', () => {
    expect(resolveServerUrl('http://my-server.example.com:9090')).toBe('http://my-server.example.com:9090');
  });

  it('strips trailing slashes from full URLs', () => {
    expect(resolveServerUrl('https://example.com/')).toBe('https://example.com');
    expect(resolveServerUrl('https://example.com///')).toBe('https://example.com');
  });

  it('auto-prepends http:// for localhost', () => {
    expect(resolveServerUrl('localhost:8080')).toBe('http://localhost:8080');
    expect(resolveServerUrl('localhost')).toBe('http://localhost');
  });

  it('auto-prepends http:// for 127.0.0.1', () => {
    expect(resolveServerUrl('127.0.0.1:8080')).toBe('http://127.0.0.1:8080');
    expect(resolveServerUrl('127.0.0.1')).toBe('http://127.0.0.1');
  });

  it('auto-prepends http:// for [::1]', () => {
    expect(resolveServerUrl('[::1]:8080')).toBe('http://[::1]:8080');
  });

  it('auto-prepends https:// for other hostnames', () => {
    expect(resolveServerUrl('my-aim-server.internal:3000')).toBe('https://my-aim-server.internal:3000');
    expect(resolveServerUrl('aim.example.com')).toBe('https://aim.example.com');
  });

  it('trims whitespace', () => {
    expect(resolveServerUrl('  cloud  ')).toBe('https://aim.oa2a.org');
    expect(resolveServerUrl('  localhost:8080  ')).toBe('http://localhost:8080');
  });
});

describe('resolveDashboardUrl', () => {
  it('maps the AIM Cloud backend host to the user-facing frontend host', () => {
    // oa2a.org = backend, opena2a.org = frontend. The CLI used to print the
    // backend URL with /dashboard appended, sending users to an API
    // health endpoint that does not render a UI.
    expect(resolveDashboardUrl('https://aim.oa2a.org')).toBe('https://aim.opena2a.org');
    expect(resolveDashboardUrl('https://aim.oa2a.org/')).toBe('https://aim.opena2a.org');
  });

  it('maps the community API host to the community frontend (drops api. prefix)', () => {
    expect(resolveDashboardUrl('https://api.aim.opena2a.org')).toBe('https://aim.opena2a.org');
  });

  it('keeps localhost untouched (self-hosted AIM serves API + UI on the same host)', () => {
    expect(resolveDashboardUrl('http://localhost:8080')).toBe('http://localhost:8080');
    expect(resolveDashboardUrl('http://127.0.0.1:8080')).toBe('http://127.0.0.1:8080');
  });

  it('keeps custom self-hosted hostnames untouched', () => {
    expect(resolveDashboardUrl('https://aim.example.internal')).toBe('https://aim.example.internal');
    expect(resolveDashboardUrl('https://aim.example.com:9090')).toBe('https://aim.example.com:9090');
  });

  it('strips trailing slashes and any path the caller passed in', () => {
    expect(resolveDashboardUrl('https://aim.example.com/api/v1/')).toBe('https://aim.example.com');
  });

  it('returns input untouched when not a parseable URL (defensive)', () => {
    expect(resolveDashboardUrl('not-a-url')).toBe('not-a-url');
  });
});
