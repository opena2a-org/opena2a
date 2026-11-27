// The registry URL refusal repeated the refused URL whole, so a user name and
// password in it reached the terminal and any JSON or log that carried the
// message.

import { describe, it, expect } from 'vitest';
import { RegistryUrlRefusal, validateRegistryUrl } from '../../src/util/validate-registry-url.js';

function refusalOf(url: string): RegistryUrlRefusal {
  try {
    validateRegistryUrl(url);
  } catch (err) {
    expect(err).toBeInstanceOf(RegistryUrlRefusal);
    return err as RegistryUrlRefusal;
  }
  throw new Error(`${JSON.stringify(url)} was not refused`);
}

describe('validateRegistryUrl', () => {
  it('accepts HTTPS and localhost URLs', () => {
    expect(() => validateRegistryUrl('https://api.oa2a.org')).not.toThrow();
    expect(() => validateRegistryUrl('http://localhost:8080')).not.toThrow();
    expect(() => validateRegistryUrl('http://127.0.0.1:8080')).not.toThrow();
    expect(() => validateRegistryUrl('')).not.toThrow();
  });

  it('accepts the IPv6 loopback over plain HTTP like 127.0.0.1', () => {
    expect(() => validateRegistryUrl('http://[::1]:8080')).not.toThrow();
    expect(() => validateRegistryUrl('http://[::1]')).not.toThrow();
  });

  it('refuses a plain HTTP IPv6 address that is not the loopback', () => {
    const err = refusalOf('http://[2001:db8::1]:8080');
    expect(err.kind).toBe('plain-http');
  });

  it('names a plain HTTP URL in its refusal with the user name and password cleared', () => {
    const err = refusalOf('http://FAKE-user:FAKE-pw@registry.internal.example/base');
    expect(err.kind).toBe('plain-http');
    expect(err.message).toContain('Registry URL must use HTTPS: http://registry.internal.example/base');
    expect(err.message).not.toMatch(/fake/i);
  });

  it('names a plain HTTP URL without user info as it was given', () => {
    const err = refusalOf('http://registry.internal.example');
    expect(err.message.split('\n')[0]).toBe('Registry URL must use HTTPS: http://registry.internal.example/');
  });

  it('keeps the user name and password out of the refusal whatever the password holds', () => {
    for (const url of [
      'http://FAKE-user:FAKE pw@registry.internal.example',
      'http://FAKE-user:FAKE\npw@registry.internal.example',
      'http://FAKE-user:FAKE@pw@registry.internal.example',
      'http://FAKE-user:FAKE/pw@registry.internal.example',
      'http://FAKE-user:12/FAKE@registry.internal.example',
      'http://FAKE-user:12?FAKE@registry.internal.example',
      'http://FAKE-user:12#FAKE@registry.internal.example',
      'http://FAKE-user:12\\FAKE@registry.internal.example',
      'http://FAKE-user:/FAKE@registry.internal.example',
      'http://FAKE-user@registry.internal.example',
    ]) {
      const err = refusalOf(url);
      expect(err.message, JSON.stringify(url)).toMatch(/^(Invalid registry URL|Registry URL must use HTTPS)/);
      expect(err.message, JSON.stringify(url)).not.toMatch(/fake/i);
      expect(err.url).toBe(url);
    }
  });

  it('keeps a user name and password out of the refusal of a value that is not a URL', () => {
    const err = refusalOf('//FAKE-user:FAKE-pw@registry.internal.example');
    expect(err.kind).toBe('not-a-url');
    expect(err.message).toMatch(/^Invalid registry URL/);
    expect(err.message).not.toMatch(/fake/i);
  });

  it('names a value that is not a URL and holds no user info', () => {
    const err = refusalOf('registry.internal.example');
    expect(err.kind).toBe('not-a-url');
    expect(err.message).toBe('Invalid registry URL: registry.internal.example');
  });
});
