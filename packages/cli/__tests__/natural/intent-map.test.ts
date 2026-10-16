import { describe, it, expect } from 'vitest';
import { matchIntent } from '../../src/natural/intent-map.js';

describe('intent map', () => {
  it('matches scanning intents', () => {
    expect(matchIntent('is my agent safe?')?.command).toBe('opena2a scan secure');
    expect(matchIntent('scan my MCP server')?.command).toBe('opena2a scan secure');
    expect(matchIntent('find vulnerabilities')?.command).toBe('opena2a scan secure');
    expect(matchIntent('security audit')?.command).toBe('opena2a scan secure');
  });

  it('matches attack intents', () => {
    expect(matchIntent('attack my agent')?.command).toBe('opena2a scan attack');
    expect(matchIntent('pentest the server')?.command).toBe('opena2a scan attack');
    expect(matchIntent('red team my MCP server')?.command).toBe('opena2a scan attack');
  });

  it('matches credential migration intents to protect', () => {
    expect(matchIntent('move secrets to vault')?.command).toBe('opena2a protect');
    expect(matchIntent('migrate API keys')?.command).toBe('opena2a protect');
    expect(matchIntent('fix hardcoded credentials')?.command).toBe('opena2a protect');
  });

  // The semantic index (src/semantic/command-index.json) lists these phrases
  // under `opena2a secrets init`; the matcher follows it.
  it('matches credential hiding intents to secrets init', () => {
    expect(matchIntent('protect my API keys')?.command).toBe('opena2a secrets init');
    expect(matchIntent('hide credentials from AI')?.command).toBe('opena2a secrets init');
    expect(matchIntent('encrypt secrets')?.command).toBe('opena2a secrets init');
  });

  // A request to find credentials is a read-only scan. It used
  // to resolve to `opena2a protect`, which migrates credentials and writes
  // to the project and the keychain.
  it('matches a credential scan request to the read-only secrets scan', () => {
    expect(matchIntent('find leaked API keys')?.command).toBe('opena2a secrets scan');
    expect(matchIntent('find secrets')?.command).toBe('opena2a secrets scan');
    expect(matchIntent('find secrets')?.command).not.toBe('opena2a protect');
    expect(matchIntent('scan for hardcoded secrets')?.command).toBe('opena2a secrets scan');
    expect(matchIntent('look for exposed tokens in my repo')?.command).toBe('opena2a secrets scan');
    expect(matchIntent('check for credentials')?.command).toBe('opena2a secrets scan');
    expect(matchIntent('search the project for api keys')?.command).toBe('opena2a secrets scan');
    expect(matchIntent('hardcoded secrets')?.command).toBe('opena2a secrets scan');
  });

  it('reaches protect only from a request to change credentials', () => {
    for (const phrase of [
      'find secrets', 'find leaked credentials', 'detect hardcoded api keys',
      'scan my project for leaked secrets', 'check for tokens', 'hardcoded credentials',
      'my credentials are exposed',
    ]) {
      expect(matchIntent(phrase)?.command, phrase).not.toBe('opena2a protect');
    }
  });

  it('matches runtime monitoring intents', () => {
    expect(matchIntent('monitor my agent')?.command).toBe('opena2a runtime start');
    expect(matchIntent('watch network calls')?.command).toBe('opena2a runtime start');
  });

  it('matches benchmark intents', () => {
    expect(matchIntent('benchmark my agent')?.command).toBe('opena2a benchmark');
    expect(matchIntent('compliance check')?.command).toBe('opena2a benchmark');
  });

  it('matches crypto intents', () => {
    expect(matchIntent('quantum readiness check')?.command).toBe('opena2a crypto scan');
    expect(matchIntent('tls configuration check')?.command).toBe('opena2a crypto scan');
  });

  it('matches setup intents', () => {
    expect(matchIntent('get started')?.command).toBe('opena2a shield init');
    expect(matchIntent('how do I start')?.command).toBe('opena2a shield init');
    expect(matchIntent('set up security for this project')?.command).toBe('opena2a shield init');
  });

  // `opena2a nanomind setup` (a command another tool printed) resolved to the
  // 11-step project setup because `set\s*up` matched the bare token `setup`.
  it('does not read a lone setup verb as the setup intent', () => {
    expect(matchIntent('nanomind setup')).toBeNull();
    expect(matchIntent('setup')).toBeNull();
    expect(matchIntent('nanomind initialize')).toBeNull();
    expect(matchIntent('foo onboard')).toBeNull();
  });

  it('returns null for unrecognized input', () => {
    expect(matchIntent('hello world')).toBeNull();
    expect(matchIntent('random gibberish')).toBeNull();
  });

  it('returns high confidence for all matches', () => {
    const result = matchIntent('scan my agent');
    expect(result?.confidence).toBe('high');
  });
});
