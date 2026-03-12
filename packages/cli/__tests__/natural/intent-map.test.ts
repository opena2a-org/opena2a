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

  it('matches credential protection intents', () => {
    expect(matchIntent('protect my API keys')?.command).toBe('opena2a protect');
    expect(matchIntent('hide credentials from AI')?.command).toBe('opena2a protect');
    expect(matchIntent('move secrets to vault')?.command).toBe('opena2a protect');
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
