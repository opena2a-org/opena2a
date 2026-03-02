import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  verifyGeminiAccess,
  verifyDriftFindings,
  applyLivenessResults,
} from '../../src/util/drift-verification.js';
import type { CredentialMatch } from '../../src/util/credential-patterns.js';

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function makeDriftMatch(overrides: Partial<CredentialMatch> = {}): CredentialMatch {
  return {
    value: 'AIza' + 'X'.repeat(35),
    filePath: '/tmp/test/config.ts',
    line: 5,
    findingId: 'DRIFT-001',
    envVar: 'GOOGLE_API_KEY',
    severity: 'high',
    title: 'Google API Key (Gemini drift risk)',
    explanation: 'Google API key may have been provisioned for Maps.',
    businessImpact: 'Attacker could run AI workloads billed to your account.',
    ...overrides,
  };
}

function makeCredMatch(overrides: Partial<CredentialMatch> = {}): CredentialMatch {
  return {
    value: 'sk-ant-api03-' + 'A'.repeat(80),
    filePath: '/tmp/test/config.ts',
    line: 3,
    findingId: 'CRED-001',
    envVar: 'ANTHROPIC_API_KEY',
    severity: 'critical',
    title: 'Anthropic API Key',
    explanation: 'Anthropic API key hardcoded.',
    businessImpact: 'Unauthorized API charges.',
    ...overrides,
  };
}

describe('verifyGeminiAccess', () => {
  it('returns live=true and escalates severity on 200', async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      json: async () => ({ models: [{ name: 'gemini-pro' }, { name: 'gemini-1.5-flash' }] }),
    });

    const result = await verifyGeminiAccess('AIzaTestKey123456789012345678901234');

    expect(result.checked).toBe(true);
    expect(result.live).toBe(true);
    expect(result.escalatedSeverity).toBe('critical');
    expect(result.originalSeverity).toBe('high');
    expect(result.detail).toContain('2 model(s)');
    expect(result.error).toBeUndefined();
  });

  it('returns live=true even if response body parsing fails', async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      json: async () => { throw new Error('bad json'); },
    });

    const result = await verifyGeminiAccess('AIzaTestKey123456789012345678901234');

    expect(result.live).toBe(true);
    expect(result.escalatedSeverity).toBe('critical');
    expect(result.detail).toContain('authenticates to Generative Language API');
  });

  it('returns live=false on 403', async () => {
    mockFetch.mockResolvedValueOnce({
      status: 403,
      json: async () => ({ error: { message: 'forbidden' } }),
    });

    const result = await verifyGeminiAccess('AIzaTestKey123456789012345678901234');

    expect(result.checked).toBe(true);
    expect(result.live).toBe(false);
    expect(result.escalatedSeverity).toBe('high');
    expect(result.detail).toContain('No Gemini access');
  });

  it('returns live=false on 401', async () => {
    mockFetch.mockResolvedValueOnce({
      status: 401,
      json: async () => ({}),
    });

    const result = await verifyGeminiAccess('AIzaTestKey123456789012345678901234');

    expect(result.live).toBe(false);
    expect(result.detail).toContain('No Gemini access');
  });

  it('returns live=false on 400', async () => {
    mockFetch.mockResolvedValueOnce({
      status: 400,
      json: async () => ({}),
    });

    const result = await verifyGeminiAccess('AIzaTestKey123456789012345678901234');

    expect(result.live).toBe(false);
    expect(result.detail).toContain('revoked or restricted');
  });

  it('handles network errors gracefully', async () => {
    mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

    const result = await verifyGeminiAccess('AIzaTestKey123456789012345678901234');

    expect(result.checked).toBe(true);
    expect(result.live).toBe(false);
    expect(result.error).toBe('ECONNREFUSED');
    expect(result.detail).toContain('Network error');
  });

  it('handles AbortError (timeout) gracefully', async () => {
    const abortError = new Error('The operation was aborted');
    abortError.name = 'AbortError';
    mockFetch.mockRejectedValueOnce(abortError);

    const result = await verifyGeminiAccess('AIzaTestKey123456789012345678901234');

    expect(result.checked).toBe(true);
    expect(result.live).toBe(false);
    expect(result.error).toBe('timeout');
    expect(result.detail).toContain('timed out');
  });

  it('calls the correct Google API endpoint', async () => {
    mockFetch.mockResolvedValueOnce({ status: 403 });

    await verifyGeminiAccess('AIzaMyTestKey1234567890');

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe('https://generativelanguage.googleapis.com/v1beta/models?key=AIzaMyTestKey1234567890');
    expect(opts.method).toBe('GET');
    expect(opts.headers['User-Agent']).toBe('opena2a-drift-check/1.0');
  });
});

describe('verifyDriftFindings', () => {
  it('skips non-DRIFT findings', async () => {
    const matches = [makeCredMatch()];
    const results = await verifyDriftFindings(matches);

    expect(results.size).toBe(0);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('deduplicates same key value', async () => {
    mockFetch.mockResolvedValue({ status: 403 });

    const key = 'AIza' + 'D'.repeat(35);
    const matches = [
      makeDriftMatch({ value: key, filePath: '/a/config.ts' }),
      makeDriftMatch({ value: key, filePath: '/b/config.ts' }),
    ];

    const results = await verifyDriftFindings(matches);

    expect(results.size).toBe(1);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it('verifies multiple unique keys', async () => {
    mockFetch
      .mockResolvedValueOnce({
        status: 200,
        json: async () => ({ models: [{ name: 'gemini-pro' }] }),
      })
      .mockResolvedValueOnce({ status: 403 });

    const matches = [
      makeDriftMatch({ value: 'AIza' + 'A'.repeat(35) }),
      makeDriftMatch({ value: 'AIza' + 'B'.repeat(35) }),
    ];

    const results = await verifyDriftFindings(matches);

    expect(results.size).toBe(2);
    expect(mockFetch).toHaveBeenCalledTimes(2);

    const resultA = results.get('AIza' + 'A'.repeat(35))!;
    expect(resultA.live).toBe(true);

    const resultB = results.get('AIza' + 'B'.repeat(35))!;
    expect(resultB.live).toBe(false);
  });

  it('handles unknown DRIFT IDs gracefully', async () => {
    const matches = [makeDriftMatch({ findingId: 'DRIFT-999' })];

    const results = await verifyDriftFindings(matches);

    expect(results.size).toBe(1);
    const result = results.get(matches[0].value)!;
    expect(result.checked).toBe(false);
    expect(result.detail).toContain('No liveness check available');
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

describe('applyLivenessResults', () => {
  it('escalates severity for confirmed drift', () => {
    const matches = [makeDriftMatch()];
    const livenessResults = new Map([
      [matches[0].value, {
        findingId: 'DRIFT-001',
        checked: true,
        live: true,
        originalSeverity: 'high',
        escalatedSeverity: 'critical',
        detail: 'Gemini access confirmed: key can reach 5 model(s)',
      }],
    ]);

    const updated = applyLivenessResults(matches, livenessResults);

    expect(updated[0].severity).toBe('critical');
    expect(updated[0].explanation).toContain('CONFIRMED');
    expect(updated[0].explanation).toContain('5 model(s)');
    expect(updated[0].businessImpact).toContain('active exposure');
  });

  it('preserves non-DRIFT matches', () => {
    const credMatch = makeCredMatch();
    const driftMatch = makeDriftMatch();

    const livenessResults = new Map([
      [driftMatch.value, {
        findingId: 'DRIFT-001',
        checked: true,
        live: true,
        originalSeverity: 'high',
        escalatedSeverity: 'critical',
        detail: 'Gemini access confirmed',
      }],
    ]);

    const updated = applyLivenessResults([credMatch, driftMatch], livenessResults);

    // CRED-001 unchanged
    expect(updated[0].severity).toBe('critical');
    expect(updated[0].explanation).toBe(credMatch.explanation);

    // DRIFT-001 escalated
    expect(updated[1].severity).toBe('critical');
    expect(updated[1].explanation).toContain('CONFIRMED');
  });

  it('appends verification note for checked but not live', () => {
    const matches = [makeDriftMatch()];
    const livenessResults = new Map([
      [matches[0].value, {
        findingId: 'DRIFT-001',
        checked: true,
        live: false,
        originalSeverity: 'high',
        escalatedSeverity: 'high',
        detail: 'No Gemini access: key is restricted',
      }],
    ]);

    const updated = applyLivenessResults(matches, livenessResults);

    expect(updated[0].severity).toBe('high');
    expect(updated[0].explanation).toContain('Verification:');
    expect(updated[0].explanation).toContain('restricted');
  });

  it('does not modify matches with errors', () => {
    const matches = [makeDriftMatch()];
    const livenessResults = new Map([
      [matches[0].value, {
        findingId: 'DRIFT-001',
        checked: true,
        live: false,
        originalSeverity: 'high',
        escalatedSeverity: 'high',
        detail: 'Network error',
        error: 'ECONNREFUSED',
      }],
    ]);

    const updated = applyLivenessResults(matches, livenessResults);

    // Original explanation preserved (no "Verification:" appended for errors)
    expect(updated[0].explanation).toBe(matches[0].explanation);
  });

  it('does not mutate original matches', () => {
    const original = makeDriftMatch();
    const originalSeverity = original.severity;
    const originalExplanation = original.explanation;

    const livenessResults = new Map([
      [original.value, {
        findingId: 'DRIFT-001',
        checked: true,
        live: true,
        originalSeverity: 'high',
        escalatedSeverity: 'critical',
        detail: 'Gemini access confirmed',
      }],
    ]);

    applyLivenessResults([original], livenessResults);

    expect(original.severity).toBe(originalSeverity);
    expect(original.explanation).toBe(originalExplanation);
  });
});
