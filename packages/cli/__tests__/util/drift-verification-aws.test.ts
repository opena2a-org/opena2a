import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  verifyBedrockAccess,
  verifyDriftFindings,
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

function makeAwsDriftMatch(overrides: Partial<CredentialMatch> = {}): CredentialMatch {
  return {
    value: 'AKIAIOSFODNN7EXAMPLE',
    filePath: '/tmp/test/config.ts',
    line: 5,
    findingId: 'DRIFT-002',
    envVar: 'AWS_ACCESS_KEY_ID',
    severity: 'high',
    title: 'AWS Access Key (Bedrock drift risk)',
    explanation: 'AWS access key may have Bedrock AI access.',
    businessImpact: 'Attacker could run AI workloads on your AWS account.',
    ...overrides,
  };
}

describe('verifyBedrockAccess', () => {
  it('returns checked=false when no secret key provided', async () => {
    const result = await verifyBedrockAccess('AKIAIOSFODNN7EXAMPLE');

    expect(result.checked).toBe(false);
    expect(result.live).toBe(false);
    expect(result.detail).toContain('Secret access key not found');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('returns live=true and escalates severity when STS returns 200', async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      text: async () => '<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/test</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>',
    });
    // Mock Bedrock returning 403 (no access)
    mockFetch.mockResolvedValueOnce({ status: 403 });

    const result = await verifyBedrockAccess('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');

    expect(result.checked).toBe(true);
    expect(result.live).toBe(true);
    expect(result.escalatedSeverity).toBe('critical');
    expect(result.detail).toContain('Account 123456789012');
    expect(result.detail).toContain('No Bedrock access');
  });

  it('returns live=true with Bedrock access when both STS and Bedrock return 200', async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      text: async () => '<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/test</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>',
    });
    mockFetch.mockResolvedValueOnce({
      status: 200,
      json: async () => ({ modelSummaries: [{ modelId: 'anthropic.claude-v2' }, { modelId: 'amazon.titan-text-express-v1' }] }),
    });

    const result = await verifyBedrockAccess('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');

    expect(result.live).toBe(true);
    expect(result.escalatedSeverity).toBe('critical');
    expect(result.detail).toContain('Bedrock access confirmed');
    expect(result.detail).toContain('2 foundation model(s)');
  });

  it('returns live=false when STS returns 403 (dead key)', async () => {
    mockFetch.mockResolvedValueOnce({ status: 403 });

    const result = await verifyBedrockAccess('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');

    expect(result.checked).toBe(true);
    expect(result.live).toBe(false);
    expect(result.detail).toContain('invalid or expired');
    expect(mockFetch).toHaveBeenCalledTimes(1); // Only STS call, no Bedrock call
  });

  it('handles network timeout', async () => {
    const abortError = new Error('The operation was aborted');
    abortError.name = 'AbortError';
    mockFetch.mockRejectedValueOnce(abortError);

    const result = await verifyBedrockAccess('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');

    expect(result.live).toBe(false);
    expect(result.error).toBe('timeout');
  });

  it('handles network errors gracefully', async () => {
    mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

    const result = await verifyBedrockAccess('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');

    expect(result.live).toBe(false);
    expect(result.error).toBe('ECONNREFUSED');
  });

  it('sends correct STS request with SigV4 signature', async () => {
    mockFetch.mockResolvedValueOnce({ status: 403 });

    await verifyBedrockAccess('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe('https://sts.amazonaws.com/');
    expect(opts.method).toBe('POST');
    expect(opts.body).toBe('Action=GetCallerIdentity&Version=2011-06-15');
    expect(opts.headers['Authorization']).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/);
    expect(opts.headers['X-Amz-Date']).toMatch(/^\d{8}T\d{6}Z$/);
    expect(opts.headers['User-Agent']).toBe('opena2a-drift-check/1.0');
  });

  it('handles Bedrock check failure gracefully after STS success', async () => {
    mockFetch.mockResolvedValueOnce({
      status: 200,
      text: async () => '<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/test</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>',
    });
    // Bedrock throws network error
    mockFetch.mockRejectedValueOnce(new Error('ECONNRESET'));

    const result = await verifyBedrockAccess('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');

    expect(result.live).toBe(true);
    expect(result.escalatedSeverity).toBe('critical');
    expect(result.detail).toContain('Bedrock check inconclusive');
    expect(result.detail).toContain('still live');
  });
});

describe('verifyDriftFindings with DRIFT-002', () => {
  it('handles DRIFT-002 matches', async () => {
    // DRIFT-002 without a nearby secret key should return checked: false
    // since findSecretKeyNearAccessKey reads the file
    const matches = [makeAwsDriftMatch()];

    const results = await verifyDriftFindings(matches);

    expect(results.size).toBe(1);
    const result = results.get('AKIAIOSFODNN7EXAMPLE')!;
    // File doesn't exist in test environment, so secret key won't be found
    expect(result.checked).toBe(false);
    expect(result.detail).toContain('Secret access key not found');
  });
});
