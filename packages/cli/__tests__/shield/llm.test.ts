import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

import type { ShieldEvent, LlmCache, WeeklyReport } from '../../src/shield/types.js';

// ---------------------------------------------------------------------------
// Mock node:os so that homedir() returns our temp directory.
// ---------------------------------------------------------------------------

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => _mockHomeDir,
  };
});

// Mock @opena2a/shared for LLM consent checks
let _llmEnabled = true;

vi.mock('@opena2a/shared', () => ({
  isLlmEnabled: () => _llmEnabled,
  setLlmEnabled: (v: boolean) => { _llmEnabled = v; },
}));

// Import after mocks
const {
  loadCache,
  saveCache,
  cacheKey,
  getCached,
  callHaiku,
  checkLlmAvailable,
  suggestPolicy,
  explainAnomaly,
  generateNarrative,
  triageIncident,
  getCacheStats,
} = await import('../../src/shield/llm.js');

// ---------------------------------------------------------------------------
// Temp directory setup
// ---------------------------------------------------------------------------

let tempDir: string;
let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-llm-test-'));
  _mockHomeDir = tempDir;
  _llmEnabled = true;
  savedEnv = { ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY };
  process.env.ANTHROPIC_API_KEY = 'test-key-for-unit-tests';
});

afterEach(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
  // Restore env
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

// ===========================================================================
// 1. Cache management
// ===========================================================================

describe('cache management', () => {
  it('loadCache returns empty cache when no file exists', () => {
    const cache = loadCache();
    expect(cache).toEqual({ version: 1, entries: [] });
  });

  it('saveCache + loadCache round-trip', () => {
    const cache: LlmCache = {
      version: 1,
      entries: [{
        key: 'test-key',
        analysisType: 'anomaly-explanation',
        result: {
          eventId: 'evt-1',
          severity: 'medium',
          explanation: 'test',
          riskFactors: ['factor1'],
          suggestedAction: 'investigate',
        },
        createdAt: new Date().toISOString(),
        ttlMs: 60 * 60 * 1000,
        inputTokens: 100,
        outputTokens: 50,
      }],
    };

    saveCache(cache);
    const loaded = loadCache();
    expect(loaded.entries).toHaveLength(1);
    expect(loaded.entries[0].key).toBe('test-key');
  });

  it('saveCache prunes expired entries', () => {
    const cache: LlmCache = {
      version: 1,
      entries: [
        {
          key: 'expired',
          analysisType: 'anomaly-explanation',
          result: {
            eventId: 'old',
            severity: 'info',
            explanation: 'old',
            riskFactors: [],
            suggestedAction: 'ignore',
          },
          createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
          ttlMs: 60 * 60 * 1000, // 1h TTL, created 2h ago
          inputTokens: 50,
          outputTokens: 25,
        },
        {
          key: 'valid',
          analysisType: 'anomaly-explanation',
          result: {
            eventId: 'new',
            severity: 'high',
            explanation: 'new',
            riskFactors: [],
            suggestedAction: 'investigate',
          },
          createdAt: new Date().toISOString(),
          ttlMs: 60 * 60 * 1000,
          inputTokens: 100,
          outputTokens: 50,
        },
      ],
    };

    saveCache(cache);
    const loaded = loadCache();
    expect(loaded.entries).toHaveLength(1);
    expect(loaded.entries[0].key).toBe('valid');
  });

  it('saveCache caps at 200 entries', () => {
    const entries = [];
    for (let i = 0; i < 250; i++) {
      entries.push({
        key: `key-${i}`,
        analysisType: 'anomaly-explanation' as const,
        result: {
          eventId: `evt-${i}`,
          severity: 'info' as const,
          explanation: 'test',
          riskFactors: [],
          suggestedAction: 'ignore' as const,
        },
        createdAt: new Date().toISOString(),
        ttlMs: 7 * 24 * 60 * 60 * 1000,
        inputTokens: 10,
        outputTokens: 5,
      });
    }
    const cache: LlmCache = { version: 1, entries };

    saveCache(cache);
    const loaded = loadCache();
    expect(loaded.entries.length).toBeLessThanOrEqual(200);
  });
});

// ===========================================================================
// 2. Cache key and lookup
// ===========================================================================

describe('cacheKey and getCached', () => {
  it('cacheKey produces deterministic 32-char hex', () => {
    const key1 = cacheKey('anomaly-explanation', 'test-input');
    const key2 = cacheKey('anomaly-explanation', 'test-input');
    expect(key1).toBe(key2);
    expect(key1).toMatch(/^[0-9a-f]{32}$/);
  });

  it('cacheKey differs for different analysis types', () => {
    const k1 = cacheKey('anomaly-explanation', 'same-input');
    const k2 = cacheKey('policy-suggestion', 'same-input');
    expect(k1).not.toBe(k2);
  });

  it('getCached returns entry when valid', () => {
    const cache: LlmCache = {
      version: 1,
      entries: [{
        key: 'my-key',
        analysisType: 'anomaly-explanation',
        result: {
          eventId: 'evt-1',
          severity: 'high',
          explanation: 'found it',
          riskFactors: [],
          suggestedAction: 'investigate',
        },
        createdAt: new Date().toISOString(),
        ttlMs: 60 * 60 * 1000,
        inputTokens: 100,
        outputTokens: 50,
      }],
    };

    const entry = getCached(cache, 'my-key');
    expect(entry).not.toBeNull();
    expect((entry!.result as any).explanation).toBe('found it');
  });

  it('getCached returns null for expired entry', () => {
    const cache: LlmCache = {
      version: 1,
      entries: [{
        key: 'expired-key',
        analysisType: 'anomaly-explanation',
        result: {
          eventId: 'old',
          severity: 'info',
          explanation: 'expired',
          riskFactors: [],
          suggestedAction: 'ignore',
        },
        createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
        ttlMs: 60 * 60 * 1000,
        inputTokens: 50,
        outputTokens: 25,
      }],
    };

    const entry = getCached(cache, 'expired-key');
    expect(entry).toBeNull();
  });

  it('getCached returns null for missing key', () => {
    const cache: LlmCache = { version: 1, entries: [] };
    expect(getCached(cache, 'nonexistent')).toBeNull();
  });
});

// ===========================================================================
// 3. Consent and availability checks
// ===========================================================================

describe('checkLlmAvailable', () => {
  it('returns API key when available and consented', async () => {
    process.env.ANTHROPIC_API_KEY = 'sk-test-key';
    _llmEnabled = true;
    const key = await checkLlmAvailable();
    expect(key).toBe('sk-test-key');
  });

  it('returns null when API key is missing', async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const key = await checkLlmAvailable();
    expect(key).toBeNull();
  });

  it('returns null when LLM is disabled', async () => {
    process.env.ANTHROPIC_API_KEY = 'sk-test-key';
    _llmEnabled = false;
    const key = await checkLlmAvailable();
    expect(key).toBeNull();
  });
});

// ===========================================================================
// 4. API call (mocked)
// ===========================================================================

describe('callHaiku', () => {
  it('returns null when fetch fails', async () => {
    // Use an invalid URL to force failure
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('network error'));

    const result = await callHaiku('system', 'user', 100, 'test-key');
    expect(result).toBeNull();

    globalThis.fetch = originalFetch;
  });

  it('returns parsed response on success', async () => {
    const mockResponse = {
      ok: true,
      json: async () => ({
        content: [{ type: 'text', text: '{"key": "value"}' }],
        usage: { input_tokens: 50, output_tokens: 30 },
      }),
    };
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse);

    const result = await callHaiku('system', 'user', 100, 'test-key');
    expect(result).not.toBeNull();
    expect(result!.text).toBe('{"key": "value"}');
    expect(result!.inputTokens).toBe(50);
    expect(result!.outputTokens).toBe(30);

    globalThis.fetch = originalFetch;
  });

  it('returns null on non-ok response', async () => {
    const mockResponse = { ok: false, status: 401 };
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue(mockResponse);

    const result = await callHaiku('system', 'user', 100, 'test-key');
    expect(result).toBeNull();

    globalThis.fetch = originalFetch;
  });
});

// ===========================================================================
// 5. suggestPolicy (with mocked API)
// ===========================================================================

describe('suggestPolicy', () => {
  it('returns null when LLM is not available', async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const result = await suggestPolicy('claude-code', {
      totalActions: 100,
      totalSessions: 5,
      topProcesses: [{ name: 'git', count: 50 }],
      topCredentials: [],
      topFilePaths: [],
      topNetworkHosts: [],
    });
    expect(result).toBeNull();
  });

  it('returns suggestion when API responds', async () => {
    const apiResponse = JSON.stringify({
      rules: {
        processes: { allow: ['git', 'npm'], deny: ['rm -rf'] },
      },
      reasoning: 'Based on observed safe behavior',
      confidence: 0.9,
    });

    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        content: [{ type: 'text', text: apiResponse }],
        usage: { input_tokens: 200, output_tokens: 100 },
      }),
    });

    const result = await suggestPolicy('claude-code', {
      totalActions: 100,
      totalSessions: 5,
      topProcesses: [{ name: 'git', count: 50 }, { name: 'npm', count: 30 }],
      topCredentials: [],
      topFilePaths: [],
      topNetworkHosts: [],
    });

    expect(result).not.toBeNull();
    expect(result!.agent).toBe('claude-code');
    expect(result!.confidence).toBe(0.9);
    expect(result!.reasoning).toBe('Based on observed safe behavior');

    globalThis.fetch = originalFetch;
  });

  it('uses cache on second call with same input', async () => {
    const apiResponse = JSON.stringify({
      rules: { processes: { allow: ['git'], deny: [] } },
      reasoning: 'Cached result',
      confidence: 0.8,
    });

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        content: [{ type: 'text', text: apiResponse }],
        usage: { input_tokens: 200, output_tokens: 100 },
      }),
    });

    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchMock;

    const input = {
      totalActions: 50,
      totalSessions: 3,
      topProcesses: [{ name: 'tsc', count: 20 }],
      topCredentials: [],
      topFilePaths: [],
      topNetworkHosts: [],
    };

    // First call - hits API
    const result1 = await suggestPolicy('cursor', input);
    expect(result1).not.toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);

    // Second call - should use cache
    const result2 = await suggestPolicy('cursor', input);
    expect(result2).not.toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1); // No additional API call

    globalThis.fetch = originalFetch;
  });
});

// ===========================================================================
// 6. explainAnomaly (with mocked API)
// ===========================================================================

describe('explainAnomaly', () => {
  const makeEvent = (): ShieldEvent => ({
    id: 'evt-anomaly-1',
    timestamp: new Date().toISOString(),
    version: 1,
    source: 'arp',
    category: 'process.spawn',
    severity: 'high',
    agent: 'claude-code',
    sessionId: 'session-1',
    action: 'process.spawn',
    target: 'aws s3 ls',
    outcome: 'monitored',
    detail: {},
    prevHash: 'abc',
    eventHash: 'def',
    orgId: null,
    managed: false,
    agentId: null,
  });

  it('returns null when LLM is not available', async () => {
    delete process.env.ANTHROPIC_API_KEY;
    const result = await explainAnomaly(makeEvent(), {
      agentName: 'claude-code',
      normalActions: ['git status', 'npm test'],
      isFirstOccurrence: true,
    });
    expect(result).toBeNull();
  });

  it('returns explanation when API responds', async () => {
    const apiResponse = JSON.stringify({
      severity: 'high',
      explanation: 'AWS S3 access is unusual for this agent which normally only runs git and npm.',
      riskFactors: ['first occurrence', 'cloud access'],
      suggestedAction: 'investigate',
    });

    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        content: [{ type: 'text', text: apiResponse }],
        usage: { input_tokens: 150, output_tokens: 60 },
      }),
    });

    const result = await explainAnomaly(makeEvent(), {
      agentName: 'claude-code',
      normalActions: ['git status', 'npm test'],
      isFirstOccurrence: true,
    });

    expect(result).not.toBeNull();
    expect(result!.eventId).toBe('evt-anomaly-1');
    expect(result!.severity).toBe('high');
    expect(result!.suggestedAction).toBe('investigate');
    expect(result!.riskFactors).toContain('first occurrence');

    globalThis.fetch = originalFetch;
  });
});

// ===========================================================================
// 7. generateNarrative (with mocked API)
// ===========================================================================

describe('generateNarrative', () => {
  const makeReport = (): WeeklyReport => ({
    version: 1,
    generatedAt: new Date().toISOString(),
    periodStart: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
    periodEnd: new Date().toISOString(),
    hostname: 'test-host',
    agentActivity: {
      totalSessions: 15,
      totalActions: 342,
      byAgent: {
        'claude-code': {
          sessions: 12,
          actions: 300,
          firstSeen: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
          lastSeen: new Date().toISOString(),
          topActions: [{ action: 'git status', count: 50 }],
        },
      },
    },
    policyEvaluation: {
      monitored: 300,
      wouldBlock: 5,
      blocked: 0,
      topViolations: [],
    },
    credentialExposure: {
      accessAttempts: 3,
      uniqueCredentials: 1,
      byProvider: { aws: 3 },
      recommendations: [],
    },
    supplyChain: {
      packagesInstalled: 12,
      advisoriesFound: 0,
      blockedInstalls: 0,
      lowTrustPackages: [],
    },
    configIntegrity: {
      filesMonitored: 5,
      tamperedFiles: [],
      signatureStatus: 'valid',
    },
    runtimeProtection: {
      arpActive: true,
      processesSpawned: 200,
      networkConnections: 50,
      anomalies: 1,
    },
    posture: {
      score: 82,
      grade: 'B+',
      factors: [],
      trend: 'stable',
      comparative: null,
    },
  });

  it('returns narrative when API responds', async () => {
    const apiResponse = JSON.stringify({
      summary: 'Your workstation security is in good shape.',
      highlights: ['No policy violations detected'],
      concerns: ['3 AWS credential access attempts observed'],
      recommendations: ['Consider migrating AWS credentials to vault'],
    });

    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        content: [{ type: 'text', text: apiResponse }],
        usage: { input_tokens: 300, output_tokens: 80 },
      }),
    });

    const result = await generateNarrative(makeReport());
    expect(result).not.toBeNull();
    expect(result!.summary).toContain('good shape');
    expect(result!.highlights).toHaveLength(1);
    expect(result!.concerns).toHaveLength(1);
    expect(result!.recommendations).toHaveLength(1);

    globalThis.fetch = originalFetch;
  });
});

// ===========================================================================
// 8. triageIncident (with mocked API)
// ===========================================================================

describe('triageIncident', () => {
  it('returns triage when API responds', async () => {
    const events: ShieldEvent[] = [
      {
        id: 'evt-1',
        timestamp: new Date().toISOString(),
        version: 1,
        source: 'arp',
        category: 'process.spawn',
        severity: 'critical',
        agent: 'claude-code',
        sessionId: 's1',
        action: 'process.spawn',
        target: 'aws iam create-access-key',
        outcome: 'monitored',
        detail: {},
        prevHash: 'a',
        eventHash: 'b',
        orgId: null,
        managed: false,
        agentId: null,
      },
      {
        id: 'evt-2',
        timestamp: new Date().toISOString(),
        version: 1,
        source: 'arp',
        category: 'process.spawn',
        severity: 'high',
        agent: 'claude-code',
        sessionId: 's1',
        action: 'process.spawn',
        target: 'aws s3 cp s3://prod-data .',
        outcome: 'monitored',
        detail: {},
        prevHash: 'b',
        eventHash: 'c',
        orgId: null,
        managed: false,
        agentId: null,
      },
    ];

    const apiResponse = JSON.stringify({
      classification: 'suspicious',
      severity: 'high',
      explanation: 'Agent created IAM keys and downloaded from S3 in the same session.',
      responseSteps: ['Review IAM key creation', 'Check S3 access logs', 'Revoke if unauthorized'],
    });

    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        content: [{ type: 'text', text: apiResponse }],
        usage: { input_tokens: 250, output_tokens: 90 },
      }),
    });

    const result = await triageIncident(events, {
      policyMode: 'monitor',
      agentName: 'claude-code',
      recentBaseline: ['git status', 'npm test', 'tsc'],
    });

    expect(result).not.toBeNull();
    expect(result!.classification).toBe('suspicious');
    expect(result!.severity).toBe('high');
    expect(result!.eventIds).toEqual(['evt-1', 'evt-2']);
    expect(result!.responseSteps.length).toBeGreaterThan(0);

    globalThis.fetch = originalFetch;
  });
});

// ===========================================================================
// 9. getCacheStats
// ===========================================================================

describe('getCacheStats', () => {
  it('returns zero stats for empty cache', () => {
    const stats = getCacheStats();
    expect(stats.totalEntries).toBe(0);
    expect(stats.validEntries).toBe(0);
    expect(stats.totalInputTokens).toBe(0);
    expect(stats.estimatedCostUsd).toBe(0);
  });

  it('computes stats from cached entries', () => {
    const cache: LlmCache = {
      version: 1,
      entries: [
        {
          key: 'k1',
          analysisType: 'anomaly-explanation',
          result: {
            eventId: 'e1',
            severity: 'info',
            explanation: 'test',
            riskFactors: [],
            suggestedAction: 'ignore',
          },
          createdAt: new Date().toISOString(),
          ttlMs: 7 * 24 * 60 * 60 * 1000,
          inputTokens: 1000,
          outputTokens: 500,
        },
        {
          key: 'k2',
          analysisType: 'policy-suggestion',
          result: {
            agent: 'test',
            rules: {},
            reasoning: 'test',
            confidence: 0.8,
            basedOnActions: 100,
            basedOnSessions: 5,
          },
          createdAt: new Date().toISOString(),
          ttlMs: 24 * 60 * 60 * 1000,
          inputTokens: 2000,
          outputTokens: 1000,
        },
      ],
    };
    saveCache(cache);

    const stats = getCacheStats();
    expect(stats.totalEntries).toBe(2);
    expect(stats.validEntries).toBe(2);
    expect(stats.totalInputTokens).toBe(3000);
    expect(stats.totalOutputTokens).toBe(1500);
    expect(stats.estimatedCostUsd).toBeGreaterThan(0);
    expect(stats.byType['anomaly-explanation']).toBe(1);
    expect(stats.byType['policy-suggestion']).toBe(1);
  });
});
