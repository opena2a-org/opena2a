/**
 * Shield LLM Intelligence Layer
 *
 * Uses Claude Haiku for lightweight, cost-efficient security analysis:
 *   1. Policy suggestions from observed agent behavior
 *   2. Anomaly explanations for unusual actions
 *   3. Weekly report narrative generation
 *   4. Incident triage and severity classification
 *
 * Design principles:
 *   - Batch processing: aggregate events, analyze in bulk (not per-event)
 *   - Aggressive caching: file-based cache with TTLs per analysis type
 *   - Graceful degradation: returns null if no API key or no consent
 *   - Cost target: <$1/month at typical usage (~$0.40/month estimated)
 *   - Zero network by default: only calls API when LLM is explicitly enabled
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type {
  AnomalyExplanation,
  EventSeverity,
  IncidentTriage,
  LlmAnalysisType,
  LlmCache,
  LlmCacheEntry,
  PolicyRules,
  PolicySuggestion,
  ReportNarrative,
  ShieldEvent,
  WeeklyReport,
} from './types.js';

import {
  LLM_CACHE_TTL_ANOMALY,
  LLM_CACHE_TTL_NARRATIVE,
  LLM_CACHE_TTL_POLICY,
  LLM_CACHE_TTL_TRIAGE,
  SHIELD_LLM_CACHE_FILE,
} from './types.js';

import { getShieldDir } from './events.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MODEL = 'claude-haiku-4-5-20251001';
const API_URL = 'https://api.anthropic.com/v1/messages';
const API_VERSION = '2023-06-01';
const REQUEST_TIMEOUT_MS = 15_000;

// Max tokens per analysis type (minimize cost)
const MAX_TOKENS: Record<LlmAnalysisType, number> = {
  'policy-suggestion': 500,
  'anomaly-explanation': 200,
  'report-narrative': 400,
  'incident-triage': 300,
};

// ---------------------------------------------------------------------------
// Cache management
// ---------------------------------------------------------------------------

function getCachePath(): string {
  return join(getShieldDir(), SHIELD_LLM_CACHE_FILE);
}

/** Load the LLM response cache from disk. */
export function loadCache(): LlmCache {
  const cachePath = getCachePath();
  if (!existsSync(cachePath)) {
    return { version: 1, entries: [] };
  }
  try {
    const raw = readFileSync(cachePath, 'utf-8');
    const parsed = JSON.parse(raw) as LlmCache;
    if (parsed.version !== 1) return { version: 1, entries: [] };
    return parsed;
  } catch {
    return { version: 1, entries: [] };
  }
}

/** Save the cache to disk, pruning expired entries. */
export function saveCache(cache: LlmCache): void {
  const now = Date.now();
  // Prune expired entries before saving
  cache.entries = cache.entries.filter(entry => {
    const created = new Date(entry.createdAt).getTime();
    return now - created < entry.ttlMs;
  });
  // Cap at 200 entries to prevent unbounded growth
  if (cache.entries.length > 200) {
    cache.entries = cache.entries.slice(-200);
  }
  try {
    writeFileSync(getCachePath(), JSON.stringify(cache, null, 2), { mode: 0o600 });
  } catch {
    // Best effort
  }
}

/** Compute a cache key from input data. */
export function cacheKey(analysisType: LlmAnalysisType, input: string): string {
  return createHash('sha256').update(`${analysisType}:${input}`).digest('hex').slice(0, 32);
}

/** Look up a cached result. Returns null if not found or expired. */
export function getCached(
  cache: LlmCache,
  key: string,
): LlmCacheEntry | null {
  const now = Date.now();
  const entry = cache.entries.find(e => e.key === key);
  if (!entry) return null;
  const created = new Date(entry.createdAt).getTime();
  if (now - created >= entry.ttlMs) return null;
  return entry;
}

function getTtl(analysisType: LlmAnalysisType): number {
  switch (analysisType) {
    case 'policy-suggestion': return LLM_CACHE_TTL_POLICY;
    case 'anomaly-explanation': return LLM_CACHE_TTL_ANOMALY;
    case 'report-narrative': return LLM_CACHE_TTL_NARRATIVE;
    case 'incident-triage': return LLM_CACHE_TTL_TRIAGE;
  }
}

// ---------------------------------------------------------------------------
// API call
// ---------------------------------------------------------------------------

interface ApiResponse {
  content: Array<{ type: string; text: string }>;
  usage?: { input_tokens: number; output_tokens: number };
}

/**
 * Make a single API call to Claude Haiku.
 * Returns the text response and token usage, or null on failure.
 */
export async function callHaiku(
  systemPrompt: string,
  userPrompt: string,
  maxTokens: number,
  apiKey: string,
): Promise<{ text: string; inputTokens: number; outputTokens: number } | null> {
  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': API_VERSION,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: MODEL,
        max_tokens: maxTokens,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) return null;

    const data = (await response.json()) as ApiResponse;
    const text = data.content?.[0]?.text;
    if (!text) return null;

    return {
      text,
      inputTokens: data.usage?.input_tokens ?? 0,
      outputTokens: data.usage?.output_tokens ?? 0,
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Consent & availability check
// ---------------------------------------------------------------------------

/**
 * Check if LLM intelligence is available (API key + consent).
 * Returns the API key if available, null otherwise.
 */
export async function checkLlmAvailable(): Promise<string | null> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return null;

  try {
    const shared = await import('@opena2a/shared');
    const mod = 'default' in shared ? (shared as any).default : shared;
    if (typeof mod?.isLlmEnabled !== 'function') return null;
    if (!mod.isLlmEnabled()) return null;
  } catch {
    // shared not available -- deny (require explicit consent)
    return null;
  }

  return apiKey;
}

// ---------------------------------------------------------------------------
// 1. Policy Suggestion
// ---------------------------------------------------------------------------

const POLICY_SYSTEM_PROMPT = `You are a security policy advisor for AI coding agents. Analyze the observed agent behavior and recommend a security policy.

Respond with ONLY a JSON object matching this schema:
{
  "rules": {
    "processes": { "allow": ["list of safe commands"], "deny": ["list of dangerous commands"] },
    "credentials": { "allow": [], "deny": ["patterns that should be blocked"] },
    "filesystem": { "allow": ["safe paths"], "deny": ["sensitive paths"] },
    "network": { "allow": [], "deny": [] }
  },
  "reasoning": "1-2 sentence explanation",
  "confidence": 0.85
}

Focus on the most impactful rules. Keep allow/deny lists concise (max 15 items each).
Only include rules where you have strong evidence from the observed behavior.`;

/**
 * Analyze observed agent behavior and suggest a security policy.
 *
 * Input: summarized event data (not raw events -- pre-aggregated to save tokens).
 */
export async function suggestPolicy(
  agent: string,
  behaviorSummary: {
    totalActions: number;
    totalSessions: number;
    topProcesses: { name: string; count: number }[];
    topCredentials: { name: string; count: number }[];
    topFilePaths: { path: string; count: number }[];
    topNetworkHosts: { host: string; count: number }[];
  },
): Promise<PolicySuggestion | null> {
  const apiKey = await checkLlmAvailable();
  if (!apiKey) return null;

  // Build cache key from behavior summary
  const summaryKey = JSON.stringify({
    agent,
    actions: behaviorSummary.totalActions,
    sessions: behaviorSummary.totalSessions,
    procs: behaviorSummary.topProcesses.map(p => p.name).sort(),
  });
  const key = cacheKey('policy-suggestion', summaryKey);

  // Check cache
  const cache = loadCache();
  const cached = getCached(cache, key);
  if (cached) return cached.result as PolicySuggestion;

  // Build prompt
  const userPrompt = `Agent: ${agent}
Observed over ${behaviorSummary.totalSessions} sessions, ${behaviorSummary.totalActions} total actions.

Top processes spawned:
${behaviorSummary.topProcesses.slice(0, 20).map(p => `  ${p.name} (${p.count}x)`).join('\n')}

Credential access patterns:
${behaviorSummary.topCredentials.slice(0, 10).map(c => `  ${c.name} (${c.count}x)`).join('\n') || '  (none observed)'}

Filesystem paths accessed:
${behaviorSummary.topFilePaths.slice(0, 15).map(f => `  ${f.path} (${f.count}x)`).join('\n') || '  (none observed)'}

Network connections:
${behaviorSummary.topNetworkHosts.slice(0, 10).map(n => `  ${n.host} (${n.count}x)`).join('\n') || '  (none observed)'}

Generate a security policy that allows the observed safe behavior and blocks potentially dangerous actions.`;

  const result = await callHaiku(
    POLICY_SYSTEM_PROMPT,
    userPrompt,
    MAX_TOKENS['policy-suggestion'],
    apiKey,
  );
  if (!result) return null;

  try {
    const parsed = JSON.parse(result.text) as {
      rules: Partial<PolicyRules>;
      reasoning: string;
      confidence: number;
    };

    const suggestion: PolicySuggestion = {
      agent,
      rules: typeof parsed.rules === 'object' && parsed.rules !== null ? parsed.rules : {},
      reasoning: typeof parsed.reasoning === 'string' ? parsed.reasoning : '',
      confidence: Math.max(0, Math.min(1, typeof parsed.confidence === 'number' ? parsed.confidence : 0.5)),
      basedOnActions: behaviorSummary.totalActions,
      basedOnSessions: behaviorSummary.totalSessions,
    };

    // Cache the result
    cache.entries.push({
      key,
      analysisType: 'policy-suggestion',
      result: suggestion,
      createdAt: new Date().toISOString(),
      ttlMs: getTtl('policy-suggestion'),
      inputTokens: result.inputTokens,
      outputTokens: result.outputTokens,
    });
    saveCache(cache);

    return suggestion;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 2. Anomaly Explanation
// ---------------------------------------------------------------------------

const ANOMALY_SYSTEM_PROMPT = `You are a security analyst reviewing AI agent actions on a developer workstation. Explain why the flagged action is anomalous and assess its risk.

Respond with ONLY a JSON object:
{
  "severity": "info|low|medium|high|critical",
  "explanation": "1-2 sentence explanation of why this is anomalous",
  "riskFactors": ["factor1", "factor2"],
  "suggestedAction": "ignore|investigate|block"
}

Be concise. Focus on actual risk, not theoretical concerns.`;

/**
 * Explain why a specific event or action is anomalous.
 *
 * Designed for batch use: call with a few flagged events, not every event.
 */
export async function explainAnomaly(
  event: ShieldEvent,
  context: {
    agentName: string;
    normalActions: string[];  // typical actions this agent performs
    isFirstOccurrence: boolean;
  },
): Promise<AnomalyExplanation | null> {
  const apiKey = await checkLlmAvailable();
  if (!apiKey) return null;

  const key = cacheKey('anomaly-explanation', `${event.id}:${event.action}:${event.target}`);

  const cache = loadCache();
  const cached = getCached(cache, key);
  if (cached) return cached.result as AnomalyExplanation;

  const userPrompt = `Agent "${context.agentName}" performed an action that may be anomalous.

Action: ${event.action}
Target: ${event.target}
Category: ${event.category}
Source: ${event.source}
First time: ${context.isFirstOccurrence ? 'yes' : 'no'}

Normal behavior for this agent:
${context.normalActions.slice(0, 10).map(a => `  - ${a}`).join('\n')}

Assess this action.`;

  const result = await callHaiku(
    ANOMALY_SYSTEM_PROMPT,
    userPrompt,
    MAX_TOKENS['anomaly-explanation'],
    apiKey,
  );
  if (!result) return null;

  try {
    const parsed = JSON.parse(result.text) as {
      severity: EventSeverity;
      explanation: string;
      riskFactors: string[];
      suggestedAction: 'ignore' | 'investigate' | 'block';
    };

    // Validate enum fields against allowlists
    const validSeverities = ['info', 'low', 'medium', 'high', 'critical'];
    const validActions = ['ignore', 'investigate', 'block'];
    const severity = validSeverities.includes(parsed.severity) ? parsed.severity : event.severity;
    const suggestedAction = validActions.includes(parsed.suggestedAction)
      ? parsed.suggestedAction : 'investigate';

    const explanation: AnomalyExplanation = {
      eventId: event.id,
      severity,
      explanation: typeof parsed.explanation === 'string' ? parsed.explanation : '',
      riskFactors: Array.isArray(parsed.riskFactors)
        ? parsed.riskFactors.filter((f: unknown) => typeof f === 'string') : [],
      suggestedAction,
    };

    cache.entries.push({
      key,
      analysisType: 'anomaly-explanation',
      result: explanation,
      createdAt: new Date().toISOString(),
      ttlMs: getTtl('anomaly-explanation'),
      inputTokens: result.inputTokens,
      outputTokens: result.outputTokens,
    });
    saveCache(cache);

    return explanation;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 3. Report Narrative
// ---------------------------------------------------------------------------

const NARRATIVE_SYSTEM_PROMPT = `You are a security report writer for AI agent workstation security. Generate a concise, actionable narrative for a weekly security report.

Respond with ONLY a JSON object:
{
  "summary": "2-3 sentence overall summary",
  "highlights": ["positive finding 1", "positive finding 2"],
  "concerns": ["concern 1", "concern 2"],
  "recommendations": ["actionable recommendation 1", "actionable recommendation 2"]
}

Use clear, non-alarmist language. Focus on actionable insights. Max 3 items per array.`;

/**
 * Generate a human-readable narrative for a weekly report.
 *
 * Input: pre-computed report metrics (not raw events).
 */
export async function generateNarrative(
  report: WeeklyReport,
): Promise<ReportNarrative | null> {
  const apiKey = await checkLlmAvailable();
  if (!apiKey) return null;

  const key = cacheKey('report-narrative', `${report.periodStart}:${report.periodEnd}`);

  const cache = loadCache();
  const cached = getCached(cache, key);
  if (cached) return cached.result as ReportNarrative;

  const userPrompt = `Weekly Security Report (${report.periodStart.slice(0, 10)} to ${report.periodEnd.slice(0, 10)})

Agent Activity:
  Total sessions: ${report.agentActivity.totalSessions}
  Total actions: ${report.agentActivity.totalActions}
  Agents: ${Object.keys(report.agentActivity.byAgent).join(', ') || 'none'}

Policy Evaluation:
  Monitored: ${report.policyEvaluation.monitored}
  Would block: ${report.policyEvaluation.wouldBlock}
  Blocked: ${report.policyEvaluation.blocked}
  Top violations: ${report.policyEvaluation.topViolations.slice(0, 3).map(v => `${v.action} (${v.count}x, ${v.severity})`).join(', ') || 'none'}

Credential Exposure:
  Access attempts: ${report.credentialExposure.accessAttempts}
  Unique credentials: ${report.credentialExposure.uniqueCredentials}
  Providers: ${Object.entries(report.credentialExposure.byProvider).map(([k, v]) => `${k}: ${v}`).join(', ') || 'none'}

Supply Chain:
  Packages installed: ${report.supplyChain.packagesInstalled}
  Advisories: ${report.supplyChain.advisoriesFound}
  Blocked installs: ${report.supplyChain.blockedInstalls}

Config Integrity: ${report.configIntegrity.signatureStatus}
  Tampered files: ${report.configIntegrity.tamperedFiles.length}

Posture Score: ${report.posture.score}/100 (${report.posture.grade})
Trend: ${report.posture.trend ?? 'first report'}

Generate a weekly narrative.`;

  const result = await callHaiku(
    NARRATIVE_SYSTEM_PROMPT,
    userPrompt,
    MAX_TOKENS['report-narrative'],
    apiKey,
  );
  if (!result) return null;

  try {
    const parsed = JSON.parse(result.text) as ReportNarrative;

    const filterStrings = (arr: unknown): string[] =>
      Array.isArray(arr) ? arr.filter((s: unknown) => typeof s === 'string') : [];

    const narrative: ReportNarrative = {
      summary: typeof parsed.summary === 'string' ? parsed.summary : '',
      highlights: filterStrings(parsed.highlights),
      concerns: filterStrings(parsed.concerns),
      recommendations: filterStrings(parsed.recommendations),
    };

    cache.entries.push({
      key,
      analysisType: 'report-narrative',
      result: narrative,
      createdAt: new Date().toISOString(),
      ttlMs: getTtl('report-narrative'),
      inputTokens: result.inputTokens,
      outputTokens: result.outputTokens,
    });
    saveCache(cache);

    return narrative;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// 4. Incident Triage
// ---------------------------------------------------------------------------

const TRIAGE_SYSTEM_PROMPT = `You are a security incident analyst for AI agent workstation security. Classify the incident severity and recommend response steps.

Respond with ONLY a JSON object:
{
  "classification": "false-positive|suspicious|confirmed-threat",
  "severity": "info|low|medium|high|critical",
  "explanation": "1-2 sentence classification rationale",
  "responseSteps": ["step 1", "step 2"]
}

Be precise. Only classify as "confirmed-threat" if there is clear evidence of malicious intent. Max 4 response steps.`;

/**
 * Triage a batch of related events as a potential incident.
 *
 * Input: a small batch of related high-severity events.
 */
export async function triageIncident(
  events: ShieldEvent[],
  context: {
    policyMode: string;
    agentName: string;
    recentBaseline: string[]; // known-safe actions for this agent
  },
): Promise<IncidentTriage | null> {
  const apiKey = await checkLlmAvailable();
  if (!apiKey) return null;

  const eventIds = events.map(e => e.id);
  const key = cacheKey('incident-triage', eventIds.sort().join(':'));

  const cache = loadCache();
  const cached = getCached(cache, key);
  if (cached) return cached.result as IncidentTriage;

  const eventSummary = events.slice(0, 10).map(e =>
    `  [${e.severity}] ${e.action} -> ${e.target} (${e.outcome})`
  ).join('\n');

  const userPrompt = `Incident triage for agent "${context.agentName}" (policy mode: ${context.policyMode})

Events (${events.length} total):
${eventSummary}

Known-safe baseline actions:
${context.recentBaseline.slice(0, 10).map(a => `  - ${a}`).join('\n') || '  (no baseline established)'}

Classify this incident.`;

  const result = await callHaiku(
    TRIAGE_SYSTEM_PROMPT,
    userPrompt,
    MAX_TOKENS['incident-triage'],
    apiKey,
  );
  if (!result) return null;

  try {
    const parsed = JSON.parse(result.text) as {
      classification: 'false-positive' | 'suspicious' | 'confirmed-threat';
      severity: EventSeverity;
      explanation: string;
      responseSteps: string[];
    };

    // Validate enum fields against allowlists
    const validClassifications = ['false-positive', 'suspicious', 'confirmed-threat'];
    const validSeverities = ['info', 'low', 'medium', 'high', 'critical'];
    const classification = validClassifications.includes(parsed.classification)
      ? parsed.classification : 'suspicious';
    const severity = validSeverities.includes(parsed.severity)
      ? parsed.severity : 'medium';

    const triage: IncidentTriage = {
      eventIds,
      classification,
      severity,
      explanation: typeof parsed.explanation === 'string' ? parsed.explanation : '',
      responseSteps: Array.isArray(parsed.responseSteps)
        ? parsed.responseSteps.filter((s: unknown) => typeof s === 'string') : [],
    };

    cache.entries.push({
      key,
      analysisType: 'incident-triage',
      result: triage,
      createdAt: new Date().toISOString(),
      ttlMs: getTtl('incident-triage'),
      inputTokens: result.inputTokens,
      outputTokens: result.outputTokens,
    });
    saveCache(cache);

    return triage;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Cache statistics (for status/diagnostics)
// ---------------------------------------------------------------------------

export interface LlmCacheStats {
  totalEntries: number;
  validEntries: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  estimatedCostUsd: number;
  byType: Record<LlmAnalysisType, number>;
}

/**
 * Compute cache statistics for diagnostics.
 *
 * Estimated cost uses Haiku pricing:
 *   Input: $0.80 per million tokens
 *   Output: $4.00 per million tokens
 */
export function getCacheStats(): LlmCacheStats {
  const cache = loadCache();
  const now = Date.now();

  let totalInput = 0;
  let totalOutput = 0;
  let validCount = 0;
  const byType: Record<LlmAnalysisType, number> = {
    'policy-suggestion': 0,
    'anomaly-explanation': 0,
    'report-narrative': 0,
    'incident-triage': 0,
  };

  for (const entry of cache.entries) {
    const created = new Date(entry.createdAt).getTime();
    const isValid = now - created < entry.ttlMs;
    if (isValid) validCount++;

    totalInput += entry.inputTokens;
    totalOutput += entry.outputTokens;
    byType[entry.analysisType] = (byType[entry.analysisType] ?? 0) + 1;
  }

  // Haiku pricing: $0.80/M input, $4.00/M output
  const costInput = (totalInput / 1_000_000) * 0.80;
  const costOutput = (totalOutput / 1_000_000) * 4.00;

  return {
    totalEntries: cache.entries.length,
    validEntries: validCount,
    totalInputTokens: totalInput,
    totalOutputTokens: totalOutput,
    estimatedCostUsd: Math.round((costInput + costOutput) * 10000) / 10000,
    byType,
  };
}
