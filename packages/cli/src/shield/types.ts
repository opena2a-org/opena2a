// Shield: Unified Developer Workstation Security Orchestration
// All TypeScript interfaces for the Shield module.

// --- Environment Detection ---

export type ProjectType = 'node' | 'go' | 'python' | 'unknown';

export interface DetectedCli {
  name: string;
  path: string;
  version: string | null;
  configDir: string | null;
  hasCredentials: boolean;
}

export interface DetectedAssistant {
  name: string;
  detected: boolean;
  method: 'process' | 'env' | 'config';
  detail: string;
  configPaths: string[];
}

export interface DetectedMcpServer {
  name: string;
  source: string;
  command: string;
  args: string[];
  env: Record<string, string>;
  tools: string[];
}

export interface DetectedOAuthSession {
  provider: string;
  configDir: string;
  hasActiveSession: boolean;
  lastModified: string | null;
  scopes: string[];
}

export interface EnvironmentScan {
  timestamp: string;
  hostname: string;
  platform: string;
  shell: string;
  clis: DetectedCli[];
  assistants: DetectedAssistant[];
  mcpServers: DetectedMcpServer[];
  oauthSessions: DetectedOAuthSession[];
  projectType: ProjectType;
  projectName: string | null;
}

// --- Unified Event Schema ---

export type ShieldEventSource =
  | 'secretless'
  | 'arp'
  | 'browser-guard'
  | 'hma'
  | 'registry'
  | 'configguard'
  | 'shield';

export type EventSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type EventOutcome = 'allowed' | 'blocked' | 'monitored';

export interface ShieldEvent {
  id: string;
  timestamp: string;
  version: 1;

  source: ShieldEventSource;
  category: string;
  severity: EventSeverity;

  agent: string | null;
  sessionId: string | null;

  action: string;
  target: string;
  outcome: EventOutcome;
  detail: Record<string, unknown>;

  prevHash: string;
  eventHash: string;

  orgId: string | null;
  managed: boolean;
  agentId: string | null;
}

// --- Policy Schema ---

export type PolicyMode = 'adaptive' | 'monitor' | 'enforce';

export interface PolicyRules {
  credentials: { allow: string[]; deny: string[] };
  processes: { allow: string[]; deny: string[] };
  network: { allow: string[]; deny: string[] };
  filesystem: { allow: string[]; deny: string[] };
  mcpServers: { allow: string[]; deny: string[] };
  supplyChain: { requireTrustScore: number; blockAdvisories: boolean };
}

export interface ShieldPolicy {
  version: 1;
  mode: PolicyMode;
  default: PolicyRules;
  agents: Record<string, Partial<PolicyRules>>;
}

export interface PolicyDecision {
  allowed: boolean;
  outcome: EventOutcome;
  rule: string;
  agent: string | null;
}

// --- Adaptive Enforcement ---

/**
 * Adaptive enforcement uses continuous learning with graduated confidence.
 * Shield never stops learning. It starts suggesting policies once behavior
 * is statistically stable (no new binaries/credentials for N consecutive
 * sessions). It never blocks automatically -- the developer must approve.
 *
 * Phase transitions:
 *   learn -> suggest: behavior stabilized (stability score >= 0.8)
 *   suggest -> protect: developer approved recommended policy
 *   protect (ongoing): continues learning, prompts for never-seen actions
 *
 * Stability is measured by "new behavior rate": if the agent hasn't used
 * a new binary or accessed a new credential in the last 5 sessions,
 * the baseline is considered stable enough to recommend a policy.
 */
export interface AgentBaseline {
  agent: string;
  observationStart: string;
  observationEnd: string;
  totalActions: number;
  totalSessions: number;
  phase: 'learn' | 'suggest' | 'protect';
  stabilityScore: number; // 0.0-1.0, based on new-behavior rate
  lastNewBehaviorAt: string | null; // ISO 8601
  observed: {
    processes: Record<string, number>;
    credentials: Record<string, number>;
    filesystemPaths: Record<string, number>;
    networkHosts: Record<string, number>;
    mcpServers: Record<string, number>;
  };
  recommended: Partial<PolicyRules> | null;
  thresholds: {
    maxProcessesPerHour: number;
    maxCredentialAccessPerSession: number;
    maxNewBinariesPerDay: number;
  };
}

// --- Session Identification ---

export type SessionSignalType = 'env' | 'process' | 'tty' | 'pid' | 'hook' | 'timing';

export interface SessionSignal {
  type: SessionSignalType;
  name: string;
  value: string;
  confidence: number;
}

export interface SessionIdentity {
  sessionId: string;
  agent: string;
  confidence: number;
  signals: SessionSignal[];
  startedAt: string;
  lastSeenAt: string;
}

// --- Self-Healing / Integrity ---

export type IntegrityStatus = 'healthy' | 'degraded' | 'compromised' | 'lockdown';

export interface IntegrityCheck {
  name: string;
  status: 'pass' | 'warn' | 'fail';
  detail: string;
  checkedAt: string;
}

export interface IntegrityState {
  status: IntegrityStatus;
  checks: IntegrityCheck[];
  lastVerified: string;
  chainHash: string;
}

// --- Weekly Report ---

export interface AgentActivitySummary {
  sessions: number;
  actions: number;
  firstSeen: string;
  lastSeen: string;
  topActions: { action: string; count: number }[];
}

export interface PolicyViolation {
  action: string;
  target: string;
  agent: string;
  count: number;
  severity: EventSeverity;
  recommendation: string;
}

export interface PostureFactor {
  name: string;
  score: number;
  weight: number;
  detail: string;
}

export interface ComparativeMetric {
  percentile: number;
  sampleSize: number;
  optInDate: string;
}

export interface PostureScore {
  score: number;
  grade: string;
  factors: PostureFactor[];
  trend: 'improving' | 'stable' | 'declining' | null;
  comparative: ComparativeMetric | null;
}

export interface WeeklyReport {
  version: 1;
  generatedAt: string;
  periodStart: string;
  periodEnd: string;
  hostname: string;

  agentActivity: {
    totalSessions: number;
    totalActions: number;
    byAgent: Record<string, AgentActivitySummary>;
  };

  policyEvaluation: {
    monitored: number;
    wouldBlock: number;
    blocked: number;
    topViolations: PolicyViolation[];
  };

  credentialExposure: {
    accessAttempts: number;
    uniqueCredentials: number;
    byProvider: Record<string, number>;
    recommendations: string[];
  };

  supplyChain: {
    packagesInstalled: number;
    advisoriesFound: number;
    blockedInstalls: number;
    lowTrustPackages: string[];
  };

  configIntegrity: {
    filesMonitored: number;
    tamperedFiles: string[];
    signatureStatus: 'valid' | 'tampered' | 'unsigned';
  };

  runtimeProtection: {
    arpActive: boolean;
    processesSpawned: number;
    networkConnections: number;
    anomalies: number;
  };

  posture: PostureScore;
}

// --- Product Status ---

export interface ProductStatus {
  name: string;
  installed: boolean;
  active: boolean;
  version: string | null;
  keyMetric: string;
}

export interface ShieldStatus {
  timestamp: string;
  products: ProductStatus[];
  policyLoaded: boolean;
  policyMode: PolicyMode | null;
  shellIntegration: boolean;
  integrityStatus: IntegrityStatus;
  lastReportScore: number | null;
  lastReportDate: string | null;
}

// --- Shield Command Options ---

export type ShieldSubcommand =
  | 'init'
  | 'status'
  | 'log'
  | 'report'
  | 'check'
  | 'policy'
  | 'evaluate'
  | 'selfcheck'
  | 'recover';

export interface ShieldOptions {
  subcommand: ShieldSubcommand;
  targetDir?: string;
  agent?: string;
  count?: number;
  since?: string;
  severity?: string;
  source?: string;
  category?: string;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
  // recover flags
  verify?: boolean;
  reset?: boolean;
  forensic?: boolean;
  // LLM intelligence flags
  analyze?: boolean;
}

// --- Shield User Config ---

export interface ShieldUserConfig {
  initialized: boolean;
  shellIntegration: {
    enabled: boolean;
    shell: 'zsh' | 'bash' | 'fish' | null;
    installedAt: string | null;
  };
  report: {
    scheduled: boolean;
    scheduledDay: number;
    scheduledHour: number;
    lastGenerated: string | null;
  };
}

// --- LLM Intelligence ---

export type LlmAnalysisType =
  | 'policy-suggestion'
  | 'anomaly-explanation'
  | 'report-narrative'
  | 'incident-triage';

export interface PolicySuggestion {
  agent: string;
  rules: Partial<PolicyRules>;
  reasoning: string;
  confidence: number; // 0.0-1.0
  basedOnActions: number;
  basedOnSessions: number;
}

export interface AnomalyExplanation {
  eventId: string;
  severity: EventSeverity;
  explanation: string;
  riskFactors: string[];
  suggestedAction: 'ignore' | 'investigate' | 'block';
}

export interface ReportNarrative {
  summary: string;
  highlights: string[];
  concerns: string[];
  recommendations: string[];
}

export interface IncidentTriage {
  eventIds: string[];
  classification: 'false-positive' | 'suspicious' | 'confirmed-threat';
  severity: EventSeverity;
  explanation: string;
  responseSteps: string[];
}

export interface LlmCacheEntry {
  key: string;
  analysisType: LlmAnalysisType;
  result: PolicySuggestion | AnomalyExplanation | ReportNarrative | IncidentTriage;
  createdAt: string;
  ttlMs: number;
  inputTokens: number;
  outputTokens: number;
}

export interface LlmCache {
  version: 1;
  entries: LlmCacheEntry[];
}

// --- Constants ---

export const SHIELD_DIR = '.opena2a/shield';
export const SHIELD_EVENTS_FILE = 'events.jsonl';
export const SHIELD_POLICY_FILE = 'policy.yaml';
export const SHIELD_POLICY_CACHE = 'policy-cache.json';
export const SHIELD_SCAN_FILE = 'scan.json';
export const SHIELD_CONFIG_FILE = 'config.json';
export const SHIELD_BASELINES_DIR = 'baselines';
export const SHIELD_REPORTS_DIR = 'reports';
export const SHIELD_LLM_CACHE_FILE = 'llm-cache.json';

// LLM cache TTLs (milliseconds)
export const LLM_CACHE_TTL_POLICY = 24 * 60 * 60 * 1000;      // 24h
export const LLM_CACHE_TTL_ANOMALY = 7 * 24 * 60 * 60 * 1000; // 7d
export const LLM_CACHE_TTL_NARRATIVE = 30 * 24 * 60 * 60 * 1000; // 30d (per report)
export const LLM_CACHE_TTL_TRIAGE = 60 * 60 * 1000;            // 1h

export const MAX_EVENTS_FILE_SIZE = 10 * 1024 * 1024; // 10MB

// Adaptive enforcement: continuous learning, not timer-based.
// Suggestions appear when behavior stabilizes, not after a fixed period.
export const STABILITY_THRESHOLD = 0.8; // suggest policy when stability >= this
export const STABILITY_WINDOW_SESSIONS = 5; // sessions without new behavior = stable
export const LEARN_PHASE_MIN_ACTIONS = 50; // minimum actions before stability is checked
export const LEARN_PHASE_MIN_SESSIONS = 3; // minimum sessions before stability is checked

export const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
export const EVALUATE_BUDGET_MS = 50;
