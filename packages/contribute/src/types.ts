/**
 * Universal contribution event -- works for all OpenA2A tools:
 * HMA, ai-trust, detect, ARP, BrowserGuard, Secretless.
 */
export interface ContributionEvent {
  type: 'scan_result' | 'detection' | 'behavior' | 'interaction' | 'adoption';
  tool: string;
  toolVersion: string;
  timestamp: string;

  /** Package being scanned (for scan results). */
  package?: {
    name: string;
    version?: string;
    ecosystem?: string;
  };

  /** Anonymized scan summary (no raw findings). */
  scanSummary?: {
    totalChecks: number;
    passed: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    score: number;
    verdict: string;
    durationMs: number;
  };

  /** Detection summary (for detect, BrowserGuard). */
  detectionSummary?: {
    agentsFound: number;
    mcpServersFound: number;
    frameworkTypes?: string[];
  };

  /** Behavior summary (for ARP). */
  behaviorSummary?: {
    interactions: number;
    successRate: number;
    anomalies: number;
    protocols?: string[];
  };

  /** Adoption stats (for Secretless). */
  adoptionSummary?: {
    backendType?: string;
  };
}

export interface ContributionBatch {
  contributorToken: string;
  events: ContributionEvent[];
  submittedAt: string;
}
