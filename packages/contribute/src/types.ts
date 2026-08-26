/**
 * Identity row for a check the scan suppressed or scoped out: id-level
 * metadata only — no path, no matched bytes, by construction.
 */
export interface SuppressionRow {
  checkId: string;
  name: string;
  category: string;
  severity: string;
  count: number;
  suppressedBy: string;
}

/**
 * Universal contribution event -- works for all OpenA2A tools:
 * HMA, ai-trust, detect, ARP, BrowserGuard, Secretless.
 */
export interface ContributionEvent {
  type: 'scan_result' | 'scan_ping' | 'detection' | 'behavior' | 'interaction' | 'adoption';
  tool: string;
  toolVersion: string;
  timestamp: string;

  /** Package being scanned (for scan results). */
  package?: {
    name: string;
    version?: string;
    ecosystem?: string;
  };

  /**
   * Anonymized scan summary (no raw findings). `totalChecks` is optional
   * since 0.2.0: a tool reports it from a measured coverage record or omits
   * it — a derived stand-in number is worse than no number.
   */
  scanSummary?: {
    totalChecks?: number;
    passed: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    score: number;
    verdict: string;
    durationMs: number;
    /**
     * Settled-outcome extras (0.3.0, all optional): the exit code the run
     * returned, the pre-clamp score and whether the clamp fired, and the
     * identity rows for suppressed / out-of-scope checks. A tool that has a
     * settled record reports these; one that does not omits them.
     */
    exitCode?: number;
    rawScore?: number;
    scoreClamped?: boolean;
    suppressed?: SuppressionRow[];
    outOfScope?: SuppressionRow[];
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
