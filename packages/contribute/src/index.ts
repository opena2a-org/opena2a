export type { ContributionEvent, ContributionBatch, SuppressionRow } from './types.js';
export { getContributorToken } from './contributor.js';
export { queueEvent, getQueuedEvents, clearQueue, shouldFlush, buildBatch } from './queue.js';
export { submitBatch } from './client.js';
export { isContributeEnabled } from './config.js';

import { isContributeEnabled } from './config.js';
import { ContributionEvent } from './types.js';
import { queueEvent, shouldFlush, buildBatch, clearQueue } from './queue.js';
import { submitBatch } from './client.js';

/**
 * Main entry point for tools to contribute scan summaries.
 * Queues the event locally. If the queue reaches the flush threshold,
 * submits the batch to the Registry. No-op if contribution is disabled.
 *
 * Usage:
 *   import { contribute } from '@opena2a/contribute';
 *   await contribute.scanResult({ tool: 'hackmyagent', ... });
 */
export const contribute = {
  /**
   * Record a scan result. Queues locally, flushes when threshold reached.
   */
  async scanResult(params: {
    tool: string;
    toolVersion: string;
    packageName: string;
    packageVersion?: string;
    ecosystem?: string;
    /** From a measured coverage record, or omitted — never a derived stand-in. */
    totalChecks?: number;
    passed: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    score: number;
    verdict: string;
    durationMs: number;
    registryUrl?: string;
    verbose?: boolean;
  }): Promise<void> {
    if (!isContributeEnabled()) return;

    const event: ContributionEvent = {
      type: 'scan_result',
      tool: params.tool,
      toolVersion: params.toolVersion,
      timestamp: new Date().toISOString(),
      package: {
        name: params.packageName,
        version: params.packageVersion,
        ecosystem: params.ecosystem,
      },
      scanSummary: {
        totalChecks: params.totalChecks,
        passed: params.passed,
        critical: params.critical,
        high: params.high,
        medium: params.medium,
        low: params.low,
        score: params.score,
        verdict: params.verdict,
        durationMs: params.durationMs,
      },
    };

    queueEvent(event);

    if (shouldFlush()) {
      await this.flush(params.registryUrl, params.verbose);
    }
  },

  /**
   * Record a detection event (for opena2a detect, BrowserGuard).
   */
  async detection(params: {
    tool: string;
    toolVersion: string;
    agentsFound: number;
    mcpServersFound: number;
    frameworkTypes?: string[];
    registryUrl?: string;
    verbose?: boolean;
  }): Promise<void> {
    if (!isContributeEnabled()) return;

    const event: ContributionEvent = {
      type: 'detection',
      tool: params.tool,
      toolVersion: params.toolVersion,
      timestamp: new Date().toISOString(),
      detectionSummary: {
        agentsFound: params.agentsFound,
        mcpServersFound: params.mcpServersFound,
        frameworkTypes: params.frameworkTypes,
      },
    };

    queueEvent(event);

    if (shouldFlush()) {
      await this.flush(params.registryUrl, params.verbose);
    }
  },

  /**
   * Flush queued events to Registry.
   *
   * Resolves `true` when the queue is clear afterwards: the batch was
   * accepted (and the queue cleared), or the queue was already empty and no
   * request was made. Resolves `false` when the Registry refused the batch
   * or could not be reached; the events stay queued for the next flush.
   * Pass `verbose` to have the reason printed to stderr.
   */
  async flush(registryUrl?: string, verbose?: boolean): Promise<boolean> {
    const batch = buildBatch();
    if (!batch) return true;

    const success = await submitBatch(batch, registryUrl, verbose);
    if (success) {
      clearQueue();
    }
    return success;
  },
};
