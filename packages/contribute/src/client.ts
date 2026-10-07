import { ContributionBatch } from './types.js';

const DEFAULT_REGISTRY_URL = 'https://api.oa2a.org';
const TIMEOUT_MS = 10_000;

/**
 * Submit a batch to the Registry. Resolves `true` only when the Registry
 * accepted it. `false` means nothing was accepted: the Registry refused the
 * batch, could not be reached, or there was nothing to submit (a `null` or
 * empty batch, e.g. `buildBatch()` on an empty queue, which makes no request).
 * With `verbose`, every outcome prints one line to stderr.
 */
export async function submitBatch(
  batch: ContributionBatch | null | undefined,
  registryUrl?: string,
  verbose?: boolean,
): Promise<boolean> {
  if (!batch || !Array.isArray(batch.events) || batch.events.length === 0) {
    if (verbose) {
      process.stderr.write('  Note: nothing to submit (empty batch); no request made\n');
    }
    return false;
  }

  const url = `${(registryUrl || DEFAULT_REGISTRY_URL).replace(/\/+$/, '')}/api/v1/contribute`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(batch),
      signal: controller.signal,
    });

    if (response.ok) {
      if (verbose) {
        process.stderr.write(
          `  Shared: scan summaries for ${batch.events.length} event(s) (community trust)\n`,
        );
      }
      return true;
    }

    if (verbose) {
      process.stderr.write(`  Note: Registry returned ${response.status} (non-blocking)\n`);
    }
    return false;
  } catch (err) {
    // Offline or unreachable -- events stay in queue for next time
    if (verbose) {
      const cause = controller.signal.aborted
        ? `no response within ${TIMEOUT_MS / 1000}s`
        : err instanceof Error ? err.message : String(err);
      process.stderr.write(
        `  Note: could not reach the Registry at ${url} (${cause}); events stay queued (non-blocking)\n`,
      );
    }
    return false;
  } finally {
    // Cleared on every path: a pending abort timer would otherwise hold the
    // process open for up to TIMEOUT_MS after a failed request.
    clearTimeout(timer);
  }
}
