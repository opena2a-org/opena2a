import { ContributionBatch } from './types.js';

const DEFAULT_REGISTRY_URL = 'https://registry.opena2a.org';
const TIMEOUT_MS = 10_000;

export async function submitBatch(
  batch: ContributionBatch,
  registryUrl?: string,
  verbose?: boolean,
): Promise<boolean> {
  const url = `${(registryUrl || DEFAULT_REGISTRY_URL).replace(/\/+$/, '')}/api/v1/contribute`;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(batch),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (response.ok) {
      if (verbose) {
        process.stderr.write(
          `  Shared: anonymized results for ${batch.events.length} event(s) (community trust)\n`,
        );
      }
      return true;
    }

    if (verbose) {
      process.stderr.write(`  Note: Registry returned ${response.status} (non-blocking)\n`);
    }
    return false;
  } catch {
    // Offline or unreachable -- events stay in queue for next time
    return false;
  }
}
