/**
 * opena2a watch -- Live agent activity tail
 *
 * Polls the AIM server for agent activity events and displays them
 * in real-time, similar to `kubectl logs -f` or `tail -f`.
 */

import { bold, dim, green, red, cyan, gray } from '../util/colors.js';
import { AimClient, AimServerError, loadServerConfig } from '../util/aim-client.js';
import { loadAuth, isAuthValid } from '../util/auth.js';

export interface WatchOptions {
  ci?: boolean;
  format?: string;
  verbose?: boolean;
  json?: boolean;
  interval?: number;  // Poll interval in seconds (default: 3)
}

/** Statuses that say the server refuses the poll; waiting will not change them. */
const REFUSED_STATUSES = new Set([401, 403, 404]);

/** Consecutive refused polls after which the watch gives up with exit 1. */
export const MAX_CONSECUTIVE_REFUSALS = 3;

export async function watch(options: WatchOptions): Promise<number> {
  const isJson = options.json || options.format === 'json';
  const pollInterval = (options.interval ?? 3) * 1000;

  // Resolve auth
  const auth = loadAuth();
  if (!auth || !isAuthValid(auth)) {
    process.stderr.write('Not authenticated. Run: opena2a login\n');
    return 1;
  }

  // Resolve agent ID
  const config = loadServerConfig();
  const agentId = config?.agentId;
  if (!agentId) {
    process.stderr.write('No agent registered. Run: opena2a setup\n');
    return 1;
  }

  const client = new AimClient(auth.serverUrl, { accessToken: auth.accessToken });

  let lastSeenId: string | null = null;
  let running = true;
  let refusals = 0;
  // Aborted on SIGINT/SIGTERM so a stalled poll or the wait between polls
  // ends at once instead of holding the process until it returns.
  const abort = new AbortController();

  // Handle graceful shutdown. The handlers go in before the banner says
  // Ctrl+C stops the watch: an interrupt sent the moment that line appears
  // must end the run with exit 0, not by the signal's default action.
  const cleanup = () => {
    running = false;
    abort.abort();
    if (!isJson) {
      process.stdout.write('\n' + dim('  Stopped watching.') + '\n');
    }
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  if (!isJson) {
    process.stdout.write(bold('Agent Activity Watch') + '\n');
    process.stdout.write(dim(`  Agent: ${agentId}`) + '\n');
    process.stdout.write(dim(`  Server: ${auth.serverUrl}`) + '\n');
    process.stdout.write(dim(`  Polling every ${options.interval ?? 3}s (Ctrl+C to stop)`) + '\n');
    process.stdout.write(gray('-'.repeat(70)) + '\n');
    // Header
    process.stdout.write(
      dim('  TIME'.padEnd(14)) +
      dim('TYPE'.padEnd(14)) +
      dim('RESOURCE'.padEnd(20)) +
      dim('RESULT') + '\n'
    );
    process.stdout.write(gray('-'.repeat(70)) + '\n');
  }

  try {
    while (running) {
      try {
        const resp = await client.getAgentActivity(agentId, { pageSize: 20 }, abort.signal);
        const events = resp.events ?? resp.activity ?? [];
        refusals = 0;

        // Find new events (everything after lastSeenId)
        let newEvents = events;
        if (lastSeenId) {
          const lastIdx = events.findIndex((e: any) => (e.id ?? e.eventId) === lastSeenId);
          if (lastIdx >= 0) {
            newEvents = events.slice(0, lastIdx);
          }
        }

        // Display new events (in reverse order so oldest first)
        for (const event of newEvents.reverse()) {
          const eventId = event.id ?? event.eventId ?? '';
          const ts = (event.createdAt ?? event.timestamp ?? '').slice(11, 19);
          const type = event.action ?? event.type ?? 'unknown';
          const resource = event.resource ?? event.target ?? event.details ?? '';
          const result = event.result ?? event.status ?? '--';

          if (isJson) {
            process.stdout.write(JSON.stringify({
              time: event.createdAt ?? event.timestamp,
              type,
              resource,
              result,
              id: eventId,
            }) + '\n');
          } else {
            const resultColor = result === 'denied' || result === 'DENIED'
              ? red
              : result === 'allowed' || result === 'success'
                ? green
                : dim;

            process.stdout.write(
              `  ${dim(ts)}  ` +
              `${type.padEnd(14)}` +
              `${cyan(truncate(resource, 18).padEnd(20))}` +
              `${resultColor(result)}\n`
            );
          }

          lastSeenId = eventId;
        }

        // Update lastSeenId to most recent event even if no new events
        if (events.length > 0 && !lastSeenId) {
          lastSeenId = events[0].id ?? events[0].eventId ?? null;
        }
      } catch (err) {
        if (!running) break;
        const message = err instanceof Error ? err.message : String(err);
        if (err instanceof AimServerError && REFUSED_STATUSES.has(err.statusCode)) {
          // A refusal will not go away by polling again: say so without
          // --verbose, and stop once it has happened several times in a row.
          refusals++;
          process.stderr.write(red(`  Poll refused: ${message}`) + '\n');
          if (refusals >= MAX_CONSECUTIVE_REFUSALS) {
            process.stderr.write(
              `Stopped watching: the server refused ${refusals} polls in a row. ` +
              'Check the login (opena2a login) and the agent (opena2a setup).\n',
            );
            return 1;
          }
        } else {
          refusals = 0;
          if (options.verbose) {
            process.stderr.write(dim(`  Poll error: ${message}`) + '\n');
          }
        }
      }

      // Wait before next poll
      if (running) {
        await new Promise<void>(resolve => {
          const onAbort = () => { clearTimeout(timer); resolve(); };
          const timer = setTimeout(() => {
            abort.signal.removeEventListener('abort', onAbort);
            resolve();
          }, pollInterval);
          abort.signal.addEventListener('abort', onAbort, { once: true });
        });
      }
    }
  } finally {
    process.removeListener('SIGINT', cleanup);
    process.removeListener('SIGTERM', cleanup);
  }

  return 0;
}

function truncate(s: string, maxLen: number): string {
  return s.length > maxLen ? s.slice(0, maxLen - 1) + '\u2026' : s;
}
