import type { UsageEvent } from "./types.js";
import { debugPrintEnabled, endpointURL } from "./config.js";

const SEND_TIMEOUT_MS = 2000;
const DEBOUNCE_MS = 200;

let lastSendAt = 0;
let inFlight = 0;
const MAX_IN_FLIGHT = 4;

/**
 * Fire-and-forget send.
 *
 * - Caps in-flight requests so a stuck endpoint can't accumulate handles.
 * - Honors a 200ms debounce per process (drops events that fire faster).
 * - Resolves regardless of network outcome — never throws, never rejects.
 * - When OPENA2A_TELEMETRY_DEBUG=print, echoes the payload to stderr.
 */
export async function sendEvent(event: UsageEvent): Promise<void> {
  const now = Date.now();
  if (now - lastSendAt < DEBOUNCE_MS) return;
  if (inFlight >= MAX_IN_FLIGHT) return;
  lastSendAt = now;

  if (debugPrintEnabled()) {
    process.stderr.write(`[opena2a:telemetry] ${JSON.stringify(event)}\n`);
  }

  inFlight++;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), SEND_TIMEOUT_MS);
  try {
    await fetch(endpointURL(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(event),
      signal: controller.signal,
    }).catch(() => undefined);
  } finally {
    clearTimeout(timeout);
    inFlight--;
  }
}
