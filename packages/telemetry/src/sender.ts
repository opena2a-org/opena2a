import type { UsageEvent } from "./types.js";
import { debugPrintEnabled, endpointURL } from "./config.js";

const SEND_TIMEOUT_MS = 2000;
const DEBOUNCE_MS = 200;

let lastSendAt = 0;
const inFlight = new Set<Promise<void>>();
const MAX_IN_FLIGHT = 4;
let beforeExitInstalled = false;

/**
 * Drain in-flight events on natural process exit so short-lived CLI commands
 * (`dvaa agents`, `hma scan`, …) don't lose events when their dispatcher
 * calls `process.exit()` immediately after `tele.track()`. Each request is
 * already capped at 2s by SEND_TIMEOUT_MS, so the worst-case extra latency
 * is bounded.
 *
 * Installed lazily on first send to avoid attaching to import-only consumers
 * that never fire an event.
 */
function installBeforeExitDrain(): void {
  if (beforeExitInstalled || typeof process === "undefined") return;
  beforeExitInstalled = true;
  process.on("beforeExit", async () => {
    if (inFlight.size > 0) await flush();
  });
}

/**
 * Fire-and-forget send.
 *
 * - Caps in-flight requests so a stuck endpoint can't accumulate handles.
 * - Honors a 200ms debounce per process (drops events that fire faster).
 * - Resolves regardless of network outcome — never throws, never rejects.
 * - When OPENA2A_TELEMETRY_DEBUG=print, echoes the payload to stderr.
 * - Tracks the in-flight set so `flush()` and the beforeExit drain can wait.
 */
export async function sendEvent(event: UsageEvent): Promise<void> {
  const now = Date.now();
  if (now - lastSendAt < DEBOUNCE_MS) return;
  if (inFlight.size >= MAX_IN_FLIGHT) return;
  lastSendAt = now;

  installBeforeExitDrain();

  if (debugPrintEnabled()) {
    process.stderr.write(`[opena2a:telemetry] ${JSON.stringify(event)}\n`);
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), SEND_TIMEOUT_MS);
  const task = fetch(endpointURL(), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(event),
    signal: controller.signal,
  })
    .catch(() => undefined)
    .finally(() => {
      clearTimeout(timeout);
    })
    .then(() => undefined);
  inFlight.add(task);
  task.finally(() => inFlight.delete(task));
  await task;
}

/**
 * Wait for all in-flight events to settle. Call before `process.exit()` in a
 * short-lived script if you can't rely on Node's natural exit hook (e.g.
 * after manual `process.exit(N)`). The beforeExit handler covers natural
 * exits automatically.
 */
export async function flush(): Promise<void> {
  await Promise.allSettled([...inFlight]);
}
