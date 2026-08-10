/**
 * Child process for concurrent-write.test.ts.
 *
 * Writes exactly one Shield event, after spinning until a shared start
 * instant so every sibling enters `writeEvent` at the same time.  Must be a
 * separate PROCESS: `writeEvent` is synchronous, so nothing inside one
 * process can interleave with it, and the fork this reproduces is between
 * processes.
 *
 * argv: <startAtEpochMs> <index>
 */
import { writeEvent } from '../../../src/shield/events.js';

const startAt = Number(process.argv[2]);
const index = Number(process.argv[3]);

while (Date.now() < startAt) {
  // Barrier: align every child on the same instant.
}

writeEvent({
  source: 'shield',
  category: 'concurrency-test',
  severity: 'info',
  agent: null,
  sessionId: null,
  action: 'concurrent.write',
  target: `child-${index}`,
  outcome: 'monitored',
  detail: { index },
  orgId: null,
  managed: false,
  agentId: null,
});
