/**
 * OPA-01.AC1, the off-switch clause: with the trace variable unset the lock
 * code path writes no trace file and the event chain it guards is the same
 * chain the traced path writes.
 *
 * Two writes can never be byte-identical: every event carries a uuidv7 id and
 * an ISO timestamp, and the hash chain is computed over them. So the chains
 * are compared after normalising exactly those per-write fields (id,
 * timestamp, prevHash, eventHash) -- everything the caller supplied and the
 * chain's shape must match. The trace file's absence is asserted literally.
 */
import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { LOCK_TRACE_ENV } from '../../src/shield/lock.js';
import { getEventsPath, writeEvent } from '../../src/shield/events.js';

const temps: string[] = [];
function makeProject(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shield-lock-trace-'));
  fs.mkdirSync(path.join(dir, '.opena2a'), { recursive: true });
  temps.push(dir);
  return dir;
}

const savedTrace = process.env[LOCK_TRACE_ENV];
afterEach(() => {
  if (savedTrace === undefined) delete process.env[LOCK_TRACE_ENV];
  else process.env[LOCK_TRACE_ENV] = savedTrace;
  while (temps.length > 0) fs.rmSync(temps.pop()!, { recursive: true, force: true });
});

function writeThree(projectDir: string): void {
  for (const index of [0, 1, 2]) {
    writeEvent(
      {
        source: 'shield',
        category: 'trace-off-test',
        severity: 'info',
        agent: null,
        sessionId: null,
        action: 'trace.compare',
        target: `event-${index}`,
        outcome: 'monitored',
        detail: { index },
        orgId: null,
        managed: false,
        agentId: null,
      },
      projectDir,
    );
  }
}

const VOLATILE = new Set(['id', 'timestamp', 'prevHash', 'eventHash']);
function normalisedChain(projectDir: string): string {
  const raw = fs.readFileSync(getEventsPath(projectDir), 'utf-8');
  const lines = raw.split('\n').filter(l => l.trim().length > 0);
  return lines
    .map(l => {
      const ev = JSON.parse(l) as Record<string, unknown>;
      const kept: Record<string, unknown> = {};
      for (const k of Object.keys(ev).sort()) kept[k] = VOLATILE.has(k) ? `<${k}>` : ev[k];
      return JSON.stringify(kept);
    })
    .join('\n');
}

describe('lock trace off-switch (OPA-01.AC1)', () => {
  it('writes no trace file with the variable unset, and the same chain either way', () => {
    // Traced write: the variable names a file inside the project temp dir.
    const traced = makeProject();
    const traceFile = path.join(traced, 'lock-trace.jsonl');
    process.env[LOCK_TRACE_ENV] = traceFile;
    writeThree(traced);
    expect(fs.existsSync(traceFile)).toBe(true);
    const tracedLines = fs.readFileSync(traceFile, 'utf-8').split('\n').filter(l => l.length > 0);
    expect(tracedLines.length).toBeGreaterThan(0);
    const seqs = tracedLines.map(l => Number(JSON.parse(l).seq));
    for (let i = 1; i < seqs.length; i += 1) expect(seqs[i]).toBeGreaterThan(seqs[i - 1]);

    // Untraced write: variable unset. No trace file, no sequence file, no mutex dir.
    delete process.env[LOCK_TRACE_ENV];
    const untraced = makeProject();
    const untracedTrace = path.join(untraced, 'lock-trace.jsonl');
    writeThree(untraced);
    expect(fs.existsSync(untracedTrace)).toBe(false);
    expect(fs.existsSync(`${untracedTrace}.seq`)).toBe(false);
    expect(fs.existsSync(`${untracedTrace}.seqlock`)).toBe(false);
    expect(fs.readdirSync(untraced).filter(n => n.includes('trace'))).toEqual([]);

    // The chains match once the per-write id/timestamp/hash fields are normalised.
    expect(normalisedChain(untraced)).toBe(normalisedChain(traced));
    expect(normalisedChain(untraced).split('\n')).toHaveLength(3);
  });

  it('treats an empty variable as unset', () => {
    process.env[LOCK_TRACE_ENV] = '';
    const project = makeProject();
    writeThree(project);
    expect(fs.readdirSync(project).filter(n => n.includes('trace'))).toEqual([]);
    expect(normalisedChain(project).split('\n')).toHaveLength(3);
  });
});
