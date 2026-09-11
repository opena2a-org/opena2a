/**
 * OPA-01.AC4: run the concurrent-write suite repeatedly with the lock trace on,
 * and stop on the first round that reports a forked chain.
 *
 * This loop is an INSTRUMENT, not a fix. On a fork it preserves that round's
 * trace file and the children's stderr (the AC3 harness keeps stderr on every
 * exit code, and the round assertion's message carries it) and prints their
 * paths. On N clean rounds it prints the round count, the host and the phrase
 * `not recurred` -- it never claims the fork is fixed, bounded or gone.
 *
 *   npm run shield:lock-trace-loop -- 40          # N rounds (default 40)
 *   SHIELD_LOCK_TRACE_DIR=/path npm run shield:lock-trace-loop
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import * as path from 'node:path';
import { LOCK_TRACE_ENV } from '../src/shield/lock.js';

const PKG = path.resolve(__dirname, '..');
const SUITE = path.join('__tests__', 'shield', 'concurrent-write.test.ts');
const FORK_MARKER = /valid:\s*false/;

function usage(msg: string): never {
  process.stderr.write(`shield-lock-trace-loop: ${msg}\n`);
  process.exit(2);
}

const roundsArg = process.argv[2] ?? process.env.SHIELD_LOCK_TRACE_ROUNDS ?? '40';
const rounds = Number(roundsArg);
if (!Number.isInteger(rounds) || rounds < 1) usage(`rounds must be a positive integer, got ${roundsArg}`);

const keepDir = process.env.SHIELD_LOCK_TRACE_DIR ?? mkdtempSync(path.join(tmpdir(), 'shield-lock-trace-'));
mkdirSync(keepDir, { recursive: true });

const vitest = [
  path.join(PKG, 'node_modules', '.bin', 'vitest'),
  path.join(PKG, '..', '..', 'node_modules', '.bin', 'vitest'),
].find(p => existsSync(p));
if (!vitest) usage('vitest not found under node_modules/.bin (run npm ci first)');

function seqBounds(traceFile: string): { first: number | null; last: number | null; lines: number } {
  if (!existsSync(traceFile)) return { first: null, last: null, lines: 0 };
  const lines = readFileSync(traceFile, 'utf-8').split('\n').filter(l => l.length > 0);
  const seq = (l: string): number | null => {
    try { const n = JSON.parse(l).seq; return Number.isFinite(n) ? n : null; } catch { return null; }
  };
  return { first: lines.length ? seq(lines[0]) : null, last: lines.length ? seq(lines[lines.length - 1]) : null, lines: lines.length };
}

process.stdout.write(`shield-lock-trace-loop: ${rounds} round(s) on ${hostname()}, traces under ${keepDir}\n`);

for (let round = 1; round <= rounds; round += 1) {
  const roundDir = path.join(keepDir, `round-${String(round).padStart(3, '0')}`);
  mkdirSync(roundDir, { recursive: true });
  const traceFile = path.join(roundDir, 'lock-trace.jsonl');
  const stderrFile = path.join(roundDir, 'suite-output.txt');

  const res = spawnSync(vitest, ['run', SUITE], {
    cwd: PKG,
    encoding: 'utf-8',
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, [LOCK_TRACE_ENV]: traceFile, SHIELD_CONCURRENT_ROUNDS: process.env.SHIELD_CONCURRENT_ROUNDS ?? '1' },
  });
  const output = `${res.stdout ?? ''}\n${res.stderr ?? ''}`;
  writeFileSync(stderrFile, output);
  const bounds = seqBounds(traceFile);

  if (res.status === 0) {
    process.stdout.write(`round ${round}/${rounds}: chain intact (trace ${bounds.lines} line(s), seq ${bounds.first}..${bounds.last})\n`);
    rmSync(roundDir, { recursive: true, force: true });
    continue;
  }

  if (FORK_MARKER.test(output)) {
    process.stdout.write(
      [
        `round ${round}/${rounds}: FORK observed on ${hostname()}`,
        `  trace file:        ${traceFile} (${bounds.lines} line(s), seq ${bounds.first}..${bounds.last})`,
        `  children's stderr: ${stderrFile} (the round assertion's message carries every child's stderr)`,
        '',
      ].join('\n'),
    );
    process.exit(1);
  }

  process.stdout.write(
    [
      `round ${round}/${rounds}: the suite failed for a reason other than a fork (exit ${res.status ?? 'signal'})`,
      `  output preserved: ${stderrFile}`,
      `  trace file:       ${traceFile}`,
      '',
    ].join('\n'),
  );
  process.exit(3);
}

process.stdout.write(`shield-lock-trace-loop: ${rounds} round(s) on ${hostname()}: fork not recurred\n`);
