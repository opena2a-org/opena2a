/**
 * QGF-305: the shared yes/no confirm prompt (src/util/confirm.ts).
 *
 * AC1 -- affirmative lines resolve true.
 * AC2 -- every other line, an empty line and EOF resolve false; the promise
 *        settles exactly once on every input.
 * AC5 -- the readline interface is created only inside the shared function;
 *        guard-snapshots.ts and admin.ts hold no createInterface call and both
 *        call the shared function.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Readable, Writable } from 'node:stream';
import { confirm } from '../../src/util/confirm.js';

const SRC = path.resolve(__dirname, '../../src');

function sink(): { output: Writable; text: () => string } {
  const chunks: string[] = [];
  const output = new Writable({
    write(chunk, _enc, cb) { chunks.push(String(chunk)); cb(); },
  });
  return { output, text: () => chunks.join('') };
}

/** An input that supplies exactly `lines` (each followed by a newline) and then ends. */
function linesThenEof(lines: string[]): Readable {
  return Readable.from(lines.map(l => l + '\n'));
}

/**
 * Run `fn` (which must synchronously construct and return a Promise) with a
 * counting Promise constructor installed for the duration of the call, so
 * every resolve/reject the implementation issues on that promise is counted.
 * Derived promises (then/await) are plain Promises via Symbol.species and so
 * do not count.
 */
async function countSettlements(fn: () => Promise<boolean>): Promise<{ value: boolean; settlements: number }> {
  const RealPromise = Promise;
  let settlements = 0;
  class CountingPromise<T> extends RealPromise<T> {
    static get [Symbol.species]() { return RealPromise; }
    constructor(executor: (resolve: (v: T | PromiseLike<T>) => void, reject: (r?: unknown) => void) => void) {
      super((resolve, reject) => executor(
        (v) => { settlements++; resolve(v); },
        (r) => { settlements++; reject(r); },
      ));
    }
  }
  globalThis.Promise = CountingPromise as unknown as PromiseConstructor;
  let p: Promise<boolean>;
  try {
    p = fn();
  } finally {
    globalThis.Promise = RealPromise;
  }
  expect(p).toBeInstanceOf(CountingPromise);
  const value = await p;
  // Give a trailing 'close' (fired synchronously inside rl.close(), or by the
  // input ending after the line) every chance to issue a second settlement.
  await new RealPromise(r => setImmediate(r));
  await new RealPromise(r => setImmediate(r));
  return { value, settlements };
}

describe('confirm (shared yes/no prompt)', () => {
  it('QGF-305.AC1 resolves true for y, Y, yes, YES and " yes " (surrounding spaces)', async () => {
    for (const line of ['y', 'Y', 'yes', 'YES', ' yes ']) {
      const s = sink();
      const result = await confirm('Proceed? [y/N] ', { input: linesThenEof([line]), output: s.output });
      expect(result, `line ${JSON.stringify(line)}`).toBe(true);
      expect(s.text()).toBe('Proceed? [y/N] ');
    }
  });

  it('QGF-305.AC1 the affirmative answer wins even though readline fires close right after the line', async () => {
    // A single 'y' line followed by EOF: both 'line' and 'close' fire; the
    // result must be the typed answer, not the close default.
    const result = await confirm('? ', { input: linesThenEof(['y']), output: sink().output });
    expect(result).toBe(true);
  });

  it('QGF-305.AC2 resolves false for n, no, an empty line and any other text', async () => {
    for (const line of ['n', 'no', '', 'maybe', 'yess', 'y es', 'true', '1']) {
      const result = await confirm('? ', { input: linesThenEof([line]), output: sink().output });
      expect(result, `line ${JSON.stringify(line)}`).toBe(false);
    }
  });

  it('QGF-305.AC2 resolves false when the input ends before any line arrives (EOF)', async () => {
    const result = await confirm('? ', { input: Readable.from([]), output: sink().output });
    expect(result).toBe(false);
  });

  it('QGF-305.AC2 settles exactly once on every affirmative, negative and EOF input', async () => {
    const cases: Array<{ lines: string[]; expected: boolean }> = [
      { lines: ['y'], expected: true },
      { lines: ['Y'], expected: true },
      { lines: ['yes'], expected: true },
      { lines: ['YES'], expected: true },
      { lines: [' yes '], expected: true },
      { lines: ['n'], expected: false },
      { lines: ['no'], expected: false },
      { lines: [''], expected: false },
      { lines: ['anything else'], expected: false },
      { lines: [], expected: false },
    ];
    for (const c of cases) {
      const input = linesThenEof(c.lines);
      const { value, settlements } = await countSettlements(() => confirm('? ', { input, output: sink().output }));
      expect(value, `lines ${JSON.stringify(c.lines)}`).toBe(c.expected);
      expect(settlements, `lines ${JSON.stringify(c.lines)}`).toBe(1);
    }
  });

  it('QGF-305.AC2 reads only the first line; later lines do not change the result', async () => {
    const first = await confirm('? ', { input: linesThenEof(['n', 'y']), output: sink().output });
    expect(first).toBe(false);
    const second = await confirm('? ', { input: linesThenEof(['y', 'n']), output: sink().output });
    expect(second).toBe(true);
  });
});

describe('confirm -- single readline site (invariant)', () => {
  const guardSnapshotsSrc = fs.readFileSync(path.join(SRC, 'commands/guard-snapshots.ts'), 'utf-8');
  const adminSrc = fs.readFileSync(path.join(SRC, 'commands/admin.ts'), 'utf-8');
  const confirmSrc = fs.readFileSync(path.join(SRC, 'util/confirm.ts'), 'utf-8');

  it('QGF-305.AC5 neither guard-snapshots.ts nor admin.ts calls readline createInterface', () => {
    expect(guardSnapshotsSrc).not.toMatch(/createInterface/);
    expect(adminSrc).not.toMatch(/createInterface/);
    expect(guardSnapshotsSrc).not.toMatch(/readline/);
    expect(adminSrc).not.toMatch(/readline/);
  });

  it('QGF-305.AC5 the readline interface that reads the answer is created inside the shared confirm function', () => {
    expect(confirmSrc).toMatch(/import \{ createInterface \} from 'node:readline'/);
    expect(confirmSrc.match(/createInterface\(/g)?.length).toBe(1);
  });

  it('QGF-305.AC1 both the guard resign prompt and the admin destructive-action prompt call the shared confirm', () => {
    expect(guardSnapshotsSrc).toMatch(/import \{ confirm \} from '\.\.\/util\/confirm\.js'/);
    expect(guardSnapshotsSrc).toMatch(/await confirm\('\\nConfirm re-sign\? \[y\/N\] '\)/);
    expect(adminSrc).toMatch(/import \{ confirm \} from '\.\.\/util\/confirm\.js'/);
    expect(adminSrc).toMatch(/await confirm\(promptText\)/);
  });
});
