/**
 * Shared yes/no confirmation prompt (QGF-305).
 *
 * The one place in packages/cli that reads a typed confirmation off a
 * readline interface. `guard resign` and the `admin sensors approve|reject`
 * destructive-action gate both call it; neither creates a readline interface
 * of its own.
 *
 * The prompt resolves true for `y` / `yes` (any case, surrounding whitespace
 * ignored) and false for anything else, including an empty line and an input
 * that ends before a line arrives (EOF).
 *
 * Why the settle guard: readline's `close()` emits 'close' synchronously, so
 * an implementation that calls `rl.close()` inside its 'line' handler and
 * resolves afterwards has already been resolved false by its own 'close'
 * listener -- a typed `y` read as a decline. The answer is settled here
 * BEFORE the interface is closed, and `settle` ignores any later call, so the
 * promise settles exactly once with the value the user typed.
 */

import { createInterface } from 'node:readline';

export interface ConfirmOptions {
  /** Stream the answer is read from. Defaults to process.stdin. */
  input?: NodeJS.ReadableStream;
  /** Stream the prompt text is written to. Defaults to process.stdout. */
  output?: NodeJS.WritableStream;
}

const AFFIRMATIVE = new Set(['y', 'yes']);

/**
 * Write `promptText` and resolve with whether the next line read from the
 * input is an affirmative answer. Resolves false on EOF without a line.
 */
export function confirm(promptText: string, options: ConfirmOptions = {}): Promise<boolean> {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  return new Promise<boolean>((resolve) => {
    let settled = false;
    const settle = (value: boolean): void => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    output.write(promptText);
    const rl = createInterface({ input, terminal: false });
    rl.once('line', (answer: string) => {
      settle(AFFIRMATIVE.has(answer.trim().toLowerCase()));
      rl.close();
    });
    rl.once('close', () => settle(false));
  });
}
