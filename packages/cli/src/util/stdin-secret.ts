/**
 * Read one secret from standard input (for `--api-key-stdin`), so it never appears in the
 * process list or the shell history the way a command-line value does. Reads to end of input
 * and trims the trailing newline a pipe or `echo` adds. At a terminal it says what it is
 * waiting for, since the read otherwise looks like a hang.
 *
 * Limitation: the key is held as a JavaScript string for the life of this short-lived process,
 * as it is when it comes from AIM_API_KEY. Node cannot zero a string, and the key must be a
 * string to go into the request header, so it is not copied anywhere else and is never logged
 * or echoed.
 */
import { readFileSync } from 'node:fs';

export function readSecretFromStdin(): string {
  if (process.stdin.isTTY) {
    process.stderr.write('Paste the agent API key, then press Enter and Ctrl-D:\n');
  }
  return readFileSync(0, 'utf-8').trim();
}
