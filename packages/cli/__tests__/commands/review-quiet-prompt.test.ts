// `review --quiet` keeps the contribute prompt off the terminal.
//
// The prompt is guidance written to stderr, shown by recordScanAndMaybePrompt
// only when its caller does not ask for machine-readable output and stdout is a
// terminal. review.test.ts records the flag review passes; this file runs the
// real function under a terminal, so a review that stops passing the flag shows
// the prompt here.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
// Under vitest the CommonJS package's `default` export arrives with its
// functions undefined, which loadShared would pick over the named exports and
// the scan count would never be recorded. Hand it the named exports alone, as
// the built CLI sees them.
vi.mock('@opena2a/shared', async (importOriginal) => {
  const { default: _default, ...named } = await importOriginal<Record<string, unknown>>();
  return named;
});

import { incrementScanCount, shouldPromptContribute } from '@opena2a/shared';
import { review } from '../../src/commands/review.js';

const PROMPT_TEXT = 'Your scans help the community detect unsafe tools.';

describe('review contribute prompt under a terminal', () => {
  let tempDir: string;
  let tempHome: string;
  let prevHome: string | undefined;
  let ttyDescriptor: PropertyDescriptor | undefined;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-quiet-prompt-'));
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-review-quiet-prompt-home-'));
    prevHome = process.env.OPENA2A_HOME;
    process.env.OPENA2A_HOME = tempHome;
    // Past the scan threshold, so the prompt is due on the next scan.
    for (let i = 0; i < 3; i++) incrementScanCount();
    expect(shouldPromptContribute()).toBe(true);
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'quiet-prompt' }));
    ttyDescriptor = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true, writable: true });
  });

  afterEach(() => {
    if (ttyDescriptor) Object.defineProperty(process.stdout, 'isTTY', ttyDescriptor);
    else delete (process.stdout as { isTTY?: boolean }).isTTY;
    if (prevHome === undefined) delete process.env.OPENA2A_HOME;
    else process.env.OPENA2A_HOME = prevHome;
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  async function runReview(quiet: boolean): Promise<string> {
    const stderr: string[] = [];
    const origOut = process.stdout.write;
    const origErr = process.stderr.write;
    process.stdout.write = (() => true) as typeof process.stdout.write;
    process.stderr.write = ((chunk: unknown) => { stderr.push(String(chunk)); return true; }) as typeof process.stderr.write;
    try {
      const code = await review({
        targetDir: tempDir,
        reportPath: path.join(tempDir, 'review.html'),
        autoOpen: false,
        skipHma: true,
        quiet,
      });
      expect(code).toBe(0);
    } finally {
      process.stdout.write = origOut;
      process.stderr.write = origErr;
    }
    return stderr.join('');
  }

  it('--quiet shows no contribute prompt and leaves it due', async () => {
    const stderr = await runReview(true);

    expect(stderr).not.toContain(PROMPT_TEXT);
    expect(shouldPromptContribute()).toBe(true);
  });

  it('without --quiet the same review shows the prompt', async () => {
    const stderr = await runReview(false);

    expect(stderr).toContain(PROMPT_TEXT);
    expect(shouldPromptContribute()).toBe(false);
  });
});
