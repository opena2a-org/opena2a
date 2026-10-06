/**
 * `guard resign` consent: a typed yes counts only at a terminal.
 *
 * Before this rule, `--ci` and `--format json` re-signed without a prompt and
 * wrote identical `config.resigned` events, and a `y` piped from a
 * non-terminal stdin was read as a confirmation. An automated actor that
 * changed a signed config could therefore re-sign it as if a person had
 * confirmed the change. Now `--ci` is the one way to re-sign without a
 * prompt, a non-terminal stdin or `--format json` without `--ci` refuses and
 * names `--ci`, and the event records how consent was given.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { PassThrough } from 'node:stream';

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => _mockHomeDir };
});

const { guard } = await import('../../src/commands/guard.js');
const { readEvents } = await import('../../src/shield/events.js');

let tempHome: string;
let targetDir: string;
let storePath: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'guard-resign-consent-home-'));
  targetDir = fs.mkdtempSync(path.join(tmpdir(), 'guard-resign-consent-target-'));
  storePath = path.join(targetDir, '.opena2a/guard/signatures.json');
  _mockHomeDir = tempHome;
});

afterEach(() => {
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(targetDir, { recursive: true, force: true });
});

/** Replace process.stdin with a stream holding one answer line. */
function withStdin(answer: string, isTTY: boolean): () => void {
  const fake = new PassThrough();
  if (isTTY) Object.assign(fake, { isTTY: true });
  fake.end(answer + '\n');
  const original = Object.getOwnPropertyDescriptor(process, 'stdin')!;
  Object.defineProperty(process, 'stdin', { value: fake, configurable: true, enumerable: true, writable: true });
  return () => { Object.defineProperty(process, 'stdin', original); };
}

async function run(
  opts: { format?: string; ci?: boolean },
  stdin: { answer: string; isTTY: boolean },
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const outSpy = vi.spyOn(process.stdout, 'write').mockImplementation((c: any) => { out.push(String(c)); return true; });
  const errSpy = vi.spyOn(process.stderr, 'write').mockImplementation((c: any) => { err.push(String(c)); return true; });
  const restoreStdin = withStdin(stdin.answer, stdin.isTTY);
  try {
    const exitCode = await guard({ subcommand: 'resign', targetDir, ...opts });
    return { exitCode, stdout: out.join(''), stderr: err.join('') };
  } finally {
    restoreStdin();
    outSpy.mockRestore();
    errSpy.mockRestore();
  }
}

/** Sign one file, then change it so there is something to re-sign. */
async function signThenChange(): Promise<void> {
  fs.writeFileSync(path.join(targetDir, 'package.json'), '{"name":"original"}');
  const outSpy = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
  try {
    await guard({ subcommand: 'sign', targetDir, format: 'json' });
  } finally {
    outSpy.mockRestore();
  }
  fs.writeFileSync(path.join(targetDir, 'package.json'), '{"name":"modified"}');
}

function resignedEvents() {
  return readEvents({ category: 'config.resigned' });
}

describe('guard resign consent', () => {
  it('refuses a yes piped from a non-terminal stdin, names --ci, and leaves the store and log unchanged', async () => {
    await signThenChange();
    const storeBefore = fs.readFileSync(storePath, 'utf-8');

    const r = await run({}, { answer: 'y', isTTY: false });

    expect(r.exitCode).toBe(1);
    expect(r.stderr).toContain('Refusing to re-sign');
    expect(r.stderr).toContain('--ci');
    expect(r.stdout).not.toContain('Confirm re-sign?');
    expect(r.stdout).not.toContain('Re-signed');
    expect(fs.readFileSync(storePath, 'utf-8')).toBe(storeBefore);
    expect(resignedEvents()).toHaveLength(0);
  });

  it('refuses --format json without --ci even at a terminal, with a JSON error that names --ci', async () => {
    await signThenChange();
    const storeBefore = fs.readFileSync(storePath, 'utf-8');

    const r = await run({ format: 'json' }, { answer: 'y', isTTY: true });

    expect(r.exitCode).toBe(1);
    const body = JSON.parse(r.stdout);
    expect(body.error).toContain('--ci');
    expect(body.files).toEqual(['package.json']);
    expect(body.resigned).toBeUndefined();
    expect(fs.readFileSync(storePath, 'utf-8')).toBe(storeBefore);
    expect(resignedEvents()).toHaveLength(0);
  });

  it('records consent "prompt" when the re-sign is confirmed by a yes typed at a terminal', async () => {
    await signThenChange();

    const r = await run({}, { answer: 'y', isTTY: true });

    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('Confirm re-sign? [y/N]');
    expect(r.stdout).toContain('Re-signed 1 file.');
    const events = resignedEvents();
    expect(events).toHaveLength(1);
    expect(events[0].detail).toMatchObject({ fileCount: 1, files: ['package.json'], consent: 'prompt' });
  });

  it('re-signs with --ci from a non-terminal stdin without prompting and records consent "ci"', async () => {
    await signThenChange();

    const r = await run({ ci: true, format: 'json' }, { answer: '', isTTY: false });

    expect(r.exitCode).toBe(0);
    expect(JSON.parse(r.stdout)).toEqual({ resigned: 1, files: ['package.json'] });
    const events = resignedEvents();
    expect(events).toHaveLength(1);
    expect(events[0].detail).toMatchObject({ fileCount: 1, files: ['package.json'], consent: 'ci' });
  });

  it('records consent "ci" for --ci at a terminal too: --ci never counts as a confirmation', async () => {
    await signThenChange();

    const r = await run({ ci: true }, { answer: 'y', isTTY: true });

    expect(r.exitCode).toBe(0);
    expect(r.stdout).not.toContain('Confirm re-sign?');
    expect(resignedEvents()[0].detail).toMatchObject({ consent: 'ci' });
  });

  it('does not refuse when nothing changed: there is nothing to consent to', async () => {
    fs.writeFileSync(path.join(targetDir, 'package.json'), '{}');
    const outSpy = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    try {
      await guard({ subcommand: 'sign', targetDir, format: 'json' });
    } finally {
      outSpy.mockRestore();
    }

    const r = await run({}, { answer: '', isTTY: false });

    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain('Nothing to re-sign.');
    expect(r.stderr).not.toContain('Refusing');
  });
});
