/**
 * The Shield event log is one home-scoped resource.
 *
 * `writeEvent` and the log path helpers take no location, and `opena2a init`
 * writes its posture and credential events to `~/.opena2a/shield/events.jsonl`
 * with `target` naming the project. Before this, init passed its target
 * directory to `writeEvent`, so any project that already had `.opena2a/` (for
 * example after `guard sign`) received a second chain at
 * `<project>/.opena2a/shield/events.jsonl` that no reader verifies or shows,
 * holding absolute paths and credential-finding locations, while the home
 * log, the one every reader uses, received nothing.
 */
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mockHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => mockHome.dir || actual.homedir() };
});

import {
  getEventsPath, getShieldDir, verifyEventChain, writeEvent,
} from '../../src/shield/events.js';
import type { ShieldEvent } from '../../src/shield/types.js';
import { init } from '../../src/commands/init.js';

const FAKE_KEY = 'sk-ant-api03-' + 'A'.repeat(85);
const temps: string[] = [];

function tempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

/** A project that already has `.opena2a/`, as `guard sign` leaves it. */
function makeProject(): string {
  const dir = tempDir('shield-one-log-proj-');
  fs.mkdirSync(path.join(dir, '.opena2a', 'guard'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'p', version: '1.0.0' }));
  fs.writeFileSync(path.join(dir, 'app.js'), `const key = "${FAKE_KEY}";\n`);
  return dir;
}

function homeEvents(): ShieldEvent[] {
  const logPath = path.join(mockHome.dir, '.opena2a', 'shield', 'events.jsonl');
  if (!fs.existsSync(logPath)) return [];
  return fs.readFileSync(logPath, 'utf-8')
    .split('\n').filter(l => l.trim().length > 0)
    .map(l => JSON.parse(l) as ShieldEvent);
}

function sha256File(file: string): string {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

beforeEach(() => {
  mockHome.dir = tempDir('shield-one-log-home-');
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
  mockHome.dir = '';
  while (temps.length > 0) fs.rmSync(temps.pop()!, { recursive: true, force: true });
});

describe('Shield event log is one home log', () => {
  it('writeEvent and the log path helpers take no location', () => {
    expect(writeEvent.length).toBe(1);
    expect(getEventsPath.length).toBe(0);
    expect(getShieldDir.length).toBe(0);
    expect(getEventsPath()).toBe(path.join(mockHome.dir, '.opena2a', 'shield', 'events.jsonl'));
  });

  it('init writes its events to the home log, scoped by target, and nothing into the project', async () => {
    const project = makeProject();

    await init({ targetDir: project, format: 'json' });

    expect(fs.existsSync(path.join(project, '.opena2a', 'shield'))).toBe(false);

    const events = homeEvents();
    const posture = events.filter(e => e.action === 'posture-assessment');
    const creds = events.filter(e => e.action === 'credential-finding');
    expect(posture).toHaveLength(1);
    expect(posture[0].target).toBe(project);
    expect(creds.length).toBeGreaterThanOrEqual(1);
    for (const e of creds) expect(e.target.startsWith(project + path.sep)).toBe(true);
    expect(verifyEventChain(events).valid).toBe(true);
  }, 30_000);

  it('init leaves an existing project-local log byte-identical and out of the home chain', async () => {
    const withLog = makeProject();
    const oldDir = path.join(withLog, '.opena2a', 'shield');
    fs.mkdirSync(oldDir, { recursive: true });
    const oldLog = path.join(oldDir, 'events.jsonl');
    fs.writeFileSync(oldLog, JSON.stringify({ id: 'project-local-line', action: 'old' }) + '\n');
    const before = sha256File(oldLog);

    const withLogExit = await init({ targetDir: withLog, format: 'json' });

    expect(sha256File(oldLog)).toBe(before);
    expect(fs.readdirSync(oldDir)).toEqual(['events.jsonl']);
    const events = homeEvents();
    expect(events.some(e => e.id === 'project-local-line')).toBe(false);
    expect(events.filter(e => e.action === 'posture-assessment').map(e => e.target)).toEqual([withLog]);

    // The old file changes nothing about the run's verdict.
    const withoutLogExit = await init({ targetDir: makeProject(), format: 'json' });
    expect(withLogExit).toBe(withoutLogExit);
  }, 60_000);
});
