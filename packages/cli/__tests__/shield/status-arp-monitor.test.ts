/**
 * `shield status` reports Runtime Guard (ARP) as `monitoring` only when a
 * running monitor's witness (`.opena2a/arp/monitor.pid`) names a live
 * process. An events file is left behind after the monitor exits, so on its
 * own it is reported as recorded events with the age of the last one.
 *
 * Every file is written into an `mkdtemp` directory passed as the target, and
 * HOME and PATH point at scratch directories, so nothing on the test machine
 * is read or started. No network.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let root: string;
let project: string;
let child: ChildProcess | null = null;

async function arpStatus(dir: string) {
  const { getShieldStatus, formatStatus } = await import('../../src/shield/status.js');
  const status = getShieldStatus(dir);
  const arp = status.tools.find(t => t.name === 'Runtime Guard (ARP)');
  if (!arp) throw new Error('no ARP row');
  return { arp, text: formatStatus(status, 'text') };
}

function writeEvents(lastTs: string): void {
  mkdirSync(join(project, '.opena2a', 'arp'), { recursive: true });
  writeFileSync(
    join(project, '.opena2a', 'arp', 'events.jsonl'),
    JSON.stringify({ timestamp: '2019-06-01T00:00:00Z' }) + '\n' + JSON.stringify({ ts: lastTs }) + '\n',
  );
}

function writeWitness(pid: number): void {
  mkdirSync(join(project, '.opena2a', 'arp'), { recursive: true });
  writeFileSync(join(project, '.opena2a', 'arp', 'monitor.pid'), JSON.stringify({ pid, startedAt: new Date().toISOString() }));
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'shield-status-arp-'));
  project = join(root, 'project');
  const home = join(root, 'home');
  mkdirSync(project, { recursive: true });
  mkdirSync(home, { recursive: true });
  writeFileSync(join(project, 'arp.yaml'), 'monitors: {}\n');
  vi.stubEnv('HOME', home);
  vi.stubEnv('PATH', join(root, 'empty-bin'));
  vi.resetModules();
});

afterEach(() => {
  if (child && child.exitCode === null) child.kill('SIGKILL');
  child = null;
  vi.unstubAllEnvs();
  vi.resetModules();
  rmSync(root, { recursive: true, force: true });
});

describe('Runtime Guard (ARP) in shield status', () => {
  it('an old events file with no monitor reports no monitor running, with the age', async () => {
    writeEvents('2020-01-01T00:00:00Z');
    const { arp, text } = await arpStatus(project);
    expect(arp.active).toBe(false);
    expect(arp.keyMetric).toMatch(/^events recorded, no monitor running \(last event \d+y ago\)$/);
    expect(text).toContain('no monitor running');
    expect(text).not.toContain('Runtime Guard (ARP)    monitoring');
  });

  it('a witness naming a process that has exited is not a monitor', async () => {
    writeEvents(new Date(Date.now() - 5 * 60_000).toISOString());
    const dead = spawn(process.execPath, ['-e', '']);
    await new Promise<void>(r => dead.once('exit', () => r()));
    writeWitness(dead.pid!);
    const { arp } = await arpStatus(project);
    expect(arp.active).toBe(false);
    expect(arp.keyMetric).toBe('events recorded, no monitor running (last event 5m ago)');
  });

  it('a witness naming a live process reports monitoring', async () => {
    writeEvents('2020-01-01T00:00:00Z');
    child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
    writeWitness(child.pid!);
    const { arp, text } = await arpStatus(project);
    expect(arp.active).toBe(true);
    expect(arp.keyMetric).toBe('monitoring');
    expect(text).toMatch(/Runtime Guard \(ARP\)\s+monitoring/);
  });

  it('reads the directory it is given, not the working directory', async () => {
    writeEvents('2020-01-01T00:00:00Z');
    const { arp } = await arpStatus(join(root, 'home'));
    expect(arp.keyMetric).toBe('not configured');
    const fromTarget = await arpStatus(project);
    expect(fromTarget.arp.keyMetric).toContain('no monitor running');
  });

  it('a witness without a usable pid is not a monitor', async () => {
    writeEvents('2020-01-01T00:00:00Z');
    for (const body of ['0', '-1', '{"pid":"abc"}', 'not a pid']) {
      writeFileSync(join(project, '.opena2a', 'arp', 'monitor.pid'), body);
      const { arp } = await arpStatus(project);
      expect(arp.active).toBe(false);
    }
  });
});
