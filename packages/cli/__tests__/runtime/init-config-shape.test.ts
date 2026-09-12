/**
 * `opena2a runtime init` must emit an arp.yaml whose keys the ARP engine
 * actually honors.
 *
 * The regression this pins: init used to write `interceptors: { process: true }`
 * and `aiLayer: { prompt: true, mcp-protocol: true }`. The engine reads
 * `ic?.process?.enabled` and `al?.mcp?.enabled`, so a bare boolean and the
 * hyphenated key both evaluate to undefined. The YAML parsed, the file said the
 * detectors were on, and no interceptor was ever constructed — while
 * `runtime status` reported them as configured.
 *
 * The assertions run against the real engine (hackmyagent/arp), not against a
 * copy of the CLI's own predicates, so a future template edit that stops
 * matching the engine fails here.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runtimeInitSilent } from '../../src/commands/runtime.js';

type ARPClass = new (configOrPath: string) => {
  getStatus(): { monitors: Array<{ type: string; running: boolean }> };
};

let AgentRuntimeProtection: ARPClass;

/** Detector types the engine actually constructed for this config file. */
function builtDetectors(configPath: string): string[] {
  const instance = new AgentRuntimeProtection(configPath);
  return instance.getStatus().monitors.map((m) => m.type).sort();
}

function initInto(dir: string): string {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ name: 'fixture-agent', version: '1.0.0' }),
  );
  return path.join(dir, 'arp.yaml');
}

describe('runtime init emits a config the ARP engine honors', () => {
  let tmp: string;
  let configPath: string;

  beforeAll(async () => {
    const mod = await import('hackmyagent/arp');
    AgentRuntimeProtection = (mod as unknown as { AgentRuntimeProtection: ARPClass })
      .AgentRuntimeProtection;

    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'arp-init-'));
    configPath = initInto(tmp);
    const result = await runtimeInitSilent(tmp);
    expect(result.created).toBe(true);
    expect(fs.existsSync(configPath)).toBe(true);
  });

  it('builds the three polling monitors', () => {
    const built = builtDetectors(configPath);
    expect(built).toContain('process');
    expect(built).toContain('network');
    expect(built).toContain('filesystem');
  });

  it('uses object blocks with an enabled field, never bare booleans', () => {
    const raw = fs.readFileSync(configPath, 'utf-8');
    const active = raw
      .split('\n')
      .filter((l) => !l.trimStart().startsWith('#'))
      .join('\n');
    // A bare `key: true` under interceptors/aiLayer parses but builds nothing.
    expect(active).not.toMatch(/^\s+(process|network|filesystem|prompt|mcp|a2a):\s*(true|false)\s*$/m);
    // The engine's AILayerConfig keys are prompt/mcp/a2a, not the hyphenated
    // MonitorType spellings that the event `source` field uses.
    expect(active).not.toContain('mcp-protocol:');
    expect(active).not.toContain('a2a-protocol:');
  });

  it('constructs every interceptor and AI-layer scanner once turned on', () => {
    const raw = fs.readFileSync(configPath, 'utf-8');
    const enabledPath = path.join(tmp, 'arp-enabled.yaml');
    fs.writeFileSync(enabledPath, raw.replace(/enabled: false/g, 'enabled: true'));

    const built = builtDetectors(enabledPath);

    // Flipping the emitted flags must actually reach the engine. Under the old
    // template these three stayed absent no matter what the file said.
    expect(built).toContain('prompt');
    expect(built).toContain('mcp-protocol');
    expect(built).toContain('a2a-protocol');
    // Interceptors register alongside the polling monitors of the same name.
    expect(built.filter((t) => t === 'process').length).toBe(2);
    expect(built.filter((t) => t === 'network').length).toBe(2);
    expect(built.filter((t) => t === 'filesystem').length).toBe(2);
  });
});
