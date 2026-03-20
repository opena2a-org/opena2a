import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { runtime } from '../../src/commands/runtime.js';

function captureStdout(fn: () => Promise<number>): Promise<{ exitCode: number; output: string }> {
  const chunks: string[] = [];
  const origWrite = process.stdout.write;
  process.stdout.write = ((chunk: any) => {
    chunks.push(String(chunk));
    return true;
  }) as any;

  return fn().then(exitCode => {
    process.stdout.write = origWrite;
    return { exitCode, output: chunks.join('') };
  }).catch(err => {
    process.stdout.write = origWrite;
    throw err;
  });
}

function captureStderr(fn: () => Promise<number>): Promise<{ exitCode: number; output: string }> {
  const chunks: string[] = [];
  const origWrite = process.stderr.write;
  process.stderr.write = ((chunk: any) => {
    chunks.push(String(chunk));
    return true;
  }) as any;

  return fn().then(exitCode => {
    process.stderr.write = origWrite;
    return { exitCode, output: chunks.join('') };
  }).catch(err => {
    process.stderr.write = origWrite;
    throw err;
  });
}

describe('runtime', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-runtime-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('init generates valid config file', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'my-agent' }));

    const { exitCode, output } = await captureStdout(() => runtime({
      subcommand: 'init',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.created).toBe(true);
    expect(result.agentName).toBe('my-agent');

    // Verify config file was created
    const configPath = path.join(tempDir, 'arp.yaml');
    expect(fs.existsSync(configPath)).toBe(true);

    const configContent = fs.readFileSync(configPath, 'utf-8');
    expect(configContent).toContain('agentName: my-agent');
    expect(configContent).toContain('monitors:');
    expect(configContent).toContain('interceptors:');
  });

  it('init enables MCP monitoring when MCP config detected', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'mcp-server' }));
    fs.writeFileSync(path.join(tempDir, 'mcp.json'), '{}');

    const { exitCode } = await captureStdout(() => runtime({
      subcommand: 'init',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const configContent = fs.readFileSync(path.join(tempDir, 'arp.yaml'), 'utf-8');
    expect(configContent).toContain('mcp-protocol: true');
  });

  it('status returns JSON with expected fields', async () => {
    const { exitCode, output } = await captureStdout(() => runtime({
      subcommand: 'status',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const status = JSON.parse(output);
    expect(status).toHaveProperty('running');
    expect(status).toHaveProperty('monitors');
    expect(status).toHaveProperty('interceptors');
    expect(status).toHaveProperty('eventCount');
    expect(status).toHaveProperty('configFile');
  });

  it('tail with no events returns empty', async () => {
    const { exitCode, output } = await captureStdout(() => runtime({
      subcommand: 'tail',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.events).toHaveLength(0);
  });

  it('tail reads events from file', async () => {
    // Create events file
    const eventsDir = path.join(tempDir, '.opena2a/arp');
    fs.mkdirSync(eventsDir, { recursive: true });
    const events = [
      { timestamp: '2026-03-01T10:00:00Z', severity: 'info', message: 'Monitor started' },
      { timestamp: '2026-03-01T10:01:00Z', severity: 'high', message: 'Suspicious network request' },
    ];
    fs.writeFileSync(
      path.join(eventsDir, 'events.jsonl'),
      events.map(e => JSON.stringify(e)).join('\n') + '\n',
    );

    const { exitCode, output } = await captureStdout(() => runtime({
      subcommand: 'tail',
      targetDir: tempDir,
      count: 5,
      format: 'json',
    }));

    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result.events).toHaveLength(2);
    expect(result.total).toBe(2);
  });

  it('start returns 1 when hackmyagent is not installed', async () => {
    const { exitCode, output } = await captureStdout(() => runtime({
      subcommand: 'start',
      targetDir: tempDir,
      format: 'json',
    }));

    expect(exitCode).toBe(1);
    const result = JSON.parse(output);
    expect(result.error).toBeTruthy();
  });
});
