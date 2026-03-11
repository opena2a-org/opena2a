import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  scanProcesses,
  parseMcpConfig,
  scanMcpServers,
  scanIdentity,
  detect,
} from '../../src/commands/detect.js';

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

describe('scanProcesses', () => {
  it('detects Claude Code from ps output', () => {
    const psOutput = [
      'USER       PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND',
      'user     12345   0.5  1.2  1234567  89012 s001  S    10:00AM   0:05.00 node /usr/local/bin/claude --project .',
    ].join('\n');

    const agents = scanProcesses(psOutput);
    expect(agents).toHaveLength(1);
    expect(agents[0].name).toBe('Claude Code');
    expect(agents[0].pid).toBe(12345);
    expect(agents[0].identityStatus).toBe('no identity');
    expect(agents[0].governanceStatus).toBe('no governance');
  });

  it('detects Cursor from ps output', () => {
    const psOutput = [
      'USER       PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND',
      'user     23456   1.0  2.0  2345678  90123 s002  S    10:01AM   0:10.00 /Applications/Cursor.app/Contents/MacOS/Cursor',
    ].join('\n');

    const agents = scanProcesses(psOutput);
    expect(agents).toHaveLength(1);
    expect(agents[0].name).toBe('Cursor');
    expect(agents[0].pid).toBe(23456);
  });

  it('detects GitHub Copilot from ps output', () => {
    const psOutput = [
      'USER       PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND',
      'user     34567   0.3  0.5  3456789  12345 s003  S    10:02AM   0:02.00 node copilot-agent --stdio',
    ].join('\n');

    const agents = scanProcesses(psOutput);
    expect(agents).toHaveLength(1);
    expect(agents[0].name).toBe('GitHub Copilot');
  });

  it('detects Windsurf from ps output', () => {
    const psOutput = [
      'USER       PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND',
      'user     45678   0.8  1.5  4567890  23456 s004  S    10:03AM   0:08.00 /Applications/Windsurf.app/Contents/MacOS/Windsurf',
    ].join('\n');

    const agents = scanProcesses(psOutput);
    expect(agents).toHaveLength(1);
    expect(agents[0].name).toBe('Windsurf');
  });

  it('detects Aider from ps output', () => {
    const psOutput = [
      'USER       PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND',
      'user     56789   0.2  0.8  5678901  34567 s005  S    10:04AM   0:01.00 python3 /usr/local/bin/aider --model gpt-4',
    ].join('\n');

    const agents = scanProcesses(psOutput);
    expect(agents).toHaveLength(1);
    expect(agents[0].name).toBe('Aider');
  });

  it('detects multiple agents simultaneously', () => {
    const psOutput = [
      'USER       PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND',
      'user     12345   0.5  1.2  1234567  89012 s001  S    10:00AM   0:05.00 node /usr/local/bin/claude',
      'user     23456   1.0  2.0  2345678  90123 s002  S    10:01AM   0:10.00 /Applications/Cursor.app/Contents/MacOS/Cursor',
      'user     34567   0.3  0.5  3456789  12345 s003  S    10:02AM   0:02.00 node copilot-agent --stdio',
    ].join('\n');

    const agents = scanProcesses(psOutput);
    expect(agents).toHaveLength(3);
    expect(agents.map((a) => a.name)).toEqual(['Claude Code', 'Cursor', 'GitHub Copilot']);
  });

  it('does not duplicate agents from multiple matching processes', () => {
    const psOutput = [
      'USER       PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND',
      'user     12345   0.5  1.2  1234567  89012 s001  S    10:00AM   0:05.00 node /usr/local/bin/claude',
      'user     12346   0.1  0.2  1234568  89013 s001  S    10:00AM   0:01.00 node @anthropic-ai/claude-code/worker',
    ].join('\n');

    const agents = scanProcesses(psOutput);
    expect(agents).toHaveLength(1);
    expect(agents[0].name).toBe('Claude Code');
  });

  it('returns empty array when no agents found', () => {
    const psOutput = [
      'USER       PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND',
      'user     99999   0.1  0.1  1234567  89012 s001  S    10:00AM   0:00.50 /usr/sbin/syslogd',
      'user     99998   0.0  0.0  1234568  89013 s001  S    10:00AM   0:00.10 /usr/libexec/logd',
    ].join('\n');

    const agents = scanProcesses(psOutput);
    expect(agents).toHaveLength(0);
  });

  it('handles empty ps output', () => {
    const agents = scanProcesses('');
    expect(agents).toHaveLength(0);
  });
});

describe('parseMcpConfig', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-mcp-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('parses mcpServers format', () => {
    const configPath = path.join(tempDir, 'mcp_servers.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem'] },
        'brave-search': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-brave-search'] },
      },
    }));

    const servers = parseMcpConfig(configPath, 'test-source');
    expect(servers).toHaveLength(2);
    expect(servers[0].name).toBe('filesystem');
    expect(servers[0].transport).toBe('stdio');
    expect(servers[0].source).toBe('test-source');
    expect(servers[0].verified).toBe(false);
    expect(servers[1].name).toBe('brave-search');
  });

  it('parses SSE transport servers', () => {
    const configPath = path.join(tempDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        postgres: { url: 'http://localhost:3001/sse', transport: 'sse' },
      },
    }));

    const servers = parseMcpConfig(configPath, 'test-source');
    expect(servers).toHaveLength(1);
    expect(servers[0].name).toBe('postgres');
    expect(servers[0].transport).toBe('sse');
  });

  it('detects SSE from url field even without explicit transport', () => {
    const configPath = path.join(tempDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        remote: { url: 'https://api.example.com/mcp' },
      },
    }));

    const servers = parseMcpConfig(configPath, 'test-source');
    expect(servers).toHaveLength(1);
    expect(servers[0].transport).toBe('sse');
  });

  it('returns empty array for non-existent file', () => {
    const servers = parseMcpConfig('/nonexistent/path/mcp.json', 'test');
    expect(servers).toHaveLength(0);
  });

  it('returns empty array for invalid JSON', () => {
    const configPath = path.join(tempDir, 'bad.json');
    fs.writeFileSync(configPath, 'not valid json {{{');

    const servers = parseMcpConfig(configPath, 'test');
    expect(servers).toHaveLength(0);
  });

  it('handles flat object format (servers as top-level keys)', () => {
    const configPath = path.join(tempDir, 'flat.json');
    fs.writeFileSync(configPath, JSON.stringify({
      myServer: { command: 'node', args: ['server.js'] },
    }));

    const servers = parseMcpConfig(configPath, 'test');
    expect(servers).toHaveLength(1);
    expect(servers[0].name).toBe('myServer');
    expect(servers[0].transport).toBe('stdio');
  });
});

describe('scanMcpServers', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-scan-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('finds project-local mcp.json', () => {
    fs.writeFileSync(
      path.join(tempDir, 'mcp.json'),
      JSON.stringify({
        mcpServers: {
          local: { command: 'node', args: ['local-server.js'] },
        },
      })
    );

    const servers = scanMcpServers(tempDir);
    const projectServers = servers.filter((s) => s.source.includes('project'));
    expect(projectServers.length).toBeGreaterThanOrEqual(1);
    expect(projectServers[0].name).toBe('local');
    expect(projectServers[0].source).toBe('mcp.json (project)');
  });

  it('finds project-local .mcp.json (hidden)', () => {
    fs.writeFileSync(
      path.join(tempDir, '.mcp.json'),
      JSON.stringify({
        mcpServers: {
          hidden: { command: 'node', args: ['hidden-server.js'] },
        },
      })
    );

    const servers = scanMcpServers(tempDir);
    const projectServers = servers.filter((s) => s.source.includes('project'));
    expect(projectServers.length).toBeGreaterThanOrEqual(1);
    expect(projectServers.some((s) => s.name === 'hidden')).toBe(true);
  });
});

describe('scanIdentity', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-id-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('detects .opena2a directory as AIM identity', () => {
    fs.mkdirSync(path.join(tempDir, '.opena2a'));
    const summary = scanIdentity(tempDir);
    expect(summary.aimIdentities).toBeGreaterThanOrEqual(1);
  });

  it('detects SOUL.md governance file', () => {
    fs.writeFileSync(path.join(tempDir, 'SOUL.md'), '# Agent Soul\n');
    const summary = scanIdentity(tempDir);
    expect(summary.soulFiles).toBe(1);
  });

  it('detects SOUL.md inside .opena2a directory', () => {
    fs.mkdirSync(path.join(tempDir, '.opena2a'));
    fs.writeFileSync(path.join(tempDir, '.opena2a', 'SOUL.md'), '# Soul\n');
    const summary = scanIdentity(tempDir);
    expect(summary.soulFiles).toBe(1);
  });

  it('detects capability policy files', () => {
    fs.mkdirSync(path.join(tempDir, '.opena2a'));
    fs.writeFileSync(path.join(tempDir, '.opena2a', 'policy.yml'), 'rules: []\n');
    const summary = scanIdentity(tempDir);
    expect(summary.capabilityPolicies).toBe(1);
  });

  it('returns zeros when nothing found', () => {
    const summary = scanIdentity(tempDir);
    expect(summary.soulFiles).toBe(0);
    expect(summary.capabilityPolicies).toBe(0);
  });
});

describe('detect command', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-cmd-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('returns exit code 0 for text output', async () => {
    const { exitCode, output } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'text' })
    );
    expect(exitCode).toBe(0);
    expect(output).toContain('Shadow AI Agent Audit');
    expect(output).toContain('Running AI Agents');
    expect(output).toContain('MCP Servers');
    expect(output).toContain('Identity Status');
    expect(output).toContain('Next Steps');
  });

  it('returns valid JSON for json format', async () => {
    const { exitCode, output } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'json' })
    );
    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    expect(result).toHaveProperty('agents');
    expect(result).toHaveProperty('mcpServers');
    expect(result).toHaveProperty('identity');
    expect(Array.isArray(result.agents)).toBe(true);
    expect(Array.isArray(result.mcpServers)).toBe(true);
    expect(typeof result.identity.aimIdentities).toBe('number');
    expect(typeof result.identity.totalAgents).toBe('number');
    expect(typeof result.identity.soulFiles).toBe('number');
    expect(typeof result.identity.capabilityPolicies).toBe('number');
  });

  it('includes MCP servers from project-local config in JSON', async () => {
    fs.writeFileSync(
      path.join(tempDir, 'mcp.json'),
      JSON.stringify({
        mcpServers: {
          testServer: { command: 'node', args: ['test.js'] },
        },
      })
    );

    const { exitCode, output } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'json' })
    );
    expect(exitCode).toBe(0);
    const result = JSON.parse(output);
    const projServers = result.mcpServers.filter(
      (s: any) => s.source.includes('project')
    );
    expect(projServers.length).toBeGreaterThanOrEqual(1);
    expect(projServers[0].name).toBe('testServer');
  });

  it('reports identity status in text output', async () => {
    fs.writeFileSync(path.join(tempDir, 'SOUL.md'), '# Soul\n');

    const { output } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'text' })
    );
    expect(output).toContain('1 SOUL.md files found');
  });

  it('verbose mode adds detection method details', async () => {
    const { output } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'text', verbose: true })
    );
    expect(output).toContain('Detection methods');
    expect(output).toContain('ps aux');
  });

  it('returns exit code 1 for inaccessible directory', async () => {
    const { exitCode, output } = await captureStderr(() =>
      detect({ targetDir: '/nonexistent/directory/that/does/not/exist', format: 'text' })
    );
    expect(exitCode).toBe(1);
    expect(output).toContain('Cannot access directory');
  });

  it('does not contain emojis in output', async () => {
    const { output } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'text' })
    );
    // Check for common emoji Unicode ranges
    const emojiPattern = /[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/u;
    expect(emojiPattern.test(output)).toBe(false);
  });

  it('uses informative tone, not alarming language', async () => {
    const { output } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'text' })
    );
    // Should not contain scary language
    expect(output).not.toContain('WARNING');
    expect(output).not.toContain('DANGER');
    expect(output).not.toContain('CRITICAL');
    expect(output).not.toContain('unidentified agents detected');
  });
});
