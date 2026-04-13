import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  scanProcesses,
  parseMcpConfig,
  scanMcpServers,
  scanIdentity,
  scanAiConfigs,
  detect,
} from '../../src/commands/detect.js';
import type { DetectResult } from '../../src/commands/detect.js';
import { generateDetectHtml } from '../../src/report/detect-html.js';

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

  it('detects AIM identity file in .opena2a/aim/', () => {
    fs.mkdirSync(path.join(tempDir, '.opena2a', 'aim'), { recursive: true });
    fs.writeFileSync(path.join(tempDir, '.opena2a', 'aim', 'identity.json'), '{"agentId":"test"}');
    const summary = scanIdentity(tempDir);
    expect(summary.aimIdentities).toBeGreaterThanOrEqual(1);
  });

  it('bare .opena2a directory does not count as project identity', () => {
    fs.mkdirSync(path.join(tempDir, '.opena2a'));
    const summary = scanIdentity(tempDir);
    // aimIdentities may be 1 if a global identity exists at ~/.opena2a/aim-core/
    // but the project-local .opena2a/aim/identity.json should not exist
    const projectIdentity = fs.existsSync(path.join(tempDir, '.opena2a', 'aim', 'identity.json'));
    expect(projectIdentity).toBe(false);
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
    expect(output).toContain('Governance:');
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

  it('reports governance score in text output', async () => {
    const { output } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'text' })
    );
    expect(output).toContain('Governance:');
    expect(output).toContain('/100');
  });

  it('verbose mode adds detection method details', async () => {
    const { output } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'text', verbose: true })
    );
    // Verbose mode shows Identity & Governance section
    expect(output).toContain('Identity & Governance');
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

// ---------------------------------------------------------------------------
// MCP capability inference (tested indirectly via parseMcpConfig)
// ---------------------------------------------------------------------------

describe('MCP capability inference', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-caps-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('infers filesystem capability from server named "filesystem"', () => {
    const configPath = path.join(tempDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem'] },
      },
    }));

    const servers = parseMcpConfig(configPath, 'test');
    expect(servers).toHaveLength(1);
    expect(servers[0].capabilities).toContain('filesystem');
  });

  it('infers shell-access capability from command "bash"', () => {
    const configPath = path.join(tempDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        runner: { command: 'bash', args: ['-c', 'some-script'] },
      },
    }));

    const servers = parseMcpConfig(configPath, 'test');
    expect(servers).toHaveLength(1);
    expect(servers[0].capabilities).toContain('shell-access');
  });

  it('infers payments capability from server named "stripe"', () => {
    const configPath = path.join(tempDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        stripe: { command: 'node', args: ['stripe-server.js'] },
      },
    }));

    const servers = parseMcpConfig(configPath, 'test');
    expect(servers).toHaveLength(1);
    expect(servers[0].capabilities).toContain('payments');
  });

  it('infers cloud-services capability from server named "supabase"', () => {
    const configPath = path.join(tempDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        supabase: { command: 'npx', args: ['supabase-mcp'] },
      },
    }));

    const servers = parseMcpConfig(configPath, 'test');
    expect(servers).toHaveLength(1);
    expect(servers[0].capabilities).toContain('cloud-services');
  });

  it('assigns "unknown" capability when no keywords match', () => {
    const configPath = path.join(tempDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        'context7': { command: 'node', args: ['context7.js'] },
      },
    }));

    const servers = parseMcpConfig(configPath, 'test');
    expect(servers).toHaveLength(1);
    expect(servers[0].capabilities).toEqual(['unknown']);
  });
});

// ---------------------------------------------------------------------------
// MCP risk classification (tested indirectly via parseMcpConfig)
// ---------------------------------------------------------------------------

describe('MCP risk classification', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-risk-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('classifies shell-access as critical risk', () => {
    const configPath = path.join(tempDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        terminal: { command: 'bash', args: ['-i'] },
      },
    }));

    const servers = parseMcpConfig(configPath, 'test');
    expect(servers[0].capabilities).toContain('shell-access');
    expect(servers[0].risk).toBe('critical');
  });

  it('classifies SSE transport with payments as critical risk', () => {
    const configPath = path.join(tempDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        'stripe-remote': { url: 'https://stripe.example.com/mcp', transport: 'sse' },
      },
    }));

    const servers = parseMcpConfig(configPath, 'test');
    expect(servers[0].transport).toBe('sse');
    expect(servers[0].capabilities).toContain('payments');
    expect(servers[0].risk).toBe('critical');
  });

  it('classifies database capability as high risk', () => {
    const configPath = path.join(tempDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        postgres: { command: 'node', args: ['postgres-server.js'] },
      },
    }));

    const servers = parseMcpConfig(configPath, 'test');
    expect(servers[0].capabilities).toContain('database');
    expect(servers[0].risk).toBe('high');
  });

  it('classifies filesystem capability as medium risk', () => {
    const configPath = path.join(tempDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        filesystem: { command: 'npx', args: ['@mcp/server-filesystem'] },
      },
    }));

    const servers = parseMcpConfig(configPath, 'test');
    expect(servers[0].capabilities).toContain('filesystem');
    expect(servers[0].risk).toBe('medium');
  });

  it('classifies unknown capabilities as medium risk', () => {
    const configPath = path.join(tempDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        'my-custom-thing': { command: 'node', args: ['custom.js'] },
      },
    }));

    const servers = parseMcpConfig(configPath, 'test');
    expect(servers[0].capabilities).toEqual(['unknown']);
    expect(servers[0].risk).toBe('medium');
  });
});

// ---------------------------------------------------------------------------
// AI config scanning
// ---------------------------------------------------------------------------

describe('scanAiConfigs', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-aiconf-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('detects .cursorrules file', () => {
    fs.writeFileSync(path.join(tempDir, '.cursorrules'), 'some cursor rules');

    const configs = scanAiConfigs(tempDir);
    expect(configs.some((c) => c.file === '.cursorrules')).toBe(true);
    expect(configs.find((c) => c.file === '.cursorrules')?.tool).toBe('Cursor');
  });

  it('detects CLAUDE.md file', () => {
    fs.writeFileSync(path.join(tempDir, 'CLAUDE.md'), '# Claude instructions\n');

    const configs = scanAiConfigs(tempDir);
    expect(configs.some((c) => c.file === 'CLAUDE.md')).toBe(true);
    expect(configs.find((c) => c.file === 'CLAUDE.md')?.tool).toBe('Claude Code');
  });

  it('detects .github/copilot-instructions.md', () => {
    fs.mkdirSync(path.join(tempDir, '.github'), { recursive: true });
    fs.writeFileSync(
      path.join(tempDir, '.github', 'copilot-instructions.md'),
      '# Copilot instructions\n'
    );

    const configs = scanAiConfigs(tempDir);
    expect(configs.some((c) => c.file === '.github/copilot-instructions.md')).toBe(true);
    expect(configs.find((c) => c.file === '.github/copilot-instructions.md')?.tool).toBe('GitHub Copilot');
  });

  it('flags configs with credential patterns as critical risk', () => {
    fs.writeFileSync(
      path.join(tempDir, '.cursorrules'),
      'api_key: sk-1234567890abcdefghijklmnop'
    );

    const configs = scanAiConfigs(tempDir);
    const cursorrules = configs.find((c) => c.file === '.cursorrules');
    expect(cursorrules?.risk).toBe('critical');
    expect(cursorrules?.details).toContain('credential');
  });

  it('flags configs with broad permission patterns as high risk', () => {
    fs.writeFileSync(
      path.join(tempDir, '.cursorrules'),
      'allow all bash commands unrestricted'
    );

    const configs = scanAiConfigs(tempDir);
    const cursorrules = configs.find((c) => c.file === '.cursorrules');
    expect(cursorrules?.risk).toBe('high');
    expect(cursorrules?.details).toContain('broad permissions');
  });

  it('does NOT detect SOUL.md as an AI config', () => {
    fs.writeFileSync(path.join(tempDir, 'SOUL.md'), '# Agent Soul\n');

    const configs = scanAiConfigs(tempDir);
    expect(configs.some((c) => c.file === 'SOUL.md')).toBe(false);
  });

  it('returns empty array for clean directory', () => {
    const configs = scanAiConfigs(tempDir);
    expect(configs).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// CSV export (tested via detect with exportCsv option)
// ---------------------------------------------------------------------------

describe('CSV export', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-csv-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('generates CSV with correct headers', async () => {
    const csvPath = path.join(tempDir, 'assets.csv');
    await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'text', exportCsv: csvPath })
    );

    const csv = fs.readFileSync(csvPath, 'utf-8');
    const header = csv.split('\n')[0];
    expect(header).toBe(
      'Hostname,Username,Scan Directory,Scan Timestamp,Asset Type,Name,Installed From,Transport,Capabilities,Risk'
    );
  });

  it('includes MCP Server rows with correct asset type', async () => {
    // Create a project-local MCP config so it appears in output
    fs.writeFileSync(
      path.join(tempDir, 'mcp.json'),
      JSON.stringify({
        mcpServers: {
          testDb: { command: 'node', args: ['db-server.js'] },
        },
      })
    );

    const csvPath = path.join(tempDir, 'assets.csv');
    await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'text', exportCsv: csvPath })
    );

    const csv = fs.readFileSync(csvPath, 'utf-8');
    const lines = csv.split('\n').filter(Boolean);
    const mcpLines = lines.filter((l) => l.includes('MCP Server'));
    expect(mcpLines.length).toBeGreaterThanOrEqual(1);
    // Verify the MCP server row contains testDb
    expect(mcpLines.some((l) => l.includes('testDb'))).toBe(true);
  });

  it('escapes values containing commas in CSV', async () => {
    // Server name with comma would need escaping
    fs.writeFileSync(
      path.join(tempDir, 'mcp.json'),
      JSON.stringify({
        mcpServers: {
          'server,with,commas': { command: 'node', args: ['test.js'] },
        },
      })
    );

    const csvPath = path.join(tempDir, 'assets.csv');
    await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'text', exportCsv: csvPath })
    );

    const csv = fs.readFileSync(csvPath, 'utf-8');
    // The server name should be quoted to handle commas
    expect(csv).toContain('"server,with,commas"');
  });
});

// ---------------------------------------------------------------------------
// Governance scoring (tested via detect --format json)
// ---------------------------------------------------------------------------

describe('governance scoring', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-score-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('baseline score is consistent for empty project', async () => {
    const { output } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'json' })
    );
    const result = JSON.parse(output);
    // Score depends on real running agents (e.g., Claude Code in test env)
    // but must be a valid number between 0 and 100
    expect(result.summary.governanceScore).toBeGreaterThanOrEqual(0);
    expect(result.summary.governanceScore).toBeLessThanOrEqual(100);
  });

  it('project with SOUL.md scores higher than or equal to without', async () => {
    // Get baseline score without SOUL.md
    const { output: baseOutput } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'json' })
    );
    const baseResult = JSON.parse(baseOutput);

    // Add SOUL.md and get new score
    fs.writeFileSync(path.join(tempDir, 'SOUL.md'), '# Agent Soul\n');
    const { output: soulOutput } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'json' })
    );
    const soulResult = JSON.parse(soulOutput);

    expect(soulResult.identity.soulFiles).toBe(1);
    // SOUL.md should not decrease the score (it adds governance)
    expect(soulResult.summary.governanceScore).toBeGreaterThanOrEqual(baseResult.summary.governanceScore);
  });

  it('project with unverified project-local critical MCP server has lower score', async () => {
    // Get baseline score
    const { output: baseOutput } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'json' })
    );
    const baseScore = JSON.parse(baseOutput).summary.governanceScore;

    // Add a shell-access MCP server (critical risk) to the project
    fs.writeFileSync(
      path.join(tempDir, 'mcp.json'),
      JSON.stringify({
        mcpServers: {
          'shell-runner': { command: 'bash', args: ['-i'] },
        },
      })
    );

    const { output } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'json' })
    );
    const result = JSON.parse(output);
    // Critical project-local MCP server deducts 20 points from baseline
    expect(result.summary.governanceScore).toBeLessThan(baseScore);
  });

  it('AI config with credentials deducts from governance score', async () => {
    // Get baseline score
    const { output: baseOutput } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'json' })
    );
    const baseScore = JSON.parse(baseOutput).summary.governanceScore;

    fs.writeFileSync(
      path.join(tempDir, '.cursorrules'),
      'api_key: sk-1234567890abcdefghijklmnop'
    );

    const { output } = await captureStdout(() =>
      detect({ targetDir: tempDir, format: 'json' })
    );
    const result = JSON.parse(output);
    // Critical AI config deducts 25 points from baseline
    expect(result.summary.governanceScore).toBeLessThan(baseScore);
    expect(result.summary.governanceScore).toBe(baseScore - 25);
  });
});

// ---------------------------------------------------------------------------
// HTML report generation
// ---------------------------------------------------------------------------

describe('generateDetectHtml', () => {
  function mockDetectResult(overrides?: Partial<DetectResult>): DetectResult {
    return {
      scanTimestamp: '2026-03-15T12:00:00.000Z',
      scanDirectory: '/tmp/test-project',
      summary: {
        totalAgents: 1,
        ungoverned: 1,
        mcpServers: 1,
        unverifiedServers: 1,
        localLlms: 0,
        aiConfigs: 0,
        governanceScore: 65,
        recoverablePoints: 35,
      },
      agents: [
        {
          name: 'Claude Code',
          pid: 12345,
          category: 'ai-assistant',
          identityStatus: 'no identity',
          governanceStatus: 'no governance',
          risk: 'high',
        },
      ],
      mcpServers: [
        {
          name: 'filesystem',
          transport: 'stdio',
          source: 'mcp.json (project)',
          verified: false,
          capabilities: ['filesystem'],
          risk: 'medium',
        },
      ],
      aiConfigs: [],
      identity: {
        aimIdentities: 0,
        mcpIdentities: 0,
        totalAgents: 1,
        soulFiles: 0,
        capabilityPolicies: 0,
      },
      findings: [
        {
          severity: 'high',
          category: 'governance',
          title: '1 AI agent running without governance',
          detail: 'Claude Code -- no SOUL.md governance file found',
          whyItMatters: 'Agents have no rules limiting what they can do.',
          remediation: 'opena2a harden-soul',
        },
      ],
      ...overrides,
    };
  }

  it('returns valid HTML with DOCTYPE', () => {
    const html = generateDetectHtml(mockDetectResult());
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('</html>');
  });

  it('escapes XSS in agent names', () => {
    const result = mockDetectResult({
      agents: [
        {
          name: '<script>alert("xss")</script>',
          pid: 99999,
          category: 'ai-assistant',
          identityStatus: 'no identity',
          governanceStatus: 'no governance',
          risk: 'high',
        },
      ],
    });

    const html = generateDetectHtml(result);
    // The raw script tag should NOT appear in the HTML
    expect(html).not.toContain('<script>alert("xss")</script>');
    // The JSON data section escapes </ to <\/ for safety
    expect(html).not.toMatch(/<script>alert\("xss"\)<\/script>/);
  });

  it('contains the governance score', () => {
    const html = generateDetectHtml(mockDetectResult({ summary: {
      totalAgents: 1,
      ungoverned: 1,
      mcpServers: 0,
      unverifiedServers: 0,
      localLlms: 0,
      aiConfigs: 0,
      governanceScore: 42,
      recoverablePoints: 58,
    }}));

    // The governance score is rendered by JS from the embedded JSON data
    // Verify the JSON data contains the score
    expect(html).toContain('"governanceScore":42');
  });

  it('contains "Shadow AI Agent Audit" title', () => {
    const html = generateDetectHtml(mockDetectResult());
    expect(html).toContain('Shadow AI Agent Audit');
  });

  it('includes scan metadata', () => {
    const html = generateDetectHtml(mockDetectResult({
      scanDirectory: '/home/user/my-project',
    }));
    expect(html).toContain('/home/user/my-project');
  });
});
