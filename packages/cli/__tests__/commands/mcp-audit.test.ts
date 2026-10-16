import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { PackageNotFoundError, RegistryApiError } from '@opena2a/registry-client';
import { mcpCommand, _internals } from '../../src/commands/mcp-audit.js';

// No test reaches the network: every trust lookup goes to this stub, which
// fails unless a test answers for the name it is asked about.
const registryStub = vi.hoisted(() => ({ checkTrust: vi.fn() }));

vi.mock('@opena2a/registry-client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@opena2a/registry-client')>();
  return {
    ...actual,
    RegistryClient: class {
      checkTrust(name: string, type?: string) {
        return registryStub.checkTrust(name, type);
      }
    },
  };
});

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

function captureStderr(fn: () => Promise<number>): Promise<{ exitCode: number; output: string; stderr: string }> {
  const stdoutChunks: string[] = [];
  const stderrChunks: string[] = [];
  const origStdout = process.stdout.write;
  const origStderr = process.stderr.write;
  process.stdout.write = ((chunk: any) => {
    stdoutChunks.push(String(chunk));
    return true;
  }) as any;
  process.stderr.write = ((chunk: any) => {
    stderrChunks.push(String(chunk));
    return true;
  }) as any;

  return fn().then(exitCode => {
    process.stdout.write = origStdout;
    process.stderr.write = origStderr;
    return { exitCode, output: stdoutChunks.join(''), stderr: stderrChunks.join('') };
  }).catch(err => {
    process.stdout.write = origStdout;
    process.stderr.write = origStderr;
    throw err;
  });
}

describe('mcp-audit', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-mcp-test-'));
    registryStub.checkTrust.mockReset();
    registryStub.checkTrust.mockRejectedValue(new Error('registry not stubbed for this test'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  describe('parseConfigFile', () => {
    it('parses Claude Code mcp_servers.json format', () => {
      const configPath = path.join(tempDir, 'mcp_servers.json');
      const config = {
        mcpServers: {
          filesystem: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'],
          },
          'brave-search': {
            command: 'npx',
            args: ['-y', '@anthropic/brave-search'],
            env: { BRAVE_API_KEY: 'test-key' },
          },
        },
      };
      fs.writeFileSync(configPath, JSON.stringify(config));

      const servers = _internals.parseConfigFile(configPath, 'Claude Code');
      expect(servers).toHaveLength(2);

      expect(servers[0].name).toBe('filesystem');
      expect(servers[0].transport).toBe('stdio');
      expect(servers[0].command).toBe('npx');
      expect(servers[0].args).toEqual(['-y', '@modelcontextprotocol/server-filesystem', '/tmp']);
      expect(servers[0].sourceLabel).toBe('Claude Code');

      expect(servers[1].name).toBe('brave-search');
      expect(servers[1].transport).toBe('stdio');
      expect(servers[1].env).toEqual({ BRAVE_API_KEY: 'test-key' });
    });

    it('parses SSE transport format', () => {
      const configPath = path.join(tempDir, 'mcp.json');
      const config = {
        mcpServers: {
          'remote-server': {
            url: 'http://localhost:3001/sse',
          },
        },
      };
      fs.writeFileSync(configPath, JSON.stringify(config));

      const servers = _internals.parseConfigFile(configPath, 'project-local');
      expect(servers).toHaveLength(1);
      expect(servers[0].name).toBe('remote-server');
      expect(servers[0].transport).toBe('sse');
      expect(servers[0].url).toBe('http://localhost:3001/sse');
    });

    it('parses flat config format (no mcpServers wrapper)', () => {
      const configPath = path.join(tempDir, 'mcp.json');
      const config = {
        myserver: {
          command: 'node',
          args: ['server.js'],
        },
      };
      fs.writeFileSync(configPath, JSON.stringify(config));

      const servers = _internals.parseConfigFile(configPath, 'test');
      expect(servers).toHaveLength(1);
      expect(servers[0].name).toBe('myserver');
    });

    it('returns empty array for missing file', () => {
      const servers = _internals.parseConfigFile('/nonexistent/path.json', 'test');
      expect(servers).toEqual([]);
    });

    it('returns empty array for invalid JSON', () => {
      const configPath = path.join(tempDir, 'bad.json');
      fs.writeFileSync(configPath, 'not json');
      const servers = _internals.parseConfigFile(configPath, 'test');
      expect(servers).toEqual([]);
    });

    it('skips entries without command or url', () => {
      const configPath = path.join(tempDir, 'mcp.json');
      const config = {
        mcpServers: {
          valid: { command: 'npx', args: ['server'] },
          invalid: { description: 'no command or url' },
        },
      };
      fs.writeFileSync(configPath, JSON.stringify(config));

      const servers = _internals.parseConfigFile(configPath, 'test');
      expect(servers).toHaveLength(1);
      expect(servers[0].name).toBe('valid');
    });
  });

  describe('extractCapabilities', () => {
    it('returns empty array when no capabilities', () => {
      expect(_internals.extractCapabilities({})).toEqual([]);
    });

    it('extracts tools, resources, prompts', () => {
      const caps = _internals.extractCapabilities({
        tools: true,
        resources: ['file'],
        prompts: { greeting: {} },
      });
      expect(caps).toEqual(['tools', 'resources', 'prompts']);
    });
  });

  describe('detectPinnedVersion', () => {
    it('detects version in args like @1.2.3', () => {
      expect(_internals.detectPinnedVersion('npx', ['-y', '@org/pkg@1.2.3'])).toBe(true);
    });

    it('returns false for unpinned packages', () => {
      expect(_internals.detectPinnedVersion('npx', ['-y', '@org/pkg'])).toBe(false);
    });

    it('returns false when no args', () => {
      expect(_internals.detectPinnedVersion('npx', undefined)).toBe(false);
    });
  });

  describe('computeConfigHash', () => {
    it('produces consistent hash for stdio server', () => {
      const entry = {
        name: 'test',
        transport: 'stdio' as const,
        command: 'npx',
        args: ['-y', 'server'],
        pinnedVersion: false,
        capabilities: [],
        sourceFile: '/test',
        sourceLabel: 'test',
      };
      const hash1 = _internals.computeConfigHash(entry);
      const hash2 = _internals.computeConfigHash(entry);
      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/);
    });

    it('produces different hash for different configs', () => {
      const entry1 = {
        name: 'test',
        transport: 'stdio' as const,
        command: 'npx',
        args: ['server-a'],
        pinnedVersion: false,
        capabilities: [],
        sourceFile: '/test',
        sourceLabel: 'test',
      };
      const entry2 = { ...entry1, args: ['server-b'] };
      expect(_internals.computeConfigHash(entry1)).not.toBe(_internals.computeConfigHash(entry2));
    });

    it('uses url for sse transport', () => {
      const entry = {
        name: 'test',
        transport: 'sse' as const,
        url: 'http://localhost:3001',
        pinnedVersion: false,
        capabilities: [],
        sourceFile: '/test',
        sourceLabel: 'test',
      };
      const hash = _internals.computeConfigHash(entry);
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  describe('audit subcommand', () => {
    it('reports no configs found when directory is empty', async () => {
      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'audit',
          targetDir: tempDir,
          ci: true,
          format: 'text',
        }),
      );

      expect(exitCode).toBe(0);
      expect(output).toContain('No MCP server configurations found');
    });

    it('discovers project-local mcp.json', async () => {
      const config = {
        mcpServers: {
          'test-server': {
            command: 'node',
            args: ['server.js'],
          },
        },
      };
      fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify(config));

      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'audit',
          targetDir: tempDir,
          ci: true,
          format: 'text',
        }),
      );

      expect(exitCode).toBe(0);
      expect(output).toContain('test-server');
      expect(output).toContain('Servers found');
    });

    it('discovers project-local .mcp.json (hidden)', async () => {
      const config = {
        mcpServers: {
          'hidden-server': {
            url: 'http://localhost:5000/sse',
          },
        },
      };
      fs.writeFileSync(path.join(tempDir, '.mcp.json'), JSON.stringify(config));

      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'audit',
          targetDir: tempDir,
          ci: true,
          format: 'text',
        }),
      );

      expect(exitCode).toBe(0);
      expect(output).toContain('hidden-server');
    });

    it('returns JSON format when requested', async () => {
      const config = {
        mcpServers: {
          'json-server': {
            command: 'npx',
            args: ['-y', '@test/server'],
          },
        },
      };
      fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify(config));

      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'audit',
          targetDir: tempDir,
          ci: true,
          format: 'json',
        }),
      );

      expect(exitCode).toBe(0);
      const result = JSON.parse(output);
      expect(result.servers).toHaveLength(1);
      expect(result.servers[0].name).toBe('json-server');
      expect(result.servers[0].transport).toBe('stdio');
      expect(result.servers[0].signed).toBe(false);
      expect(result.servers[0].verified).toBe(false);
      expect(result.summary.total).toBe(1);
      expect(result.summary.signed).toBe(0);
    });

    it('shows signed status for servers with identity files', async () => {
      const config = {
        mcpServers: {
          'signed-server': {
            command: 'node',
            args: ['server.js'],
          },
        },
      };
      fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify(config));

      // Sign the server first
      await mcpCommand({
        subcommand: 'sign',
        server: 'signed-server',
        targetDir: tempDir,
        format: 'json',
      });

      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'audit',
          targetDir: tempDir,
          ci: true,
          format: 'json',
        }),
      );

      expect(exitCode).toBe(0);
      const result = JSON.parse(output);
      expect(result.servers[0].signed).toBe(true);
      expect(result.servers[0].verified).toBe(true);
      expect(result.summary.signed).toBe(1);
      expect(result.summary.verified).toBe(1);
    });

    it('detects config drift after signing', async () => {
      const configPath = path.join(tempDir, 'mcp.json');
      fs.writeFileSync(configPath, JSON.stringify({
        mcpServers: {
          'drift-server': { command: 'node', args: ['v1.js'] },
        },
      }));

      // Sign with original config
      await mcpCommand({
        subcommand: 'sign',
        server: 'drift-server',
        targetDir: tempDir,
        format: 'json',
      });

      // Change config
      fs.writeFileSync(configPath, JSON.stringify({
        mcpServers: {
          'drift-server': { command: 'node', args: ['v2.js'] },
        },
      }));

      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'audit',
          targetDir: tempDir,
          ci: true,
          format: 'json',
        }),
      );

      expect(exitCode).toBe(0);
      const result = JSON.parse(output);
      expect(result.servers[0].signed).toBe(true);
      expect(result.servers[0].verified).toBe(false); // config changed
    });

    it('shows verbose details when requested', async () => {
      const config = {
        mcpServers: {
          'verbose-server': {
            command: 'npx',
            args: ['-y', '@test/server@1.2.3'],
            env: { API_KEY: 'test' },
            tools: true,
          },
        },
      };
      fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify(config));

      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'audit',
          targetDir: tempDir,
          ci: true,
          format: 'text',
          verbose: true,
        }),
      );

      expect(exitCode).toBe(0);
      expect(output).toContain('version pinned');
      expect(output).toContain('capabilities: tools');
      expect(output).toContain('env vars: API_KEY');
    });
  });

  describe('sign subcommand', () => {
    it('requires server name argument', async () => {
      const { exitCode, stderr } = await captureStderr(() =>
        mcpCommand({
          subcommand: 'sign',
          targetDir: tempDir,
        }),
      );

      expect(exitCode).toBe(1);
      expect(stderr).toContain('Missing required argument');
    });

    it('fails when server not found in any config', async () => {
      const { exitCode, stderr } = await captureStderr(() =>
        mcpCommand({
          subcommand: 'sign',
          server: 'nonexistent',
          targetDir: tempDir,
        }),
      );

      expect(exitCode).toBe(1);
      expect(stderr).toContain('not found');
    });

    it('creates identity file on success', async () => {
      const config = {
        mcpServers: {
          'sign-test': { command: 'node', args: ['server.js'] },
        },
      };
      fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify(config));

      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'sign',
          server: 'sign-test',
          targetDir: tempDir,
          format: 'json',
        }),
      );

      expect(exitCode).toBe(0);
      const result = JSON.parse(output);
      expect(result.status).toBe('signed');
      expect(result.serverName).toBe('sign-test');
      expect(result.fingerprint).toMatch(/^[a-f0-9]{16}$/);
      expect(result.configHash).toMatch(/^[a-f0-9]{64}$/);

      // Verify identity file exists
      const idPath = _internals.getIdentityPath(tempDir, 'sign-test');
      expect(fs.existsSync(idPath)).toBe(true);

      const identity = JSON.parse(fs.readFileSync(idPath, 'utf-8'));
      expect(identity.serverName).toBe('sign-test');
      expect(identity.publicKey).toBeTruthy();
      expect(identity.privateKey).toBeTruthy();
      expect(identity.signature).toBeTruthy();
      expect(identity.createdAt).toBeTruthy();
    });

    it('produces text output', async () => {
      const config = {
        mcpServers: {
          'text-sign': { command: 'node', args: ['server.js'] },
        },
      };
      fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify(config));

      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'sign',
          server: 'text-sign',
          targetDir: tempDir,
          format: 'text',
        }),
      );

      expect(exitCode).toBe(0);
      expect(output).toContain('signed successfully');
      expect(output).toContain('text-sign');
      expect(output).toContain('Fingerprint');
    });
  });

  describe('verify subcommand', () => {
    it('requires server name argument', async () => {
      const { exitCode, stderr } = await captureStderr(() =>
        mcpCommand({
          subcommand: 'verify',
          targetDir: tempDir,
        }),
      );

      expect(exitCode).toBe(1);
      expect(stderr).toContain('Missing required argument');
    });

    it('fails when no identity file exists', async () => {
      const { exitCode, stderr } = await captureStderr(() =>
        mcpCommand({
          subcommand: 'verify',
          server: 'nosign',
          targetDir: tempDir,
        }),
      );

      expect(exitCode).toBe(1);
      expect(stderr).toContain('No identity found');
    });

    it('returns not_signed in JSON when no identity exists', async () => {
      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'verify',
          server: 'nosign',
          targetDir: tempDir,
          format: 'json',
        }),
      );

      expect(exitCode).toBe(1);
      const result = JSON.parse(output);
      expect(result.status).toBe('not_signed');
    });

    it('verifies a correctly signed server', async () => {
      const config = {
        mcpServers: {
          'verify-ok': { command: 'node', args: ['server.js'] },
        },
      };
      fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify(config));

      // Sign
      await captureStdout(() =>
        mcpCommand({
          subcommand: 'sign',
          server: 'verify-ok',
          targetDir: tempDir,
          format: 'json',
        }),
      );

      // Verify
      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'verify',
          server: 'verify-ok',
          targetDir: tempDir,
          format: 'json',
        }),
      );

      expect(exitCode).toBe(0);
      const result = JSON.parse(output);
      expect(result.status).toBe('verified');
      expect(result.signatureValid).toBe(true);
      expect(result.configMatch).toBe(true);
    });

    it('detects config change after signing', async () => {
      const configPath = path.join(tempDir, 'mcp.json');
      fs.writeFileSync(configPath, JSON.stringify({
        mcpServers: {
          'verify-drift': { command: 'node', args: ['v1.js'] },
        },
      }));

      // Sign with v1 config
      await captureStdout(() =>
        mcpCommand({
          subcommand: 'sign',
          server: 'verify-drift',
          targetDir: tempDir,
          format: 'json',
        }),
      );

      // Change config to v2
      fs.writeFileSync(configPath, JSON.stringify({
        mcpServers: {
          'verify-drift': { command: 'node', args: ['v2.js'] },
        },
      }));

      // Verify should fail
      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'verify',
          server: 'verify-drift',
          targetDir: tempDir,
          format: 'json',
        }),
      );

      expect(exitCode).toBe(1);
      const result = JSON.parse(output);
      expect(result.status).toBe('failed');
      expect(result.signatureValid).toBe(true); // signature itself is valid
      expect(result.configMatch).toBe(false); // but config hash changed
    });

    it('detects tampered signature', async () => {
      const config = {
        mcpServers: {
          'verify-tamper': { command: 'node', args: ['server.js'] },
        },
      };
      fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify(config));

      // Sign
      await captureStdout(() =>
        mcpCommand({
          subcommand: 'sign',
          server: 'verify-tamper',
          targetDir: tempDir,
          format: 'json',
        }),
      );

      // Tamper with signature
      const idPath = _internals.getIdentityPath(tempDir, 'verify-tamper');
      const identity = JSON.parse(fs.readFileSync(idPath, 'utf-8'));
      identity.signature = 'deadbeef'.repeat(16);
      fs.writeFileSync(idPath, JSON.stringify(identity));

      // Verify should fail
      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'verify',
          server: 'verify-tamper',
          targetDir: tempDir,
          format: 'json',
        }),
      );

      expect(exitCode).toBe(1);
      const result = JSON.parse(output);
      expect(result.status).toBe('failed');
      expect(result.signatureValid).toBe(false);
    });

    it('produces text output for verification pass', async () => {
      const config = {
        mcpServers: {
          'text-verify': { command: 'node', args: ['server.js'] },
        },
      };
      fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify(config));

      await captureStdout(() =>
        mcpCommand({
          subcommand: 'sign',
          server: 'text-verify',
          targetDir: tempDir,
          format: 'json',
        }),
      );

      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'verify',
          server: 'text-verify',
          targetDir: tempDir,
          format: 'text',
        }),
      );

      expect(exitCode).toBe(0);
      expect(output).toContain('PASS');
      expect(output).toContain('text-verify');
      expect(output).toContain('valid');
    });

    it('produces text output for verification fail', async () => {
      const configPath = path.join(tempDir, 'mcp.json');
      fs.writeFileSync(configPath, JSON.stringify({
        mcpServers: {
          'fail-text': { command: 'node', args: ['v1.js'] },
        },
      }));

      await captureStdout(() =>
        mcpCommand({
          subcommand: 'sign',
          server: 'fail-text',
          targetDir: tempDir,
          format: 'json',
        }),
      );

      fs.writeFileSync(configPath, JSON.stringify({
        mcpServers: {
          'fail-text': { command: 'node', args: ['v2.js'] },
        },
      }));

      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'verify',
          server: 'fail-text',
          targetDir: tempDir,
          format: 'text',
        }),
      );

      expect(exitCode).toBe(1);
      expect(output).toContain('FAIL');
      expect(output).toContain('config has changed');
    });

    it('handles server not found in configs after signing', async () => {
      const configPath = path.join(tempDir, 'mcp.json');
      fs.writeFileSync(configPath, JSON.stringify({
        mcpServers: {
          'removed-server': { command: 'node', args: ['server.js'] },
        },
      }));

      await captureStdout(() =>
        mcpCommand({
          subcommand: 'sign',
          server: 'removed-server',
          targetDir: tempDir,
          format: 'json',
        }),
      );

      // Remove the config
      fs.unlinkSync(configPath);

      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'verify',
          server: 'removed-server',
          targetDir: tempDir,
          format: 'json',
        }),
      );

      expect(exitCode).toBe(1);
      const result = JSON.parse(output);
      expect(result.configFound).toBe(false);
      expect(result.configMatch).toBe(false);
    });
  });

  describe('unknown subcommand', () => {
    it('returns error for unknown subcommand', async () => {
      const { exitCode, stderr } = await captureStderr(() =>
        mcpCommand({
          subcommand: 'invalid',
          targetDir: tempDir,
        }),
      );

      expect(exitCode).toBe(1);
      expect(stderr).toContain('Unknown mcp subcommand');
      expect(stderr).toContain('audit|sign|verify');
    });
  });

  describe('aim-core graceful degradation', () => {
    it('sign still works without aim-core (uses native crypto)', async () => {
      // sign uses native crypto, not aim-core -- it should work regardless
      const config = {
        mcpServers: {
          'no-aim': { command: 'node', args: ['server.js'] },
        },
      };
      fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify(config));

      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'sign',
          server: 'no-aim',
          targetDir: tempDir,
          format: 'json',
        }),
      );

      // Even though aim-core import fails, the signing uses native crypto
      // and should succeed
      expect(exitCode).toBe(0);
      const result = JSON.parse(output);
      expect(result.status).toBe('signed');
    });
  });

  describe('multiple config sources', () => {
    it('discovers servers from multiple project-local configs', async () => {
      // mcp.json
      fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify({
        mcpServers: {
          'server-a': { command: 'node', args: ['a.js'] },
        },
      }));

      // .mcp.json
      fs.writeFileSync(path.join(tempDir, '.mcp.json'), JSON.stringify({
        mcpServers: {
          'server-b': { url: 'http://localhost:5000' },
        },
      }));

      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({
          subcommand: 'audit',
          targetDir: tempDir,
          ci: true,
          format: 'json',
        }),
      );

      expect(exitCode).toBe(0);
      const result = JSON.parse(output);
      expect(result.servers).toHaveLength(2);
      expect(result.servers.map((s: any) => s.name).sort()).toEqual(['server-a', 'server-b']);
    });
  });

  describe('registryNameFor', () => {
    const stdio = (command: string, args: string[]) => ({ transport: 'stdio', command, args });

    it('returns the scoped package an npx server runs', () => {
      expect(_internals.registryNameFor(stdio('npx', ['-y', '@modelcontextprotocol/server-filesystem', '/'])))
        .toBe('@modelcontextprotocol/server-filesystem');
    });

    it('strips a version suffix and keeps a scope', () => {
      expect(_internals.registryNameFor(stdio('npx', ['-y', 'pkg@1.2.3']))).toBe('pkg');
      expect(_internals.registryNameFor(stdio('npx', ['--yes', '@scope/pkg@latest']))).toBe('@scope/pkg');
    });

    it('reads npm exec, pnpm dlx and bunx', () => {
      expect(_internals.registryNameFor(stdio('npm', ['exec', '--yes', '--', '@scope/pkg@2.0.0', '.']))).toBe('@scope/pkg');
      expect(_internals.registryNameFor(stdio('pnpm', ['dlx', 'pkg@1']))).toBe('pkg');
      expect(_internals.registryNameFor(stdio('bunx', ['pkg', '--port', '3000']))).toBe('pkg');
      expect(_internals.registryNameFor(stdio('/usr/local/bin/npx', ['-y', 'pkg']))).toBe('pkg');
    });

    it('returns the package --package= names, not the binary after it', () => {
      expect(_internals.registryNameFor(stdio('npx', ['-y', '--package=@scope/pkg@1.0.0', 'pkg-bin']))).toBe('@scope/pkg');
    });

    it('returns null for a node <file>, a bare binary and a URL server', () => {
      expect(_internals.registryNameFor(stdio('node', ['server.js']))).toBeNull();
      expect(_internals.registryNameFor(stdio('mcp-server-git', ['--repository', '.']))).toBeNull();
      expect(_internals.registryNameFor(stdio('npm', ['run', 'serve']))).toBeNull();
      expect(_internals.registryNameFor(stdio('pnpm', ['start']))).toBeNull();
      expect(_internals.registryNameFor({ transport: 'sse', url: 'http://localhost:5000/sse' })).toBeNull();
    });

    it('returns null when the runner argument is not an npm package name', () => {
      expect(_internals.registryNameFor(stdio('npx', ['-y', './local-server']))).toBeNull();
      expect(_internals.registryNameFor(stdio('npx', ['github:user/repo']))).toBeNull();
      expect(_internals.registryNameFor(stdio('npx', ['user/repo']))).toBeNull();
      expect(_internals.registryNameFor(stdio('npx', ['-y']))).toBeNull();
    });
  });

  describe('trust lookup', () => {
    let savedHome: string | undefined;

    // The server entries of the adversarial fixture's mcp.json. Its env blocks
    // are left out: they hold credential-shaped values and the lookup never
    // reads them.
    const FIXTURE_MCP = {
      mcpServers: {
        'filesystem-root': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
        'shell-executor': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-shell'] },
        'database-admin': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres'] },
        'network-fetch': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-fetch'] },
        'external-analytics': { command: 'node', args: ['analytics-agent.js'] },
        'wildcard-tools': { transport: { type: 'sse', url: 'http://0.0.0.0:9999/mcp' }, tools: ['*'] },
      },
    };

    // filesystem is scored, shell has no record (404), postgres is listed and
    // never scanned, fetch cannot be reached.
    function answerLikeTheRegistry(): void {
      registryStub.checkTrust.mockImplementation(async (name: string) => {
        if (name === '@modelcontextprotocol/server-filesystem') {
          return { packageId: '7b70f85f-d988-4fbf-8d5e-993ce58ed10c', name, trustScore: 0.7866666666666666, trustLevel: 3, verdict: 'passed', found: true };
        }
        if (name === '@modelcontextprotocol/server-postgres') {
          return { packageId: '16b7fe58-7e28-41d0-a88c-e2bef2a2c7d9', name, trustScore: 0, trustLevel: 2, verdict: 'listed', scanStatus: '', found: true };
        }
        if (name === '@modelcontextprotocol/server-fetch') {
          throw new RegistryApiError('Network error contacting registry', 'network');
        }
        throw new PackageNotFoundError(name);
      });
    }

    function rowFor(output: string, serverName: string): string {
      return output.split('\n').find(line => line.trimStart().startsWith(`${serverName} `)) ?? '';
    }

    beforeEach(() => {
      savedHome = process.env.HOME;
      process.env.HOME = path.join(tempDir, 'home');
      fs.writeFileSync(path.join(tempDir, 'mcp.json'), JSON.stringify(FIXTURE_MCP));
    });

    afterEach(() => {
      if (savedHome === undefined) delete process.env.HOME;
      else process.env.HOME = savedHome;
    });

    it('looks up the package a server runs, not its config key', async () => {
      answerLikeTheRegistry();

      const { exitCode, output } = await captureStdout(() =>
        mcpCommand({ subcommand: 'audit', targetDir: tempDir, format: 'text' }),
      );

      expect(exitCode).toBe(0);
      expect(rowFor(output, 'filesystem-root')).toContain('trust: 79');
      expect(registryStub.checkTrust).toHaveBeenCalledWith('@modelcontextprotocol/server-filesystem', 'mcp_server');
      expect(registryStub.checkTrust).not.toHaveBeenCalledWith('filesystem-root', expect.anything());
      expect(registryStub.checkTrust).toHaveBeenCalledTimes(4);
    });

    it('tells a missing record, an unscanned record, a server without a package and a failed lookup apart', async () => {
      answerLikeTheRegistry();

      const { output } = await captureStdout(() =>
        mcpCommand({ subcommand: 'audit', targetDir: tempDir, format: 'text' }),
      );

      expect(rowFor(output, 'shell-executor')).toContain('not in registry');
      expect(rowFor(output, 'database-admin')).toContain('listed, not scanned');
      expect(rowFor(output, 'database-admin')).not.toContain('trust:');
      expect(rowFor(output, 'network-fetch')).toContain('lookup failed');
      expect(rowFor(output, 'external-analytics')).toContain('no package to look up');
      expect(output).not.toContain('no trust score');
      expect(output).toContain(
        'Trust scores:      1 / 4 looked up; 1 listed, not scanned; 1 lookup failed; 1 server has no package name',
      );
    });

    it('reads an answer without a record as not in registry', async () => {
      const server = { name: 'pg', transport: 'stdio' as const, command: 'npx', args: ['-y', 'pkg'], pinnedVersion: false, sourceFile: 'mcp.json', sourceLabel: 'project-local' };
      const answer = (data: object) => () => Promise.resolve({ checkTrust: async () => data as any });

      expect(await _internals.lookupTrust(server, answer({ name: 'pkg', trustScore: 0, verdict: 'unknown', found: false })))
        .toEqual({ registryName: 'pkg', trustLookup: 'notInRegistry', trustScore: null });
      expect(await _internals.lookupTrust(server, answer({ name: 'pkg', verdict: 'passed', found: true })))
        .toEqual({ registryName: 'pkg', trustLookup: 'failed', trustScore: null });
      expect(await _internals.lookupTrust(server, null))
        .toEqual({ registryName: 'pkg', trustLookup: 'skipped', trustScore: null });
    });

    it('carries registryName and trustLookup per server in JSON', async () => {
      answerLikeTheRegistry();

      const { output } = await captureStdout(() =>
        mcpCommand({ subcommand: 'audit', targetDir: tempDir, format: 'json' }),
      );

      const result = JSON.parse(output);
      const byName = Object.fromEntries(result.servers.map((s: any) => [s.name, s]));
      expect(byName['filesystem-root']).toMatchObject({
        registryName: '@modelcontextprotocol/server-filesystem',
        trustLookup: 'scored',
        trustScore: 79,
      });
      expect(byName['shell-executor']).toMatchObject({ registryName: '@modelcontextprotocol/server-shell', trustLookup: 'notInRegistry', trustScore: null });
      expect(byName['database-admin']).toMatchObject({ trustLookup: 'notScanned', trustScore: null });
      expect(byName['network-fetch']).toMatchObject({ trustLookup: 'failed', trustScore: null });
      expect(byName['external-analytics']).toMatchObject({ registryName: null, trustLookup: 'noPackage', trustScore: null });
      expect(result.summary).toMatchObject({ total: 5, trustScores: 1, lookedUp: 4, notScanned: 1, lookupsFailed: 1, noPackage: 1 });
    });

    it('--ci sends no lookup and labels the rows as not looked up', async () => {
      const text = await captureStdout(() =>
        mcpCommand({ subcommand: 'audit', targetDir: tempDir, ci: true, format: 'text' }),
      );
      const json = await captureStdout(() =>
        mcpCommand({ subcommand: 'audit', targetDir: tempDir, ci: true, format: 'json' }),
      );

      expect(registryStub.checkTrust).not.toHaveBeenCalled();
      expect(rowFor(text.output, 'filesystem-root')).toContain('not looked up (--ci)');
      expect(rowFor(text.output, 'external-analytics')).toContain('no package to look up');
      expect(text.output).toContain('Trust scores:      not looked up (--ci); 1 server has no package name');
      const byName = Object.fromEntries(JSON.parse(json.output).servers.map((s: any) => [s.name, s]));
      expect(byName['filesystem-root']).toMatchObject({ registryName: '@modelcontextprotocol/server-filesystem', trustLookup: 'skipped' });
      expect(byName['external-analytics']).toMatchObject({ registryName: null, trustLookup: 'noPackage' });
    });

    it('mcp verify looks up the package the server runs', async () => {
      answerLikeTheRegistry();
      await captureStdout(() =>
        mcpCommand({ subcommand: 'sign', server: 'filesystem-root', targetDir: tempDir, format: 'json' }),
      );

      const { output } = await captureStdout(() =>
        mcpCommand({ subcommand: 'verify', server: 'filesystem-root', targetDir: tempDir, format: 'json' }),
      );

      expect(JSON.parse(output)).toMatchObject({
        status: 'verified',
        trustScore: 79,
        registryName: '@modelcontextprotocol/server-filesystem',
        trustLookup: 'scored',
      });
      expect(registryStub.checkTrust).not.toHaveBeenCalledWith('filesystem-root', expect.anything());
    });
  });

  describe('getIdentityPath', () => {
    it('returns correct path structure', () => {
      const p = _internals.getIdentityPath('/project', 'my-server');
      expect(p).toBe(path.join('/project', '.opena2a', 'mcp-identities', 'my-server.json'));
    });
  });
});
