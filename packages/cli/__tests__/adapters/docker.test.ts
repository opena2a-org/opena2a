import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DockerAdapter } from '../../src/adapters/docker.js';
import type { AdapterConfig } from '../../src/adapters/types.js';
import { ADAPTER_REGISTRY } from '../../src/adapters/registry.js';

// Mock child_process.spawn to capture docker args without running docker
vi.mock('node:child_process', () => ({
  spawn: vi.fn(() => {
    const handlers: Record<string, Function> = {};
    const mockStream = {
      on: vi.fn(),
    };
    const child = {
      stdout: mockStream,
      stderr: mockStream,
      on: vi.fn((event: string, handler: Function) => {
        handlers[event] = handler;
        // Auto-resolve with exit code 0 on 'close'
        if (event === 'close') {
          setTimeout(() => handler(0), 0);
        }
      }),
    };
    return child;
  }),
}));

describe('DockerAdapter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('uses configured ports from adapter config', async () => {
    const { spawn } = await import('node:child_process');

    const config: AdapterConfig = {
      name: 'test',
      method: 'docker',
      image: 'test/image',
      ports: ['3001-3008:3001-3008', '9000:9000'],
      description: 'Test adapter',
    };

    const adapter = new DockerAdapter(config);
    await adapter.run({ args: [], quiet: true });

    expect(spawn).toHaveBeenCalledWith(
      'docker',
      expect.arrayContaining(['-p', '3001-3008:3001-3008', '-p', '9000:9000', 'test/image']),
      expect.any(Object),
    );
  });

  it('falls back to port 3000 when no ports configured', async () => {
    const { spawn } = await import('node:child_process');

    const config: AdapterConfig = {
      name: 'test',
      method: 'docker',
      image: 'test/image',
      description: 'Test adapter',
    };

    const adapter = new DockerAdapter(config);
    await adapter.run({ args: [], quiet: true });

    expect(spawn).toHaveBeenCalledWith(
      'docker',
      expect.arrayContaining(['-p', '3000:3000', 'test/image']),
      expect.any(Object),
    );
  });

  it('train adapter has DVAA port mappings', () => {
    const train = ADAPTER_REGISTRY['train'];
    expect(train).toBeDefined();
    expect(train.ports).toBeDefined();
    expect(train.ports).toContain('3001-3008:3001-3008');
    expect(train.ports).toContain('3010-3013:3010-3013');
    expect(train.ports).toContain('3020-3021:3020-3021');
    expect(train.ports).toContain('9000:9000');
  });

  it('passes additional args after image name', async () => {
    const { spawn } = await import('node:child_process');

    const config: AdapterConfig = {
      name: 'test',
      method: 'docker',
      image: 'test/image',
      ports: ['8080:8080'],
      description: 'Test adapter',
    };

    const adapter = new DockerAdapter(config);
    await adapter.run({ args: ['--verbose', 'start'], quiet: true });

    expect(spawn).toHaveBeenCalledWith(
      'docker',
      expect.arrayContaining(['test/image', '--verbose', 'start']),
      expect.any(Object),
    );
  });

  it('returns error when no image configured', async () => {
    const config: AdapterConfig = {
      name: 'test',
      method: 'docker',
      description: 'Test adapter',
    };

    const adapter = new DockerAdapter(config);
    const result = await adapter.run({ args: [], quiet: true });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('No image configured');
  });
});
