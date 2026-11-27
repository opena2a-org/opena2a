import { describe, it, expect } from 'vitest';
import { registryPackageFor } from '../../src/util/mcp-registry-name.js';

const stdio = (command: string, args: string[]) => ({ transport: 'stdio', command, args });

describe('registryPackageFor', () => {
  it('reads the npm package an npm package runner starts', () => {
    expect(registryPackageFor(stdio('npx', ['-y', '@scope/pkg@1.2.3']))).toEqual({ name: '@scope/pkg', ecosystem: 'npm' });
    expect(registryPackageFor(stdio('pnpm', ['dlx', 'pkg']))).toEqual({ name: 'pkg', ecosystem: 'npm' });
    expect(registryPackageFor(stdio('bunx', ['pkg']))).toEqual({ name: 'pkg', ecosystem: 'npm' });
  });

  it('reads the PyPI package uvx and uv tool run start, without its version or extras, normalized', () => {
    expect(registryPackageFor(stdio('uvx', ['mcp-server-fetch']))).toEqual({ name: 'mcp-server-fetch', ecosystem: 'pypi' });
    expect(registryPackageFor(stdio('uvx', ['mcp-server-fetch@2025.4.7', '--ignore-robots-txt']))).toEqual({ name: 'mcp-server-fetch', ecosystem: 'pypi' });
    expect(registryPackageFor(stdio('uvx', ['mcp-server-fetch==1.0']))).toEqual({ name: 'mcp-server-fetch', ecosystem: 'pypi' });
    expect(registryPackageFor(stdio('uvx', ['Mcp_Server.Time[extra]>=1']))).toEqual({ name: 'mcp-server-time', ecosystem: 'pypi' });
    expect(registryPackageFor(stdio('/usr/local/bin/uvx', ['pkg']))).toEqual({ name: 'pkg', ecosystem: 'pypi' });
    expect(registryPackageFor(stdio('uvx.exe', ['pkg']))).toEqual({ name: 'pkg', ecosystem: 'pypi' });
    expect(registryPackageFor(stdio('uv', ['tool', 'run', 'pkg', '--flag']))).toEqual({ name: 'pkg', ecosystem: 'pypi' });
  });

  it('skips the options uvx knows, with their values, and reads --from as the package', () => {
    expect(registryPackageFor(stdio('uvx', ['--python', '3.12', '-q', 'pkg']))).toEqual({ name: 'pkg', ecosystem: 'pypi' });
    expect(registryPackageFor(stdio('uvx', ['--with=extra', '--offline', 'pkg']))).toEqual({ name: 'pkg', ecosystem: 'pypi' });
    expect(registryPackageFor(stdio('uvx', ['--from', 'pkg-dist', 'pkg-bin']))).toEqual({ name: 'pkg-dist', ecosystem: 'pypi' });
    expect(registryPackageFor(stdio('uvx', ['--from=pkg-dist@1.0', 'pkg-bin']))).toEqual({ name: 'pkg-dist', ecosystem: 'pypi' });
  });

  it('derives no package when the command names none it can read with certainty', () => {
    expect(registryPackageFor(stdio('uvx', ['--from', 'git+https://github.com/example/server', 'server']))).toBeNull();
    expect(registryPackageFor(stdio('uvx', ['./local/server']))).toBeNull();
    expect(registryPackageFor(stdio('uvx', ['--some-new-option', 'value', 'pkg']))).toBeNull();
    expect(registryPackageFor(stdio('uvx', []))).toBeNull();
    expect(registryPackageFor(stdio('uv', ['run', 'server.py']))).toBeNull();
    expect(registryPackageFor(stdio('python', ['-m', 'mcp_server_fetch']))).toBeNull();
    expect(registryPackageFor(stdio('node', ['server.js']))).toBeNull();
    expect(registryPackageFor({ transport: 'sse', url: 'http://localhost:5000/sse' })).toBeNull();
  });
});
