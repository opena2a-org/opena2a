// Regression: what `opena2a detect` sends to the Registry when contribution
// is on, and what directory the scan it sends describes.
//
// Every run outside --ci published a summary of the scanned tree as a scan of
// a package named `shadow-ai-audit`, typed `detect`, which the Registry
// recorded as a community scan of an npm package of that name. A scan of the
// servers the Registry did not know (--auto-scan, or the prompt) sent each
// server under the key of its config entry, such as `filesystem-root`, which
// names no package, and looked that key up under node_modules, so the
// directory it scanned was the project directory. detect now sends only the
// scan of such a server whose npm package is installed, under the project's
// node_modules or the global npm prefix, and the directory scanned is that
// package's; it is sent under the package name, as an `mcp_server` package in
// the `npm` ecosystem. A server whose package is not installed, or that runs
// no npm package, is scanned in the project directory and not sent, and the
// tree's summary is not sent. A package directory counts as installed only
// when it lies under the node_modules directory it was looked up in, symbolic
// links followed, and the global npm prefix only when `npm prefix -g` answers
// one absolute path in normalized form.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const submission = vi.hoisted(() => ({
  isContributeEnabled: vi.fn(async () => true),
  submitScanReport: vi.fn(async () => true),
  recordScanAndMaybePrompt: vi.fn(async () => undefined),
}));

vi.mock('../../src/util/report-submission.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/util/report-submission.js')>()),
  recordScanAndMaybePrompt: submission.recordScanAndMaybePrompt,
  isContributeEnabled: submission.isContributeEnabled,
  getRegistryUrl: async () => 'https://api.oa2a.org',
  submitScanReport: submission.submitScanReport,
}));

// The Registry knows none of the servers, so every one is scanned.
vi.mock('../../src/util/registry-enrichment.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/util/registry-enrichment.js')>()),
  enrichFromRegistry: async () => new Map(),
}));

// One scan result for every server; what the scanner finds is not what this
// file tests. Which directory it is given is.
const scanner = vi.hoisted(() => ({
  scan: vi.fn(async () => ({
    overallScore: 90,
    maxScore: 100,
    findings: [],
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    infoCount: 0,
    scanDurationMs: 5,
    scannerVersion: '0.30.0',
  })),
}));

vi.mock('hackmyagent', () => ({
  HardeningScanner: class {
    scan = scanner.scan;
  },
}));

// No host process is an agent, and the global npm prefix holds only what a
// case installs there.
const host = vi.hoisted(() => ({ npmPrefix: '' }));

vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  return {
    ...actual,
    execSync: ((command: string, options?: Parameters<typeof actual.execSync>[1]) => {
      if (command === 'ps aux') return 'USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND\n';
      if (command === 'npm prefix -g') return host.npmPrefix;
      return actual.execSync(command, options);
    }) as typeof actual.execSync,
  };
});

import { detect, installedPackageDir } from '../../src/commands/detect.js';

async function runDetect(options: Parameters<typeof detect>[0]): Promise<{ exitCode: number; stdout: string }> {
  const chunks: string[] = [];
  const origOut = process.stdout.write;
  const origErr = process.stderr.write;
  process.stdout.write = ((chunk: unknown) => {
    chunks.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    const exitCode = await detect(options);
    return { exitCode, stdout: chunks.join('') };
  } finally {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
  }
}

function writeMcpConfig(dir: string, mcpServers: Record<string, unknown>): void {
  fs.writeFileSync(path.join(dir, 'mcp.json'), JSON.stringify({ mcpServers }));
}

/** Lay a package out as npm does, `<root>/node_modules/<name>/package.json`, and return its directory. */
function installPackage(root: string, name: string): string {
  const dir = path.join(root, 'node_modules', name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name, version: '0.0.0' }));
  return dir;
}

/** The directory each scan was given, in scan order. */
function scannedDirs(): string[] {
  return scanner.scan.mock.calls.map((call) => (call as unknown as [{ targetDir: string }])[0].targetDir);
}

describe('detect contribution', () => {
  let tempDir: string;
  let tempHome: string;
  /** The directory the global prefix answer names; a case may answer with something else. */
  let prefixDir: string;
  let savedHome: string | undefined;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-contrib-'));
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-contrib-home-'));
    prefixDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-contrib-prefix-'));
    host.npmPrefix = prefixDir;
    // detect reads MCP configs under the home directory too; none of the
    // host's may reach these runs.
    savedHome = process.env.HOME;
    process.env.HOME = tempHome;
    submission.isContributeEnabled.mockClear();
    submission.submitScanReport.mockClear();
    submission.recordScanAndMaybePrompt.mockClear();
    scanner.scan.mockClear();
  });

  afterEach(() => {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
    fs.rmSync(prefixDir, { recursive: true, force: true });
  });

  // The config key is a label; the package is found under node_modules by the
  // name the server runs.
  it('a server whose npm package is installed under node_modules is scanned there and sent under that package, as an mcp_server package in the npm ecosystem', async () => {
    const packageDir = installPackage(tempDir, '@modelcontextprotocol/server-filesystem');
    writeMcpConfig(tempDir, {
      'filesystem-root': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
    });

    const { exitCode, stdout } = await runDetect({ targetDir: tempDir, format: 'json', ci: true, registry: true, autoScan: true });

    expect(exitCode).toBe(0);
    expect(scannedDirs()).toEqual([packageDir]);
    expect(submission.submitScanReport).toHaveBeenCalledTimes(1);
    const [registryUrl, report] = submission.submitScanReport.mock.calls[0] as unknown as [string, Record<string, unknown>];
    expect(registryUrl).toBe('https://api.oa2a.org');
    expect(report.packageName).toBe('@modelcontextprotocol/server-filesystem');
    expect(report.packageType).toBe('mcp_server');
    expect(report.ecosystem).toBe('npm');
    expect(report.scannerName).toBe('HackMyAgent');
    const server = JSON.parse(stdout).mcpServers.find((s: { name: string }) => s.name === 'filesystem-root');
    expect(server.scanResult.contributed).toBe(true);
  });

  // Before, the config key was looked up under node_modules, found nothing,
  // and the project directory's scan went out under the package name.
  it('a server whose npm package is not installed is scanned in the project directory and not sent', async () => {
    writeMcpConfig(tempDir, {
      'filesystem-root': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
    });

    const { exitCode, stdout } = await runDetect({ targetDir: tempDir, format: 'json', ci: true, registry: true, autoScan: true });

    expect(exitCode).toBe(0);
    expect(scannedDirs()).toEqual([tempDir]);
    expect(submission.submitScanReport).not.toHaveBeenCalled();
    const server = JSON.parse(stdout).mcpServers.find((s: { name: string }) => s.name === 'filesystem-root');
    expect(server.scanResult.contributed).toBe(false);
  });

  it('a server whose npm package is installed under the global npm prefix is scanned there and sent', async () => {
    const packageDir = installPackage(path.join(host.npmPrefix, 'lib'), '@modelcontextprotocol/server-filesystem');
    writeMcpConfig(tempDir, {
      'filesystem-root': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
    });

    const { exitCode, stdout } = await runDetect({ targetDir: tempDir, format: 'json', ci: true, registry: true, autoScan: true });

    expect(exitCode).toBe(0);
    expect(scannedDirs()).toEqual([packageDir]);
    expect(submission.submitScanReport).toHaveBeenCalledTimes(1);
    const [, report] = submission.submitScanReport.mock.calls[0] as unknown as [string, Record<string, unknown>];
    expect(report.packageName).toBe('@modelcontextprotocol/server-filesystem');
    const server = JSON.parse(stdout).mcpServers.find((s: { name: string }) => s.name === 'filesystem-root');
    expect(server.scanResult.contributed).toBe(true);
  });

  it('a scanned server that runs no npm package is scanned in the project directory and not sent: its config key names no package', async () => {
    writeMcpConfig(tempDir, {
      local: { command: 'node', args: ['server.js'] },
    });

    const { exitCode, stdout } = await runDetect({ targetDir: tempDir, format: 'json', ci: true, registry: true, autoScan: true });

    expect(exitCode).toBe(0);
    expect(scannedDirs()).toEqual([tempDir]);
    expect(submission.submitScanReport).not.toHaveBeenCalled();
    const server = JSON.parse(stdout).mcpServers.find((s: { name: string }) => s.name === 'local');
    expect(server.scanResult.contributed).toBe(false);
  });

  it('of two scanned servers, only the one whose npm package is installed is sent, with the scan of its package directory', async () => {
    const packageDir = installPackage(tempDir, '@modelcontextprotocol/server-postgres');
    writeMcpConfig(tempDir, {
      local: { command: 'node', args: ['server.js'] },
      'database-admin': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres@latest'] },
    });

    await runDetect({ targetDir: tempDir, format: 'json', ci: true, registry: true, autoScan: true });

    expect([...scannedDirs()].sort()).toEqual([packageDir, tempDir].sort());
    expect(submission.submitScanReport).toHaveBeenCalledTimes(1);
    const [, report] = submission.submitScanReport.mock.calls[0] as unknown as [string, Record<string, unknown>];
    expect(report.packageName).toBe('@modelcontextprotocol/server-postgres');
    expect(report.packageType).toBe('mcp_server');
    expect(report.ecosystem).toBe('npm');
  });

  // Text mode outside --ci is where the tree's summary used to be sent. The
  // run still counts toward the contribute prompt, which shows the step ran.
  it('the summary of the scanned tree is not sent', async () => {
    writeMcpConfig(tempDir, {
      'filesystem-root': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
    });

    const { exitCode } = await runDetect({ targetDir: tempDir, format: 'text', ci: false });

    expect(exitCode).toBe(0);
    expect(submission.recordScanAndMaybePrompt).toHaveBeenCalledTimes(1);
    expect(submission.submitScanReport).not.toHaveBeenCalled();
  });

  it('with contribution off, a scanned server whose package is installed is not sent', async () => {
    submission.isContributeEnabled.mockResolvedValue(false);
    installPackage(tempDir, '@modelcontextprotocol/server-filesystem');
    writeMcpConfig(tempDir, {
      'filesystem-root': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
    });

    await runDetect({ targetDir: tempDir, format: 'json', ci: true, registry: true, autoScan: true });

    expect(scanner.scan).toHaveBeenCalledTimes(1);
    expect(submission.submitScanReport).not.toHaveBeenCalled();
    submission.isContributeEnabled.mockResolvedValue(true);
  });

  // The package looked for is the one the launch names. A launch whose package
  // argument is a path, or a name no npm package can have, names no package:
  // the lookup never leaves node_modules, the project directory is scanned,
  // and nothing is sent.
  it('a server whose launch names a path or a malformed package name is scanned in the project directory and not sent', async () => {
    writeMcpConfig(tempDir, {
      traversal: { command: 'npx', args: ['-y', '../../../outside/server'] },
      absolute: { command: 'npx', args: ['-y', '/opt/outside/server'] },
      control: { command: 'npx', args: ['-y', 'server\u0000name'] },
    });

    const { exitCode, stdout } = await runDetect({ targetDir: tempDir, format: 'json', ci: true, registry: true, autoScan: true });

    expect(exitCode).toBe(0);
    expect(scannedDirs()).toEqual([tempDir, tempDir, tempDir]);
    expect(submission.submitScanReport).not.toHaveBeenCalled();
    const servers = JSON.parse(stdout).mcpServers as Array<{ name: string; scanResult: { contributed: boolean } }>;
    expect(servers.map((s) => s.name).sort()).toEqual(['absolute', 'control', 'traversal']);
    for (const server of servers) expect(server.scanResult.contributed).toBe(false);
  });

  // `npm prefix -g` prints one absolute path. An answer in any other form is
  // not a place to look for the package. Before, a relative answer was joined
  // as it came and resolved against the working directory.
  it('a global npm prefix answered as a relative path is not searched, so the server is scanned in the project directory and not sent', async () => {
    installPackage(path.join(host.npmPrefix, 'lib'), '@modelcontextprotocol/server-filesystem');
    host.npmPrefix = path.relative(process.cwd(), host.npmPrefix);
    expect(path.isAbsolute(host.npmPrefix)).toBe(false);
    expect(fs.existsSync(path.join(host.npmPrefix, 'lib', 'node_modules', '@modelcontextprotocol/server-filesystem'))).toBe(true);
    writeMcpConfig(tempDir, {
      'filesystem-root': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
    });

    const { exitCode, stdout } = await runDetect({ targetDir: tempDir, format: 'json', ci: true, registry: true, autoScan: true });

    expect(exitCode).toBe(0);
    expect(scannedDirs()).toEqual([tempDir]);
    expect(submission.submitScanReport).not.toHaveBeenCalled();
    const server = JSON.parse(stdout).mcpServers.find((s: { name: string }) => s.name === 'filesystem-root');
    expect(server.scanResult.contributed).toBe(false);
  });

  it('a global npm prefix answered as more than one line is not searched', async () => {
    installPackage(path.join(host.npmPrefix, 'lib'), '@modelcontextprotocol/server-filesystem');
    host.npmPrefix = `${host.npmPrefix}\n${host.npmPrefix}`;
    writeMcpConfig(tempDir, {
      'filesystem-root': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
    });

    await runDetect({ targetDir: tempDir, format: 'json', ci: true, registry: true, autoScan: true });

    expect(scannedDirs()).toEqual([tempDir]);
    expect(submission.submitScanReport).not.toHaveBeenCalled();
  });

  // `npm prefix -g` prints the prefix in normalized form. An answer that
  // reaches the same directory through a `..` segment is not that form and
  // is not a place to look. Before, the join normalized the segment away, and
  // the package under the directory it reached was found and sent.
  it('a global npm prefix answered with a `..` segment is not searched, so the server is scanned in the project directory and not sent', async () => {
    installPackage(path.join(prefixDir, 'lib'), '@modelcontextprotocol/server-filesystem');
    host.npmPrefix = `${prefixDir}${path.sep}lib${path.sep}..`;
    expect(path.isAbsolute(host.npmPrefix)).toBe(true);
    expect(path.normalize(host.npmPrefix)).toBe(prefixDir);
    expect(fs.existsSync(path.join(host.npmPrefix, 'lib', 'node_modules', '@modelcontextprotocol/server-filesystem'))).toBe(true);
    writeMcpConfig(tempDir, {
      'filesystem-root': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
    });

    const { exitCode, stdout } = await runDetect({ targetDir: tempDir, format: 'json', ci: true, registry: true, autoScan: true });

    expect(exitCode).toBe(0);
    expect(scannedDirs()).toEqual([tempDir]);
    expect(submission.submitScanReport).not.toHaveBeenCalled();
    const server = JSON.parse(stdout).mcpServers.find((s: { name: string }) => s.name === 'filesystem-root');
    expect(server.scanResult.contributed).toBe(false);
  });

  it('a global npm prefix answered with a control character is not searched', async () => {
    installPackage(path.join(prefixDir, 'lib'), '@modelcontextprotocol/server-filesystem');
    host.npmPrefix = `${prefixDir}\u0000`;
    writeMcpConfig(tempDir, {
      'filesystem-root': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
    });

    await runDetect({ targetDir: tempDir, format: 'json', ci: true, registry: true, autoScan: true });

    expect(scannedDirs()).toEqual([tempDir]);
    expect(submission.submitScanReport).not.toHaveBeenCalled();
  });

  // A link under node_modules to a directory outside it, as `npm link` lays
  // out a development copy, is not an installed copy of the package. Before,
  // the link was followed, and the scan of the directory it pointed to was
  // sent under the package name.
  it.skipIf(process.platform === 'win32')('a server whose package under node_modules is a link to a directory outside node_modules is scanned in the project directory and not sent', async () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-contrib-outside-'));
    try {
      fs.writeFileSync(path.join(outside, 'package.json'), JSON.stringify({ name: '@modelcontextprotocol/server-filesystem', version: '0.0.0' }));
      const link = path.join(tempDir, 'node_modules', '@modelcontextprotocol', 'server-filesystem');
      fs.mkdirSync(path.dirname(link), { recursive: true });
      fs.symlinkSync(outside, link, 'dir');
      expect(fs.existsSync(path.join(link, 'package.json'))).toBe(true);
      writeMcpConfig(tempDir, {
        'filesystem-root': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
      });

      const { exitCode, stdout } = await runDetect({ targetDir: tempDir, format: 'json', ci: true, registry: true, autoScan: true });

      expect(exitCode).toBe(0);
      expect(scannedDirs()).toEqual([tempDir]);
      expect(submission.submitScanReport).not.toHaveBeenCalled();
      const server = JSON.parse(stdout).mcpServers.find((s: { name: string }) => s.name === 'filesystem-root');
      expect(server.scanResult.contributed).toBe(false);
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  // pnpm lays a package out under node_modules/.pnpm and links it from
  // node_modules/<name>: the link stays under node_modules and is followed.
  it.skipIf(process.platform === 'win32')('a server whose package under node_modules is a link to a directory under node_modules is scanned there and sent', async () => {
    const store = path.join(tempDir, 'node_modules', '.pnpm', '@modelcontextprotocol+server-filesystem@0.0.0');
    const real = installPackage(store, '@modelcontextprotocol/server-filesystem');
    const link = path.join(tempDir, 'node_modules', '@modelcontextprotocol', 'server-filesystem');
    fs.mkdirSync(path.dirname(link), { recursive: true });
    fs.symlinkSync(path.relative(path.dirname(link), real), link, 'dir');
    expect(fs.realpathSync(link)).toBe(fs.realpathSync(real));
    writeMcpConfig(tempDir, {
      'filesystem-root': { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
    });

    const { exitCode, stdout } = await runDetect({ targetDir: tempDir, format: 'json', ci: true, registry: true, autoScan: true });

    expect(exitCode).toBe(0);
    expect(scannedDirs()).toEqual([link]);
    expect(submission.submitScanReport).toHaveBeenCalledTimes(1);
    const [, report] = submission.submitScanReport.mock.calls[0] as unknown as [string, Record<string, unknown>];
    expect(report.packageName).toBe('@modelcontextprotocol/server-filesystem');
    const server = JSON.parse(stdout).mcpServers.find((s: { name: string }) => s.name === 'filesystem-root');
    expect(server.scanResult.contributed).toBe(true);
  });
});

// The lookup itself, with names registryNameFor never produces: the
// directory it answers must lie under the node_modules directory it was
// given, whatever the name.
describe('installedPackageDir', () => {
  let root: string;
  let nodeModules: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-detect-lookup-'));
    nodeModules = path.join(root, 'node_modules');
    installPackage(root, 'pkg');
    installPackage(root, '@scope/pkg');
    fs.mkdirSync(path.join(root, 'outside'), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('answers the directory of an installed unscoped or scoped package, and null for one that is not installed', () => {
    expect(installedPackageDir(nodeModules, 'pkg')).toBe(path.join(nodeModules, 'pkg'));
    expect(installedPackageDir(nodeModules, '@scope/pkg')).toBe(path.join(nodeModules, '@scope', 'pkg'));
    expect(installedPackageDir(nodeModules, 'other')).toBeNull();
    expect(installedPackageDir(nodeModules, '@scope/other')).toBeNull();
    expect(installedPackageDir(path.join(root, 'no-such-dir'), 'pkg')).toBeNull();
  });

  it('refuses a name that would resolve outside node_modules, or inside it under another name', () => {
    const outsideFromRoot = path.relative(nodeModules, path.join(root, 'outside'));
    expect(fs.existsSync(path.resolve(nodeModules, outsideFromRoot))).toBe(true);
    for (const name of [
      '',
      '.',
      '..',
      outsideFromRoot,
      path.join(root, 'outside'),
      path.join(nodeModules, 'pkg'),
      'pkg/..',
      'pkg/../pkg',
      '@scope/../pkg',
      './pkg',
      'pkg/',
      '/pkg',
      'pkg//',
      '@scope\\..\\pkg',
      'pkg\u0000',
      'pkg\n',
      '@scope/pkg\u001b',
    ]) {
      expect(installedPackageDir(nodeModules, name), JSON.stringify(name)).toBeNull();
    }
  });

  it.skipIf(process.platform === 'win32')('follows a link that stays under node_modules and refuses one that leaves it', () => {
    const inside = path.join(nodeModules, '.store', 'linked');
    fs.mkdirSync(inside, { recursive: true });
    fs.symlinkSync(inside, path.join(nodeModules, 'linked-inside'), 'dir');
    fs.symlinkSync(path.join(root, 'outside'), path.join(nodeModules, 'linked-outside'), 'dir');
    fs.symlinkSync(os.homedir(), path.join(nodeModules, 'linked-home'), 'dir');

    expect(installedPackageDir(nodeModules, 'linked-inside')).toBe(path.join(nodeModules, 'linked-inside'));
    expect(installedPackageDir(nodeModules, 'linked-outside')).toBeNull();
    expect(installedPackageDir(nodeModules, 'linked-home')).toBeNull();
  });
});
