// Regression (#464): tests that ran review() or init() without stubbing
// fetch sent the advisory request to the default Registry, and its answer was
// cached under HOME as ~/.opena2a/cache/advisories.json with registryUrl
// https://api.oa2a.org. The suite's setup file (setup/offline-fetch.ts)
// refuses every non-loopback request.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import type { AddressInfo } from 'node:net';
import { init } from '../src/commands/init.js';

describe('the CLI test suite runs offline', () => {
  let tempDir: string;
  let tempHome: string;
  const savedHome = process.env.HOME;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-offline-'));
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-offline-home-'));
    // os.homedir() reads HOME, here and in the shared config reader.
    process.env.HOME = tempHome;
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({
      name: 'offline-fixture', version: '1.0.0', dependencies: { 'left-pad': '1.0.0' },
    }));
  });

  afterEach(() => {
    process.env.HOME = savedHome;
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  it('a request to a non-loopback host is refused', async () => {
    await expect(fetch('https://api.oa2a.org/api/v1/trust/advisories')).rejects.toThrow(/runs offline/);
  });

  it('a request to a loopback server goes through', async () => {
    const server = http.createServer((_req, res) => res.end('ok'));
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const { port } = server.address() as AddressInfo;
      const res = await fetch(`http://127.0.0.1:${port}/`);
      expect(await res.text()).toBe('ok');
    } finally {
      server.close();
    }
  });

  it('init() with no fetch stub reads no advisory list and caches nothing under HOME', async () => {
    const origOut = process.stdout.write;
    let stdout = '';
    process.stdout.write = ((chunk: unknown) => { stdout += String(chunk); return true; }) as typeof process.stdout.write;
    try {
      await init({ targetDir: tempDir, format: 'json' });
    } finally {
      process.stdout.write = origOut;
    }

    expect(JSON.parse(stdout).advisories.checked).toBe(false);
    expect(fs.existsSync(path.join(tempHome, '.opena2a', 'cache', 'advisories.json'))).toBe(false);
  });
});
