/**
 * End-to-end integration test for `opena2a protect --grant`.
 *
 * The Secretless broker is the policy decision point for this command. The
 * implementation lives in another repo (opena2a-org/secretless), so this test
 * stands up a minimal fake broker that speaks AAP §6 over a Unix socket and
 * proves the CLI:
 *   1. Refuses to run --grant without --atx.
 *   2. Proceeds when the broker authorizes (200).
 *   3. Hard-fails 3 with an actionable message on uniform opaque denial (403).
 *   4. Hard-fails 4 when the broker socket is unreachable.
 *
 * The broker test suite in secretless/src/broker/aap-conformance.test.ts runs
 * the *real* broker; this test gates the wrapper. Both must pass before a
 * release.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { protect } from '../../src/commands/protect.js';

interface FakeBroker {
  socketPath: string;
  tokenPath: string;
  token: string;
  server: http.Server;
  next: { status: number; body: unknown };
  calls: number;
  lastBody?: string;
  close(): Promise<void>;
}

async function startFakeBroker(tmpDir: string): Promise<FakeBroker> {
  const socketPath = path.join(tmpDir, 'broker.sock');
  const tokenPath = path.join(tmpDir, 'broker.token');
  const token = 'protect-integ-' + Math.random().toString(36).slice(2);
  fs.writeFileSync(tokenPath, token, { mode: 0o600 });

  const broker: FakeBroker = {
    socketPath,
    tokenPath,
    token,
    server: undefined as unknown as http.Server,
    next: { status: 200, body: { result: { status: 200, body: { authorized: true } } } },
    calls: 0,
    async close() {
      await new Promise<void>((resolve) => broker.server.close(() => resolve()));
    },
  };

  broker.server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      broker.calls += 1;
      broker.lastBody = Buffer.concat(chunks).toString('utf-8');
      const body = JSON.stringify(broker.next.body);
      res.writeHead(broker.next.status, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      });
      res.end(body);
    });
  });

  await new Promise<void>((resolve, reject) => {
    broker.server.once('error', reject);
    broker.server.listen(socketPath, () => resolve());
  });

  return broker;
}

function writeAtxFixture(dir: string): string {
  const atxPath = path.join(dir, 'atx.json');
  fs.writeFileSync(
    atxPath,
    JSON.stringify({
      atcVersion: '1.0',
      agentId: 'opena2a_protect_cli',
      agentDid: 'did:opena2a:agent:opena2a-org/opena2a-cli',
      version: '0.10.5',
      contentHash: 'sha256:test',
      issuerDid: 'did:opena2a:authority:opena2a.org',
      trustLevel: 4,
      trustScore: 0.95,
      issuedAt: '2026-05-25T00:00:00Z',
      expiresAt: '2026-06-08T00:00:00Z',
      capabilities: ['protect:scan'],
      signatures: [],
    }),
  );
  return atxPath;
}

describe('opena2a protect --grant', () => {
  let tmpDir: string;
  let scanDir: string;
  let broker: FakeBroker;
  let stderr: string;
  let stdout: string;
  const origStderrWrite = process.stderr.write.bind(process.stderr);
  const origStdoutWrite = process.stdout.write.bind(process.stdout);

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aap-protect-'));
    scanDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aap-scandir-'));
    broker = await startFakeBroker(tmpDir);
    stderr = '';
    stdout = '';
    // Suppress + capture protect's chatter so test logs stay legible.
    (process.stderr.write as any) = (chunk: any) => {
      stderr += typeof chunk === 'string' ? chunk : String(chunk);
      return true;
    };
    (process.stdout.write as any) = (chunk: any) => {
      stdout += typeof chunk === 'string' ? chunk : String(chunk);
      return true;
    };
  });

  afterEach(async () => {
    (process.stderr.write as any) = origStderrWrite;
    (process.stdout.write as any) = origStdoutWrite;
    await broker.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(scanDir, { recursive: true, force: true });
  });

  it('refuses --grant without --atx (exit code 2)', async () => {
    const exitCode = await protect({
      targetDir: scanDir,
      grant: 'grant://opena2a-protect',
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });
    expect(exitCode).toBe(2);
    expect(broker.calls).toBe(0); // Broker never contacted
    expect(stderr).toMatch(/--grant requires --atx/);
  });

  it('proceeds with the scan when the broker returns 200', async () => {
    broker.next = { status: 200, body: { result: { status: 200, body: { authorized: true } } } };
    const atxPath = writeAtxFixture(tmpDir);

    const exitCode = await protect({
      targetDir: scanDir,
      grant: 'grant://opena2a-protect',
      atxPath,
      brokerSocket: broker.socketPath,
      brokerTokenPath: broker.tokenPath,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    expect(exitCode).toBe(0);
    expect(broker.calls).toBe(1);
    // The body the broker received is well-formed and references our grant + ATX.
    const sent = JSON.parse(broker.lastBody!);
    expect(sent.agentId).toBe('opena2a_protect_cli');
    expect(sent.grant).toBe('grant://opena2a-protect');
    expect(sent.atx.agentId).toBe('opena2a_protect_cli');
    expect(sent.operation.method).toBe('POST');
    expect(sent.operation.path).toBe('/protect/scan');
  });

  it('hard-fails 3 with an actionable message on 403 (AAP §6.6 opaque denial)', async () => {
    broker.next = { status: 403, body: { error: 'denied' } };
    const atxPath = writeAtxFixture(tmpDir);

    const exitCode = await protect({
      targetDir: scanDir,
      grant: 'grant://opena2a-protect',
      atxPath,
      brokerSocket: broker.socketPath,
      brokerTokenPath: broker.tokenPath,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    expect(exitCode).toBe(3);
    expect(broker.calls).toBe(1);
    // User gets a concrete next step, not a stack trace.
    expect(stderr).toMatch(/AAP broker denied/);
    expect(stderr).toMatch(/Next step/);
    expect(stderr).toMatch(/grant:\/\/opena2a-protect/);
    expect(stderr).toMatch(/\.secretless-ai\/policies/);
    // No internal broker detail leaked into the user message.
    expect(stderr).not.toMatch(/policy.*reason|matched-rule|backend/i);
  });

  it('hard-fails 4 with a broker-start hint when the socket is unreachable', async () => {
    // Stop the broker, then call protect with the dead socket path.
    await broker.close();
    const atxPath = writeAtxFixture(tmpDir);

    const exitCode = await protect({
      targetDir: scanDir,
      grant: 'grant://opena2a-protect',
      atxPath,
      brokerSocket: broker.socketPath,
      brokerTokenPath: broker.tokenPath,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    expect(exitCode).toBe(4);
    expect(stderr).toMatch(/AAP broker unreachable/);
    expect(stderr).toMatch(/secretless broker start/);
  });

  it('emits a JSON-shaped denial when --format json is set', async () => {
    broker.next = { status: 403, body: { error: 'denied' } };
    const atxPath = writeAtxFixture(tmpDir);

    const exitCode = await protect({
      targetDir: scanDir,
      grant: 'grant://opena2a-protect',
      atxPath,
      brokerSocket: broker.socketPath,
      brokerTokenPath: broker.tokenPath,
      ci: true,
      format: 'json',
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    expect(exitCode).toBe(3);
    // The JSON payload should be parseable and carry the grant + remediation.
    const jsonLine = stdout.trim().split('\n').find((l) => l.startsWith('{'));
    expect(jsonLine).toBeDefined();
    const parsed = JSON.parse(jsonLine!);
    expect(parsed.status).toBe('aap-denied');
    expect(parsed.grant).toBe('grant://opena2a-protect');
    expect(parsed.remediation).toMatch(/grant:\/\/opena2a-protect/);
  });
});
