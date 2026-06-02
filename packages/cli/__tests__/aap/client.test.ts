import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  BrokerClient,
  BrokerGrantError,
  GrantDeniedError,
} from '../../src/aap/client.js';

/**
 * The tests stand up a minimal HTTP-over-Unix-socket server that imitates the
 * Secretless broker's POST /grant contract (the real broker source is in the
 * `secretless` repo; the wire format is the integration surface, not the
 * implementation). This validates that the TS client speaks AAP §6 correctly
 * and routes denials and transport errors to the right typed errors.
 */

interface FakeBroker {
  socketPath: string;
  tokenPath: string;
  token: string;
  server: http.Server;
  /** Set by the test before each call to configure the next response. */
  next: { status: number; body: unknown };
  /** Recorded by the server for assertions. */
  last?: { method: string; url: string; auth: string | undefined; body: string };
  close(): Promise<void>;
}

async function startFakeBroker(): Promise<FakeBroker> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aap-client-'));
  const socketPath = path.join(tmpDir, 'broker.sock');
  const tokenPath = path.join(tmpDir, 'broker.token');
  const token = 'test-broker-token-' + Math.random().toString(36).slice(2);
  fs.writeFileSync(tokenPath, token, { mode: 0o600 });

  const broker: FakeBroker = {
    socketPath,
    tokenPath,
    token,
    server: undefined as unknown as http.Server,
    next: { status: 200, body: { result: { ok: true } } },
    last: undefined,
    async close() {
      await new Promise<void>((resolve) => broker.server.close(() => resolve()));
      fs.rmSync(tmpDir, { recursive: true, force: true });
    },
  };

  broker.server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      broker.last = {
        method: req.method ?? '',
        url: req.url ?? '',
        auth: req.headers.authorization,
        body: Buffer.concat(chunks).toString('utf-8'),
      };
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

describe('BrokerClient', () => {
  let broker: FakeBroker;

  beforeEach(async () => {
    broker = await startFakeBroker();
  });

  afterEach(async () => {
    await broker.close();
  });

  it('sends a well-formed POST /grant body and returns the result', async () => {
    broker.next = { status: 200, body: { result: { status: 200, body: { rows: 3 } } } };
    const client = new BrokerClient({
      socketPath: broker.socketPath,
      tokenPath: broker.tokenPath,
    });

    const result = await client.grant({
      agentId: 'opena2a_protect_cli',
      atx: { atcVersion: '1.0', agentId: 'opena2a_protect_cli', signatures: [] },
      grant: 'grant://opena2a-protect',
      operation: { method: 'POST', path: '/scan', query: { target: 'fixture' } },
    });

    expect(result).toEqual({ status: 200, body: { rows: 3 } });
    expect(broker.last?.method).toBe('POST');
    expect(broker.last?.url).toBe('/grant');
    expect(broker.last?.auth).toBe(`Bearer ${broker.token}`);
    const sent = JSON.parse(broker.last!.body);
    expect(sent).toMatchObject({
      agentId: 'opena2a_protect_cli',
      grant: 'grant://opena2a-protect',
      operation: { method: 'POST', path: '/scan' },
    });
    expect(sent.operation.query.target).toBe('fixture');
  });

  it('throws GrantDeniedError on 403 (uniform opaque denial per AAP §6.6)', async () => {
    broker.next = { status: 403, body: { error: 'denied' } };
    const client = new BrokerClient({
      socketPath: broker.socketPath,
      tokenPath: broker.tokenPath,
    });

    await expect(
      client.grant({
        agentId: 'a',
        atx: {},
        grant: 'grant://opena2a-protect',
        operation: { method: 'POST', path: '/scan' },
      }),
    ).rejects.toBeInstanceOf(GrantDeniedError);
  });

  it('GrantDeniedError carries the grant reference but no broker-side detail', async () => {
    broker.next = { status: 403, body: { error: 'denied', secret: 'should-not-be-read' } };
    const client = new BrokerClient({
      socketPath: broker.socketPath,
      tokenPath: broker.tokenPath,
    });

    try {
      await client.grant({
        agentId: 'a',
        atx: {},
        grant: 'grant://opena2a-protect',
        operation: { method: 'POST', path: '/scan' },
      });
      throw new Error('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(GrantDeniedError);
      const denied = err as GrantDeniedError;
      expect(denied.grant).toBe('grant://opena2a-protect');
      expect(denied.message).not.toContain('should-not-be-read');
    }
  });

  it('throws BrokerGrantError on 401 (token rotation hint)', async () => {
    broker.next = { status: 401, body: { error: 'Unauthorized' } };
    const client = new BrokerClient({
      socketPath: broker.socketPath,
      tokenPath: broker.tokenPath,
    });

    await expect(
      client.grant({
        agentId: 'a',
        atx: {},
        grant: 'grant://opena2a-protect',
        operation: { method: 'POST', path: '/scan' },
      }),
    ).rejects.toThrow(/rotate broker.token/);
  });

  it('throws BrokerGrantError when the broker socket is unreachable', async () => {
    const client = new BrokerClient({
      socketPath: path.join(os.tmpdir(), 'definitely-does-not-exist.sock'),
      token: 'irrelevant',
    });

    await expect(
      client.grant({
        agentId: 'a',
        atx: {},
        grant: 'grant://opena2a-protect',
        operation: { method: 'POST', path: '/scan' },
      }),
    ).rejects.toBeInstanceOf(BrokerGrantError);
  });

  it('throws BrokerGrantError when the token file is missing', async () => {
    const client = new BrokerClient({
      socketPath: broker.socketPath,
      tokenPath: path.join(os.tmpdir(), 'absent.token'),
    });

    await expect(
      client.grant({
        agentId: 'a',
        atx: {},
        grant: 'grant://opena2a-protect',
        operation: { method: 'POST', path: '/scan' },
      }),
    ).rejects.toThrow(/broker token not found/);
  });

  it('prefers an explicit token over the token file', async () => {
    broker.next = { status: 200, body: { result: 'ok' } };
    const client = new BrokerClient({
      socketPath: broker.socketPath,
      token: 'explicit-token',
      tokenPath: path.join(os.tmpdir(), 'absent.token'),
    });

    const result = await client.grant({
      agentId: 'a',
      atx: {},
      grant: 'grant://opena2a-protect',
      operation: { method: 'POST', path: '/scan' },
    });
    expect(result).toBe('ok');
    expect(broker.last?.auth).toBe('Bearer explicit-token');
  });
});
