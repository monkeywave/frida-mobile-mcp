import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import {
  startHttpServer,
  isLoopbackHost,
  allowedHostHeaders,
  isAllowedOrigin,
  checkBearerToken,
  assertHttpOptions,
  type HttpServerHandle,
} from '../../src/transport/http.js';
import { createSessionServer, DEFAULT_CONFIG } from '../../src/lib.js';

const TOKEN = 'test-token-123';
const INITIALIZE_BODY = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } },
});

interface RawResponse {
  status: number;
  body: string;
}

function rawPost(port: number, headers: Record<string, string>, body = INITIALIZE_BODY, method = 'POST'): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port,
        path: '/mcp',
        method,
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          ...headers,
        },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

describe('http transport helpers', () => {
  it('recognises loopback hosts', () => {
    expect(isLoopbackHost('127.0.0.1')).toBe(true);
    expect(isLoopbackHost('localhost')).toBe(true);
    expect(isLoopbackHost('::1')).toBe(true);
    expect(isLoopbackHost('0.0.0.0')).toBe(false);
    expect(isLoopbackHost('192.168.1.5')).toBe(false);
  });

  it('builds allowed host headers for loopback binds', () => {
    const allowed = allowedHostHeaders('127.0.0.1', 4321);
    expect(allowed).toContain('localhost:4321');
    expect(allowed).toContain('127.0.0.1:4321');
    expect(allowed).toContain('[::1]:4321');
  });

  it('validates origins against the allowed hosts', () => {
    const allowed = allowedHostHeaders('127.0.0.1', 4321);
    expect(isAllowedOrigin(undefined, allowed)).toBe(true);
    expect(isAllowedOrigin('http://localhost:4321', allowed)).toBe(true);
    expect(isAllowedOrigin('http://evil.example.com', allowed)).toBe(false);
    expect(isAllowedOrigin('not a url', allowed)).toBe(false);
  });

  it('checks bearer tokens in constant time', () => {
    expect(checkBearerToken('Bearer secret', 'secret')).toBe(true);
    expect(checkBearerToken('bearer secret', 'secret')).toBe(true);
    expect(checkBearerToken('Bearer nope', 'secret')).toBe(false);
    expect(checkBearerToken(undefined, 'secret')).toBe(false);
  });

  it('rejects blank bearer tokens and tolerates surrounding whitespace', () => {
    expect(checkBearerToken('Bearer    ', 'secret')).toBe(false);
    expect(checkBearerToken('Bearer   secret  ', 'secret')).toBe(true);
  });

  it('rejects pathological whitespace headers in linear time (ReDoS regression)', () => {
    // A mid-header line break makes `$` fail, forcing the old /^Bearer\s+(.+)$/ to backtrack quadratically.
    const header = 'Bearer ' + ' '.repeat(50_000) + '!\n!';
    const started = performance.now();
    expect(checkBearerToken(header, 'secret')).toBe(false);
    expect(performance.now() - started).toBeLessThan(100);
  });

  it('refuses non-loopback binds without a token', () => {
    expect(() => assertHttpOptions({ host: '0.0.0.0' })).toThrow(/token/);
    expect(() => assertHttpOptions({ host: '0.0.0.0', token: 'x' })).not.toThrow();
    expect(() => assertHttpOptions({ host: '127.0.0.1' })).not.toThrow();
  });
});

describe('startHttpServer', () => {
  let handle: HttpServerHandle;

  beforeAll(async () => {
    const config = { ...DEFAULT_CONFIG, auditLogPath: join(tmpdir(), 'frida-mcp-http-test-audit.jsonl') };
    handle = await startHttpServer({
      host: '127.0.0.1',
      port: 0,
      token: TOKEN,
      createSessionServer: () => createSessionServer({ config }),
    });
  });

  afterAll(async () => {
    await handle.close();
  });

  it('listens on an ephemeral loopback port at /mcp', () => {
    expect(handle.port).toBeGreaterThan(0);
    expect(handle.url).toBe(`http://127.0.0.1:${handle.port}/mcp`);
  });

  it('serves initialize and tools/list to an SDK client, then ends the session on DELETE', async () => {
    const transport = new StreamableHTTPClientTransport(new URL(handle.url), {
      requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
    });
    const client = new Client({ name: 'http-test', version: '0.0.0' });
    await client.connect(transport);
    expect(handle.sessionCount()).toBe(1);

    const { tools } = await client.listTools();
    expect(tools.length).toBeGreaterThanOrEqual(30);
    expect(tools.map((t) => t.name)).toContain('get_status');

    await transport.terminateSession();
    expect(handle.sessionCount()).toBe(0);
    await client.close();
  });

  it('rejects requests without a bearer token with 401', async () => {
    const res = await rawPost(handle.port, {});
    expect(res.status).toBe(401);
  });

  it('rejects a wrong bearer token with 401', async () => {
    const res = await rawPost(handle.port, { Authorization: 'Bearer wrong' });
    expect(res.status).toBe(401);
  });

  it('rejects a foreign Host header with 403', async () => {
    const res = await rawPost(handle.port, { Authorization: `Bearer ${TOKEN}`, Host: 'evil.example.com' });
    expect(res.status).toBe(403);
  });

  it('rejects a foreign Origin header with 403', async () => {
    const res = await rawPost(handle.port, { Authorization: `Bearer ${TOKEN}`, Origin: 'http://evil.example.com' });
    expect(res.status).toBe(403);
  });

  it('returns 404 for an unknown session id', async () => {
    const res = await rawPost(handle.port, { Authorization: `Bearer ${TOKEN}`, 'Mcp-Session-Id': 'does-not-exist' });
    expect(res.status).toBe(404);
  });

  it('returns 400 for a non-initialize request without a session', async () => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    const res = await rawPost(handle.port, { Authorization: `Bearer ${TOKEN}` }, body);
    expect(res.status).toBe(400);
  });
});
