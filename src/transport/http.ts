/**
 * Streamable HTTP transport on Node's built-in `http` module (no express).
 *
 * One `McpServer` is created per MCP session because the SDK only allows a single transport
 * per server, while the Frida state (devices, sessions, hooks) stays process-global. The
 * endpoint is `POST|GET|DELETE /mcp`; `DELETE` with `Mcp-Session-Id` ends a session.
 *
 * Security: the server binds to loopback by default and validates `Host`/`Origin` against the
 * bound address (DNS-rebinding protection). A bearer token is optional on loopback and
 * mandatory on any other bind address. The SDK's own `allowedHosts` option is deprecated in
 * favour of external middleware, which is what `validateRequest` below implements.
 */
import { createServer as createNodeServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { isInitializeRequest } from '@modelcontextprotocol/server';
import type { McpServer } from '@modelcontextprotocol/server';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import { log } from '../helpers/logger.js';

export const DEFAULT_HTTP_PATH = '/mcp';
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const LOOPBACK_NAMES = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '::ffff:127.0.0.1', '0.0.0.0', '::']);

export interface HttpTransportOptions {
  /** Interface to bind; loopback unless a token is configured. */
  host: string;
  /** TCP port; 0 picks an ephemeral port. */
  port: number;
  /** Bearer token clients must send. Required when `host` is not loopback. */
  token?: string;
  /** Endpoint path (default `/mcp`). */
  path?: string;
  /** Produces the `McpServer` connected to each new MCP session. */
  createSessionServer: () => McpServer;
}

export interface HttpServerHandle {
  url: string;
  host: string;
  port: number;
  sessionCount(): number;
  close(): Promise<void>;
}

interface McpSession {
  transport: NodeStreamableHTTPServerTransport;
  server: McpServer;
  closing: boolean;
}

/** True for addresses that only accept connections from the local machine. */
export function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  if (LOOPBACK_NAMES.has(normalized)) return normalized !== '0.0.0.0' && normalized !== '::';
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(normalized);
}

/** Host header values accepted for a given bind address and port. */
export function allowedHostHeaders(bindHost: string, port: number): string[] {
  const names = isLoopbackHost(bindHost)
    ? ['localhost', '127.0.0.1', '[::1]']
    : [bindHost.includes(':') ? `[${bindHost}]` : bindHost];
  return names.flatMap((name) => [name, `${name}:${port}`]);
}

export function isAllowedHostHeader(hostHeader: string | undefined, allowed: readonly string[]): boolean {
  if (!hostHeader) return false;
  return allowed.includes(hostHeader.trim().toLowerCase());
}

/** A missing Origin (non-browser client) is fine; a present one must point at an allowed host. */
export function isAllowedOrigin(origin: string | undefined, allowed: readonly string[]): boolean {
  if (!origin) return true;
  try {
    const url = new URL(origin);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
    return isAllowedHostHeader(url.host, allowed);
  } catch {
    return false;
  }
}

/** Constant-time comparison of an `Authorization: Bearer ...` header with the expected token. */
export function checkBearerToken(header: string | undefined, token: string): boolean {
  const match = /^Bearer\s+(.+)$/i.exec(header?.trim() ?? '');
  if (!match) return false;
  const presented = Buffer.from(match[1].trim());
  const expected = Buffer.from(token);
  return presented.length === expected.length && timingSafeEqual(presented, expected);
}

/** Throws when the configuration would expose the server without authentication. */
export function assertHttpOptions(options: Pick<HttpTransportOptions, 'host' | 'token'>): void {
  if (!isLoopbackHost(options.host) && !options.token) {
    throw new Error(
      `Refusing to bind HTTP transport to non-loopback host "${options.host}" without a token. ` +
        'Pass --http-token <token> or set FRIDA_MCP_HTTP_TOKEN.'
    );
  }
}

function sendJsonError(res: ServerResponse, status: number, message: string, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message }, id: null }));
}

function readBody(req: IncomingMessage, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

class HttpSessionRouter {
  private readonly sessions = new Map<string, McpSession>();
  private readonly allowedHosts: string[];

  constructor(private readonly options: HttpTransportOptions, port: number) {
    this.allowedHosts = allowedHostHeaders(options.host, port);
  }

  get sessionCount(): number {
    return this.sessions.size;
  }

  async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!this.validateRequest(req, res)) return;
    try {
      await this.route(req, res);
    } catch (err) {
      log('error', `HTTP request failed: ${String(err)}`);
      if (!res.headersSent) sendJsonError(res, 500, 'Internal server error');
    }
  }

  /** Host, Origin, token and path checks; writes the error response and returns false on failure. */
  private validateRequest(req: IncomingMessage, res: ServerResponse): boolean {
    if (!isAllowedHostHeader(req.headers.host, this.allowedHosts)) {
      sendJsonError(res, 403, 'Forbidden: Host header not allowed');
      return false;
    }
    if (!isAllowedOrigin(req.headers.origin, this.allowedHosts)) {
      sendJsonError(res, 403, 'Forbidden: Origin not allowed');
      return false;
    }
    if (this.options.token && !checkBearerToken(req.headers.authorization, this.options.token)) {
      sendJsonError(res, 401, 'Unauthorized', { 'WWW-Authenticate': 'Bearer realm="frida-mobile-mcp"' });
      return false;
    }
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    if (path !== (this.options.path ?? DEFAULT_HTTP_PATH)) {
      sendJsonError(res, 404, 'Not found');
      return false;
    }
    return true;
  }

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const sessionId = headerValue(req.headers['mcp-session-id']);
    if (req.method === 'POST') return this.handlePost(req, res, sessionId);
    if (req.method === 'GET' || req.method === 'DELETE') return this.handleExisting(req, res, sessionId);
    sendJsonError(res, 405, 'Method not allowed', { Allow: 'GET, POST, DELETE' });
  }

  private async handlePost(req: IncomingMessage, res: ServerResponse, sessionId: string | undefined): Promise<void> {
    let body: unknown;
    try {
      body = JSON.parse(await readBody(req, MAX_BODY_BYTES));
    } catch (err) {
      sendJsonError(res, 400, `Bad Request: ${err instanceof Error ? err.message : 'invalid JSON'}`);
      return;
    }
    if (sessionId) {
      const session = this.sessions.get(sessionId);
      if (!session) return sendJsonError(res, 404, 'Session not found');
      return session.transport.handleRequest(req, res, body);
    }
    if (!isInitializeRequest(body)) {
      return sendJsonError(res, 400, 'Bad Request: Mcp-Session-Id header is required');
    }
    const session = await this.createSession();
    await session.transport.handleRequest(req, res, body);
  }

  private async handleExisting(req: IncomingMessage, res: ServerResponse, sessionId: string | undefined): Promise<void> {
    if (!sessionId) return sendJsonError(res, 400, 'Bad Request: Mcp-Session-Id header is required');
    const session = this.sessions.get(sessionId);
    if (!session) return sendJsonError(res, 404, 'Session not found');
    await session.transport.handleRequest(req, res);
  }

  private async createSession(): Promise<McpSession> {
    const server = this.options.createSessionServer();
    const session: McpSession = { server, closing: false, transport: undefined as unknown as NodeStreamableHTTPServerTransport };
    session.transport = new NodeStreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        this.sessions.set(id, session);
        log('info', `HTTP MCP session started: ${id}`);
      },
      onsessionclosed: (id) => this.closeSession(id, session),
    });
    session.transport.onclose = () => {
      const id = session.transport.sessionId;
      if (id) this.closeSession(id, session).catch(() => undefined);
    };
    await server.connect(session.transport);
    return session;
  }

  private async closeSession(id: string, session: McpSession): Promise<void> {
    if (session.closing) return;
    session.closing = true;
    this.sessions.delete(id);
    log('info', `HTTP MCP session ended: ${id}`);
    await session.server.close().catch(() => undefined);
  }

  async closeAll(): Promise<void> {
    const open = Array.from(this.sessions.entries());
    await Promise.all(open.map(([id, session]) => this.closeSession(id, session)));
  }
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function listen(server: Server, host: string, port: number): Promise<AddressInfo> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve(server.address() as AddressInfo);
    });
  });
}

function formatUrlHost(host: string): string {
  return host.includes(':') ? `[${host}]` : host;
}

/** Start the Streamable HTTP endpoint and resolve once it is listening. */
export async function startHttpServer(options: HttpTransportOptions): Promise<HttpServerHandle> {
  assertHttpOptions(options);
  let router: HttpSessionRouter | null = null;
  const nodeServer = createNodeServer((req, res) => {
    router?.handle(req, res).catch(() => undefined);
  });

  const address = await listen(nodeServer, options.host, options.port);
  router = new HttpSessionRouter(options, address.port);
  const path = options.path ?? DEFAULT_HTTP_PATH;
  const url = `http://${formatUrlHost(options.host)}:${address.port}${path}`;
  const activeRouter = router;

  return {
    url,
    host: options.host,
    port: address.port,
    sessionCount: () => activeRouter.sessionCount,
    close: async () => {
      await activeRouter.closeAll();
      nodeServer.closeAllConnections();
      await new Promise<void>((resolve) => nodeServer.close(() => resolve()));
    },
  };
}
