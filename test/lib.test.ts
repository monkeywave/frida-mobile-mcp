import { describe, it, expect, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { McpServer, InMemoryTransport } from '@modelcontextprotocol/server';
import * as lib from '../src/lib.js';

const TEST_CONFIG = { ...lib.DEFAULT_CONFIG, auditLogPath: join(tmpdir(), 'frida-mcp-lib-test-audit.jsonl') };

describe('lib entry point', () => {
  it('exports the public API', () => {
    expect(typeof lib.createServer).toBe('function');
    expect(typeof lib.registerFridaTools).toBe('function');
    expect(typeof lib.createSessionServer).toBe('function');
    expect(typeof lib.initState).toBe('function');
    expect(typeof lib.loadConfig).toBe('function');
    expect(typeof lib.composeAgentSource).toBe('function');
    expect(typeof lib.createAgentScript).toBe('function');
    expect(typeof lib.findRemovedApis).toBe('function');
    expect(typeof lib.startHttpServer).toBe('function');
    expect(typeof lib.getCharacterLimit).toBe('function');
  });

  it('exposes the prebuilt script registry', () => {
    const names = lib.scriptRegistry.listAll().map((t) => t.name);
    expect(names).toContain('ssl_pinning_bypass');
    expect(names.length).toBeGreaterThanOrEqual(8);
    expect(lib.scriptRegistry.get('method_hook')).toBeDefined();
  });

  it('registers the Frida tools on a fresh McpServer', async () => {
    const server = new McpServer({ name: 'host', version: '0.0.0' });
    const deviceManager = lib.registerFridaTools(server, { config: TEST_CONFIG });
    expect(deviceManager).toBeInstanceOf(lib.DeviceManager);

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: 'lib-test', version: '0.0.0' });
    await client.connect(clientTransport);

    const { tools } = await client.listTools();
    expect(tools.length).toBeGreaterThanOrEqual(30);
    expect(tools.map((t) => t.name)).toContain('frida_help');

    await client.close();
    await server.close();
  });

  it('createSessionServer yields independent servers sharing global state', async () => {
    const a = lib.createSessionServer({ config: TEST_CONFIG });
    const b = lib.createSessionServer({ config: TEST_CONFIG });
    expect(a).not.toBe(b);
    expect(lib.getState()).toBe(lib.ensureState());
  });
});

describe('getCharacterLimit', () => {
  const original = process.env.FRIDA_MCP_MAX_RESPONSE_CHARS;

  afterEach(() => {
    if (original === undefined) delete process.env.FRIDA_MCP_MAX_RESPONSE_CHARS;
    else process.env.FRIDA_MCP_MAX_RESPONSE_CHARS = original;
    lib.loadConfig();
  });

  it('defaults to CHARACTER_LIMIT', () => {
    delete process.env.FRIDA_MCP_MAX_RESPONSE_CHARS;
    lib.loadConfig();
    expect(lib.getCharacterLimit()).toBe(lib.CHARACTER_LIMIT);
  });

  it('honours FRIDA_MCP_MAX_RESPONSE_CHARS', () => {
    process.env.FRIDA_MCP_MAX_RESPONSE_CHARS = '1234';
    lib.loadConfig();
    expect(lib.getCharacterLimit()).toBe(1234);
  });

  it('ignores invalid FRIDA_MCP_MAX_RESPONSE_CHARS', () => {
    process.env.FRIDA_MCP_MAX_RESPONSE_CHARS = '-5';
    lib.loadConfig();
    expect(lib.getCharacterLimit()).toBe(lib.CHARACTER_LIMIT);
  });
});
