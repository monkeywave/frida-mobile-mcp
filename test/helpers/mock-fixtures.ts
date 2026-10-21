/**
 * Shared test infrastructure.
 *
 * Reusable fakes and harnesses extracted from the unit tests so the in-memory
 * MCP harness, the crypto/session state fixtures and the frida device/session
 * fakes are defined once instead of copy-pasted across test files.
 *
 * This file is intentionally named WITHOUT a `.test` suffix: `vitest.config.ts`
 * only collects `test/**\/*.test.ts`, so nothing here is picked up as a suite.
 * It deliberately contains no `describe`/`it`/`test` blocks.
 */
import { vi } from 'vitest';
import { Client } from '@modelcontextprotocol/client';
import { McpServer, InMemoryTransport } from '@modelcontextprotocol/server';
import { registerAllTools } from '../../src/tools/register-all.js';
import type { ServerState } from '../../src/state.js';
import type { FridaMcpConfig, SessionEntry, ScriptEntry } from '../../src/types.js';

/** Loosely-typed JSON blob, matching the casts the tests use on tool output and schemas. */
export type Json = Record<string, any>;

// --- In-memory MCP harness -------------------------------------------------

export interface McpHarness {
  server: McpServer;
  client: Client;
  /** Tears down the client and server; state teardown stays with the caller. */
  close: () => Promise<void>;
}

/**
 * Spin up an `McpServer` linked to a `Client` over an in-memory transport.
 * `register` installs the tool(s) under test before the pair connects.
 */
export async function makeMcpHarness(register: (server: McpServer) => void): Promise<McpHarness> {
  const server = new McpServer({ name: 't', version: '0' });
  register(server);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '0' });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return {
    server,
    client,
    async close() {
      await client.close();
      await server.close();
    },
  };
}

/** Call a tool over the harness in `json` response format and parse the envelope. */
export async function callJson(client: Client, name: string, args: Record<string, unknown>): Promise<Json> {
  const response = (await client.callTool({ name, arguments: { ...args, response_format: 'json' } })) as Json;
  return JSON.parse(response.content[0].text);
}

// --- Session / script state fixtures --------------------------------------

export interface FakeScript {
  isDestroyed: boolean;
  unloadCalls: number;
  unload: () => Promise<void>;
}

/** A stand-in for `frida.Script` that records `unload()` calls and can fail or start destroyed. */
export function fakeScript(options: { failWith?: string; destroyed?: boolean } = {}): FakeScript {
  const script: FakeScript = {
    isDestroyed: options.destroyed ?? false,
    unloadCalls: 0,
    async unload() {
      script.unloadCalls++;
      if (options.failWith) throw new Error(options.failWith);
      script.isDestroyed = true;
    },
  };
  return script;
}

export function scriptEntry(id: string, script: FakeScript, name = `hook:${id}`): ScriptEntry {
  return { id, script: script as unknown as ScriptEntry['script'], messages: [], name, persistent: true, createdAt: Date.now() };
}

/**
 * A minimal `frida.Script` stub for the registered hook/trace/intercept handler tests: a
 * loadable/unloadable script whose `message` channel can be connected to. Every member is a
 * `vi.fn()` so tests can assert that `load`/`unload` were called.
 */
export function stubAgentScript() {
  return {
    load: vi.fn().mockResolvedValue(undefined),
    unload: vi.fn().mockResolvedValue(undefined),
    message: { connect: vi.fn() },
  };
}

/** Default identifiers used by the session/hook/trace fixtures so callers may override them. */
export const DEFAULT_SESSION_ID = 'sess-1';

export interface SeedSessionOverrides {
  id?: string;
  pid?: number;
  deviceId?: string;
  target?: string;
  platform?: string;
}

/** Register a session with the given scripts in `state` and return the entry. */
export function seedSession(state: ServerState, scripts: ScriptEntry[], overrides: SeedSessionOverrides = {}): SessionEntry {
  const entry = {
    id: overrides.id ?? DEFAULT_SESSION_ID,
    session: { detach: async () => undefined },
    pid: overrides.pid ?? 4242,
    deviceId: overrides.deviceId ?? 'emulator-5554',
    target: overrides.target ?? 'com.example.app',
    platform: overrides.platform ?? 'android',
    scripts: new Map(scripts.map((s) => [s.id, s])),
    createdAt: Date.now(),
  } as unknown as SessionEntry;
  state.sessions.set(entry.id, entry);
  return entry;
}

export function seedHook(state: ServerState, id: string, scriptId: string, sessionId: string = DEFAULT_SESSION_ID): void {
  state.hooks.set(id, { id, scriptId, sessionId, target: 'm', type: 'java', invocations: [], status: 'active', createdAt: Date.now() });
}

export function seedTrace(state: ServerState, id: string, scriptId: string, sessionId: string = DEFAULT_SESSION_ID): void {
  state.traces.set(id, { id, scriptId, sessionId, targets: ['m'], callCount: 0, startedAt: Date.now() });
}

// --- Frida device / session fakes -----------------------------------------

/**
 * Minimal `FridaMcpConfig` for unit tests: everything locked down, two session
 * slots and generous rate limits so the limits themselves are opt-in per test.
 */
export const TEST_CONFIG: FridaMcpConfig = {
  allowCustomScripts: false,
  memoryWriteEnabled: false,
  allowedDevices: [],
  maxSessions: 2,
  sessionTimeoutMinutes: 30,
  maxMessageBuffer: 100,
  auditLogPath: '',
  mobileMcp: { enabled: false, command: '', args: [] },
  rateLimits: { scriptsPerMinute: 10, memoryReadsPerMinute: 10, sessionsPerMinute: 10 },
};

export const SPAWNED_PID = 4242;
export const TARGET = 'com.example.app';

export function makeSession() {
  return {
    detached: { connect: vi.fn() },
    detach: vi.fn().mockResolvedValue(undefined),
  };
}

export function makeDevice(over: Record<string, unknown> = {}) {
  const session = makeSession();
  return {
    id: 'dev1',
    name: 'Dev',
    type: 'usb',
    enumerateApplications: vi.fn().mockResolvedValue([]),
    enumerateProcesses: vi.fn().mockResolvedValue([]),
    spawn: vi.fn().mockResolvedValue(SPAWNED_PID),
    attach: vi.fn().mockResolvedValue(session),
    resume: vi.fn().mockResolvedValue(undefined),
    kill: vi.fn().mockResolvedValue(undefined),
    processCrashed: { connect: vi.fn() },
    querySystemParameters: vi.fn().mockResolvedValue({ platform: 'android' }),
    ...over,
    _session: session,
  };
}

export type FakeDevice = ReturnType<typeof makeDevice>;

export function makeDeviceManager(device: FakeDevice) {
  return {
    resolve: vi.fn().mockResolvedValue(device),
    getDevice: vi.fn().mockResolvedValue(device),
    detectPlatform: vi.fn().mockResolvedValue('android'),
  } as any;
}

// --- Scripting session fakes (device-free agent script execution) ----------

/**
 * A stand-in for the `frida.Script` returned by `session.createScript(...)`. It records the
 * composed `source` and script options so composition/escaping can be asserted, exposes the
 * rpc `exports` the tool will call, and lets a test drive `message` events to the tool.
 */
export interface FakeAgentScript {
  name?: string;
  /** The fully composed agent source (preamble + bridges + body) the factory produced. */
  source: string;
  scriptOptions: Record<string, any>;
  loadCalls: number;
  unloadCalls: number;
  exports: Record<string, (...args: any[]) => any>;
  message: { connect: (fn: (m: any, d: any) => void) => void };
  /** Fire a message to every connected listener, as frida would on `send(...)`. */
  emit: (message: any, data?: any) => void;
  load: () => Promise<void>;
  unload: () => Promise<void>;
}

/** How a created script behaves: the rpc exports it offers and any messages emitted on load. */
export interface ScriptBehavior {
  exports?: Record<string, (...args: any[]) => any>;
  emitOnLoad?: Array<{ message: any; data?: any }>;
}

/** Context handed to the per-script behavior resolver so it can branch on the script name. */
export interface ScriptContext {
  name: string;
  source: string;
  options: Record<string, any>;
}

/**
 * A frida `Session` fake whose `createScript` returns {@link FakeAgentScript}s. Every created
 * script is recorded in the returned `scripts` array so tests can inspect the composed source.
 */
export function makeScriptingSession(behaviorFor: (ctx: ScriptContext) => ScriptBehavior = () => ({})) {
  const scripts: FakeAgentScript[] = [];
  const base = makeSession();
  const session = {
    ...base,
    createScript(source: string, scriptOptions: Record<string, any> = {}) {
      const behavior = behaviorFor({ name: scriptOptions.name, source, options: scriptOptions }) ?? {};
      const listeners: Array<(m: any, d: any) => void> = [];
      const script: FakeAgentScript = {
        name: scriptOptions.name,
        source,
        scriptOptions,
        loadCalls: 0,
        unloadCalls: 0,
        exports: behavior.exports ?? {},
        message: { connect: (fn) => listeners.push(fn) },
        emit: (message, data) => listeners.forEach((fn) => fn(message, data ?? null)),
        async load() {
          this.loadCalls++;
          for (const ev of behavior.emitOnLoad ?? []) this.emit(ev.message, ev.data);
        },
        async unload() {
          this.unloadCalls++;
        },
      };
      scripts.push(script);
      return script;
    },
  };
  return { session, scripts };
}

/**
 * Full device-manager + scripting session wiring for a tool that resolves a session through
 * `getOrCreateSession` and then creates agent scripts. The target is spawned (the fake device
 * enumerates nothing), attached to, and its session's `createScript` is the scripting fake.
 */
export function makeScriptingSetup(
  behaviorFor: (ctx: ScriptContext) => ScriptBehavior = () => ({}),
  deviceOverrides: Record<string, unknown> = {}
) {
  const { session, scripts } = makeScriptingSession(behaviorFor);
  const device = makeDevice({ attach: vi.fn().mockResolvedValue(session), ...deviceOverrides });
  const deviceManager = makeDeviceManager(device);
  return { session, scripts, device, deviceManager };
}

// --- Composed agent source introspection ----------------------------------

const AGENT_OPTIONS_ASSIGN_PREFIX = 'globalThis.__FRIDA_MCP__ = ';

/** The raw JSON literal assigned to `__FRIDA_MCP__` (splitting on \n keeps U+2028/U+2029 intact). */
export function agentLiteral(source: string): string {
  const line = source.split('\n').find((l) => l.startsWith(AGENT_OPTIONS_ASSIGN_PREFIX));
  if (!line) throw new Error('composed source is missing the __FRIDA_MCP__ literal');
  return line.slice(AGENT_OPTIONS_ASSIGN_PREFIX.length).replace(/;$/, '');
}

/** Pull the `__FRIDA_MCP__` options literal back out of a composed agent source. */
export function agentOptions(source: string): Record<string, any> {
  return JSON.parse(agentLiteral(source)).options;
}

// --- Tool registry introspection ------------------------------------------

/**
 * The canonical set of tool names this server registers, read from a live
 * `registerAllTools` + `listTools()` rather than a hand-maintained list. This is
 * the single source of truth the tool-list sync test and the help coverage test
 * check every other surface (README, help.ts, manifest.json) against.
 */
export async function getRegisteredToolNames(): Promise<string[]> {
  const deviceManager = makeDeviceManager(makeDevice());
  const harness = await makeMcpHarness((server) =>
    registerAllTools(server, deviceManager, { resources: false, prompts: false })
  );
  try {
    const { tools } = await harness.client.listTools();
    return tools.map((t) => t.name).sort();
  } finally {
    await harness.close();
  }
}
