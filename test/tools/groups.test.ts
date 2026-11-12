import { describe, it, expect } from 'vitest';
import { InMemoryTransport, McpServer } from '@modelcontextprotocol/server';
import { Client } from '@modelcontextprotocol/client';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { DeviceManager } from '../../src/device/manager.js';
import { registerTier1Tools, registerTier2Tools } from '../../src/tools/register-all.js';
import * as lib from '../../src/lib.js';

function recordNames(register: (server: McpServer) => void): string[] {
  const names: string[] = [];
  register({ registerTool: (name: string) => names.push(name) } as unknown as McpServer);
  return names;
}

describe('tool groups', () => {
  it('all groups register exactly the tier 1 + tier 2 tool set', () => {
    const dm = {} as DeviceManager;
    const tiers = recordNames((s) => { registerTier1Tools(s, dm); registerTier2Tools(s, dm); });
    expect([...lib.toolNamesInGroups()].sort()).toEqual([...tiers].sort());
  });

  it('groups are disjoint and classify representative tools', () => {
    const core = lib.toolNamesInGroups(['core']);
    const mobile = lib.toolNamesInGroups(['mobile']);
    const fritap = lib.toolNamesInGroups(['fritap']);
    expect(core).toContain('hook_method');
    expect(mobile).toEqual(expect.arrayContaining(['adb_shell', 'frida_server_status', 'get_app_info']));
    expect(fritap).toEqual(['capture_tls']);
    const all = [...core, ...mobile, ...fritap];
    expect(new Set(all).size).toBe(all.length);
  });

  it('dedupes and always registers in ALL_TOOL_GROUPS order', () => {
    expect(lib.toolNamesInGroups(['fritap', 'core', 'fritap'])).toEqual([
      ...lib.toolNamesInGroups(['core']),
      ...lib.toolNamesInGroups(['fritap']),
    ]);
    expect(lib.toolNamesInGroups([])).toEqual([]);
  });

  it('throws on an unknown group', () => {
    expect(() => lib.toolNamesInGroups(['bogus' as lib.ToolGroup])).toThrow(/Unknown tool group.*bogus/);
  });

  it('registerFridaTools honours options.groups', async () => {
    const config = { ...lib.DEFAULT_CONFIG, auditLogPath: join(tmpdir(), 'frida-mcp-groups-test-audit.jsonl'), toolProfile: 'full' as const, toolsExclude: [] };
    const server = new McpServer({ name: 'host', version: '0.0.0' });
    lib.registerFridaTools(server, { config, groups: ['fritap'] });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: 'groups-test', version: '0.0.0' });
    await client.connect(clientTransport);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual(['capture_tls']);
    await client.close();
    await server.close();
  });

  it('core excludes mobile and fritap tools but keeps generic Frida tools', () => {
    const core = lib.toolNamesInGroups(['core']);
    for (const name of [
      'get_app_info', 'run_prebuilt_script', 'drive_coverage', 'bypass_ssl_pinning',
      'mobile_action', 'detect_app_technologies', 'search_recipes', 'capture_tls',
    ]) {
      expect(core).not.toContain(name);
    }
    expect(core.filter((name) => name.startsWith('frida_server_') || name.startsWith('adb_'))).toEqual([]);
    expect(core).toEqual(expect.arrayContaining(['attach_process', 'hook_method', 'read_memory', 'enumerate_modules']));
  });

  it('no argument yields the duplicate-free union of every group', () => {
    const all = lib.toolNamesInGroups();
    const union = lib.ALL_TOOL_GROUPS.flatMap((group) => lib.toolNamesInGroups([group]));
    expect(all).toEqual(union);
    expect(new Set(all).size).toBe(all.length);
  });

  async function listRegisteredToolNames(options: lib.RegisterFridaToolsOptions): Promise<string[]> {
    const server = new McpServer({ name: 'host', version: '0.0.0' });
    lib.registerFridaTools(server, options);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: 'groups-test', version: '0.0.0' });
    await client.connect(clientTransport);
    const { tools } = await client.listTools();
    await client.close();
    await server.close();
    return tools.map((t) => t.name);
  }

  it('registerFridaTools with groups [core] lists exactly the core tools under the full profile', async () => {
    const config = { ...lib.DEFAULT_CONFIG, auditLogPath: join(tmpdir(), 'frida-mcp-groups-test-audit.jsonl'), toolProfile: 'full' as const, toolsExclude: [] };
    const names = await listRegisteredToolNames({ config, groups: ['core'] });
    expect([...names].sort()).toEqual([...lib.toolNamesInGroups(['core'])].sort());
  });

  it('groups combine with toolsExclude', async () => {
    const config = { ...lib.DEFAULT_CONFIG, auditLogPath: join(tmpdir(), 'frida-mcp-groups-test-audit.jsonl'), toolProfile: 'full' as const, toolsExclude: ['adb_*'] };
    const names = await listRegisteredToolNames({ config, groups: ['core', 'mobile'] });
    expect(names.filter((name) => name.startsWith('adb_'))).toEqual([]);
    expect(names).toContain('frida_server_status');
    expect(names).toContain('hook_method');
    expect(names).not.toContain('capture_tls');
  });
});
