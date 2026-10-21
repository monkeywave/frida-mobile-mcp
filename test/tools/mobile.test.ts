import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import { registerMobileTool } from '../../src/tools/mobile.js';
import { initState, getState } from '../../src/state.js';
import {
  callJson,
  makeMcpHarness,
  TEST_CONFIG,
  type Json,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

// The tool reaches mobile-mcp through a dynamic `import('../mobile-mcp/proxy.js')`;
// stub the proxy so routing/error handling can be exercised without a real backend.
const { listTools, callTool, getMobileMcpProxy } = vi.hoisted(() => {
  const listTools = vi.fn();
  const callTool = vi.fn();
  return { listTools, callTool, getMobileMcpProxy: vi.fn(async () => ({ listTools, callTool })) };
});

vi.mock('../../src/mobile-mcp/proxy.js', () => ({ getMobileMcpProxy }));

function enableMobileMcp(enabled: boolean): void {
  initState({ ...TEST_CONFIG, mobileMcp: { enabled, command: '', args: [] } });
}

describe('mobile_action MCP tool', () => {
  let client: McpHarness['client'];
  let close: McpHarness['close'];

  beforeAll(async () => {
    enableMobileMcp(true);
    ({ client, close } = await makeMcpHarness((server) => registerMobileTool(server)));
  });

  afterAll(async () => {
    await close();
    getState().stopCleanupTimer();
  });

  beforeEach(() => {
    enableMobileMcp(true);
    listTools.mockReset();
    callTool.mockReset();
    getMobileMcpProxy.mockClear();
  });

  it('is registered as a non-read-only, open-world gateway tool', async () => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === 'mobile_action');
    expect(tool).toBeDefined();
    expect(tool!.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true });
    expect(tool!.outputSchema).toBeDefined();
  });

  it('refuses with MOBILE_MCP_UNAVAILABLE when integration is disabled in config', async () => {
    enableMobileMcp(false);
    const parsed = await callJson(client, 'mobile_action', { action: 'mobile_take_screenshot' });
    expect(parsed.error.code).toBe('MOBILE_MCP_UNAVAILABLE');
    expect(parsed.error.category).toBe('capability');
    expect(callTool).not.toHaveBeenCalled();
  });

  it('lists the backend actions when called without an action', async () => {
    listTools.mockResolvedValue([{ name: 'mobile_take_screenshot' }, { name: 'mobile_list_apps' }]);

    const parsed = await callJson(client, 'mobile_action', {});

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.available_actions).toEqual(['mobile_take_screenshot', 'mobile_list_apps']);
    expect(callTool).not.toHaveBeenCalled();
    expect(parsed.suggested_next.map((s: Json) => s.args.action)).toContain('mobile_take_screenshot');
  });

  it('falls back to the built-in action list when the backend cannot be listed', async () => {
    listTools.mockRejectedValue(new Error('spawn failed'));

    const parsed = await callJson(client, 'mobile_action', {});

    expect(parsed.error).toBeUndefined();
    expect(parsed.result.available_actions).toContain('mobile_take_screenshot');
    expect(parsed.result.available_actions.length).toBeGreaterThan(5);
  });

  it('routes an action to the proxy and returns its result', async () => {
    callTool.mockResolvedValue({ content: [{ type: 'text', text: 'ok' }] });

    const parsed = await callJson(client, 'mobile_action', {
      action: 'mobile_click_on_screen_at_coordinates',
      params: { x: 100, y: 200 },
    });

    expect(parsed.error).toBeUndefined();
    expect(callTool).toHaveBeenCalledWith('mobile_click_on_screen_at_coordinates', { x: 100, y: 200 });
    expect(parsed.result.action).toBe('mobile_click_on_screen_at_coordinates');
    expect(parsed.result.result).toEqual({ content: [{ type: 'text', text: 'ok' }] });
  });

  it('passes an empty params object to the proxy when params are omitted', async () => {
    callTool.mockResolvedValue({ ok: true });

    await callJson(client, 'mobile_action', { action: 'mobile_list_apps' });

    expect(callTool).toHaveBeenCalledWith('mobile_list_apps', {});
  });

  it('maps a missing mobile-mcp install to MOBILE_MCP_UNAVAILABLE', async () => {
    callTool.mockRejectedValue(new Error('Cannot find module @mobilenext/mobile-mcp (ENOENT)'));

    const parsed = await callJson(client, 'mobile_action', { action: 'mobile_take_screenshot' });

    expect(parsed.error.code).toBe('MOBILE_MCP_UNAVAILABLE');
    expect(parsed.error.message).toMatch(/not installed/);
  });

  it('wraps any other backend failure as MOBILE_ERROR', async () => {
    callTool.mockRejectedValue(new Error('device is offline'));

    const parsed = await callJson(client, 'mobile_action', { action: 'mobile_take_screenshot' });

    expect(parsed.error.code).toBe('MOBILE_ERROR');
    expect(parsed.error.message).toBe('device is offline');
    expect(parsed.error.recovery_actions.map((a: Json) => a.tool)).toContain('mobile_action');
  });
});
