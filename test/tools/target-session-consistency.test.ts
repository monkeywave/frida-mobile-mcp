import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { McpServer } from '@modelcontextprotocol/server';
import { registerSearchTool } from '../../src/tools/search.js';
import { registerDetectTool } from '../../src/tools/detect.js';
import { registerSslTool } from '../../src/tools/ssl.js';
import {
  makeMcpHarness,
  makeDevice,
  makeDeviceManager,
  type McpHarness,
} from '../helpers/mock-fixtures.js';

/**
 * Process-scoped tools must let a caller reuse an existing session via `session_id`
 * (from explore_app / get_status) rather than being forced to pass `target`, which
 * would re-attach / respawn the app. This asserts the input schema contract only
 * (no device): every tool below accepts `session_id` and does not require `target`.
 *
 * Note: the native tools (resolve_address / analyze_native_function) are deliberately
 * NOT here — their `target` is a native address to resolve (the actual work input),
 * not a process selector, so it stays required.
 */
describe('target / session_id input-schema consistency', () => {
  const MODIFIED_TOOLS = [
    'search_classes_and_methods',
    'detect_app_technologies',
    'bypass_ssl_pinning',
  ] as const;

  let client: McpHarness['client'];
  let close: McpHarness['close'];

  beforeAll(async () => {
    const deviceManager = makeDeviceManager(makeDevice());
    ({ client, close } = await makeMcpHarness((server: McpServer) => {
      registerSearchTool(server, deviceManager);
      registerDetectTool(server, deviceManager);
      registerSslTool(server, deviceManager);
    }));
  });

  afterAll(async () => {
    await close();
  });

  it.each(MODIFIED_TOOLS)('tool "%s" accepts session_id and does not require target', async (toolName) => {
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === toolName);
    expect(tool, `tool ${toolName} should be registered`).toBeDefined();

    const schema = tool!.inputSchema as {
      properties?: Record<string, unknown>;
      required?: string[];
    };

    // session_id is an accepted input.
    expect(schema.properties?.session_id, `${toolName} should accept a session_id input`).toBeDefined();
    // target is still an accepted input, but no longer mandatory.
    expect(schema.properties?.target, `${toolName} should still accept a target input`).toBeDefined();
    expect(schema.required ?? [], `${toolName} must not require target`).not.toContain('target');
  });
});
