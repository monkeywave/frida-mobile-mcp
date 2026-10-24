import { describe, it, expect, vi, beforeAll } from 'vitest';

// We'll test the help content directly since the tool registration requires McpServer
// Import the module to check the HELP_TOPICS map
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { getRegisteredToolNames } from '../helpers/mock-fixtures.js';

describe('frida_help tool', () => {
  let helpFileContent: string;

  beforeAll(() => {
    helpFileContent = readFileSync(
      join(process.cwd(), 'src/tools/help.ts'),
      'utf-8'
    );
  });

  const topics = ['overview', 'hooking', 'tracing', 'memory', 'scripts', 'mobile', 'examples', 'advanced'];

  it('has all 8 help topics defined', () => {
    for (const topic of topics) {
      expect(helpFileContent).toContain(`  ${topic}:`);
    }
  });

  it('overview topic mentions key tools', () => {
    expect(helpFileContent).toContain('get_status');
    expect(helpFileContent).toContain('explore_app');
    expect(helpFileContent).toContain('hook_method');
  });

  it('hooking topic explains method patterns', () => {
    expect(helpFileContent).toContain('Java (Android)');
    expect(helpFileContent).toContain('Objective-C (iOS)');
    expect(helpFileContent).toContain('Native');
  });

  it('scripts topic lists all 8 scripts', () => {
    const scriptNames = [
      'ssl_pinning_bypass', 'root_jailbreak_bypass', 'class_enumeration',
      'method_hook', 'crypto_monitor', 'network_inspector',
      'keychain_prefs', 'filesystem_monitor',
    ];
    for (const name of scriptNames) {
      expect(helpFileContent).toContain(name);
    }
  });

  it('mobile topic explains gateway pattern', () => {
    expect(helpFileContent).toContain('mobile_action');
    expect(helpFileContent).toContain('mobile_take_screenshot');
  });

  it('advanced topic lists all tier 2 tools', () => {
    const tier2Tools = [
      'list_devices', 'select_device', 'list_processes',
      'spawn_process', 'attach_process', 'enumerate_modules',
      'hook_function', 'unhook_function',
    ];
    for (const tool of tier2Tools) {
      expect(helpFileContent).toContain(tool);
    }
  });

  it('defines the evasion topic covering all four anti-RASP layers', () => {
    expect(helpFileContent).toContain('  evasion:');
    expect(helpFileContent).toContain('anti_frida_evasion');
    expect(helpFileContent).toContain('frida_server_start');
    expect(helpFileContent).toContain('gadget');
    expect(helpFileContent).toContain('DenyList');
    // The honest pre-main limitation must be stated.
    expect(helpFileContent).toContain('.init_array');
  });

  it('defines the interop topic and lists it in TOPIC_LIST', () => {
    expect(helpFileContent).toContain('  interop:');
    expect(helpFileContent).toMatch(/const TOPIC_LIST = '[^']*\binterop\b[^']*'/);
    // Routing, context budget, evidence mapping and the walkthrough must be present.
    expect(helpFileContent).toContain('inspect_android_package');
    expect(helpFileContent).toContain('inspect_android_method');
    expect(helpFileContent).toContain('FRIDA_MCP_TOOL_PROFILE=core');
    expect(helpFileContent).toContain('FRIDA_MCP_TOOLS_EXCLUDE=adb_*,frida_server_*');
    expect(helpFileContent).toContain('normalized_result');
    expect(helpFileContent).toContain('_meta.provenance');
    expect(helpFileContent).toContain('get_app_info({ target, pull_to');
    expect(helpFileContent).toContain('export_evidence_bundle({ session_id, format: "markdown"');
  });

  it('defines the native and tls topics', () => {
    expect(helpFileContent).toContain('  native:');
    expect(helpFileContent).toContain('  tls:');
    expect(helpFileContent).toContain('module+0x');
    expect(helpFileContent).toContain('capture_tls');
  });

  it('covers every registered tool in some topic', async () => {
    // Derived from the live tool registry (register-all.ts) rather than a hardcoded list, so
    // adding or renaming a tool fails here unless help.ts is updated too. The tool-list sync
    // test (tool-sync.test.ts) enforces the same against manifest.json and README.
    const registered = await getRegisteredToolNames();
    expect(registered.length).toBeGreaterThan(30);
    for (const tool of registered) {
      expect(helpFileContent, `help.ts should mention ${tool}`).toContain(tool);
    }
  });

  it('scripts topic explains the three source kinds and validate_script', () => {
    expect(helpFileContent).toContain('classic');
    expect(helpFileContent).toContain('esm');
    expect(helpFileContent).toContain('bundle');
    expect(helpFileContent).toContain('validate_script');
  });

  it('examples topic has complete workflows', () => {
    expect(helpFileContent).toContain('Explore an Unknown App');
    expect(helpFileContent).toContain('SSL Traffic Analysis');
    expect(helpFileContent).toContain('Security Audit');
  });
});
