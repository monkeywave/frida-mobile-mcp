import { describe, it, expect, vi, beforeAll } from 'vitest';

// We'll test the help content directly since the tool registration requires McpServer
// Import the module to check the HELP_TOPICS map
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

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

  it('examples topic has complete workflows', () => {
    expect(helpFileContent).toContain('Explore an Unknown App');
    expect(helpFileContent).toContain('SSL Traffic Analysis');
    expect(helpFileContent).toContain('Security Audit');
  });
});
