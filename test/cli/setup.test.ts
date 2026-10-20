import { describe, it, expect } from 'vitest';
import {
  CLIENT_NAMES,
  buildServerEntry,
  claudeCodeCommand,
  configPathFor,
  mergeJsonConfig,
  renderCodexToml,
  runSetup,
  serversKeyFor,
  type ClientName,
  type ServerEntry,
  type SetupIo,
} from '../../src/cli/setup.js';

const ENV = { platform: 'darwin' as NodeJS.Platform, home: '/home/u', cwd: '/proj' };

interface FakeIo extends SetupIo {
  files: Map<string, string>;
  dirs: string[];
  logs: string[];
  runs: Array<{ cmd: string; args: string[] }>;
}

function fakeIo(overrides: Partial<SetupIo> = {}, files: Record<string, string> = {}): FakeIo {
  const io: FakeIo = {
    files: new Map(Object.entries(files)),
    dirs: [],
    logs: [],
    runs: [],
    readFile: (p) => io.files.get(p) ?? null,
    writeFile: (p, text) => void io.files.set(p, text),
    copyFile: (src, dst) => void io.files.set(dst, io.files.get(src) ?? ''),
    mkdirp: (p) => void io.dirs.push(p),
    exists: (p) => io.files.has(p),
    which: () => null,
    run: (cmd, args) => {
      io.runs.push({ cmd, args });
      return { code: 0, output: 'added' };
    },
    log: (line) => void io.logs.push(line),
    env: { ...ENV },
    ...overrides,
  };
  return io;
}

describe('buildServerEntry', () => {
  it('builds the minimal npx entry without env', () => {
    const entry = buildServerEntry({});
    expect(entry).toEqual({ command: 'npx', args: ['-y', 'frida-mobile-mcp'] });
    expect('env' in entry).toBe(false);
  });

  it('adds permission flags and device env', () => {
    const entry = buildServerEntry({ device: 'emulator-5554', allowCustomScripts: true, allowMemoryWrite: true });
    expect(entry.args).toEqual(['-y', 'frida-mobile-mcp', '--allow-custom-scripts', '--allow-memory-write']);
    expect(entry.env).toEqual({ FRIDA_DEVICE_ID: 'emulator-5554' });
  });

  it('omits env when device is an empty string', () => {
    expect(buildServerEntry({ device: '' }).env).toBeUndefined();
  });
});

describe('configPathFor', () => {
  const platforms: NodeJS.Platform[] = ['darwin', 'win32', 'linux'];

  it('returns null for claude-code on every platform', () => {
    for (const platform of platforms) {
      expect(configPathFor('claude-code', { ...ENV, platform })).toBeNull();
    }
  });

  it('resolves claude-desktop per platform', () => {
    expect(configPathFor('claude-desktop', { ...ENV, platform: 'darwin' })).toBe(
      '/home/u/Library/Application Support/Claude/claude_desktop_config.json',
    );
    expect(configPathFor('claude-desktop', { ...ENV, platform: 'linux' })).toBe(
      '/home/u/.config/Claude/claude_desktop_config.json',
    );
    expect(configPathFor('claude-desktop', { ...ENV, platform: 'win32', home: 'C:\\Users\\u' })).toBe(
      'C:\\Users\\u\\AppData\\Roaming\\Claude\\claude_desktop_config.json',
    );
    expect(
      configPathFor('claude-desktop', { ...ENV, platform: 'win32', home: 'C:\\Users\\u', appData: 'D:\\AppData' }),
    ).toBe('D:\\AppData\\Claude\\claude_desktop_config.json');
  });

  it('resolves home-relative clients identically on every platform', () => {
    for (const platform of platforms) {
      const env = { ...ENV, platform };
      expect(configPathFor('cursor', env)).toBe('/home/u/.cursor/mcp.json');
      expect(configPathFor('windsurf', env)).toBe('/home/u/.codeium/windsurf/mcp_config.json');
      expect(configPathFor('codex', env)).toBe('/home/u/.codex/config.toml');
      expect(configPathFor('vscode', env)).toBe('/proj/.vscode/mcp.json');
    }
  });

  it('uses the servers key only for vscode', () => {
    for (const client of CLIENT_NAMES) {
      expect(serversKeyFor(client)).toBe(client === 'vscode' ? 'servers' : 'mcpServers');
    }
  });
});

describe('mergeJsonConfig', () => {
  const entry: ServerEntry = { command: 'npx', args: ['-y', 'frida-mobile-mcp'] };

  it('creates the structure from null or empty input', () => {
    const expected = { mcpServers: { frida: entry } };
    expect(JSON.parse(mergeJsonConfig(null, 'mcpServers', entry))).toEqual(expected);
    expect(JSON.parse(mergeJsonConfig('', 'mcpServers', entry))).toEqual(expected);
    expect(JSON.parse(mergeJsonConfig('  \n', 'mcpServers', entry))).toEqual(expected);
  });

  it('keeps other top-level keys and other servers while replacing frida', () => {
    const existing = JSON.stringify({
      theme: 'dark',
      mcpServers: { other: { command: 'x', args: [] }, frida: { command: 'old', args: ['stale'] } },
    });
    const merged = JSON.parse(mergeJsonConfig(existing, 'mcpServers', entry));
    expect(merged.theme).toBe('dark');
    expect(merged.mcpServers.other).toEqual({ command: 'x', args: [] });
    expect(merged.mcpServers.frida).toEqual(entry);
  });

  it('supports a custom server name and the vscode servers key', () => {
    const merged = JSON.parse(mergeJsonConfig('{"servers":{}}', 'servers', entry, 'frida-dev'));
    expect(merged.servers['frida-dev']).toEqual(entry);
  });

  it('rejects invalid JSON and non-object roots', () => {
    expect(() => mergeJsonConfig('{not json', 'mcpServers', entry)).toThrow(/not valid JSON/);
    expect(() => mergeJsonConfig('[1,2]', 'mcpServers', entry)).toThrow(/not a JSON object/);
  });

  it('pretty-prints with two spaces and a trailing newline', () => {
    const text = mergeJsonConfig(null, 'mcpServers', entry);
    expect(text).toBe(JSON.stringify({ mcpServers: { frida: entry } }, null, 2) + '\n');
  });
});

describe('renderCodexToml', () => {
  it('renders the table without env', () => {
    const toml = renderCodexToml({ command: 'npx', args: ['-y', 'frida-mobile-mcp'] });
    expect(toml).toBe('[mcp_servers.frida]\ncommand = "npx"\nargs = ["-y", "frida-mobile-mcp"]\n');
  });

  it('renders an env sub-table when env is present', () => {
    const toml = renderCodexToml(
      { command: 'npx', args: ['-y', 'frida-mobile-mcp', '--allow-memory-write'], env: { FRIDA_DEVICE_ID: 'abc' } },
      'frida',
    );
    expect(toml).toBe(
      [
        '[mcp_servers.frida]',
        'command = "npx"',
        'args = ["-y", "frida-mobile-mcp", "--allow-memory-write"]',
        '[mcp_servers.frida.env]',
        'FRIDA_DEVICE_ID = "abc"',
        '',
      ].join('\n'),
    );
  });
});

describe('claudeCodeCommand', () => {
  it('builds the claude mcp add command without env', () => {
    expect(claudeCodeCommand({ command: 'npx', args: ['-y', 'frida-mobile-mcp'] })).toEqual([
      'claude', 'mcp', 'add', '--scope', 'user', 'frida', '--', 'npx', '-y', 'frida-mobile-mcp',
    ]);
  });

  it('passes env via -e before the server name and keeps flags after the package', () => {
    const entry = buildServerEntry({ device: 'dev1', allowCustomScripts: true });
    expect(claudeCodeCommand(entry)).toEqual([
      'claude', 'mcp', 'add', '--scope', 'user', '-e', 'FRIDA_DEVICE_ID=dev1',
      'frida', '--', 'npx', '-y', 'frida-mobile-mcp', '--allow-custom-scripts',
    ]);
  });
});

describe('runSetup', () => {
  const cursorPath = '/home/u/.cursor/mcp.json';

  it('writes a new config and creates parent directories when none exists', () => {
    const io = fakeIo();
    expect(runSetup({ client: 'cursor' }, io)).toBe(0);
    expect(io.dirs).toEqual(['/home/u/.cursor']);
    expect(io.files.has(`${cursorPath}.bak`)).toBe(false);
    expect(JSON.parse(io.files.get(cursorPath)!)).toEqual({
      mcpServers: { frida: { command: 'npx', args: ['-y', 'frida-mobile-mcp'] } },
    });
    expect(io.logs).toContain(`Wrote ${cursorPath}`);
  });

  it('backs up an existing file before merging into it', () => {
    const original = JSON.stringify({ mcpServers: { other: { command: 'x', args: [] } } });
    const io = fakeIo({}, { [cursorPath]: original });
    expect(runSetup({ client: 'cursor', device: 'd1' }, io)).toBe(0);
    expect(io.files.get(`${cursorPath}.bak`)).toBe(original);
    const written = JSON.parse(io.files.get(cursorPath)!);
    expect(written.mcpServers.other).toEqual({ command: 'x', args: [] });
    expect(written.mcpServers.frida.env).toEqual({ FRIDA_DEVICE_ID: 'd1' });
    expect(io.logs).toContain(`Wrote ${cursorPath} (backup: ${cursorPath}.bak)`);
  });

  it('uses the servers key and the cwd for vscode', () => {
    const io = fakeIo();
    runSetup({ client: 'vscode' }, io);
    expect(JSON.parse(io.files.get('/proj/.vscode/mcp.json')!).servers.frida).toBeDefined();
  });

  it('does not write anything with --print but shows the merged result', () => {
    const io = fakeIo({}, { [cursorPath]: '{"mcpServers":{"keep":{"command":"k","args":[]}}}' });
    expect(runSetup({ client: 'cursor', print: true }, io)).toBe(0);
    expect(io.files.size).toBe(1);
    expect(io.dirs).toEqual([]);
    expect(io.logs[0]).toBe(`Target: ${cursorPath}`);
    expect(io.logs.join('\n')).toContain('"keep"');
    expect(io.logs.join('\n')).toContain('"frida"');
  });

  it('refuses to write over invalid JSON', () => {
    const io = fakeIo({}, { [cursorPath]: '{oops' });
    expect(runSetup({ client: 'cursor' }, io)).toBe(1);
    expect(io.files.get(cursorPath)).toBe('{oops');
    expect(io.files.has(`${cursorPath}.bak`)).toBe(false);
    expect(io.logs.join('\n')).toMatch(/not valid JSON/);
  });

  it('only prints the TOML snippet for codex', () => {
    const io = fakeIo();
    expect(runSetup({ client: 'codex', allowMemoryWrite: true }, io)).toBe(0);
    expect(io.files.size).toBe(0);
    expect(io.logs[0]).toContain('/home/u/.codex/config.toml');
    expect(io.logs.join('\n')).toContain('[mcp_servers.frida]');
    expect(io.logs.join('\n')).toContain('--allow-memory-write');
  });

  it('prints the claude command when claude is not on PATH', () => {
    const io = fakeIo({ which: () => null });
    expect(runSetup({ client: 'claude-code' }, io)).toBe(0);
    expect(io.runs).toEqual([]);
    expect(io.logs.at(-1)).toBe('claude mcp add --scope user frida -- npx -y frida-mobile-mcp');
  });

  it('prints the claude command with --print even when claude is available', () => {
    const io = fakeIo({ which: () => '/usr/local/bin/claude' });
    expect(runSetup({ client: 'claude-code', print: true, device: 'my device' }, io)).toBe(0);
    expect(io.runs).toEqual([]);
    expect(io.logs).toEqual(['claude mcp add --scope user -e "FRIDA_DEVICE_ID=my device" frida -- npx -y frida-mobile-mcp']);
  });

  it('runs claude when found and relays its output and exit code', () => {
    const io = fakeIo({
      which: () => '/usr/local/bin/claude',
      run: (cmd, args) => {
        io.runs.push({ cmd, args });
        return { code: 3, output: 'failed to add\n' };
      },
    });
    expect(runSetup({ client: 'claude-code' }, io)).toBe(3);
    expect(io.runs).toEqual([
      { cmd: '/usr/local/bin/claude', args: ['mcp', 'add', '--scope', 'user', 'frida', '--', 'npx', '-y', 'frida-mobile-mcp'] },
    ]);
    expect(io.logs).toEqual(['failed to add']);
  });

  it('rejects unknown clients with exit code 2', () => {
    const io = fakeIo();
    expect(runSetup({ client: 'emacs' as ClientName }, io)).toBe(2);
    expect(io.logs[0]).toContain(CLIENT_NAMES.join(', '));
  });
});
