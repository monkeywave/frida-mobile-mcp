import { describe, it, expect, vi } from 'vitest';
import {
  buildGadgetConfig,
  renderGadgetConfig,
  gadgetGuidance,
  defaultConfigName,
  runGadget,
  type GadgetIo,
  type GadgetOptions,
} from '../../src/cli/gadget.js';

function listenOpts(overrides: Partial<GadgetOptions> = {}): GadgetOptions {
  return { interaction: 'listen', platform: 'android', ...overrides };
}

function scriptOpts(overrides: Partial<GadgetOptions> = {}): GadgetOptions {
  return { interaction: 'script', platform: 'android', scriptPath: '/data/local/tmp/agent.js', ...overrides };
}

function fakeIo(): GadgetIo & { lines: string[]; written: Record<string, string> } {
  const lines: string[] = [];
  const written: Record<string, string> = {};
  return {
    lines,
    written,
    writeFile: (p, text) => { written[p] = text; },
    mkdirp: vi.fn(),
    log: (line) => { lines.push(line); },
  };
}

describe('buildGadgetConfig', () => {
  it('builds a listen interaction with sane defaults', () => {
    expect(buildGadgetConfig(listenOpts())).toEqual({
      interaction: { type: 'listen', address: '127.0.0.1', port: 27042, on_port_conflict: 'fail', on_load: 'wait' },
    });
  });

  it('honours listen overrides', () => {
    const config = buildGadgetConfig(
      listenOpts({ address: '0.0.0.0', port: 1337, onPortConflict: 'pick-next', onLoad: 'resume' }),
    );
    expect(config.interaction).toEqual({
      type: 'listen', address: '0.0.0.0', port: 1337, on_port_conflict: 'pick-next', on_load: 'resume',
    });
  });

  it('builds a script interaction with the on-device path', () => {
    expect(buildGadgetConfig(scriptOpts())).toEqual({
      interaction: { type: 'script', path: '/data/local/tmp/agent.js', on_change: 'reload' },
    });
  });

  it('adds a runtime override only when given', () => {
    expect(buildGadgetConfig(listenOpts()).runtime).toBeUndefined();
    expect(buildGadgetConfig(listenOpts({ runtime: 'v8' })).runtime).toBe('v8');
  });

  it('rejects a script interaction with no path', () => {
    expect(() => buildGadgetConfig({ interaction: 'script', platform: 'android' })).toThrow(/requires a script path/);
    expect(() => buildGadgetConfig(scriptOpts({ scriptPath: '  ' }))).toThrow(/requires a script path/);
  });
});

describe('renderGadgetConfig', () => {
  it('renders pretty JSON ending in a newline', () => {
    const text = renderGadgetConfig(listenOpts());
    expect(text.endsWith('\n')).toBe(true);
    expect(JSON.parse(text)).toEqual(buildGadgetConfig(listenOpts()));
  });
});

describe('defaultConfigName', () => {
  it('ships as a .so inside lib/<abi> on Android and .config on iOS', () => {
    expect(defaultConfigName('android')).toBe('libgadget.config.so');
    expect(defaultConfigName('ios')).toBe('Frida.config');
  });
});

describe('gadgetGuidance', () => {
  it('gives apktool/apksigner steps for Android', () => {
    const text = gadgetGuidance(listenOpts(), 'libgadget.config.so');
    expect(text).toContain('apktool d target.apk');
    expect(text).toContain('apksigner sign');
    expect(text).toContain('lib/arm64-v8a/');
  });

  it('gives codesign/Frameworks steps for iOS', () => {
    const text = gadgetGuidance(listenOpts({ platform: 'ios' }), 'Frida.config');
    expect(text).toContain('Frameworks/');
    expect(text).toContain('codesign -f');
  });

  it('tells the listen user the FRIDA_MCP_REMOTE address and adb forward', () => {
    const text = gadgetGuidance(listenOpts({ port: 1337 }), 'libgadget.config.so');
    expect(text).toContain('FRIDA_MCP_REMOTE=127.0.0.1:1337');
    expect(text).toContain('adb forward tcp:1337 tcp:1337');
  });

  it('tells the script user there is no listening port', () => {
    const text = gadgetGuidance(scriptOpts(), 'libgadget.config.so');
    expect(text).toContain('NO');
    expect(text).toContain('/data/local/tmp/agent.js');
  });
});

describe('runGadget', () => {
  it('writes the config to the platform default and logs guidance', () => {
    const io = fakeIo();
    const code = runGadget(listenOpts(), io);
    expect(code).toBe(0);
    const [target, text] = Object.entries(io.written)[0];
    expect(target.endsWith('libgadget.config.so')).toBe(true);
    expect(JSON.parse(text)).toEqual(buildGadgetConfig(listenOpts()));
    expect(io.lines.join('\n')).toContain('apktool');
  });

  it('writes to an explicit --out path and keeps its basename in the guidance', () => {
    const io = fakeIo();
    const code = runGadget(listenOpts({ out: '/tmp/out/my.config.so' }), io);
    expect(code).toBe(0);
    expect(io.written['/tmp/out/my.config.so']).toBeDefined();
    expect(io.lines.join('\n')).toContain('my.config.so');
  });

  it('prints instead of writing when print is set', () => {
    const io = fakeIo();
    const code = runGadget(listenOpts({ print: true }), io);
    expect(code).toBe(0);
    expect(Object.keys(io.written)).toHaveLength(0);
    expect(io.lines.join('\n')).toContain('"type": "listen"');
  });

  it('returns 1 for a script interaction with no path', () => {
    const io = fakeIo();
    const code = runGadget({ interaction: 'script', platform: 'android' }, io);
    expect(code).toBe(1);
    expect(io.lines.join('\n')).toMatch(/requires a script path/);
  });

  it('returns 2 for an unknown interaction or platform', () => {
    expect(runGadget({ interaction: 'bogus' as never, platform: 'android' }, fakeIo())).toBe(2);
    expect(runGadget({ interaction: 'listen', platform: 'bogus' as never }, fakeIo())).toBe(2);
  });

  it('returns 2 for a typo in an enum option instead of writing an invalid config', () => {
    const io = fakeIo();
    const code = runGadget(listenOpts({ onLoad: 'resumee' as never }), io);
    expect(code).toBe(2);
    expect(Object.keys(io.written)).toHaveLength(0);
    expect(io.lines.join('\n')).toMatch(/Invalid --on-load "resumee"/);
  });

  it('rejects bad on-port-conflict / on-change / runtime values', () => {
    expect(runGadget(listenOpts({ onPortConflict: 'nope' as never }), fakeIo())).toBe(2);
    expect(runGadget(scriptOpts({ onChange: 'nope' as never }), fakeIo())).toBe(2);
    expect(runGadget(listenOpts({ runtime: 'jsc' as never }), fakeIo())).toBe(2);
  });
});
