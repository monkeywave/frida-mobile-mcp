import { describe, it, expect, vi } from 'vitest';
import type frida from 'frida';
import {
  detectSourceKind,
  resolveTimeoutMs,
  runGuarded,
  ScriptTimeoutError,
  DEFAULT_ONESHOT_TIMEOUT_MS,
} from '../../src/tools/script.js';

const CLASSIC = "Java.perform(function () { send('hi'); });";
const ESM = "import Java from 'frida-java-bridge';\nJava.perform(() => send('hi'));";
const BUNDLE = '📦\n7 /agent.js\n✄\nsend(1)';

describe('detectSourceKind', () => {
  it('sniffs bundle, esm and classic sources in auto mode', () => {
    expect(detectSourceKind(BUNDLE)).toBe('bundle');
    expect(detectSourceKind(ESM)).toBe('esm');
    expect(detectSourceKind(CLASSIC)).toBe('classic');
    expect(detectSourceKind("export default 1;")).toBe('esm');
  });

  it('returns explicit kinds unchanged', () => {
    expect(detectSourceKind(CLASSIC, 'esm')).toBe('esm');
    expect(detectSourceKind(ESM, 'classic')).toBe('classic');
    expect(detectSourceKind(CLASSIC, 'bundle')).toBe('bundle');
  });
});

describe('resolveTimeoutMs', () => {
  it('defaults one-shot scripts to 30 s and persistent scripts to no timeout', () => {
    expect(resolveTimeoutMs(undefined, false)).toBe(DEFAULT_ONESHOT_TIMEOUT_MS);
    expect(resolveTimeoutMs(undefined, true)).toBe(0);
  });

  it('keeps an explicit value, including 0', () => {
    expect(resolveTimeoutMs(500, true)).toBe(500);
    expect(resolveTimeoutMs(0, false)).toBe(0);
  });
});

interface FakeScript {
  interrupt: ReturnType<typeof vi.fn>;
  unload: ReturnType<typeof vi.fn>;
  terminate: ReturnType<typeof vi.fn>;
}

function fakeScript(overrides: Partial<FakeScript> = {}): FakeScript & frida.Script {
  return {
    interrupt: vi.fn(async () => {}),
    unload: vi.fn(async () => {}),
    terminate: vi.fn(async () => {}),
    ...overrides,
  } as unknown as FakeScript & frida.Script;
}

describe('runGuarded', () => {
  it('passes through when the operation settles in time', async () => {
    const script = fakeScript();
    await expect(runGuarded(script, Promise.resolve(), 1000, 'id', [])).resolves.toBeUndefined();
    expect(script.interrupt).not.toHaveBeenCalled();
    expect(script.terminate).not.toHaveBeenCalled();
  });

  it('never times out when timeout is 0', async () => {
    const script = fakeScript();
    const slow = new Promise<void>((resolve) => setTimeout(resolve, 30));
    await expect(runGuarded(script, slow, 0, 'id', [])).resolves.toBeUndefined();
    expect(script.interrupt).not.toHaveBeenCalled();
  });

  it('propagates operation errors unchanged', async () => {
    const script = fakeScript();
    await expect(runGuarded(script, Promise.reject(new Error('boom')), 1000, 'id', [])).rejects.toThrow('boom');
    expect(script.interrupt).not.toHaveBeenCalled();
  });

  it('interrupts, then unloads when the interrupt lets the run settle', async () => {
    let finish!: () => void;
    const pending = new Promise<void>((resolve) => { finish = resolve; });
    const script = fakeScript({ interrupt: vi.fn(async () => finish()) });
    const partial = [{ type: 'send', payload: 1 }];

    const err = await runGuarded(script, pending, 20, 'script-1', partial).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(ScriptTimeoutError);
    const timeout = err as ScriptTimeoutError;
    expect(timeout.code).toBe('SCRIPT_TIMEOUT');
    expect(timeout.context).toMatchObject({ timeout_ms: 20, script_id: 'script-1', terminated: false, partial_messages: partial });
    expect(script.interrupt).toHaveBeenCalledOnce();
    expect(script.unload).toHaveBeenCalledOnce();
    expect(script.terminate).not.toHaveBeenCalled();
  });

  it('terminates after the grace period when the script stays stuck', async () => {
    vi.useFakeTimers();
    try {
      const never = new Promise<void>(() => {});
      const script = fakeScript();
      const run = runGuarded(script, never, 10, 'script-2', []);
      const outcome = run.catch((e: unknown) => e);

      await vi.advanceTimersByTimeAsync(10);
      expect(script.interrupt).toHaveBeenCalledOnce();
      expect(script.terminate).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(2000);
      const err = await outcome;
      expect(err).toBeInstanceOf(ScriptTimeoutError);
      expect((err as ScriptTimeoutError).context.terminated).toBe(true);
      expect((err as ScriptTimeoutError).message).toContain('terminated');
      expect(script.terminate).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });

  it('still terminates when interrupt() is unsupported by the remote frida-server', async () => {
    vi.useFakeTimers();
    try {
      const script = fakeScript({ interrupt: vi.fn(async () => { throw new Error('not supported'); }) });
      const outcome = runGuarded(script, new Promise<void>(() => {}), 5, 'id', []).catch((e: unknown) => e);
      await vi.advanceTimersByTimeAsync(5);
      await vi.advanceTimersByTimeAsync(2000);
      expect(await outcome).toBeInstanceOf(ScriptTimeoutError);
      expect(script.terminate).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });
});
