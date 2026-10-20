/**
 * Device E2E: several scripts that each carry the Java bridge must be loadable and unloadable
 * in any order without killing the target (frida-java-bridge 7.0.13 otherwise aborts the app with
 * "JNI DETECTED ERROR ... DeleteGlobalRef" once the last bridge instance is disposed).
 *
 * Run: FRIDA_MCP_E2E_DEVICE=emulator-5556 npx vitest run test/e2e/multi-script.test.ts
 */
import { describe, it, expect } from 'vitest';
import frida from 'frida';
import { execSync } from 'node:child_process';
import { createAgentScript } from '../../src/agent/script-factory.js';

const DEVICE = process.env.FRIDA_MCP_E2E_DEVICE;
const TARGET = process.env.FRIDA_MCP_E2E_TARGET ?? 'com.example.rc4demo';

const JAVA_BODY = `rpc.exports = { j: function () { return javaPerform(function () { return Java.use('java.io.File').$className; }); } };`;

describe.skipIf(!DEVICE)('e2e: multiple Java-bridge scripts per session', () => {
  it('survives unloading every script and still accepts new ones', async () => {
    try { execSync(`adb -s ${DEVICE} shell am force-stop ${TARGET}`); } catch { /* adb optional */ }
    const device = (await frida.enumerateDevices()).find((d) => d.id === DEVICE);
    expect(device).toBeDefined();
    const pid = await device!.spawn(TARGET);
    const session = await device!.attach(pid);
    let detached: string | null = null;
    session.detached.connect((reason) => { detached = String(reason); });
    await device!.resume(pid);
    await new Promise((r) => setTimeout(r, 1500));

    const make = (name: string) => createAgentScript(session, { source: JAVA_BODY, platform: 'android', name, kind: 'generated' });
    try {
      const s1 = await make('e2e:java-1');
      const s2 = await make('e2e:java-2');
      await s1.load();
      await s2.load();
      expect(await s1.exports.j()).toBe('java.io.File');
      expect(await s2.exports.j()).toBe('java.io.File');
      await s1.unload();
      expect(await s2.exports.j()).toBe('java.io.File');
      await s2.unload();
      const s3 = await make('e2e:java-3');
      await s3.load();
      expect(await s3.exports.j()).toBe('java.io.File');
      await s3.unload();
      expect(detached).toBeNull();
    } finally {
      try { await session.detach(); } catch { /* ignore */ }
      try { await device!.kill(pid); } catch { /* ignore */ }
    }
  }, 60000);
});
