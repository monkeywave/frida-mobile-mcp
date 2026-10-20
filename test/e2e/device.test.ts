/**
 * End-to-end check against a real device/emulator running frida-server.
 *
 * Opt in with:
 *   FRIDA_MCP_E2E_DEVICE=emulator-5556 [FRIDA_MCP_E2E_TARGET=com.example.rc4demo] npx vitest run test/e2e
 *
 * Without FRIDA_MCP_E2E_DEVICE the whole suite is skipped, so `npm test` never needs a device.
 */
import { describe, it, expect } from 'vitest';
import frida from 'frida';
import { createAgentScript } from '../../src/agent/script-factory.js';

const DEVICE_ID = process.env.FRIDA_MCP_E2E_DEVICE;
const TARGET = process.env.FRIDA_MCP_E2E_TARGET ?? 'com.example.rc4demo';
const TEST_TIMEOUT_MS = 30_000;

interface ProbeResult {
  java: boolean;
  objc: boolean;
  libcOpen: boolean;
}

interface SpawnedSession {
  device: frida.Device;
  pid: number;
  session: frida.Session;
}

async function spawnAndAttach(): Promise<SpawnedSession> {
  const device = await frida.getDevice(DEVICE_ID!, { timeout: 5000 });
  const pid = await device.spawn(TARGET);
  try {
    const session = await device.attach(pid);
    return { device, pid, session };
  } catch (error) {
    await device.kill(pid).catch(() => undefined);
    throw error;
  }
}

/** Best-effort teardown: every step runs even if an earlier one fails. */
async function teardown(spawned: SpawnedSession | undefined, script: frida.Script | undefined): Promise<void> {
  if (!spawned) return;
  const steps: Array<() => Promise<unknown>> = [
    () => spawned.device.resume(spawned.pid),
    () => (script && !script.isDestroyed ? script.unload() : Promise.resolve()),
    () => spawned.session.detach(),
    () => spawned.device.kill(spawned.pid),
  ];
  for (const step of steps) {
    await step().catch(() => undefined);
  }
}

function firstSendMessage(script: frida.Script, timeoutMs: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`no send() message within ${timeoutMs} ms`)), timeoutMs);
    script.message.connect((message) => {
      if (message.type === 'send') {
        clearTimeout(timer);
        resolve(message.payload);
      } else if (message.type === 'error') {
        clearTimeout(timer);
        reject(new Error(`script error: ${message.description}\n${message.stack ?? ''}`));
      }
    });
  });
}

describe.skipIf(!DEVICE_ID)('e2e: Frida 17 agent on a real device', () => {
  it(
    'generated script sees the Java bridge, an ObjC stub and native exports',
    async () => {
      let spawned: SpawnedSession | undefined;
      let script: frida.Script | undefined;
      try {
        spawned = await spawnAndAttach();
        script = await createAgentScript(spawned.session, {
          kind: 'generated',
          platform: 'android',
          name: 'e2e:probe',
          source:
            'rpc.exports.probe = function(){ return { java: Java.available, objc: typeof ObjC !== "undefined" && ObjC.available, libcOpen: findExport("libc.so","open") !== null }; };',
        });
        await script.load();

        const result = (await script.exports.probe()) as ProbeResult;
        expect(result.java).toBe(true);
        expect(result.objc).toBe(false);
        expect(result.libcOpen).toBe(true);
      } finally {
        await teardown(spawned, script);
      }
    },
    TEST_TIMEOUT_MS
  );

  it(
    'legacy user script using Java.perform runs via Script.evaluate and can send()',
    async () => {
      let spawned: SpawnedSession | undefined;
      let script: frida.Script | undefined;
      try {
        spawned = await spawnAndAttach();
        script = await createAgentScript(spawned.session, {
          kind: 'user',
          platform: 'android',
          name: 'e2e:legacy',
          source: `Java.perform(function(){ send({cls: Java.use('java.lang.String').class.getName()}); })`,
        });
        const message = firstSendMessage(script, TEST_TIMEOUT_MS - 5000);
        await script.load();
        // Java.perform() in a freshly spawned app defers until the app class loader exists,
        // which only happens once the process runs.
        await spawned.device.resume(spawned.pid);

        expect(await message).toEqual({ cls: 'java.lang.String' });
      } finally {
        await teardown(spawned, script);
      }
    },
    TEST_TIMEOUT_MS
  );
});
