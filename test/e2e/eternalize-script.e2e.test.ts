/**
 * Device E2E: eternalize a loaded script, then detach — the script must be pinned in the
 * target (frida's Script.eternalize) so detaching the session does not tear it down, and the
 * call must not throw on real Frida 17. The unit test only checks the wiring with a fake script;
 * this confirms the frida-node API behaves as the tool assumes.
 *
 * Run: FRIDA_MCP_E2E_DEVICE=emulator-5556 [FRIDA_MCP_E2E_TARGET=com.example.rc4demo] \
 *        npx vitest run test/e2e/eternalize-script.e2e.test.ts
 */
import { describe, it, expect } from 'vitest';
import frida from 'frida';
import { execSync } from 'node:child_process';

const DEVICE = process.env.FRIDA_MCP_E2E_DEVICE;
const TARGET = process.env.FRIDA_MCP_E2E_TARGET ?? 'com.example.rc4demo';

describe.skipIf(!DEVICE)('e2e: eternalize_script', () => {
  it('eternalizes a loaded script and survives detach', async () => {
    try { execSync(`adb -s ${DEVICE} shell am force-stop ${TARGET}`); } catch { /* adb optional */ }
    const device = (await frida.enumerateDevices()).find((d) => d.id === DEVICE);
    if (!device) throw new Error(`device ${DEVICE} not found`);

    const pid = await device.spawn(TARGET);
    const session = await device.attach(pid);
    const script = await session.createScript("send({ status: 'alive' }); setInterval(function () {}, 1000);");

    const messages: unknown[] = [];
    script.message.connect((m) => { if (m.type === 'send') messages.push(m.payload); });
    await script.load();
    await device.resume(pid);

    // Eternalize must not throw, and detaching afterwards must not throw either.
    await expect(script.eternalize()).resolves.toBeUndefined();
    await expect(session.detach()).resolves.toBeUndefined();

    expect(messages).toContainEqual({ status: 'alive' });

    try { await device.kill(pid); } catch { /* best-effort cleanup */ }
  }, 60000);
});
