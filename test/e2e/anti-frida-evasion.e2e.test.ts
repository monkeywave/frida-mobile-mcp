/**
 * Device E2E: the anti_frida_evasion template must load on real Frida 17, install its native
 * hooks, and NOT crash the target — in both report and spoof mode. This is the on-device
 * validation the unit sandbox cannot give (the sandbox never enters the hook closures).
 *
 * Run: FRIDA_MCP_E2E_DEVICE=emulator-5556 [FRIDA_MCP_E2E_TARGET=com.example.rc4demo] \
 *        npx vitest run test/e2e/anti-frida-evasion.e2e.test.ts
 */
import { describe, it, expect } from 'vitest';
import frida from 'frida';
import { execSync } from 'node:child_process';
import { createAgentScript } from '../../src/agent/script-factory.js';
import { getScriptRegistry } from '../../src/scripts/registry.js';

const DEVICE = process.env.FRIDA_MCP_E2E_DEVICE;
const TARGET = process.env.FRIDA_MCP_E2E_TARGET ?? 'com.example.rc4demo';

interface Summary {
  status?: string;
  mode?: string;
  hooks_attempted?: number;
  hooks_installed?: number;
  [k: string]: unknown;
}

async function runEvasion(mode: 'report' | 'spoof'): Promise<{ messages: Summary[]; detached: string | null }> {
  try { execSync(`adb -s ${DEVICE} shell am force-stop ${TARGET}`); } catch { /* adb optional */ }
  const device = (await frida.enumerateDevices()).find((d) => d.id === DEVICE);
  if (!device) throw new Error(`device ${DEVICE} not found`);
  const pid = await device.spawn(TARGET);
  const session = await device.attach(pid);
  let detached: string | null = null;
  const t0 = Date.now();
  session.detached.connect((reason) => { detached = `${String(reason)} @${Date.now() - t0}ms`; });

  const messages: Summary[] = [];
  const source = getScriptRegistry().get('anti_frida_evasion')!.generate({});
  const script = await createAgentScript(session, {
    source,
    platform: 'android',
    name: `e2e:anti-frida-evasion:${mode}`,
    kind: 'generated',
    options: { mode },
  });
  script.message.connect((m) => { if (m.type === 'send') messages.push(m.payload as Summary); });

  try {
    await script.load();
    await device.resume(pid);
    // Give the app a moment to run its startup (and any self-checks) under the hooks.
    await new Promise((r) => setTimeout(r, 1500));
    return { messages, detached };
  } finally {
    try { await script.unload(); } catch { /* ignore */ }
    try { await session.detach(); } catch { /* ignore */ }
    try { await device.kill(pid); } catch { /* ignore */ }
  }
}

describe.skipIf(!DEVICE)('e2e: anti_frida_evasion', () => {
  it('loads in report mode, arms hooks, and does not crash the target', async () => {
    const { messages, detached } = await runEvasion('report');
    const armed = messages.find((m) => m.status === 'evasion_armed');
    const summary = messages.find((m) => m.status === 'init_complete');
    expect(armed, 'evasion_armed message').toBeDefined();
    expect(armed!.mode).toBe('report');
    expect(summary, 'init_complete summary').toBeDefined();
    // open/openat/read/fgets/strstr/... exist on Android, so real hooks must have installed.
    expect((summary!.hooks_installed ?? 0)).toBeGreaterThan(0);
    expect(detached).toBeNull();
  }, 60000);

  it('loads in spoof mode and does not crash the target', async () => {
    const { messages, detached } = await runEvasion('spoof');
    const armed = messages.find((m) => m.status === 'evasion_armed');
    expect(armed?.mode).toBe('spoof');
    expect(detached).toBeNull();
  }, 60000);
});
