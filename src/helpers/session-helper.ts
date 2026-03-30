import type frida from 'frida';
import type { DeviceManager } from '../device/manager.js';
import type { SessionEntry } from '../types.js';
import { getState } from '../state.js';
import { log } from './logger.js';

export interface SessionOptions {
  target: string;
  device?: string;
  sessionId?: string;
  forceSpawn?: boolean;
}

/**
 * Find an existing session or create a new one for the target.
 * Handles device resolution, process lookup/spawn, session creation, and detach handlers.
 */
export async function getOrCreateSession(
  deviceManager: DeviceManager,
  options: SessionOptions
): Promise<{ sessionEntry: SessionEntry; fridaDevice: frida.Device; isNew: boolean }> {
  const state = getState();

  // Check for existing session by ID
  if (options.sessionId) {
    const existing = state.getSession(options.sessionId);
    if (existing) {
      const device = state.selectedDevice!;
      return { sessionEntry: existing, fridaDevice: device, isNew: false };
    }
  }

  // Check for existing session by target (unless forceSpawn)
  if (!options.forceSpawn) {
    const existing = state.findSessionByTarget(options.target);
    if (existing) {
      const device = state.selectedDevice!;
      return { sessionEntry: existing, fridaDevice: device, isNew: false };
    }
  }

  // Resolve device
  const fridaDevice = options.device
    ? await deviceManager.resolve({ deviceId: options.device })
    : state.selectedDevice || await deviceManager.resolve();
  state.selectedDevice = fridaDevice;

  const platform = await deviceManager.detectPlatform(fridaDevice);

  // Find running process or spawn
  let pid: number;
  if (options.forceSpawn) {
    pid = await fridaDevice.spawn(options.target);
  } else {
    try {
      const processes = await fridaDevice.enumerateProcesses();
      const proc = processes.find(
        (p) => p.name === options.target || p.pid.toString() === options.target
      );
      if (proc) {
        pid = proc.pid;
      } else {
        pid = await fridaDevice.spawn(options.target);
        await fridaDevice.resume(pid);
      }
    } catch {
      pid = await fridaDevice.spawn(options.target);
      await fridaDevice.resume(pid);
    }
  }

  // Attach and create session
  const session = await fridaDevice.attach(pid);
  const sessionId = state.generateId();

  const sessionEntry: SessionEntry = {
    id: sessionId,
    session,
    pid,
    deviceId: fridaDevice.id,
    target: options.target,
    platform,
    scripts: new Map(),
    createdAt: Date.now(),
  };
  state.addSession(sessionEntry);

  session.detached.connect((reason: any) => {
    log('info', `Session ${sessionId} detached: ${reason}`);
    state.removeSession(sessionId);
  });

  return { sessionEntry, fridaDevice, isNew: true };
}
