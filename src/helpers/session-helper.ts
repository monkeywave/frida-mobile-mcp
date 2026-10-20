import frida from 'frida';
import type { DeviceManager } from '../device/manager.js';
import type { SessionEntry } from '../types.js';
import { getState, toCrashSummary } from '../state.js';
import { DeviceNotFoundError, FridaMcpError, ProcessNotFoundError, wrapFridaError } from './errors.js';
import { log } from './logger.js';

export const FRIDA_OPERATION_TIMEOUT_MS = 20_000;

export interface SessionOptions {
  target: string;
  device?: string;
  sessionId?: string;
  /** Always spawn a fresh process and leave it suspended; the caller must resume it. */
  forceSpawn?: boolean;
  /**
   * When the target is not running and gets spawned as a fallback, resume it
   * right away (default). Set to false for early instrumentation and resume
   * via `fridaDevice.resume(sessionEntry.pid)` after loading your script.
   */
  resume?: boolean;
}

export interface SessionResolution {
  sessionEntry: SessionEntry;
  fridaDevice: frida.Device;
  isNew: boolean;
  /** True when the process was spawned and is still suspended; the caller must resume it. */
  needsResume: boolean;
}

/**
 * Find an existing session or create a new one for the target.
 * Handles device resolution, process lookup/spawn, session creation, and detach handlers.
 */
export async function getOrCreateSession(
  deviceManager: DeviceManager,
  options: SessionOptions
): Promise<SessionResolution> {
  const state = getState();

  const existing = findExistingSession(options);
  if (existing) {
    state.touchSession(existing.id);
    const fridaDevice = await deviceForSession(deviceManager, existing);
    return { sessionEntry: existing, fridaDevice, isNew: false, needsResume: false };
  }

  // Enforce the limit before touching the device so a rejected request never leaks a process.
  state.ensureSessionCapacity();

  const fridaDevice = options.device
    ? await deviceManager.resolve({ deviceId: options.device })
    : state.selectedDevice || await deviceManager.resolve();
  state.selectedDevice = fridaDevice;
  state.watchDeviceCrashes(fridaDevice);

  const platform = await deviceManager.detectPlatform(fridaDevice);

  const { pid, spawned } = await resolveTargetPid(fridaDevice, options);
  const session = await attachToPid(fridaDevice, pid, options.target, spawned);

  const sessionEntry = createSessionEntry(session, pid, fridaDevice, options.target, platform);
  state.addSession(sessionEntry);
  connectDetachHandler(sessionEntry);

  const needsResume = await resumeIfRequested(fridaDevice, pid, spawned, options);

  return { sessionEntry, fridaDevice, isNew: true, needsResume };
}

function findExistingSession(options: SessionOptions): SessionEntry | undefined {
  const state = getState();
  if (options.sessionId) {
    const byId = state.getSession(options.sessionId);
    if (byId) return byId;
  }
  if (!options.forceSpawn) {
    return state.findSessionByTarget(options.target);
  }
  return undefined;
}

/** Return the device the session actually lives on, never a possibly different "selected" device. */
async function deviceForSession(deviceManager: DeviceManager, entry: SessionEntry): Promise<frida.Device> {
  if (entry.device) return entry.device;

  try {
    const device = await deviceManager.getDevice(entry.deviceId);
    entry.device = device;
    return device;
  } catch (err) {
    const state = getState();
    if (state.selectedDevice && state.selectedDevice.id === entry.deviceId) {
      entry.device = state.selectedDevice;
      return state.selectedDevice;
    }
    log('warn', `Device ${entry.deviceId} for session ${entry.id} is not reachable: ${String(err)}`);
    throw new DeviceNotFoundError(entry.deviceId);
  }
}

/**
 * Resolve the target to a PID: numeric target → pid; otherwise running app by
 * identifier, then running process by name, then spawn (left suspended).
 */
async function resolveTargetPid(
  device: frida.Device,
  options: SessionOptions
): Promise<{ pid: number; spawned: boolean }> {
  if (options.forceSpawn) {
    return { pid: await spawnTarget(device, options.target), spawned: true };
  }

  const numericPid = parsePid(options.target);
  if (numericPid !== null) {
    return { pid: numericPid, spawned: false };
  }

  const runningPid = await findRunningPid(device, options.target);
  if (runningPid !== null) {
    return { pid: runningPid, spawned: false };
  }

  return { pid: await spawnTarget(device, options.target), spawned: true };
}

function parsePid(target: string): number | null {
  return /^\d+$/.test(target) ? Number.parseInt(target, 10) : null;
}

/** Look up a running process for `target` by application identifier first, then by process name. */
export async function findRunningPid(device: frida.Device, target: string): Promise<number | null> {
  const appPid = await findRunningAppPid(device, target);
  if (appPid !== null) return appPid;
  return findRunningProcessPid(device, target);
}

async function findRunningAppPid(device: frida.Device, identifier: string): Promise<number | null> {
  try {
    const apps = await withTimeout(
      (cancellable) => device.enumerateApplications({ identifiers: [identifier], scope: 'minimal' as frida.Scope }, cancellable),
      `enumerateApplications(${identifier})`
    );
    const running = apps.find((app) => app.identifier === identifier && app.pid > 0);
    return running ? running.pid : null;
  } catch (err) {
    // Not every device type can enumerate applications; fall through to process matching.
    log('debug', `enumerateApplications failed for ${identifier}: ${String(err)}`);
    return null;
  }
}

async function findRunningProcessPid(device: frida.Device, name: string): Promise<number | null> {
  try {
    const processes = await withTimeout(
      (cancellable) => device.enumerateProcesses({ scope: 'minimal' as frida.Scope }, cancellable),
      'enumerateProcesses'
    );
    const proc = processes.find((p) => p.name === name);
    return proc ? proc.pid : null;
  } catch (err) {
    log('debug', `enumerateProcesses failed: ${String(err)}`);
    return null;
  }
}

/** Spawn the target and leave it suspended. */
async function spawnTarget(device: frida.Device, target: string): Promise<number> {
  try {
    return await withTimeout((cancellable) => device.spawn(target, undefined, cancellable), `spawn(${target})`);
  } catch (err) {
    throw translateSpawnError(err, target);
  }
}

function translateSpawnError(err: unknown, target: string): FridaMcpError {
  if (err instanceof FridaMcpError) return err;
  const message = err instanceof Error ? err.message : String(err);
  if (/unable to find/i.test(message)) {
    return new ProcessNotFoundError(target);
  }
  return wrapFridaError(err);
}

async function attachToPid(
  device: frida.Device,
  pid: number,
  target: string,
  spawned: boolean
): Promise<frida.Session> {
  try {
    return await withTimeout((cancellable) => device.attach(pid, {}, cancellable), `attach(${pid})`);
  } catch (err) {
    if (spawned) {
      // Never leave a suspended process behind when we cannot instrument it.
      try { await device.kill(pid); } catch { /* best-effort */ }
    }
    throw translateAttachError(err, target, pid);
  }
}

function translateAttachError(err: unknown, target: string, pid: number): FridaMcpError {
  if (err instanceof FridaMcpError) return err;
  const message = err instanceof Error ? err.message : String(err);
  if (/unable to find process|no such process|process not found/i.test(message)) {
    return new ProcessNotFoundError(`${target} (pid ${pid})`);
  }
  return wrapFridaError(err);
}

function createSessionEntry(
  session: frida.Session,
  pid: number,
  device: frida.Device,
  target: string,
  platform: SessionEntry['platform']
): SessionEntry {
  const state = getState();
  const now = Date.now();
  return {
    id: state.generateId(),
    session,
    pid,
    deviceId: device.id,
    device,
    target,
    platform,
    scripts: new Map(),
    createdAt: now,
    lastActivityAt: now,
  };
}

function connectDetachHandler(entry: SessionEntry): void {
  const state = getState();
  entry.session.detached.connect((reason: frida.SessionDetachReason, crash: frida.Crash | null) => {
    const crashSummary = toCrashSummary(crash);
    entry.detachReason = reason;
    if (crashSummary) entry.crash = crashSummary;

    state.recordDetach({
      sessionId: entry.id,
      target: entry.target,
      pid: entry.pid,
      deviceId: entry.deviceId,
      reason,
      crash: crashSummary ?? entry.crash ?? null,
      timestamp: Date.now(),
    });

    const level = reason === 'application-requested' ? 'info' : 'warn';
    log(level, `Session ${entry.id} detached (${entry.target}, pid ${entry.pid}): ${reason}` +
      (crashSummary ? ` - crash: ${crashSummary.summary}` : ''));

    state.removeSession(entry.id).catch(() => { /* best-effort */ });
  });
}

/**
 * Resume a process that we spawned as a fallback, unless the caller asked to
 * do it themselves. `forceSpawn` always leaves the process suspended.
 * Returns whether the caller still has to resume the process.
 */
async function resumeIfRequested(
  device: frida.Device,
  pid: number,
  spawned: boolean,
  options: SessionOptions
): Promise<boolean> {
  if (!spawned) return false;
  if (options.forceSpawn) return true;
  if (options.resume === false) return true;

  await withTimeout((cancellable) => device.resume(pid, cancellable), `resume(${pid})`);
  return false;
}

/** Run a frida operation with a cancellation timeout and turn cancellation into a clear error. */
export async function withTimeout<T>(
  operation: (cancellable: frida.Cancellable) => Promise<T>,
  label: string,
  timeoutMs: number = FRIDA_OPERATION_TIMEOUT_MS
): Promise<T> {
  const cancellable = frida.Cancellable.withTimeout(timeoutMs);
  try {
    return await operation(cancellable);
  } catch (err) {
    if (isCancellation(err, cancellable)) {
      throw new FridaMcpError(
        'FRIDA_TIMEOUT',
        `${label} timed out after ${Math.round(timeoutMs / 1000)}s. The device or frida-server may be unresponsive.`,
        [
          { tool: 'get_status', reason: 'Check device connectivity' },
          { action: 'user_intervention', message: 'Verify frida-server is running and the device is reachable' },
        ],
        { operation: label, timeout_ms: timeoutMs }
      );
    }
    throw err;
  }
}

function isCancellation(err: unknown, cancellable: frida.Cancellable): boolean {
  if (cancellable.isCancelled) return true;
  const message = err instanceof Error ? err.message : String(err);
  return /cancelled|canceled|timed out/i.test(message);
}
