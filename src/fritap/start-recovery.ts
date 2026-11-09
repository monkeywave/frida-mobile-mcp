/**
 * Liveness of a target capture_tls spawned, and the decision whether a failed suspended start is
 * retried in early-resume mode.
 *
 * Android kills an app that is not resumed within ~10 s of its spawn (ActivityManager "start
 * timeout"). On a slow device the friTap load can exceed that window; the failure then surfaces
 * in many shapes ("The connection is closed", a FRIDA_TIMEOUT, "Process has terminated", ...) and
 * the session's detach reason often arrives only after the error. So the decision is taken on
 * observed state (detach reason, pid still alive) first and on the error text second.
 */
import type frida from 'frida';
import { FridaMcpError } from '../helpers/errors.js';
import { withTimeout } from '../helpers/session-helper.js';
import type { SessionEntry } from '../types.js';

/** Error text of a spawned app that died before it was resumed (OS launch watchdog / start timeout). */
const START_TIMEOUT_PATTERN = /start timeout|process (?:has )?terminated|process-terminated|unable to find process|no such process|process not found/i;
/** Transport failures seen when the app is killed while friTap loads into the suspended process. */
const SUSPENDED_WINDOW_FAILURE_PATTERN = /connection (?:is )?closed|timed out|timeout was reached/i;
/** Error codes of a start whose target went away or stopped answering while still suspended. */
const SUSPENDED_WINDOW_FAILURE_CODES: ReadonlySet<string> = new Set(['PROCESS_NOT_FOUND', 'PROCESS_TERMINATED', 'FRIDA_TIMEOUT']);

/** How long the pid liveness query may take before the result counts as unknown. */
const PID_PROBE_TIMEOUT_MS = 5_000;
const DETACH_POLL_INTERVAL_MS = 100;

export const PROCESS_TERMINATED_REMEDIATION =
  'The app was killed right after friTap started (e.g. Android start timeout or anti-instrumentation). ' +
  'Retry with spawn_mode="early_resume", or start the app manually and use spawn=false; probe=true or pairip_safe=true help when the instrumentation itself crashes the app.';

/**
 * Whether a failed suspended start looks like the OS killed the not-yet-resumed app (Android
 * ActivityManager "start timeout"): PROCESS_NOT_FOUND, a terminated-process error, or a session
 * that detached with reason process-terminated while the agent loaded.
 */
export function isAppStartTimeoutFailure(error: unknown, detachReason?: string | null): boolean {
  if (detachReason === 'process-terminated') return true;
  if (error instanceof FridaMcpError && error.code === 'PROCESS_NOT_FOUND') return true;
  return START_TIMEOUT_PATTERN.test(errorMessage(error));
}

/** What was observed about the spawned target after an attempt failed. */
export interface TargetObservation {
  /** Detach reason of the attempt's session, if it detached. */
  detachReason?: string | null;
  /** true/false when the pid query answered; null/undefined when unknown. */
  pidAlive?: boolean | null;
}

/**
 * Whether a failed suspended start is retried once in early-resume mode. Observed state wins:
 * - the spawned app died (pid gone, or session detached for process-terminated) -> retry;
 * - the app is observed alive and the session never detached -> never retry: the failure is the
 *   agent's own (e.g. a hang that hit FRIDA_TIMEOUT), and a retry would kill a healthy app and
 *   mask the original error;
 * - otherwise (liveness unknown, or alive with another detach reason) -> retry only when the
 *   error has the start-timeout signature (terminated/not found, connection closed, timeout).
 */
export function shouldRetrySuspendedStart(error: unknown, observation: TargetObservation = {}): boolean {
  const detachReason = observation.detachReason ?? null;
  if (observation.pidAlive === false || detachReason === 'process-terminated') return true;
  if (observation.pidAlive === true && detachReason === null) return false;
  return hasStartTimeoutSignature(error);
}

/** Whether the error looks like the OS start-timeout kill of a still-suspended app. */
function hasStartTimeoutSignature(error: unknown): boolean {
  if (isAppStartTimeoutFailure(error)) return true;
  if (error instanceof FridaMcpError && SUSPENDED_WINDOW_FAILURE_CODES.has(error.code)) return true;
  return SUSPENDED_WINDOW_FAILURE_PATTERN.test(errorMessage(error));
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Whether `pid` is still running; null when the device did not answer in time. */
export async function probePidAlive(device: frida.Device, pid: number, timeoutMs = PID_PROBE_TIMEOUT_MS): Promise<boolean | null> {
  try {
    const processes = await withTimeout(
      (c) => device.enumerateProcesses({ pids: [pid], scope: 'minimal' as frida.Scope }, c),
      `enumerateProcesses(pid ${pid})`,
      timeoutMs
    );
    return processes.some((p) => p.pid === pid);
  } catch {
    return null;
  }
}

/** Detach reason of the session, waiting up to `graceMs` for one; null when still attached. */
export async function waitForDetach(sessionEntry: SessionEntry, graceMs: number): Promise<string | null> {
  const deadline = Date.now() + graceMs;
  for (;;) {
    const reason = currentDetachReason(sessionEntry);
    if (reason || Date.now() >= deadline) return reason;
    await new Promise((resolve) => setTimeout(resolve, Math.min(DETACH_POLL_INTERVAL_MS, deadline - Date.now())));
  }
}

function currentDetachReason(sessionEntry: SessionEntry): string | null {
  if (sessionEntry.detachReason) return sessionEntry.detachReason;
  const session = sessionEntry.session as { isDetached?: () => boolean };
  return typeof session.isDetached === 'function' && session.isDetached() ? 'detached' : null;
}

/** Detach reason (after up to `graceMs`) and pid liveness of a spawned target. */
export async function observeSpawnedTarget(device: frida.Device, sessionEntry: SessionEntry, graceMs: number): Promise<TargetObservation> {
  const [detachReason, pidAlive] = await Promise.all([
    waitForDetach(sessionEntry, graceMs),
    probePidAlive(device, sessionEntry.pid),
  ]);
  return { detachReason, pidAlive };
}

/** Whether an observation shows the target dead (detached or pid gone). */
export function isTargetDead(observation: TargetObservation): boolean {
  return Boolean(observation.detachReason) || observation.pidAlive === false;
}

/** Structured error for a spawned app that died right after friTap was started in it. */
export function processTerminatedError(target: string, pid: number, observation: TargetObservation): FridaMcpError {
  const cause = observation.detachReason ? `session detached: ${observation.detachReason}` : 'process no longer running';
  return new FridaMcpError(
    'PROCESS_TERMINATED',
    `${target} (pid ${pid}) died right after friTap started (${cause}).`,
    [
      { tool: 'capture_tls', args: { target, spawn_mode: 'early_resume' }, reason: 'Load friTap after the app has started' },
      { tool: 'capture_tls', args: { target, spawn: false }, reason: 'Attach to the app once it runs' },
    ],
    { target, pid, detach_reason: observation.detachReason ?? null, pid_alive: observation.pidAlive ?? null },
    { category: 'provider', retryable: true, remediation: PROCESS_TERMINATED_REMEDIATION }
  );
}
