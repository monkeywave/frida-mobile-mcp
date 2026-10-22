import type { SessionEntry } from '../types.js';
import { getState } from '../state.js';
import { collectDelta, type DeltaMessage } from './message-delta.js';
import { withTimeout } from './with-timeout.js';

export interface TriggerAndCollectOptions {
  /** Optional mobile-mcp action to perform as the trigger. Omit for a pure wait (trigger_and_wait). */
  action?: string;
  /** Parameters for the trigger action; the session's device is injected by callMobileAction. */
  params?: Record<string, unknown>;
  /** Resolve once this many new messages have arrived (or the wait times out). */
  minCount: number;
  /** Max time to wait for new messages after the action. */
  timeoutMs: number;
  /** When set, bound the mobile call itself with withTimeout so a stuck call can't hang the caller. */
  callTimeoutMs?: number;
}

export interface TriggerAndCollectResult {
  /** True if `minCount` new messages arrived within `timeoutMs`; false on timeout. */
  reached: boolean;
  /** Messages produced since the cursor was snapshotted, in seq order. */
  delta: DeltaMessage[];
  /** Ids of the scripts that emitted in this delta — the raw material each caller maps to its own
   *  "fired" vocabulary (trigger_and_wait → hook objects, drive_coverage → coverage targets). */
  firedScriptIds: Set<string>;
  /** Whatever the mobile-mcp action returned, or null when no action was performed. */
  actionResult: unknown;
  /** The message-seq cursor snapshotted just before the action — the "since" for reading the delta. */
  afterSeq: number;
}

/**
 * The shared snapshot → (optional) action → wait → collect beat behind both trigger_and_wait and
 * drive_coverage. The cursor is snapshotted BEFORE the action so any message the action causes
 * counts as new. Throws if the mobile call fails or times out, letting the caller decide how to
 * report it (drive_coverage wraps this in its ui_error catch). The "fired" derivation stays with
 * the caller: this returns the delta and the emitting script ids, not a tool-specific shape.
 */
export async function triggerAndCollect(
  session: SessionEntry,
  opts: TriggerAndCollectOptions,
): Promise<TriggerAndCollectResult> {
  const state = getState();
  // Cursor BEFORE the trigger, so any message the trigger causes counts as new.
  const afterSeq = state.currentMessageSeq();

  let actionResult: unknown = null;
  if (opts.action) {
    const { callMobileAction } = await import('../mobile-mcp/call.js');
    const call = callMobileAction(opts.action, opts.params, session.deviceId);
    actionResult = await (opts.callTimeoutMs !== undefined ? withTimeout(call, opts.callTimeoutMs, opts.action) : call);
  }

  const reached = await state.waitForNewMessages(session.id, afterSeq, opts.minCount, opts.timeoutMs);
  const delta = collectDelta(session, afterSeq);
  const firedScriptIds = new Set(delta.map((d) => d.script_id));
  return { reached, delta, firedScriptIds, actionResult, afterSeq };
}
