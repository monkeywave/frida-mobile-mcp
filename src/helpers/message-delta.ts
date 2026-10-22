import type { SessionEntry } from '../types.js';

/** One message in a session-wide delta: which script emitted it, its global seq, type and payload. */
export interface DeltaMessage {
  script_id: string;
  script_name?: string;
  seq: number;
  type: string;
  payload: unknown;
}

/**
 * Messages across all of a session's scripts with seq strictly greater than `afterSeq`, in seq
 * order. Shared by trigger_and_wait and drive_coverage so the "what arrived since the trigger"
 * semantics stay identical between the single-shot and looped drivers.
 */
export function collectDelta(session: SessionEntry, afterSeq: number): DeltaMessage[] {
  const out: DeltaMessage[] = [];
  for (const [sid, script] of session.scripts) {
    for (const m of script.messages) {
      if (m.seq > afterSeq) out.push({ script_id: sid, script_name: script.name, seq: m.seq, type: m.type, payload: m.payload });
    }
  }
  out.sort((a, b) => a.seq - b.seq);
  return out;
}
