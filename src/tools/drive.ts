import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { responseFormatSchema } from '../constants.js';
import { type DeltaMessage } from '../helpers/message-delta.js';
import { triggerAndCollect } from '../helpers/trigger-and-collect.js';
import { withTimeout } from '../helpers/with-timeout.js';

const DEFAULT_STOP_ON = 'crypto_event';
const DEFAULT_MAX_STEPS = 12;
const DEFAULT_STEP_TIMEOUT_MS = 4000;
const MAX_STEP_TIMEOUT_MS = 30_000;
const MAX_MAX_STEPS = 50;
// A stuck mobile-mcp call must not hang the loop: cap each UI round-trip. The wait for new
// messages is already bounded by step_timeout_ms, but list/tap themselves could stall, so they
// get their own race-based timeout. This keeps the "every path terminates" guarantee.
const UI_CALL_TIMEOUT_MS = 15_000;
// How many consecutive steps without any newly-covered target before we give up (dead end).
const COVERAGE_STALL_LIMIT = 3;
const MAX_STEPS_RETURNED = 50;

/** Why the drive loop stopped — exactly one of these is returned. */
type StoppedReason =
  | 'captured'
  | 'coverage_stalled'
  | 'no_more_elements'
  | 'max_steps'
  | 'wall_clock'
  | 'ui_error';

interface ClickableElement {
  label: string;
  x: number;
  y: number;
  clickable: boolean;
  /** Dedupe key for "already tried this run": label + rounded center. */
  key: string;
}

interface DriveStep {
  tapped: { label: string; x: number; y: number };
  new_message_count: number;
  fired_targets: string[];
  newly_covered_this_step?: number;
}


/**
 * drive_coverage — a bounded, breadth-first UI tapper that drives an already-instrumented session
 * toward uncovered code and stops the instant a signal fires. It arms nothing itself: the caller
 * first arms monitor_crypto and/or trace_coverage, then calls this to correlate taps with hook
 * output (the same snapshot-seq → tap → waitForNewMessages → collectDelta primitive as
 * trigger_and_wait, run in a loop). It is a tapper, not a planner: every path terminates via
 * max_steps, a wall-clock cap, per-call timeouts, coverage-stall detection, or "no elements left".
 */
export function registerDriveTool(server: McpServer, _deviceManager: DeviceManager): void {
  server.registerTool(
    'drive_coverage',
    {
      title: 'Drive Coverage (Autonomous UI Loop)',
      description:
        'Autonomously drive the UI of an already-instrumented session toward uncovered code and stop the moment a signal fires. This arms NOTHING — first arm monitor_crypto and/or trace_coverage, then call drive_coverage to tap through on-screen elements breadth-first, correlating each tap with new hook output (snapshot → tap → wait → delta, like trigger_and_wait in a loop). It stops on the first delta message that matches `stop_on` (default "crypto_event") or looks like a captured key/secret, when coverage stalls for several steps, when no untried elements remain, or at max_steps / the wall-clock cap. Supply `coverage_id` to measure the covered delta the drive produced. Use it to reach a crypto path hands-free instead of tapping manually; read the full output afterwards with get_messages.',
      inputSchema: z.object({
        session_id: z.string().describe('A live session with hooks ALREADY armed (monitor_crypto / trace_coverage). From explore_app/get_status.'),
        coverage_id: z.string().optional().describe('Optional trace_coverage run to measure the covered/cold delta this drive produced.'),
        stop_on: z
          .string()
          .optional()
          .describe(`Stop when a new message\'s type equals this, or this substring appears in its payload / cov target (default: "${DEFAULT_STOP_ON}"). A key/secret-bearing message always stops the loop too.`),
        max_steps: z.number().int().min(1).max(MAX_MAX_STEPS).optional().describe(`Max taps before giving up (default: ${DEFAULT_MAX_STEPS}).`),
        step_timeout_ms: z.number().int().min(0).max(MAX_STEP_TIMEOUT_MS).optional().describe(`How long to wait for hook output after each tap (default: ${DEFAULT_STEP_TIMEOUT_MS}).`),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ session_id, coverage_id, stop_on, max_steps, step_timeout_ms, response_format }) => {
      try {
        const state = getState();

        // Guard the capability before touching anything, like trigger_and_wait's performMobileTrigger.
        if (!state.config.mobileMcp.enabled) {
          throw new FridaMcpError('MOBILE_ERROR', 'mobile-mcp integration is disabled in config; drive_coverage needs it to tap the UI.', [
            { tool: 'trigger_and_wait', args: { session_id }, reason: 'Drive one step manually instead (no mobile action)' },
          ]);
        }

        const session = state.getSession(session_id);
        if (!session) {
          throw new FridaMcpError('SESSION_NOT_FOUND', `Session "${session_id}" not found.`, [
            { tool: 'get_status', reason: 'List active sessions' },
          ]);
        }

        const stopOn = stop_on ?? DEFAULT_STOP_ON;
        const maxSteps = max_steps ?? DEFAULT_MAX_STEPS;
        const stepTimeoutMs = step_timeout_ms ?? DEFAULT_STEP_TIMEOUT_MS;
        // Overall wall clock: never run longer than the worst case of every step timing out plus a
        // UI allowance, so the loop is bounded in time even if the device is slow.
        const wallClockDeadline = Date.now() + maxSteps * (stepTimeoutMs + UI_CALL_TIMEOUT_MS) + UI_CALL_TIMEOUT_MS;

        const coverageEntry = coverage_id ? state.coverage.get(coverage_id) : undefined;
        // Snapshot the coverage baseline so "newly covered" is the delta this drive caused.
        const coveredAtStart = coverageEntry ? new Set(coverageEntry.hits.keys()) : new Set<string>();
        const coveredSeen = new Set(coveredAtStart);

        const { callMobileAction } = await import('../mobile-mcp/call.js');

        const loopStartSeq = state.currentMessageSeq();
        const tried = new Set<string>();
        const steps: DriveStep[] = [];
        const limitations: string[] = [];
        let captured: DeltaMessage | null = null;
        let stoppedReason: StoppedReason = 'max_steps';
        let coverageStallStreak = 0;

        for (let step = 0; step < maxSteps; step++) {
          if (Date.now() >= wallClockDeadline) {
            stoppedReason = 'wall_clock';
            break;
          }

          // 1. List what is on screen and pick the next untried, preferably clickable, element.
          let elements: ClickableElement[];
          try {
            const listResult = await withTimeout(
              callMobileAction('mobile_list_elements_on_screen', {}, session.deviceId),
              UI_CALL_TIMEOUT_MS,
              'mobile_list_elements_on_screen',
            );
            elements = parseElements(listResult);
          } catch (err) {
            stoppedReason = 'ui_error';
            limitations.push(`Could not list on-screen elements: ${err instanceof Error ? err.message : String(err)}`);
            break;
          }

          const next = pickNextElement(elements, tried);
          if (!next) {
            stoppedReason = 'no_more_elements';
            break;
          }
          tried.add(next.key);

          // 2. Tap it, then block until this tap drives at least one new message (or times out).
          // The same snapshot → tap → wait → delta primitive as trigger_and_wait; the UI call is
          // bounded by callTimeoutMs so a stuck tap cannot hang the loop.
          let delta: DeltaMessage[];
          try {
            ({ delta } = await triggerAndCollect(session, {
              action: 'mobile_click_on_screen_at_coordinates',
              params: { x: next.x, y: next.y },
              minCount: 1,
              timeoutMs: stepTimeoutMs,
              callTimeoutMs: UI_CALL_TIMEOUT_MS,
            }));
          } catch (err) {
            stoppedReason = 'ui_error';
            limitations.push(`Could not tap "${next.label}" at (${next.x}, ${next.y}): ${err instanceof Error ? err.message : String(err)}`);
            break;
          }

          // 3. Fold the results of this tap into the running record.
          const stepRecord: DriveStep = {
            tapped: { label: next.label, x: next.x, y: next.y },
            new_message_count: delta.length,
            fired_targets: deriveFiredTargets(delta),
          };

          if (coverageEntry) {
            let gained = 0;
            for (const target of coverageEntry.hits.keys()) {
              if (!coveredSeen.has(target)) {
                coveredSeen.add(target);
                gained++;
              }
            }
            stepRecord.newly_covered_this_step = gained;
            // Only a tap that produced NOTHING counts toward the stall streak. If any message
            // arrived (e.g. a crypto_event woke the wait), this tap did something and its coverage
            // hits may still be streaming in — treating that as a stall would stop the loop early.
            coverageStallStreak = gained === 0 && delta.length === 0 ? coverageStallStreak + 1 : 0;
          }
          steps.push(stepRecord);

          // 4. Stop conditions, in priority order.
          const match = delta.find((m) => isCaptureSignal(m, stopOn));
          if (match) {
            captured = match;
            stoppedReason = 'captured';
            break;
          }
          if (coverageEntry && coverageStallStreak >= COVERAGE_STALL_LIMIT) {
            stoppedReason = 'coverage_stalled';
            limitations.push(`Coverage stopped growing for ${COVERAGE_STALL_LIMIT} consecutive taps — likely a dead end for this screen.`);
            break;
          }
        }

        const newlyCovered = coverageEntry
          ? coverageEntry.allTargets.filter((t) => coveredSeen.has(t) && !coveredAtStart.has(t))
          : [];

        return formatToolResponse(
          buildResult(
            {
              session_id,
              steps_taken: steps.length,
              stopped_reason: stoppedReason,
              captured,
              newly_covered: newlyCovered,
              steps: steps.slice(0, MAX_STEPS_RETURNED),
            },
            suggestedNext(session_id, loopStartSeq, captured !== null),
            limitations.length > 0 ? { limitations } : {},
          ),
          response_format,
        );
      } catch (err) {
        if (err instanceof FridaMcpError) return formatToolResponse(err.toErrorResponse(), response_format);
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );
}

/** What to do next: always read the full output; hunt the key from memory when nothing fired. */
function suggestedNext(sessionId: string, loopStartSeq: number, didCapture: boolean): Array<{ tool: string; args: Record<string, unknown>; reason: string }> {
  const actions: Array<{ tool: string; args: Record<string, unknown>; reason: string }> = [
    { tool: 'get_messages', args: { session_id: sessionId, since: loopStartSeq }, reason: 'Read the full output the drive produced' },
  ];
  if (!didCapture) {
    // Nothing fired — recover a key by structure from memory. (find_secrets then points at
    // generate_memory_pattern with the concrete address/size it locates; suggesting that tool here
    // would fail validation since address/size are not known yet.)
    actions.push({
      tool: 'find_secrets_in_memory',
      args: { session_id: sessionId, scope: 'heap' },
      reason: 'Nothing fired — recover a key by structure from live memory, then turn it into a reusable/friTap pattern',
    });
  }
  return actions;
}

/**
 * Whether a new message is the signal to stop with `captured`. Matches when the message type
 * equals stop_on, when stop_on appears as a substring of the serialized payload (which naturally
 * covers a `cov` target string containing it), or when the payload looks key/secret-bearing. Bare
 * coverage hits are NOT a capture — they are progress that feeds newly_covered and resets the
 * stall counter — so the loop keeps driving until the real signal fires.
 */
function isCaptureSignal(msg: DeltaMessage, stopOn: string): boolean {
  if (msg.type === stopOn) return true;
  if (isKeyBearing(msg)) return true;
  try {
    if (stopOn && JSON.stringify(msg.payload ?? '').includes(stopOn)) return true;
  } catch {
    /* payload not serializable — ignore */
  }
  return false;
}

/** A message that carries key material: a crypto event, or a payload with key/plaintext fields. */
function isKeyBearing(msg: DeltaMessage): boolean {
  if (msg.type === 'crypto_event' || msg.type === 'secret') return true;
  const p = msg.payload;
  if (p && typeof p === 'object') {
    return 'key_hex' in p || 'plaintext' in p || 'key' in p;
  }
  return false;
}

/** The targets a tap fired: coverage `cov` ids where present, otherwise the message type. */
function deriveFiredTargets(delta: DeltaMessage[]): string[] {
  const out = new Set<string>();
  for (const m of delta) {
    const p = m.payload;
    if (p && typeof p === 'object' && typeof (p as { cov?: unknown }).cov === 'string') {
      out.add((p as { cov: string }).cov);
    } else {
      out.add(m.type);
    }
  }
  return Array.from(out);
}


/** Pick the next element not yet tried this run, preferring clickable/button-like ones. */
function pickNextElement(elements: ClickableElement[], tried: Set<string>): ClickableElement | null {
  const untried = elements.filter((e) => !tried.has(e.key));
  if (untried.length === 0) return null;
  return untried.find((e) => e.clickable) ?? untried[0];
}

// ---------------------------------------------------------------------------
// mobile_list_elements_on_screen parsing
//
// The real return shape is not pinned by this server (it comes from mobile-mcp), so the parser is
// defensive: it unwraps an MCP {content:[{type:'text',text}]} envelope, accepts a bare array or an
// {elements:[...]} object, and reads an element's center from several rect/coordinate spellings.
// ---------------------------------------------------------------------------

/** Unwrap whatever callMobileAction returned into a flat array of raw element objects. */
function extractElementArray(raw: unknown): Array<Record<string, unknown>> {
  if (raw == null) return [];
  if (Array.isArray(raw)) return raw.filter(isObject);

  const obj = raw as Record<string, unknown>;

  // MCP tool-result envelope: concatenate the text blocks and parse each as JSON.
  if (Array.isArray(obj.content)) {
    const collected: Array<Record<string, unknown>> = [];
    for (const block of obj.content) {
      if (isObject(block) && typeof block.text === 'string') {
        collected.push(...parseElementsFromText(block.text));
      }
    }
    if (collected.length > 0) return collected;
  }

  if (Array.isArray(obj.elements)) return obj.elements.filter(isObject);
  if (Array.isArray(obj.result)) return obj.result.filter(isObject);
  if (isObject(obj.result) && Array.isArray((obj.result as Record<string, unknown>).elements)) {
    return ((obj.result as Record<string, unknown>).elements as unknown[]).filter(isObject);
  }
  return [];
}

/** Parse one text block, which may be a JSON array, an {elements} object, or non-JSON noise. */
function parseElementsFromText(text: string): Array<Record<string, unknown>> {
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed.filter(isObject);
    if (isObject(parsed) && Array.isArray(parsed.elements)) return parsed.elements.filter(isObject);
  } catch {
    /* not JSON — mobile-mcp sometimes prefixes a human sentence; ignore */
  }
  return [];
}

function parseElements(raw: unknown): ClickableElement[] {
  const out: ClickableElement[] = [];
  for (const el of extractElementArray(raw)) {
    const center = elementCenter(el);
    if (!center) continue;
    const label = elementLabel(el);
    out.push({
      label,
      x: center.x,
      y: center.y,
      clickable: isElementClickable(el),
      key: `${label}@${Math.round(center.x)},${Math.round(center.y)}`,
    });
  }
  return out;
}

/** Tap target = the center of the element, derived from whichever rect/coordinate shape is present. */
function elementCenter(el: Record<string, unknown>): { x: number; y: number } | null {
  const rect = el.rect ?? el.bounds ?? el.frame;
  if (isObject(rect)) {
    const r = rect as Record<string, unknown>;
    // {x, y, width, height}
    if (isNum(r.x) && isNum(r.y) && isNum(r.width) && isNum(r.height)) {
      return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
    }
    // {x0, y0, x1, y1} or {left, top, right, bottom}
    const x0 = firstNum(r.x0, r.left);
    const y0 = firstNum(r.y0, r.top);
    const x1 = firstNum(r.x1, r.right);
    const y1 = firstNum(r.y1, r.bottom);
    if (x0 !== null && y0 !== null && x1 !== null && y1 !== null) {
      return { x: (x0 + x1) / 2, y: (y0 + y1) / 2 };
    }
  }
  // {coordinates:{x,y}} / {center:{x,y}}
  for (const key of ['coordinates', 'center'] as const) {
    const c = el[key];
    if (isObject(c) && isNum((c as Record<string, unknown>).x) && isNum((c as Record<string, unknown>).y)) {
      return { x: (c as { x: number }).x, y: (c as { y: number }).y };
    }
  }
  // flat {x, y}
  if (isNum(el.x) && isNum(el.y)) return { x: el.x, y: el.y };
  return null;
}

/** A human-readable label for an element, falling back through the common field names. */
function elementLabel(el: Record<string, unknown>): string {
  for (const key of ['text', 'label', 'name', 'value', 'identifier', 'accessibilityLabel', 'type', 'class']) {
    const v = el[key];
    if (typeof v === 'string' && v.trim().length > 0) return v.trim();
  }
  return 'element';
}

/** Prefer explicit clickable/focusable flags; otherwise treat button-like types as clickable. */
function isElementClickable(el: Record<string, unknown>): boolean {
  if (el.clickable === true || el.focusable === true || el.enabled === true) return true;
  if (el.clickable === false) return false;
  const hint = `${el.type ?? ''} ${el.class ?? ''} ${el.role ?? ''}`.toLowerCase();
  return /button|link|tab|menuitem|cell|checkbox|switch/.test(hint);
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isNum(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}

function firstNum(...vals: unknown[]): number | null {
  for (const v of vals) if (isNum(v)) return v;
  return null;
}
