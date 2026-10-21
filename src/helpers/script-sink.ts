/**
 * Shared sinks for the output of a loaded Frida script.
 *
 * Two things every created script needs, and historically only some paths did:
 *
 *   1. A `logHandler`. frida-node's default handler prints agent `console.log` /
 *      `console.warn` / `console.error` to the host's stdout. Under the stdio MCP
 *      transport that stdout *is* the JSON-RPC channel, so the default handler both
 *      hides the agent's own logging from the AI and risks corrupting the protocol
 *      stream. Routing it into the per-script message buffer as `log` entries fixes
 *      both: the AI reads it through `get_messages`, and nothing stray reaches stdout.
 *
 *   2. Full-fidelity `error` entries. Frida attaches `stack`, `fileName`,
 *      `lineNumber` and `columnNumber` to error messages; keeping only `description`
 *      leaves the AI nothing to locate the fault. `buildMessageEntry` preserves them.
 *
 * This module only *builds* and *routes* entries; it does not own any tool-specific
 * bookkeeping (e.g. hook-invocation tracking), so callers that need that keep their
 * own `script.message` listener and use `buildMessageEntry` for consistency.
 */
import type frida from 'frida';
import type { MessageEntry } from '../types.js';
import { getState } from '../state.js';

/** A message buffer entry before the monotonic index/seq are assigned by the state. */
export type PendingEntry = Omit<MessageEntry, 'index' | 'seq'>;

/**
 * Convert a raw Frida script message into a buffer entry, preserving error
 * diagnostics (stack / file / line / column) so the AI can locate failures.
 */
export function buildMessageEntry(message: frida.Message, data: Buffer | null): PendingEntry {
  if (message.type === 'send') {
    return { timestamp: Date.now(), type: 'send', payload: message.payload, data: data ?? null };
  }
  // type === 'error'
  return {
    timestamp: Date.now(),
    type: 'error',
    payload: {
      description: message.description,
      stack: message.stack,
      fileName: message.fileName,
      lineNumber: message.lineNumber,
      columnNumber: message.columnNumber,
    },
    data: data ?? null,
  };
}

/**
 * Route agent `console.*` output into the script's message buffer as `log` entries.
 * Install this on every script the server creates, regardless of transport, so the
 * default stdout-printing handler never runs.
 */
export function attachScriptLogHandler(script: frida.Script, sessionId: string, scriptId: string): void {
  script.logHandler = (level, text) => {
    getState().addMessageToScript(sessionId, scriptId, {
      timestamp: Date.now(),
      type: 'log',
      payload: { level, text },
      data: null,
    });
  };
}

export interface ScriptSinkOptions {
  /**
   * Custom handling for `send` messages. When provided, it is responsible for recording the
   * payload (tools use this for their own typing/bookkeeping: hook invocations, prebuilt_output,
   * watch_event, ...). When omitted, `send` messages are recorded verbatim like errors.
   */
  onSend?: (payload: unknown, data: Buffer | null) => void;
  /** Called for each entry recorded through the default path (send-without-onSend, and errors). */
  onEntry?: (entry: PendingEntry) => void;
}

/**
 * The single integration point every script-creating tool uses, so none can forget it: it
 * installs the `logHandler` (keeping agent `console.*` out of stdout) AND records `error`
 * messages with full fidelity through one shared branch. `send` messages go to `onSend` when a
 * tool needs custom typing/bookkeeping, otherwise they are recorded verbatim. This is why the
 * stdout-corruption + error-fidelity fixes cannot silently regress in a future tool.
 */
export function attachScriptSinks(
  script: frida.Script,
  sessionId: string,
  scriptId: string,
  opts: ScriptSinkOptions = {},
): void {
  attachScriptLogHandler(script, sessionId, scriptId);
  script.message.connect((message, data) => {
    if (message.type === 'send' && opts.onSend) {
      opts.onSend(message.payload, data);
      return;
    }
    const entry = buildMessageEntry(message, data);
    getState().addMessageToScript(sessionId, scriptId, entry);
    opts.onEntry?.(entry);
  });
}
