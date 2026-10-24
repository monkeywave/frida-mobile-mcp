/**
 * Output schema shared by every tool. All tools return the same envelope through
 * `formatToolResponse(buildResult(...))`: a tool-specific `result` object plus session
 * context, suggested next actions and evidence metadata (see docs/interop.md).
 *
 * Declaring it lets MCP clients (and REA/ReVa-style orchestrators) rely on the shape of
 * `structuredContent` without parsing the text rendering.
 */
import { z } from 'zod';

export const suggestedActionSchema = z.object({
  tool: z.string(),
  args: z.record(z.string(), z.unknown()).optional(),
  reason: z.string(),
  condition: z.string().optional(),
  priority: z.enum(['required', 'recommended', 'optional']).optional(),
});

export const sessionContextSchema = z.object({
  device: z.string().nullable(),
  platform: z.string().nullable(),
  active_sessions: z.array(z.object({ id: z.string(), target: z.string(), pid: z.number() })),
  active_hooks: z.number(),
  active_oracles: z.number(),
  active_scripts: z.number(),
  last_detach: z
    .object({
      target: z.string(),
      reason: z.string(),
      crash_summary: z.string().nullable().optional(),
      timestamp: z.number(),
    })
    .nullable()
    .optional(),
});

/** Zod object schema for `registerTool({ outputSchema })`. */
export const TOOL_RESULT_OUTPUT_SHAPE = z.object({
  result: z.record(z.string(), z.unknown()).describe('Tool-specific result object'),
  session_context: sessionContextSchema,
  suggested_next: z.array(suggestedActionSchema),
  evidence_id: z.string().optional().describe('Unique id of this observation (REA/ReVa evidence convention)'),
  limitations: z.array(z.string()).optional(),
  coverage: z
    .object({
      status: z.enum(['complete', 'partial', 'unknown']),
      note: z.string().optional(),
      scope: z.string().optional().describe('What was scanned (module exports, session messages ...)'),
      next_offset: z.number().optional().describe('Offset/cursor to pass back to continue a partial result'),
      truncated: z.boolean().optional().describe('True when items were dropped (limit, eviction, trimming)'),
    })
    .optional(),
  raw_result: z.unknown().optional(),
});

/**
 * Output schema to pass to `registerTool`. The `compact` schema profile drops it centrally in
 * the tool gate (`applyPolicyToConfig`), so this always returns the envelope schema.
 */
export function toolOutputSchema(): typeof TOOL_RESULT_OUTPUT_SHAPE {
  return TOOL_RESULT_OUTPUT_SHAPE;
}
