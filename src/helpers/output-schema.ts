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
  coverage: z.object({ status: z.enum(['complete', 'unknown']), note: z.string().optional() }).optional(),
  raw_result: z.unknown().optional(),
});

/**
 * Output schema to pass to `registerTool`. Returns `undefined` when the configured schema
 * profile is `compact` (FRIDA_MCP_SCHEMA_PROFILE=compact) so size-limited hosts receive a
 * smaller tool catalog; `full` (default) advertises the envelope schema.
 */
export function toolOutputSchema(): typeof TOOL_RESULT_OUTPUT_SHAPE | undefined {
  const profile = process.env.FRIDA_MCP_SCHEMA_PROFILE?.trim().toLowerCase();
  return profile === 'compact' ? undefined : TOOL_RESULT_OUTPUT_SHAPE;
}
