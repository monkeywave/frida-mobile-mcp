/**
 * Evidence store tools: re-read one persisted tool result by its `evidence_id`, or export a
 * set of them as a JSON / Markdown bundle (inline or to a host file).
 */
import { writeFileSync } from 'node:fs';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/server';
import { toolOutputSchema } from '../helpers/output-schema.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { responseFormatSchema } from '../constants.js';
import {
  buildEvidenceBundle,
  getEvidence,
  getEvidenceRoot,
  isEvidenceStoreEnabled,
  listEvidence,
  renderBundle,
} from '../helpers/evidence-store.js';
import { defaultDumpRoots, resolveDumpOutputPath } from './advanced/native.js';

/** Default record count when the bundle is written to `out_path`. */
export const DEFAULT_EXPORT_LIMIT = 200;
/** Default record count when the bundle is returned inline (it lands in the model's context). */
export const DEFAULT_INLINE_EXPORT_LIMIT = 20;
export const MAX_EXPORT_LIMIT = 1000;

function storeDisabledError(): FridaMcpError {
  return new FridaMcpError(
    'EVIDENCE_NOT_FOUND',
    'The evidence store is disabled, so no tool results are persisted.',
    [{ action: 'user_intervention', message: 'Enable it with FRIDA_MCP_EVIDENCE=1 or "evidence": { "enabled": true } in ~/.config/frida-mobile-mcp/config.json' }],
  );
}

export function registerEvidenceTools(server: McpServer): void {
  registerGetEvidenceTool(server);
  registerExportEvidenceBundleTool(server);
}

function registerGetEvidenceTool(server: McpServer): void {
  server.registerTool(
    'get_evidence',
    {
      title: 'Get Evidence Record',
      description: 'Return the persisted record of an earlier tool call by its evidence_id (from the result envelope or `_meta.evidence_id`): tool, redacted parameters, status, session, device, duration, script SHA-256 and the full structured result or error body. Records survive server restarts until evicted by the evidence size limits.',
      inputSchema: z.object({
        evidence_id: z.string().min(1).describe('The evidence_id of an earlier tool result'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ evidence_id, response_format }) => {
      try {
        if (!isEvidenceStoreEnabled()) throw storeDisabledError();
        const record = getEvidence(evidence_id);
        if (!record) {
          throw new FridaMcpError(
            'EVIDENCE_NOT_FOUND',
            `No evidence record "${evidence_id}" (unknown id, or evicted by the evidence size limits).`,
            [{ tool: 'export_evidence_bundle', reason: 'List recent records by session or time instead' }],
            { evidence_id },
          );
        }
        return formatToolResponse(buildResult({ record }, [], { coverage: { status: 'complete' } }), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );
}

/** Ids to export: the explicit list, else the newest matches of the filters in chronological order. */
function selectEvidenceIds(opts: { evidence_ids?: string[]; session_id?: string; since?: string | number; limit: number }): string[] {
  if (opts.evidence_ids && opts.evidence_ids.length > 0) return opts.evidence_ids.slice(0, opts.limit);
  return listEvidence({ session_id: opts.session_id, since: opts.since, limit: opts.limit }).map((row) => row.id).reverse();
}

function writeBundle(outPath: string, text: string): string {
  const evidenceRoot = getEvidenceRoot();
  const roots = evidenceRoot ? [...defaultDumpRoots(), evidenceRoot] : defaultDumpRoots();
  const resolved = resolveDumpOutputPath(outPath, roots);
  writeFileSync(resolved, text, { mode: 0o600 });
  return resolved;
}

function registerExportEvidenceBundleTool(server: McpServer): void {
  server.registerTool(
    'export_evidence_bundle',
    {
      title: 'Export Evidence Bundle',
      description: 'Export persisted tool results as one JSON or Markdown report for a write-up or for a static-analysis tool. Select records by explicit evidence_ids, or by session_id and/or since (newest `limit` matches, exported oldest first). With out_path (absolute, under the current directory, the OS temp directory, ~/.config/frida-mobile-mcp/dumps or the evidence directory) the bundle is written to that file (mode 0600); otherwise it is returned inline.',
      inputSchema: z.object({
        evidence_ids: z.array(z.string().min(1)).optional().describe('Explicit evidence ids to export (in this order); overrides the filters'),
        session_id: z.string().optional().describe('Only records of this session'),
        since: z.union([z.string(), z.number()]).optional().describe('Only records at or after this time: ISO timestamp or epoch milliseconds'),
        limit: z.number().int().min(1).max(MAX_EXPORT_LIMIT).optional().describe(`Max records (default ${DEFAULT_EXPORT_LIMIT} with out_path, ${DEFAULT_INLINE_EXPORT_LIMIT} inline, max ${MAX_EXPORT_LIMIT})`),
        format: z.enum(['json', 'markdown']).default('json').describe('Bundle format: "json" (default) or a "markdown" report'),
        out_path: z.string().optional().describe('Absolute host path to write the bundle to instead of returning it inline'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ evidence_ids, session_id, since, limit, format, out_path, response_format }) => {
      try {
        if (!isEvidenceStoreEnabled()) throw storeDisabledError();
        const ids = selectEvidenceIds({ evidence_ids, session_id, since, limit: limit ?? (out_path ? DEFAULT_EXPORT_LIMIT : DEFAULT_INLINE_EXPORT_LIMIT) });
        const bundle = buildEvidenceBundle(ids);
        const limitations = bundle.missing?.length ? [`${bundle.missing.length} requested id(s) not found: ${bundle.missing.join(', ')}`] : [];
        if (out_path) {
          const text = renderBundle(bundle, format);
          const written = writeBundle(out_path, text);
          const result = { count: bundle.count, out_path: written, bytes: Buffer.byteLength(text, 'utf-8'), format };
          return formatToolResponse(buildResult(result, [], { limitations }), response_format);
        }
        const inline = format === 'json' ? bundle : renderBundle(bundle, format);
        return formatToolResponse(buildResult({ count: bundle.count, format, bundle: inline }, [], { limitations }), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    },
  );
}
