/**
 * `validate_script`: syntax / type / removed-API check for a Frida script without a device.
 *
 *   classic  -> compile-only parse with node:vm plus the Frida 17 removed-API lint
 *   esm      -> frida-node Compiler diagnostics (strict = full type check)
 *   bundle   -> frida-compile output (📦 marker), accepted as-is
 */
import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import type { McpServer } from '@modelcontextprotocol/server';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError, ScriptError } from '../helpers/errors.js';
import { validateFilePath, validateScriptSource as assertScriptSourceLimits } from '../helpers/sanitize.js';
import { responseFormatSchema } from '../constants.js';
import { isFridaCompileBundle, looksLikeEsModule } from '../agent/script-factory.js';
import { getCompilerDiagnostics, type CompilerDiagnostic, type CompilerLanguage } from '../agent/compiler.js';
import { findRemovedApis } from '../agent/lint.js';
import type { SuggestedAction } from '../types.js';

export type ValidatedScriptKind = 'classic' | 'esm' | 'bundle';

export interface ValidateScriptInput {
  source?: string;
  file_path?: string;
  platform?: 'android' | 'ios';
  /** Full type check for ESM sources (default true). */
  strict?: boolean;
  language?: CompilerLanguage;
  /** Display name used in diagnostics; defaults to the file basename or 'inline'. */
  name?: string;
}

export interface ValidateScriptResult {
  ok: boolean;
  kind: ValidatedScriptKind;
  diagnostics: CompilerDiagnostic[];
  removed_apis: ReturnType<typeof findRemovedApis>;
}

const DEFAULT_NAME = 'inline';

export function detectScriptKind(source: string): ValidatedScriptKind {
  if (isFridaCompileBundle(source)) return 'bundle';
  if (looksLikeEsModule(source)) return 'esm';
  return 'classic';
}

function readScriptSource(input: ValidateScriptInput): string {
  if (input.source) return input.source;
  if (!input.file_path) throw new ScriptError('Either source or file_path must be provided');
  validateFilePath(input.file_path);
  try {
    return readFileSync(input.file_path, 'utf-8');
  } catch {
    throw new ScriptError(`Cannot read file: ${input.file_path}`);
  }
}

function displayNameFor(input: ValidateScriptInput): string {
  if (input.name) return input.name;
  return input.file_path ? basename(input.file_path) : DEFAULT_NAME;
}

/** Best-effort `line` from the first stack line (`<file>:<line>`) and `column` from the caret line. */
function locateSyntaxError(err: Error, filename: string): { line: number | null; column: number | null } {
  const lines = (err.stack ?? '').split('\n');
  const header = lines[0]?.match(new RegExp(`^${escapeRegExp(filename)}:(\\d+)$`));
  const line = header ? Number(header[1]) : null;
  const caret = lines.find((l) => /^\s*\^+\s*$/.test(l));
  const column = caret ? caret.indexOf('^') + 1 : null;
  return { line, column };
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function checkClassicSyntax(source: string, name: string): CompilerDiagnostic[] {
  try {
    new vm.Script(source, { filename: name });
    return [];
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));
    const { line, column } = locateSyntaxError(error, name);
    return [{ severity: 'error', message: error.message, file: name, line, column, code: null }];
  }
}

async function diagnosticsFor(kind: ValidatedScriptKind, source: string, input: ValidateScriptInput, name: string): Promise<CompilerDiagnostic[]> {
  switch (kind) {
    case 'bundle':
      return [];
    case 'classic':
      return checkClassicSyntax(source, name);
    case 'esm': {
      const result = await getCompilerDiagnostics(source, {
        platform: input.platform ?? 'android',
        name,
        typeCheck: input.strict === false ? 'none' : 'full',
        language: input.language,
      });
      return result.diagnostics;
    }
  }
}

/**
 * Validate a script without a device. `ok` is false when there are error diagnostics or when
 * removed Frida APIs are referenced, because those throw at runtime on Frida 17.
 */
export async function validateScriptSource(input: ValidateScriptInput): Promise<ValidateScriptResult> {
  const source = readScriptSource(input);
  assertScriptSourceLimits(source);
  const name = displayNameFor(input);
  const kind = detectScriptKind(source);
  const diagnostics = await diagnosticsFor(kind, source, input, name);
  const removed_apis = kind === 'bundle' ? [] : findRemovedApis(source);
  const hasErrors = diagnostics.some((d) => d.severity === 'error');
  return { ok: !hasErrors && removed_apis.length === 0, kind, diagnostics, removed_apis };
}

function suggestedActionsFor(result: ValidateScriptResult): SuggestedAction[] {
  if (result.ok) {
    return [{ tool: 'execute_script', reason: 'Run the validated script in a target process' }];
  }
  const reason = result.removed_apis.length > 0 ? 'See Frida 17 API replacements' : 'See script examples';
  return [{ tool: 'frida_help', args: { topic: 'examples' }, reason }];
}

export function registerValidateTool(server: McpServer): void {
  server.registerTool(
    'validate_script',
    {
      title: 'Validate Frida Script',
      description: 'Check a Frida script for syntax, type and Frida 17 API problems without a device. Use it before execute_script. Classic (non-module) scripts get a JavaScript syntax check plus a lint for APIs removed in Frida 17 (static Module/Memory helpers, *Sync enumerators); referencing them throws at runtime, so they make the result not ok. ES module scripts (import/export) are compiled with the Frida Compiler: strict (default) runs a full TypeScript type check; plain JavaScript is only syntax-checked unless language is "ts". frida-compile bundles (source starting with the 📦 marker) are accepted as-is. Provide either inline source or a file path.',
      inputSchema: z.object({
        source: z.string().optional().describe('Inline script source'),
        file_path: z.string().optional().describe('Path to a .js/.ts Frida script file'),
        platform: z.enum(['android', 'ios']).default('android').describe('Target platform (default: android)'),
        strict: z.boolean().default(true).describe('Full type check for ES module sources (default: true)'),
        language: z.enum(['auto', 'ts', 'js']).default('auto').describe('ESM loader: "ts" type-checks strictly, "js" syntax-only, "auto" sniffs the source'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ source, file_path, platform, strict, language, response_format }) => {
      try {
        const result = await validateScriptSource({ source, file_path, platform, strict, language });
        return formatToolResponse(buildResult(result, suggestedActionsFor(result)), response_format);
      } catch (err) {
        const wrapped = wrapFridaError(err);
        return formatToolResponse(wrapped.toErrorResponse(), response_format);
      }
    }
  );
}
