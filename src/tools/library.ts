/**
 * Script library: save, list, run-by-name and export Frida scripts.
 *
 *   save_script         persist a classic/ESM source under the config dir (gated by allowCustomScripts)
 *   list_saved_scripts  enumerate what was saved, with metadata (no device)
 *   run_saved_script    load a saved script into a target, exactly like execute_script (gated)
 *   export_script       turn a source (inline or saved) into a STANDALONE classic `.js` that the
 *                       external frida/frida-tools 17 CLI can run with `frida -U -f <pkg> -l file.js`
 *
 * Scripts live under `dirname(getConfigPath())/scripts` — i.e. `~/.config/frida-mobile-mcp/scripts/`.
 * Each `<name>.js` is the raw source; its sibling `<name>.json` holds the metadata.
 */
import { z } from 'zod';
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { createHash } from 'node:crypto';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { getConfigPath } from '../config.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, CustomScriptDisabledError, wrapFridaError } from '../helpers/errors.js';
import { validateScriptSource, validateFilePath } from '../helpers/sanitize.js';
import { responseFormatSchema } from '../constants.js';
import { toolOutputSchema } from '../helpers/output-schema.js';
import { buildPreamble } from '../agent/preamble.js';
import { createAgentScript } from '../agent/script-factory.js';
import { compileEsmAgent } from '../agent/compiler.js';
import { detectSourceKind, resolveTimeoutMs, runGuarded } from './script.js';
import { attachScriptSinks } from '../helpers/script-sink.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { rateLimiter } from '../helpers/rate-limiter.js';
import { audit } from '../helpers/logger.js';

/** Legal saved-script names: a plain basename, no path separators or traversal. */
const SCRIPT_NAME_PATTERN = /^[A-Za-z0-9_-]+$/;
/** How long to collect output from a one-shot (non-persistent) saved script before unloading. */
const ONESHOT_COLLECT_MS = 2_000;

/** The directory saved scripts live in. Derived at call time so tests can redirect the config dir. */
export function savedScriptsDir(): string {
  return join(dirname(getConfigPath()), 'scripts');
}

/** Reject anything that is not a bare, filesystem-safe script name. */
function assertValidScriptName(name: string): void {
  if (!SCRIPT_NAME_PATTERN.test(name)) {
    throw new FridaMcpError(
      'INVALID_ARGUMENT',
      `Invalid script name "${name}". Use only letters, digits, underscores and hyphens (matching ${SCRIPT_NAME_PATTERN}).`,
      [{ tool: 'list_saved_scripts', reason: 'See the scripts already saved' }],
      { name }
    );
  }
}

interface SavedScriptMeta {
  name: string;
  description?: string;
  created: string;
  source_sha256: string;
  size: number;
}

function savedScriptPaths(name: string): { js: string; json: string } {
  const dir = savedScriptsDir();
  return { js: join(dir, `${name}.js`), json: join(dir, `${name}.json`) };
}

// --- save_script -----------------------------------------------------------

function registerSaveScriptTool(server: McpServer): void {
  server.registerTool(
    'save_script',
    {
      title: 'Save Frida Script',
      description:
        'Save a Frida script to the local library (~/.config/frida-mobile-mcp/scripts/) so it can be re-run later with run_saved_script or shared with export_script. Stores the raw source as <name>.js plus a <name>.json metadata file (sha256, size, created timestamp, description). Names are restricted to letters, digits, underscores and hyphens. Refuses to overwrite an existing script unless overwrite is true. Requires allowCustomScripts to be enabled in config.',
      inputSchema: z.object({
        name: z.string().describe('Script name (letters, digits, underscores, hyphens); used as the <name>.js filename'),
        source: z.string().describe('The Frida script source (classic JavaScript, an ES module, or a frida-compile bundle)'),
        description: z.string().optional().describe('Optional human-readable note stored in the metadata file'),
        overwrite: z.boolean().optional().default(false).describe('Replace an existing script of the same name (default: false)'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async ({ name, source, description, overwrite, response_format }) => {
      try {
        const state = getState();
        if (!state.config.allowCustomScripts) {
          throw new CustomScriptDisabledError();
        }

        assertValidScriptName(name);
        validateScriptSource(source);

        const dir = savedScriptsDir();
        const { js: jsPath, json: jsonPath } = savedScriptPaths(name);

        if (existsSync(jsPath) && !overwrite) {
          throw new FridaMcpError(
            'INVALID_ARGUMENT',
            `A script named "${name}" already exists. Pass overwrite: true to replace it.`,
            [
              { tool: 'save_script', args: { name, overwrite: true }, reason: 'Replace the existing script' },
              { tool: 'list_saved_scripts', reason: 'See what is already saved' },
            ],
            { name, path: jsPath }
          );
        }

        mkdirSync(dir, { recursive: true });

        const bytes = Buffer.byteLength(source, 'utf-8');
        const sourceSha256 = createHash('sha256').update(source).digest('hex').slice(0, 16);
        const meta: SavedScriptMeta = {
          name,
          ...(description ? { description } : {}),
          created: new Date().toISOString(),
          source_sha256: sourceSha256,
          size: bytes,
        };

        writeFileSync(jsPath, source, 'utf-8');
        writeFileSync(jsonPath, `${JSON.stringify(meta, null, 2)}\n`, 'utf-8');

        audit({
          timestamp: meta.created,
          tool: 'save_script',
          params: { name, overwrite, bytes },
          status: 'success',
          scriptHash: sourceSha256,
        });

        return formatToolResponse(
          buildResult(
            { name, path: jsPath, bytes, saved: true },
            [
              { tool: 'run_saved_script', args: { name }, reason: 'Load this script into a target process' },
              { tool: 'export_script', args: { name }, reason: 'Export a standalone .js for the plain frida CLI' },
            ],
            { coverage: { status: 'complete' } }
          ),
          response_format
        );
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}

// --- list_saved_scripts ----------------------------------------------------

interface SavedScriptListing {
  name: string;
  description: string | null;
  created: string | null;
  bytes: number;
  path: string;
}

/** Read the sibling metadata file if present; a missing or unparseable file is not fatal. */
function readSavedMeta(jsonPath: string): Partial<SavedScriptMeta> {
  if (!existsSync(jsonPath)) return {};
  try {
    return JSON.parse(readFileSync(jsonPath, 'utf-8')) as Partial<SavedScriptMeta>;
  } catch {
    return {};
  }
}

function registerListSavedScriptsTool(server: McpServer): void {
  server.registerTool(
    'list_saved_scripts',
    {
      title: 'List Saved Frida Scripts',
      description:
        'List the Frida scripts saved in the local library (~/.config/frida-mobile-mcp/scripts/) with their description, creation time and size. Returns an empty list when nothing has been saved yet. No device is required.',
      inputSchema: z.object({
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
    async ({ response_format }) => {
      try {
        const dir = savedScriptsDir();
        const scripts: SavedScriptListing[] = [];

        if (existsSync(dir)) {
          const entries = readdirSync(dir).filter((f) => f.endsWith('.js')).sort();
          for (const file of entries) {
            const name = file.slice(0, -'.js'.length);
            const { js: jsPath, json: jsonPath } = savedScriptPaths(name);
            const meta = readSavedMeta(jsonPath);
            let bytes = typeof meta.size === 'number' ? meta.size : 0;
            try {
              bytes = statSync(jsPath).size;
            } catch {
              /* keep the metadata size if stat fails */
            }
            scripts.push({
              name,
              description: meta.description ?? null,
              created: meta.created ?? null,
              bytes,
              path: jsPath,
            });
          }
        }

        return formatToolResponse(
          buildResult(
            { count: scripts.length, scripts },
            scripts.length > 0
              ? [{ tool: 'run_saved_script', args: { name: scripts[0].name }, reason: 'Run a saved script' }]
              : [{ tool: 'save_script', reason: 'Save a script to the library first' }],
            { coverage: { status: 'complete' } }
          ),
          response_format
        );
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}

// --- run_saved_script ------------------------------------------------------

/**
 * Turn a saved source into something createAgentScript accepts, mirroring execute_script's
 * prepareAgentSource: ESM is compiled to a 📦 bundle host-side; classic sources and existing
 * bundles pass straight through (createAgentScript composes the preamble/bridges for classic
 * code and passes bundles through untouched).
 */
async function prepareSavedSource(source: string, platform: string, name: string): Promise<string> {
  const kind = detectSourceKind(source, 'auto');
  if (kind === 'esm') {
    return compileEsmAgent(source, { platform, name });
  }
  return source;
}

function registerRunSavedScriptTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'run_saved_script',
    {
      title: 'Run Saved Frida Script',
      description:
        'Load a script previously saved with save_script into a target process. Resolves (or reuses) a session the same way execute_script does and runs the stored source as a custom agent: classic JavaScript gets the Java/ObjC bridges injected by platform, ES modules are compiled with the Frida Compiler, and frida-compile bundles are loaded as-is. Provide a target (app id, process name or PID) or an existing session_id. Requires allowCustomScripts to be enabled in config.',
      inputSchema: z.object({
        name: z.string().describe('Name of a saved script (see list_saved_scripts)'),
        target: z.string().optional().describe('App bundle ID, process name, or PID (optional when session_id is given)'),
        device: z.string().optional().describe('Device ID'),
        session_id: z.string().optional().describe('Reuse an existing session'),
        persistent: z.boolean().optional().default(true).describe('Keep script loaded (default: true). Set false for a one-shot run.'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ name, target, device, session_id, persistent, response_format }) => {
      const startTime = Date.now();
      try {
        const state = getState();
        if (!state.config.allowCustomScripts) {
          throw new CustomScriptDisabledError();
        }

        assertValidScriptName(name);
        if (!target && !session_id) {
          throw new FridaMcpError(
            'INVALID_ARGUMENT',
            'Provide a target (app id, process name or PID) or an existing session_id.',
            [{ tool: 'get_status', reason: 'List active sessions to reuse one' }],
            { name }
          );
        }

        const { js: jsPath } = savedScriptPaths(name);
        if (!existsSync(jsPath)) {
          throw new FridaMcpError(
            'SCRIPT_NOT_FOUND',
            `No saved script named "${name}".`,
            [
              { tool: 'list_saved_scripts', reason: 'See the scripts that are saved' },
              { tool: 'save_script', args: { name }, reason: 'Save a script under this name first' },
            ],
            { name, path: jsPath }
          );
        }
        const source = readFileSync(jsPath, 'utf-8');

        rateLimiter.check('script', state.config.rateLimits.scriptsPerMinute);
        rateLimiter.record('script');

        const { sessionEntry } = await getOrCreateSession(deviceManager, {
          target: target ?? '',
          device,
          sessionId: session_id,
        });

        const keepLoaded = persistent ?? true;
        const timeoutMs = resolveTimeoutMs(undefined, keepLoaded);
        const scriptName = `saved:${name}`;

        const prepared = await prepareSavedSource(source, sessionEntry.platform, name);
        const script = await createAgentScript(sessionEntry.session, {
          sessionEntry,
          source: prepared,
          platform: sessionEntry.platform,
          name: scriptName,
          kind: 'user',
        });

        const scriptId = state.generateId();
        const messages: Array<Record<string, unknown>> = [];

        sessionEntry.scripts.set(scriptId, {
          id: scriptId,
          script,
          messages: [],
          name: scriptName,
          persistent: keepLoaded,
          createdAt: Date.now(),
        });

        attachScriptSinks(script, sessionEntry.id, scriptId, {
          onEntry: (entry) => messages.push({ type: entry.type, payload: entry.payload }),
        });

        try {
          await runGuarded(script, script.load(), timeoutMs, scriptId, messages);
          if (!keepLoaded) {
            await new Promise((resolve) => setTimeout(resolve, ONESHOT_COLLECT_MS));
            await runGuarded(script, script.unload(), timeoutMs, scriptId, messages);
            sessionEntry.scripts.delete(scriptId);
          }
        } catch (err) {
          sessionEntry.scripts.delete(scriptId);
          throw err;
        }

        audit({
          timestamp: new Date().toISOString(),
          sessionId: sessionEntry.id,
          tool: 'run_saved_script',
          params: { name, target, persistent: keepLoaded },
          status: 'success',
          durationMs: Date.now() - startTime,
        });

        return formatToolResponse(
          buildResult(
            {
              script_id: scriptId,
              session_id: sessionEntry.id,
              name,
              persistent: keepLoaded,
              messages_received: messages.length,
              messages: messages.slice(0, 50),
            },
            keepLoaded
              ? [
                  { tool: 'get_messages', args: { session_id: sessionEntry.id }, reason: 'Retrieve script output' },
                  { tool: 'stop_instrumentation', args: { session_id: sessionEntry.id }, reason: 'Stop and clean up' },
                ]
              : [{ tool: 'run_saved_script', args: { name }, reason: 'Run it again' }]
          ),
          response_format
        );
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}

// --- export_script ---------------------------------------------------------

/** Header comment prepended to an exported standalone script. */
function exportHeader(pkg: string, platform: 'android' | 'ios'): string {
  const bridge = platform === 'ios' ? 'ObjC' : 'Java';
  return [
    '// ===========================================================================',
    '// Standalone Frida script exported by frida-mobile-mcp (export_script).',
    '//',
    '// Run it with the external Frida 17 CLI, e.g.:',
    `//   frida -U -f ${pkg} -l <file>        # spawn and instrument`,
    `//   frida -U -n <process-name> -l <file>  # attach to a running process`,
    '//',
    '// This file bundles the frida-mobile-mcp preamble helpers (findExport, hookNative,',
    '// javaPerform, objcClassNames, reportSummary) and the script body, but it does NOT',
    `// bundle the ${bridge}/bridge runtime. It relies on the external frida / frida-tools 17`,
    `// CLI to auto-inject the Java (Android) / ObjC (iOS/macOS) bridges. The preamble's`,
    "// bridge stub guards with `if (typeof Java === 'undefined')`, so it will NOT clobber a",
    '// CLI-provided bridge; but if you run this under a CLI that did NOT inject the bridge,',
    `// any body using ${bridge} hits the \`{ available: false }\` stub and silently no-ops.`,
    '// ===========================================================================',
  ].join('\n');
}

function registerExportScriptTool(server: McpServer): void {
  server.registerTool(
    'export_script',
    {
      title: 'Export Standalone Frida Script',
      description:
        'Turn a Frida script into a STANDALONE classic .js file that the plain frida / frida-tools 17 CLI can run with `frida -U -f <package> -l file.js`, without this MCP server. The output is a header comment + the frida-mobile-mcp preamble helpers + the script body. Provide exactly one of source (inline) or name (a saved script). It does NOT bundle the Java/ObjC bridges (the Frida 17 CLI injects those) and does NOT emit TypeScript. With out_path the file is written and its path returned; otherwise the text is returned inline. This tool only transforms text, so it does not require allowCustomScripts.',
      inputSchema: z.object({
        source: z.string().optional().describe('Inline script source to export (mutually exclusive with name)'),
        name: z.string().optional().describe('Name of a saved script to export (mutually exclusive with source)'),
        package: z.string().optional().describe('Target package/bundle id, used only in the `frida -U -f <package>` example line'),
        platform: z.enum(['android', 'ios']).default('android').describe('Target platform for the preamble bridge stubs (default: android)'),
        out_path: z.string().optional().describe('Write the standalone script to this file path instead of returning it inline'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async ({ source, name, package: pkg, platform, out_path, response_format }) => {
      try {
        if ((source && name) || (!source && !name)) {
          throw new FridaMcpError(
            'INVALID_ARGUMENT',
            'Provide exactly one of "source" (inline) or "name" (a saved script).',
            [{ tool: 'list_saved_scripts', reason: 'See the saved scripts you can export by name' }],
            { has_source: Boolean(source), has_name: Boolean(name) }
          );
        }

        let body: string;
        let label: string;
        if (name) {
          assertValidScriptName(name);
          const { js: jsPath } = savedScriptPaths(name);
          if (!existsSync(jsPath)) {
            throw new FridaMcpError(
              'SCRIPT_NOT_FOUND',
              `No saved script named "${name}".`,
              [{ tool: 'list_saved_scripts', reason: 'See the scripts that are saved' }],
              { name, path: jsPath }
            );
          }
          body = readFileSync(jsPath, 'utf-8');
          label = name;
        } else {
          body = source as string;
          label = 'inline';
        }

        validateScriptSource(body);

        const targetPackage = pkg ?? '<package>';
        const preamble = buildPreamble({
          name: `exported:${label}`,
          platform,
          options: {},
          injectedBridges: [],
        });
        const exported = `${exportHeader(targetPackage, platform)}\n${preamble}\n${body}\n`;
        const bytes = Buffer.byteLength(exported, 'utf-8');

        if (out_path) {
          validateFilePath(out_path);
          writeFileSync(out_path, exported, 'utf-8');
          return formatToolResponse(
            buildResult(
              { exported: true, path: out_path, bytes },
              [{ tool: 'export_script', reason: 'Export another script' }],
              { coverage: { status: 'complete' } }
            ),
            response_format
          );
        }

        return formatToolResponse(
          buildResult(
            { exported: true, inline_text: exported, bytes },
            [{ tool: 'export_script', args: { out_path: `${label}.js` }, reason: 'Write the exported script to a file' }],
            { coverage: { status: 'complete' } }
          ),
          response_format
        );
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}

/** Register the four script-library tools. Wired from register-all.ts. */
export function registerLibraryTools(server: McpServer, deviceManager: DeviceManager): void {
  registerSaveScriptTool(server);
  registerListSavedScriptsTool(server);
  registerRunSavedScriptTool(server, deviceManager);
  registerExportScriptTool(server);
}
