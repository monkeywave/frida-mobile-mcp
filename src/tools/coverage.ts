import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { attachScriptSinks } from '../helpers/script-sink.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../helpers/errors.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { responseFormatSchema } from '../constants.js';
import { createAgentScript } from '../agent/script-factory.js';
import { resolveInstrumentationTarget, INTERCEPTOR_TARGET_SNIPPET } from './hook.js';
import { GLOB_HELPER } from './trace.js';
import type { BridgeName } from '../agent/bridges.js';
import { callRpcWithTimeout } from '../helpers/rpc-timeout.js';
import type { CoverageEntry } from '../types.js';

const NO_BRIDGES: BridgeName[] = [];
const DEFAULT_MAX_TARGETS = 300;

type CoverageKind = 'java' | 'native' | 'objc';

interface ArmResult {
  targets?: string[];
  attempted?: number;
  installed?: number;
  skipped?: number;
  error?: string;
}

export function registerCoverageTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'trace_coverage',
    {
      title: 'Trace Coverage (Reachability Map)',
      description:
        'Arm a broad set of cheap entry-hooks over a target set and track which have been REACHED (covered) vs which are still COLD — the reachability signal for a drive loop. Unlike trace_method (time-boxed, logs every call), this is persistent and entry-only: it answers "what code have I NOT exercised yet, so where should I keep driving?". Scope can be a single class (all its methods), a class/package glob ("com.example.*"), a native module glob ("libfoo.so!*"), or an ObjC pattern ("-[MyClass *]"). Workflow: arm it, then alternate trigger_and_wait (drive the UI) with trace_coverage {report_only:true} to watch the cold set shrink. Each target fires at most once (first-seen), so hot methods do not flood output.',
      inputSchema: z.object({
        target: z.string().optional().describe('App bundle ID, process name, or PID. Optional when session_id is given.'),
        session_id: z.string().optional().describe('Reuse an existing session (from explore_app/get_status).'),
        device: z.string().optional().describe('Device ID'),
        scope: z
          .string()
          .optional()
          .describe('What to cover: a class ("com.example.Crypto"), a class/package glob ("com.example.*"), a native module glob ("libfoo.so!*"), or an ObjC pattern ("-[MyClass *]"). Required unless report_only.'),
        max_targets: z.number().optional().describe(`Cap the number of hooked targets (default: ${DEFAULT_MAX_TARGETS}).`),
        report_only: z.boolean().optional().describe('Do not arm anything; just read the covered/cold map of an existing coverage run (the latest for this session, or coverage_id).'),
        coverage_id: z.string().optional().describe('Which coverage run to report on (defaults to the most recent for the session).'),
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
    async ({ target, session_id, device, scope, max_targets, report_only, coverage_id, response_format }) => {
      try {
        const state = getState();

        // ---- report_only: read an existing run, no instrumentation ----
        if (report_only) {
          const resolvedSessionId = resolveSessionIdForReport(session_id, coverage_id);
          const entry = findCoverageEntry(resolvedSessionId, coverage_id);
          if (!entry) {
            throw new FridaMcpError('COVERAGE_NOT_FOUND', 'No coverage run found. Arm one first with trace_coverage {scope: "..."}.', [
              { tool: 'trace_coverage', args: { session_id: resolvedSessionId ?? session_id, scope: 'com.example.*' }, reason: 'Arm a coverage run' },
            ]);
          }
          return formatToolResponse(buildResult(shapeReport(entry), reportActions(entry)), response_format);
        }

        // ---- arm: install the broad entry-hook set ----
        if (!scope) {
          throw new FridaMcpError('INVALID_ARGUMENT', 'scope is required to arm coverage (e.g. "com.example.*" or "libfoo.so!*").', []);
        }
        const resolved = resolveInstrumentationTarget(target, session_id);
        const { sessionEntry } = await getOrCreateSession(deviceManager, { target: resolved.target, device, sessionId: resolved.sessionId });

        const kind = detectCoverageKind(scope);
        const maxTargets = max_targets ?? DEFAULT_MAX_TARGETS;
        const options = buildCoverageOptions(scope, kind, maxTargets, resolved.target);

        const script = await createAgentScript(sessionEntry.session, {
          sessionEntry,
          source: generateCoverageScript(kind),
          platform: sessionEntry.platform,
          name: `coverage:${scope}`,
          kind: 'generated',
          options: { ...options, platform: sessionEntry.platform },
          bridges: kind === 'native' ? NO_BRIDGES : undefined,
        });

        const scriptId = state.generateId();
        const coverageId = state.generateId();

        // Store the entry first so the streaming `cov` hits (which arrive later, once the app runs
        // the hooked code via trigger_and_wait) land in a map that already exists.
        const entry: CoverageEntry = {
          id: coverageId,
          scriptId,
          sessionId: sessionEntry.id,
          scope,
          allTargets: [],
          hits: new Map(),
          createdAt: Date.now(),
        };
        state.coverage.set(coverageId, entry);

        sessionEntry.scripts.set(scriptId, { id: scriptId, script, messages: [], name: `coverage:${scope}`, persistent: true, createdAt: Date.now() });
        attachScriptSinks(script, sessionEntry.id, scriptId, {
          onSend: (payload, data) => {
            const p = payload as { cov?: string } | null;
            if (p && typeof p.cov === 'string' && !entry.hits.has(p.cov)) {
              // The agent sends each target's `cov` at most once (DEDUPE_HELPER), so this is a
              // first-seen marker, not a call counter — `hits` is always 1 (= "reached").
              entry.hits.set(p.cov, { hits: 1, firstSeenTs: Date.now() });
            }
            state.addMessageToScript(sessionEntry.id, scriptId, { timestamp: Date.now(), type: 'coverage_hit', payload, data: data ?? null });
          },
        });

        await script.load();
        let armed: ArmResult;
        try {
          armed = await callRpcWithTimeout(script.exports.arm() as Promise<ArmResult>, 'Coverage arm', 60_000);
        } catch (err) {
          state.coverage.delete(coverageId);
          throw err;
        }
        if (armed.error) {
          state.coverage.delete(coverageId);
          throw new FridaMcpError('COVERAGE_ARM_FAILED', `Could not arm coverage: ${armed.error}`, [
            { tool: 'explore_app', args: { session_id: sessionEntry.id }, reason: 'Check the scope exists (class loaded? module present?)' },
          ]);
        }
        entry.allTargets = armed.targets ?? [];

        return formatToolResponse(
          buildResult(
            {
              session_id: sessionEntry.id,
              coverage_id: coverageId,
              scope,
              kind,
              targets_installed: armed.installed ?? entry.allTargets.length,
              targets_attempted: armed.attempted ?? entry.allTargets.length,
              targets_skipped: armed.skipped ?? 0,
              covered_count: 0,
              cold_count: entry.allTargets.length,
              cold_sample: entry.allTargets.slice(0, 50),
              truncated_targets: entry.allTargets.length > 50,
            },
            [
              { tool: 'trigger_and_wait', args: { session_id: sessionEntry.id, action: 'mobile_list_elements_on_screen' }, reason: 'Drive the app to reach cold targets' },
              { tool: 'trace_coverage', args: { session_id: sessionEntry.id, report_only: true, coverage_id: coverageId }, reason: 'Re-check what is now covered vs still cold' },
            ],
            entry.allTargets.length === 0
              ? { limitations: ['No targets matched the scope. The class may not be loaded yet (drive the app first) or the module may not be present — widen the scope or retry.'] }
              : {},
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

/** For report_only: prefer the session carrying the named coverage run, else the requested session. */
function resolveSessionIdForReport(sessionId: string | undefined, coverageId: string | undefined): string | undefined {
  if (coverageId) {
    const entry = getState().coverage.get(coverageId);
    if (entry) return entry.sessionId;
  }
  return sessionId;
}

/** The named coverage run, or the most recent run for the session. */
function findCoverageEntry(sessionId: string | undefined, coverageId: string | undefined): CoverageEntry | undefined {
  const state = getState();
  if (coverageId) return state.coverage.get(coverageId);
  if (!sessionId) return undefined;
  let latest: CoverageEntry | undefined;
  for (const entry of state.coverage.values()) {
    if (entry.sessionId === sessionId && (!latest || entry.createdAt > latest.createdAt)) latest = entry;
  }
  return latest;
}

const MAX_REPORT_LIST = 200;

function shapeReport(entry: CoverageEntry): Record<string, unknown> {
  // Every hit is covered — including targets that fired but were not in the originally-armed set
  // (e.g. an extra overload id) — so one pass over `hits` is the full covered list. Cold is the
  // armed targets that never fired.
  const covered = Array.from(entry.hits, ([target, info]) => ({ target, hits: info.hits, first_seen: info.firstSeenTs }));
  const cold = entry.allTargets.filter((t) => !entry.hits.has(t));
  const total = entry.allTargets.length;
  return {
    coverage_id: entry.id,
    session_id: entry.sessionId,
    scope: entry.scope,
    total_targets: total,
    covered_count: covered.length,
    cold_count: cold.length,
    coverage_pct: total > 0 ? Math.round((covered.length / total) * 1000) / 10 : 0,
    covered: covered.slice(0, MAX_REPORT_LIST),
    cold: cold.slice(0, MAX_REPORT_LIST),
    truncated: covered.length > MAX_REPORT_LIST || cold.length > MAX_REPORT_LIST,
  };
}

function reportActions(entry: CoverageEntry): Array<{ tool: string; args: Record<string, unknown>; reason: string }> {
  return [
    { tool: 'trigger_and_wait', args: { session_id: entry.sessionId, action: 'mobile_list_elements_on_screen' }, reason: 'Drive further to cover the cold set' },
    { tool: 'trace_coverage', args: { session_id: entry.sessionId, report_only: true, coverage_id: entry.id }, reason: 'Re-check coverage after driving' },
  ];
}

export function detectCoverageKind(scope: string): CoverageKind {
  if (scope.startsWith('-[') || scope.startsWith('+[')) return 'objc';
  if (scope.includes('!')) return 'native';
  return 'java';
}

/** Split the scope into the fields the agent reads from __FRIDA_MCP__.options (never spliced into code). */
export function buildCoverageOptions(scope: string, kind: CoverageKind, maxTargets: number, resolvedTarget: string): Record<string, unknown> {
  const base: Record<string, unknown> = { kind, maxTargets };
  if (kind === 'native') {
    const [moduleName, funcGlob] = scope.split('!');
    return { ...base, moduleName, funcGlob: funcGlob || '*' };
  }
  if (kind === 'objc') {
    return { ...base, objcPattern: scope };
  }
  // java: a wildcard means a class/package glob; otherwise an exact class (hook all its methods).
  if (scope.includes('*')) return { ...base, classGlob: scope, className: null };
  return { ...base, className: scope, classGlob: null };
}

const DEDUPE_HELPER = `
  var _covFired = {};
  function onHit(id) { if (!_covFired[id]) { _covFired[id] = 1; send({ cov: id }); } }
`;

const JAVA_COVERAGE_SCRIPT = `
(function () {
  var o = __FRIDA_MCP__.options;
  ${GLOB_HELPER}
  ${DEDUPE_HELPER}
  rpc.exports.arm = function () {
    if (typeof Java === 'undefined' || !Java.available) return { error: 'java_unavailable', targets: [], attempted: 0, installed: 0, skipped: 0 };
    var re = null;
    if (o.classGlob) { try { re = globToRegExp(o.classGlob); } catch (e) { return { error: 'bad_glob: ' + e.message, targets: [], attempted: 0, installed: 0, skipped: 0 }; } }
    return javaPerform(function () {
      var classNames = [];
      if (o.className) classNames = [o.className];
      else Java.enumerateLoadedClasses({ onMatch: function (n) { if (n.charAt(0) !== '[' && re.test(n)) classNames.push(n); }, onComplete: function () {} });

      var targets = [], attempted = 0, installed = 0, skipped = 0;
      for (var c = 0; c < classNames.length && targets.length < o.maxTargets; c++) {
        var cn = classNames[c];
        try {
          var cls = Java.use(cn);
          var methods = cls.class.getDeclaredMethods();
          var seenNames = {};
          for (var mi = 0; mi < methods.length; mi++) seenNames[methods[mi].getName()] = 1;
          var names = Object.keys(seenNames);
          for (var ni = 0; ni < names.length && targets.length < o.maxTargets; ni++) {
            var mn = names[ni];
            var id = cn + '.' + mn;
            attempted++;
            try {
              var overloads = cls[mn].overloads;
              overloads.forEach(function (ov) {
                (function (id) {
                  ov.implementation = function () { onHit(id); return ov.apply(this, arguments); };
                })(id);
              });
              targets.push(id); installed++;
            } catch (e) { skipped++; }
          }
        } catch (e) { skipped++; }
      }
      return { targets: targets, attempted: attempted, installed: installed, skipped: skipped };
    });
  };
})();
`;

const NATIVE_COVERAGE_SCRIPT = `
(function () {
  var o = __FRIDA_MCP__.options;
  ${GLOB_HELPER}
  ${DEDUPE_HELPER}
  ${INTERCEPTOR_TARGET_SNIPPET}
  rpc.exports.arm = function () {
    var re; try { re = globToRegExp(o.funcGlob); } catch (e) { return { error: 'bad_glob: ' + e.message, targets: [], attempted: 0, installed: 0, skipped: 0 }; }
    var m = Process.findModuleByName(o.moduleName);
    if (!m) return { error: 'module_not_found: ' + o.moduleName, targets: [], attempted: 0, installed: 0, skipped: 0 };
    var exps = m.enumerateExports().filter(function (e) { return e.type === 'function' && re.test(e.name); });
    var targets = [], attempted = 0, installed = 0, skipped = 0;
    for (var i = 0; i < exps.length && targets.length < o.maxTargets; i++) {
      var id = o.moduleName + '!' + exps[i].name;
      attempted++;
      try {
        (function (id, addr) { Interceptor.attach(interceptorTarget(addr), { onEnter: function () { onHit(id); } }); })(id, exps[i].address);
        targets.push(id); installed++;
      } catch (e) { skipped++; }
    }
    return { targets: targets, attempted: attempted, installed: installed, skipped: skipped };
  };
})();
`;

const OBJC_COVERAGE_SCRIPT = `
(function () {
  var o = __FRIDA_MCP__.options;
  ${DEDUPE_HELPER}
  rpc.exports.arm = function () {
    if (typeof ObjC === 'undefined' || !ObjC.available) return { error: 'objc_unavailable', targets: [], attempted: 0, installed: 0, skipped: 0 };
    var matches;
    try { matches = new ApiResolver('objc').enumerateMatches(o.objcPattern); } catch (e) { return { error: 'bad_pattern: ' + e.message, targets: [], attempted: 0, installed: 0, skipped: 0 }; }
    var targets = [], attempted = 0, installed = 0, skipped = 0;
    for (var i = 0; i < matches.length && targets.length < o.maxTargets; i++) {
      var id = matches[i].name;
      attempted++;
      try {
        (function (id, addr) { Interceptor.attach(addr, { onEnter: function () { onHit(id); } }); })(id, matches[i].address);
        targets.push(id); installed++;
      } catch (e) { skipped++; }
    }
    return { targets: targets, attempted: attempted, installed: installed, skipped: skipped };
  };
})();
`;

/** Body for a coverage kind. Pattern/flags come from __FRIDA_MCP__.options at runtime. */
export function generateCoverageScript(kind: CoverageKind): string {
  switch (kind) {
    case 'objc':
      return OBJC_COVERAGE_SCRIPT;
    case 'native':
      return NATIVE_COVERAGE_SCRIPT;
    case 'java':
      return JAVA_COVERAGE_SCRIPT;
  }
}
