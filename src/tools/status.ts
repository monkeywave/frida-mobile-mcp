import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError } from '../helpers/errors.js';
import { log } from '../helpers/logger.js';
import { responseFormatSchema } from '../constants.js';
import { isToolExposed, policyFromConfig, type ExposurePolicy } from './tool-gate.js';
import { TOOL_EFFECTS } from './effects.js';
import type { SessionEntry, DetachRecord, HookLiveness } from '../types.js';

const RECENT_DETACH_LIMIT = 5;

/** Names of the known tools that `policy` keeps out of the catalog, sorted. */
export function hiddenToolNames(policy: ExposurePolicy): string[] {
  return Object.keys(TOOL_EFFECTS)
    .filter((name) => !isToolExposed(name, policy))
    .sort();
}

/** Limitation note when the tool profile / exclude list hid tools from this catalog. */
export function hiddenToolsLimitations(hiddenTools: number): string[] | undefined {
  return hiddenTools > 0
    ? [`${hiddenTools} tools hidden by FRIDA_MCP_TOOL_PROFILE/FRIDA_MCP_TOOLS_EXCLUDE`]
    : undefined;
}

export interface SessionSummary {
  id: string;
  target: string;
  pid: number;
  platform: SessionEntry['platform'];
  device: string;
  scripts: number;
  script_names: string[];
  created: string;
  last_activity_at: string;
  idle_seconds: number;
  crash_summary: string | null;
}

export interface DetachSummary {
  session_id: string | null;
  target: string;
  pid: number;
  device: string;
  reason: string;
  crash_summary: string | null;
  timestamp: string;
}

/**
 * Hook liveness as get_status reports it. `fired:false` with `installed:true` is the
 * silent-miss signal (hooked, but the code path never ran); `installed:false` with a
 * `reason` means the target itself was wrong, and for OVERLOAD_MISMATCH
 * `available_overloads` lists the signatures that do exist.
 */
export function summarizeHookLiveness(liveness: HookLiveness) {
  return {
    installed: liveness.installed,
    fired: !!liveness.firstSeenTs,
    ...(liveness.classResolved !== undefined ? { class_resolved: liveness.classResolved } : {}),
    ...(liveness.overloadsMatched !== undefined ? { overloads_matched: liveness.overloadsMatched } : {}),
    ...(liveness.matches !== undefined ? { matches: liveness.matches } : {}),
    ...(liveness.reason ? { reason: liveness.reason } : {}),
    ...(liveness.availableOverloads ? { available_overloads: liveness.availableOverloads } : {}),
  };
}

/** Pure projection of a session for get_status; `now` is injectable for tests. */
export function summarizeSession(s: SessionEntry, now: number = Date.now()): SessionSummary {
  const lastActivity = s.lastActivityAt ?? s.createdAt;
  return {
    id: s.id,
    target: s.target,
    pid: s.pid,
    platform: s.platform,
    device: s.deviceId,
    scripts: s.scripts.size,
    script_names: Array.from(s.scripts.values()).map((sc) => sc.name ?? sc.id),
    created: new Date(s.createdAt).toISOString(),
    last_activity_at: new Date(lastActivity).toISOString(),
    idle_seconds: Math.round((now - lastActivity) / 1000),
    crash_summary: s.crash?.summary ?? null,
  };
}

/** Newest-first view of the last `limit` detach/crash records. */
export function summarizeRecentDetaches(records: DetachRecord[], limit: number = RECENT_DETACH_LIMIT): DetachSummary[] {
  return records
    .slice(-limit)
    .reverse()
    .map((d) => ({
      session_id: d.sessionId,
      target: d.target,
      pid: d.pid,
      device: d.deviceId,
      reason: d.reason,
      crash_summary: d.crash?.summary ?? null,
      timestamp: new Date(d.timestamp).toISOString(),
    }));
}

export function registerStatusTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'get_status',
    {
      title: 'Get Frida Status',
      description: 'Get an overview of connected devices, active sessions (with platform, script count and last activity), hooks, traces, and the most recent session detaches / process crashes (recent_detaches). Use this first to understand what is available before starting any instrumentation work, and after a session is lost to see why.',
      inputSchema: z.object({
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ response_format }) => {
      try {
        const state = getState();

        // List devices
        let devices: Awaited<ReturnType<typeof deviceManager.listDevices>> = [];
        try {
          devices = await deviceManager.listDevices();
        } catch {
          devices = [];
        }

        // Current device info
        let currentDevice = null;
        if (state.selectedDevice) {
          try {
            currentDevice = await deviceManager.getDeviceInfo(state.selectedDevice.id);
          } catch {
            currentDevice = { id: state.selectedDevice.id, name: state.selectedDevice.name, type: state.selectedDevice.type };
          }
        }

        // Sessions
        const now = Date.now();
        const sessions = Array.from(state.sessions.values()).map((s) => summarizeSession(s, now));

        // Recent detaches / crashes (newest first)
        const recentDetaches = summarizeRecentDetaches(state.recentDetaches);
        const lastTargetCrashed = recentDetaches[0]?.reason === 'process-crashed';

        // Hooks
        const hooks = Array.from(state.hooks.values()).map((h) => ({
          id: h.id,
          target: h.target,
          type: h.type,
          status: h.status,
          invocations: h.invocations.length,
          // Liveness: did it actually attach, and has it ever fired? `fired:false` with
          // `installed:true` is the silent-miss signal (hooked, but the code path never ran);
          // `installed:false` with a `reason` means the target itself was wrong.
          ...(h.liveness ? { liveness: summarizeHookLiveness(h.liveness) } : {}),
        }));

        // Traces
        const traces = Array.from(state.traces.values()).map((t) => ({
          id: t.id,
          targets: t.targets,
          calls: t.callCount,
        }));

        // Coverage runs: how much of each armed set has been reached (covered vs. total).
        const coverage = Array.from(state.coverage.values()).map((c) => ({
          id: c.id,
          scope: c.scope,
          covered: c.hits.size,
          total: c.allTargets.length,
        }));

        // Crypto oracles: how many crypto_event hits each has captured so far.
        const oracles = Array.from(state.oracles.values()).map((o) => ({
          id: o.id,
          pattern: o.pattern,
          events: o.eventCount,
        }));

        // The policy registerAllTools applied; the config only when nothing was recorded.
        const hiddenNames = hiddenToolNames(state.toolExposure ?? policyFromConfig(state.config));
        const hiddenTools = hiddenNames.length;

        const result = buildResult(
          {
            devices,
            current_device: currentDevice,
            sessions,
            hooks,
            traces,
            coverage,
            oracles,
            recent_detaches: recentDetaches,
            hidden_tools: hiddenTools,
            hidden_tool_names: hiddenNames,
            config: {
              custom_scripts_enabled: state.config.allowCustomScripts,
              memory_write_enabled: state.config.memoryWriteEnabled,
              native_injection_enabled: state.config.allowNativeInjection,
              mobile_mcp_enabled: state.config.mobileMcp.enabled,
              max_sessions: state.config.maxSessions,
            },
          },
          [
            ...(devices.length > 0 && !currentDevice
              ? [{ tool: 'explore_app', reason: 'Start exploring an app on a connected device' }]
              : []),
            ...(sessions.length > 0
              ? [{ tool: 'get_messages', reason: 'Check output from active scripts/hooks' }]
              : []),
            ...(lastTargetCrashed
              ? [{ tool: 'explore_app', reason: 'Last target crashed; re-attach after inspecting recent_detaches' }]
              : []),
            ...(devices.length === 0
              ? [{
                  tool: 'frida_help',
                  args: { topic: 'overview' },
                  reason: 'No devices found - get help on setup',
                }]
              : []),
          ],
          { limitations: hiddenToolsLimitations(hiddenTools) }
        );

        return formatToolResponse(result, response_format);
      } catch (err) {
        const wrapped = wrapFridaError(err);
        return formatToolResponse(wrapped.toErrorResponse(), response_format);
      }
    }
  );
}
