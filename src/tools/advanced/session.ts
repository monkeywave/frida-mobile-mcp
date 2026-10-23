import { z } from 'zod';
import { toolOutputSchema } from '../../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../../device/manager.js';
import { getState } from '../../state.js';
import { buildResult, formatToolResponse } from '../../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../../helpers/errors.js';
import { validateProcessTarget } from '../../helpers/sanitize.js';
import { log } from '../../helpers/logger.js';
import { rateLimiter } from '../../helpers/rate-limiter.js';
import { responseFormatSchema } from '../../constants.js';

export function registerAdvancedSessionTools(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'spawn_process',
    {
      title: 'Spawn Process',
      description: 'Spawn a new process in suspended state for early instrumentation. The process will be paused until resume_process is called.',
      inputSchema: z.object({
        program: z.string().describe('App bundle ID or program path'),
        device: z.string().optional().describe('Device ID'),
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
    async ({ program, device: deviceId, response_format }) => {
      try {
        validateProcessTarget(program);
        const state = getState();

        rateLimiter.check('session', state.config.rateLimits.sessionsPerMinute);
        rateLimiter.record('session');
        const device = deviceId
          ? await deviceManager.resolve({ deviceId })
          : state.selectedDevice || await deviceManager.resolve();
        state.selectedDevice = device;

        const pid = await device.spawn(program);
        const session = await device.attach(pid);
        const platform = await deviceManager.detectPlatform(device);
        const sessionId = state.generateId();

        state.addSession({
          id: sessionId,
          session,
          pid,
          deviceId: device.id,
          target: program,
          platform,
          scripts: new Map(),
          createdAt: Date.now(),
        });

        session.detached.connect(() => state.removeSession(sessionId));

        return formatToolResponse(buildResult({
          session_id: sessionId,
          pid,
          status: 'suspended',
          message: `Process spawned (PID: ${pid}). Use resume_process to start execution.`,
        }, [
          { tool: 'resume_process', args: { pid }, reason: 'Resume the process' },
          { tool: 'hook_method', args: { target: program }, reason: 'Hook methods before resuming' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );

  server.registerTool(
    'attach_process',
    {
      title: 'Attach to Process',
      description: 'Attach to an already running process by PID or name.',
      inputSchema: z.object({
        target: z.union([z.string(), z.number()]).describe('PID (number) or process name (string)'),
        device: z.string().optional().describe('Device ID'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ target, device: deviceId, response_format }) => {
      try {
        const state = getState();

        rateLimiter.check('session', state.config.rateLimits.sessionsPerMinute);
        rateLimiter.record('session');

        const device = deviceId
          ? await deviceManager.resolve({ deviceId })
          : state.selectedDevice || await deviceManager.resolve();
        state.selectedDevice = device;

        let pid: number;
        if (typeof target === 'number') {
          pid = target;
        } else {
          const processes = await device.enumerateProcesses();
          const proc = processes.find((p) => p.name === target || p.pid.toString() === target);
          if (!proc) {
            throw new FridaMcpError('PROCESS_NOT_FOUND', `Process "${target}" not found.`, [
              { tool: 'list_processes', reason: 'List running processes' },
            ]);
          }
          pid = proc.pid;
        }

        const session = await device.attach(pid);
        const platform = await deviceManager.detectPlatform(device);
        const sessionId = state.generateId();

        state.addSession({
          id: sessionId,
          session,
          pid,
          deviceId: device.id,
          target: String(target),
          platform,
          scripts: new Map(),
          createdAt: Date.now(),
        });

        session.detached.connect(() => state.removeSession(sessionId));

        return formatToolResponse(buildResult({
          session_id: sessionId,
          pid,
          message: `Attached to process (PID: ${pid}).`,
        }, [
          { tool: 'hook_method', args: { target: String(target) }, reason: 'Hook methods' },
          { tool: 'search_classes_and_methods', args: { target: String(target) }, reason: 'Search for classes' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );

  server.registerTool(
    'resume_process',
    {
      title: 'Resume Process',
      description: 'Resume a suspended process (after spawn_process).',
      inputSchema: z.object({
        pid: z.number().describe('Process ID to resume'),
        device: z.string().optional().describe('Device ID'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ pid, device: deviceId, response_format }) => {
      try {
        const state = getState();
        const device = deviceId
          ? await deviceManager.getDevice(deviceId)
          : state.selectedDevice;
        if (!device) throw new FridaMcpError('DEVICE_NOT_FOUND', 'No device selected.', [{ tool: 'list_devices', reason: 'Select a device' }]);
        await device.resume(pid);
        return formatToolResponse(buildResult({ pid, status: 'resumed' }, [
          { tool: 'get_messages', reason: 'Check for hook/script output' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );

  server.registerTool(
    'kill_process',
    {
      title: 'Kill Process',
      description: 'Kill a process on the target device.',
      inputSchema: z.object({
        pid: z.number().describe('Process ID to kill'),
        device: z.string().optional().describe('Device ID'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ pid, device: deviceId, response_format }) => {
      try {
        const state = getState();
        const device = deviceId
          ? await deviceManager.getDevice(deviceId)
          : state.selectedDevice;
        if (!device) throw new FridaMcpError('DEVICE_NOT_FOUND', 'No device selected.', []);
        await device.kill(pid);
        return formatToolResponse(buildResult({ pid, status: 'killed' }, [{ tool: 'get_status', reason: 'Check state' }]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );

  server.registerTool(
    'detach_session',
    {
      title: 'Detach Session',
      description: 'Detach from a specific Frida session, unloading all scripts.',
      inputSchema: z.object({
        session_id: z.string().describe('Session ID to detach'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ session_id, response_format }) => {
      try {
        const state = getState();
        const session = state.getSession(session_id);
        if (!session) throw new FridaMcpError('SESSION_NOT_FOUND', `Session "${session_id}" not found.`, []);
        // Eternalized scripts are intentionally pinned in the target and outlive the session, so
        // don't try to unload them (that is the whole point of eternalize_script).
        for (const s of session.scripts.values()) { if (s.eternalized) continue; try { await s.script.unload(); } catch {} }
        await session.session.detach();
        state.removeSession(session_id);
        return formatToolResponse(buildResult({ session_id, status: 'detached' }, [{ tool: 'get_status', reason: 'Check state' }]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );

  server.registerTool(
    'spawn_gating',
    {
      title: 'Spawn Gating',
      description: 'Enable, disable, or list device-wide spawn gating. When enabled, every newly spawned process (including app-launched child/isolated processes that often run RASP/anti-Frida checks) is held suspended until released. Use "list" to see pending spawns and children, then attach_process + hook_method, and resume_process to release each by PID.',
      inputSchema: z.object({
        action: z.enum(['enable', 'disable', 'list']).describe('enable/disable gating, or list currently pending spawns and children.'),
        device: z.string().optional().describe('Device ID. Uses the selected/default device when omitted.'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ action, device: deviceId, response_format }) => {
      try {
        const state = getState();
        const device = deviceId
          ? await deviceManager.resolve({ deviceId })
          : state.selectedDevice || await deviceManager.resolve();
        state.selectedDevice = device;

        if (action === 'enable') {
          await device.enableSpawnGating();
          return formatToolResponse(buildResult({ spawn_gating: 'enabled', device: device.id }, [
            { tool: 'spawn_gating', args: { action: 'list' }, reason: 'List spawns as they are held' },
          ]), response_format);
        }
        if (action === 'disable') {
          await device.disableSpawnGating();
          return formatToolResponse(buildResult({ spawn_gating: 'disabled', device: device.id }, []), response_format);
        }
        const [spawns, children] = await Promise.all([
          device.enumeratePendingSpawn(),
          device.enumeratePendingChildren(),
        ]);
        return formatToolResponse(buildResult({
          pending_spawn: spawns.map((s) => ({ pid: s.pid, identifier: s.identifier })),
          pending_children: children.map((c) => ({ pid: c.pid, parent_pid: c.parentPid, identifier: c.identifier, path: c.path })),
          hint: 'Attach + hook each PID, then resume_process to release it. Android kills a process suspended > ~10s, so act promptly.',
        }, [
          { tool: 'attach_process', reason: 'Attach to a pending PID before it is resumed' },
          { tool: 'resume_process', reason: 'Release a held spawn by PID' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );

  server.registerTool(
    'child_gating',
    {
      title: 'Child Gating',
      description: 'Enable or disable child gating on an existing session. When enabled, processes forked/exec\'d by the instrumented process are held so they can be instrumented too (e.g. an app that moves detection into a child process). Requires device-wide spawn gating to catch the held children; list them with spawn_gating action="list".',
      inputSchema: z.object({
        session_id: z.string().describe('Session to enable/disable child gating on.'),
        enabled: z.boolean().default(true).describe('true enables child gating, false disables it.'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ session_id, enabled, response_format }) => {
      try {
        const state = getState();
        const entry = state.getSession(session_id);
        if (!entry) throw new FridaMcpError('SESSION_NOT_FOUND', `Session "${session_id}" not found.`, []);
        if (enabled) await entry.session.enableChildGating();
        else await entry.session.disableChildGating();
        return formatToolResponse(buildResult({ session_id, child_gating: enabled ? 'enabled' : 'disabled' }, [
          { tool: 'spawn_gating', args: { action: 'list' }, reason: 'List held children' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );

  server.registerTool(
    'eternalize_script',
    {
      title: 'Eternalize Script',
      description: "Make a loaded script survive session detach: frida pins it in the target so it keeps running after we detach (or the host exits). Trade-off — once eternalized the script can no longer send messages back, be unloaded, or be inspected; it is fire-and-forget persistence. Use it to leave a bypass/monitor running while you free the session. Give the session_id and the script_id returned by hook_method / execute_script / watch_loads.",
      inputSchema: z.object({
        session_id: z.string().describe('Session that owns the script.'),
        script_id: z.string().describe('Script to eternalize (the script_id from a hook/trace/watch/execute result).'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ session_id, script_id, response_format }) => {
      try {
        const state = getState();
        const entry = state.getSession(session_id);
        if (!entry) throw new FridaMcpError('SESSION_NOT_FOUND', `Session "${session_id}" not found.`, []);
        const scriptEntry = entry.scripts.get(script_id);
        if (!scriptEntry) {
          throw new FridaMcpError('SCRIPT_NOT_FOUND', `Script "${script_id}" not found in session "${session_id}".`, [
            { tool: 'get_status', reason: 'List sessions and their scripts' },
          ]);
        }
        await scriptEntry.script.eternalize();
        scriptEntry.eternalized = true;
        scriptEntry.persistent = true;
        log('info', `Eternalized script ${script_id} in session ${session_id}`);
        return formatToolResponse(buildResult({
          session_id,
          script_id,
          status: 'eternalized',
          message: 'Script pinned in the target; it survives detach but can no longer be messaged or unloaded.',
        }, [
          { tool: 'detach_session', args: { session_id }, reason: 'Free the session while the script keeps running' },
        ]), response_format);
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );

  server.registerTool(
    'list_sessions',
    {
      title: 'List Sessions',
      description: 'List all active Frida sessions managed by this server.',
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
      const state = getState();
      const sessions = Array.from(state.sessions.values()).map((s) => ({
        id: s.id, target: s.target, pid: s.pid, platform: s.platform,
        device: s.deviceId, scripts: s.scripts.size,
        created: new Date(s.createdAt).toISOString(),
      }));
      return formatToolResponse(buildResult({ sessions }, []), response_format);
    }
  );
}
