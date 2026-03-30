import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { DeviceManager } from '../../device/manager.js';
import { getState } from '../../state.js';
import { buildResult, formatToolResponse } from '../../helpers/result-builder.js';
import { FridaMcpError, wrapFridaError } from '../../helpers/errors.js';
import { validateProcessTarget } from '../../helpers/sanitize.js';
import { log } from '../../helpers/logger.js';
import { rateLimiter } from '../../helpers/rate-limiter.js';

export function registerAdvancedSessionTools(server: McpServer, deviceManager: DeviceManager): void {
  server.tool(
    'spawn_process',
    'Spawn a new process in suspended state for early instrumentation. The process will be paused until resume_process is called.',
    {
      program: z.string().describe('App bundle ID or program path'),
      device: z.string().optional().describe('Device ID'),
    },
    async ({ program, device: deviceId }) => {
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
        ]));
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );

  server.tool(
    'attach_process',
    'Attach to an already running process by PID or name.',
    {
      target: z.union([z.string(), z.number()]).describe('PID (number) or process name (string)'),
      device: z.string().optional().describe('Device ID'),
    },
    async ({ target, device: deviceId }) => {
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
        ]));
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );

  server.tool(
    'resume_process',
    'Resume a suspended process (after spawn_process).',
    {
      pid: z.number().describe('Process ID to resume'),
      device: z.string().optional().describe('Device ID'),
    },
    async ({ pid, device: deviceId }) => {
      try {
        const state = getState();
        const device = deviceId
          ? await deviceManager.getDevice(deviceId)
          : state.selectedDevice;
        if (!device) throw new FridaMcpError('DEVICE_NOT_FOUND', 'No device selected.', [{ tool: 'list_devices', reason: 'Select a device' }]);
        await device.resume(pid);
        return formatToolResponse(buildResult({ pid, status: 'resumed' }, [
          { tool: 'get_messages', reason: 'Check for hook/script output' },
        ]));
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );

  server.tool(
    'kill_process',
    'Kill a process on the target device.',
    {
      pid: z.number().describe('Process ID to kill'),
      device: z.string().optional().describe('Device ID'),
    },
    async ({ pid, device: deviceId }) => {
      try {
        const state = getState();
        const device = deviceId
          ? await deviceManager.getDevice(deviceId)
          : state.selectedDevice;
        if (!device) throw new FridaMcpError('DEVICE_NOT_FOUND', 'No device selected.', []);
        await device.kill(pid);
        return formatToolResponse(buildResult({ pid, status: 'killed' }, [{ tool: 'get_status', reason: 'Check state' }]));
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );

  server.tool(
    'detach_session',
    'Detach from a specific Frida session, unloading all scripts.',
    {
      session_id: z.string().describe('Session ID to detach'),
    },
    async ({ session_id }) => {
      try {
        const state = getState();
        const session = state.getSession(session_id);
        if (!session) throw new FridaMcpError('SESSION_NOT_FOUND', `Session "${session_id}" not found.`, []);
        for (const s of session.scripts.values()) { try { await s.script.unload(); } catch {} }
        await session.session.detach();
        state.removeSession(session_id);
        return formatToolResponse(buildResult({ session_id, status: 'detached' }, [{ tool: 'get_status', reason: 'Check state' }]));
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse());
      }
    }
  );

  server.tool(
    'list_sessions',
    'List all active Frida sessions managed by this server.',
    {},
    async () => {
      const state = getState();
      const sessions = Array.from(state.sessions.values()).map((s) => ({
        id: s.id, target: s.target, pid: s.pid, platform: s.platform,
        device: s.deviceId, scripts: s.scripts.size,
        created: new Date(s.createdAt).toISOString(),
      }));
      return formatToolResponse(buildResult({ sessions }, []));
    }
  );
}
