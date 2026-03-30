import frida from 'frida';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { DeviceManager } from './device/manager.js';
import { getState } from './state.js';
import { getScriptRegistry } from './scripts/registry.js';

const cache = new Map<string, { data: unknown; expiresAt: number }>();

function cached<T>(key: string, ttlMs: number, fn: () => Promise<T>): Promise<T> {
  const entry = cache.get(key);
  if (entry && Date.now() < entry.expiresAt) {
    return Promise.resolve(entry.data as T);
  }
  return fn().then((data) => {
    cache.set(key, { data, expiresAt: Date.now() + ttlMs });
    return data;
  });
}

export function registerResources(server: McpServer, deviceManager: DeviceManager): void {
  // Static: frida://version
  server.resource(
    'frida-version',
    'frida://version',
    async (uri) => ({
      contents: [{
        uri: uri.href,
        mimeType: 'application/json',
        text: JSON.stringify({ version: (frida as any).version ?? 'unknown' }),
      }],
    })
  );

  // Static: frida://devices
  server.resource(
    'frida-devices',
    'frida://devices',
    async (uri) => {
      try {
        const devices = await cached('devices', 5000, () => deviceManager.listDevices());
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(devices) }] };
      } catch {
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: '[]' }] };
      }
    }
  );

  // Template: frida://devices/{id}
  server.resource(
    'frida-device-info',
    new ResourceTemplate('frida://devices/{id}', { list: undefined }),
    async (uri, variables) => {
      const id = String(variables.id);
      try {
        const info = await deviceManager.getDeviceInfo(id);
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(info) }] };
      } catch (err) {
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify({ error: String(err) }) }] };
      }
    }
  );

  // Template: frida://devices/{id}/processes
  server.resource(
    'frida-device-processes',
    new ResourceTemplate('frida://devices/{id}/processes', { list: undefined }),
    async (uri, variables) => {
      const id = String(variables.id);
      try {
        const device = await deviceManager.getDevice(id);
        const processes = await cached(`processes:${id}`, 5000, () => device.enumerateProcesses());
        const list = processes.map((p) => ({ pid: p.pid, name: p.name }));
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(list) }] };
      } catch (err) {
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify({ error: String(err) }) }] };
      }
    }
  );

  // Template: frida://devices/{id}/apps
  server.resource(
    'frida-device-apps',
    new ResourceTemplate('frida://devices/{id}/apps', { list: undefined }),
    async (uri, variables) => {
      const id = String(variables.id);
      try {
        const device = await deviceManager.getDevice(id);
        const apps = await cached(`apps:${id}`, 10000, () => device.enumerateApplications());
        const list = apps.map((a) => ({ identifier: a.identifier, name: a.name, pid: a.pid }));
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(list) }] };
      } catch (err) {
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify({ error: String(err) }) }] };
      }
    }
  );

  // Static: frida://sessions
  server.resource(
    'frida-sessions',
    'frida://sessions',
    async (uri) => {
      const state = getState();
      const sessions = Array.from(state.sessions.values()).map((s) => ({
        id: s.id, target: s.target, pid: s.pid, platform: s.platform,
        device: s.deviceId, scripts: s.scripts.size, created: new Date(s.createdAt).toISOString(),
      }));
      return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(sessions) }] };
    }
  );

  // Template: frida://sessions/{id}
  server.resource(
    'frida-session-detail',
    new ResourceTemplate('frida://sessions/{id}', { list: undefined }),
    async (uri, variables) => {
      const state = getState();
      const session = state.getSession(String(variables.id));
      if (!session) {
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify({ error: 'Session not found' }) }] };
      }
      const hooks = Array.from(state.hooks.values()).filter((h) => h.sessionId === session.id);
      return {
        contents: [{
          uri: uri.href, mimeType: 'application/json',
          text: JSON.stringify({
            id: session.id, target: session.target, pid: session.pid, platform: session.platform,
            device: session.deviceId, scripts: session.scripts.size,
            hooks: hooks.map((h) => ({ id: h.id, target: h.target, type: h.type, status: h.status })),
            created: new Date(session.createdAt).toISOString(),
          }),
        }],
      };
    }
  );

  // Template: frida://sessions/{id}/messages
  server.resource(
    'frida-session-messages',
    new ResourceTemplate('frida://sessions/{id}/messages', { list: undefined }),
    async (uri, variables) => {
      const state = getState();
      const session = state.getSession(String(variables.id));
      if (!session) {
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: '[]' }] };
      }
      const allMessages: Array<Record<string, unknown>> = [];
      for (const [sid, scriptEntry] of session.scripts) {
        for (const msg of scriptEntry.messages.slice(-50)) {
          allMessages.push({ script_id: sid, script_name: scriptEntry.name, ...msg });
        }
      }
      allMessages.sort((a, b) => (a.timestamp as number) - (b.timestamp as number));
      return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(allMessages) }] };
    }
  );

  // Static: frida://scripts
  server.resource(
    'frida-scripts-catalog',
    'frida://scripts',
    async (uri) => {
      const registry = getScriptRegistry();
      const scripts = registry.listAll().map((s) => ({
        name: s.name, description: s.description, platforms: s.platforms,
        category: s.category, riskTier: s.riskTier,
      }));
      return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(scripts) }] };
    }
  );

  // Template: frida://scripts/{name}
  server.resource(
    'frida-script-detail',
    new ResourceTemplate('frida://scripts/{name}', { list: undefined }),
    async (uri, variables) => {
      const registry = getScriptRegistry();
      const template = registry.get(String(variables.name));
      if (!template) {
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify({ error: 'Script not found' }) }] };
      }
      return {
        contents: [{
          uri: uri.href, mimeType: 'application/json',
          text: JSON.stringify({
            name: template.name, description: template.description,
            platforms: template.platforms, category: template.category,
            riskTier: template.riskTier, options: template.options,
          }),
        }],
      };
    }
  );
}
