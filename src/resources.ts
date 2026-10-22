import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import frida from 'frida';
import { ResourceTemplate } from '@modelcontextprotocol/server';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from './device/manager.js';
import { getState } from './state.js';
import { getScriptRegistry } from './scripts/registry.js';
import { listRecipes, getRecipe } from './recipes/registry.js';

const cache = new Map<string, { data: unknown; expiresAt: number }>();

/** Skills shipped with the package (skills/<name>/SKILL.md, resolved from the package root like bridges.ts). */
const SHIPPED_SKILLS = ['mobile-dynamic-analysis'] as const;

export function getSkillPath(name: string): string {
  const packageRoot = fileURLToPath(new URL('../', import.meta.url));
  return path.join(packageRoot, 'skills', name, 'SKILL.md');
}

export function readSkill(name: string): string {
  return readFileSync(getSkillPath(name), 'utf8');
}

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
  server.registerResource(
    'frida-version',
    'frida://version',
    { description: 'Current Frida runtime version', mimeType: 'application/json' },
    async (uri) => ({
      contents: [{
        uri: uri.href,
        mimeType: 'application/json',
        text: JSON.stringify({ version: (frida as any).version ?? 'unknown' }),
      }],
    })
  );

  // Static: frida://devices
  server.registerResource(
    'frida-devices',
    'frida://devices',
    { description: 'List of connected Frida devices', mimeType: 'application/json' },
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
  server.registerResource(
    'frida-device-info',
    new ResourceTemplate('frida://devices/{id}', { list: undefined }),
    { description: 'Detailed information about a specific device', mimeType: 'application/json' },
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
  server.registerResource(
    'frida-device-processes',
    new ResourceTemplate('frida://devices/{id}/processes', { list: undefined }),
    { description: 'Running processes on a specific device', mimeType: 'application/json' },
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
  server.registerResource(
    'frida-device-apps',
    new ResourceTemplate('frida://devices/{id}/apps', { list: undefined }),
    { description: 'Installed applications on a specific device', mimeType: 'application/json' },
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
  server.registerResource(
    'frida-sessions',
    'frida://sessions',
    { description: 'Active Frida instrumentation sessions', mimeType: 'application/json' },
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
  server.registerResource(
    'frida-session-detail',
    new ResourceTemplate('frida://sessions/{id}', { list: undefined }),
    { description: 'Details of a specific instrumentation session', mimeType: 'application/json' },
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
  server.registerResource(
    'frida-session-messages',
    new ResourceTemplate('frida://sessions/{id}/messages', { list: undefined }),
    { description: 'Messages from scripts in a specific session', mimeType: 'application/json' },
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

  // Static: frida://skills/<name> - Agent Skills documents shipped with the package
  for (const skill of SHIPPED_SKILLS) {
    server.registerResource(
      `frida-skill-${skill}`,
      `frida://skills/${skill}`,
      { description: `Agent skill: ${skill} (when to use frida-mobile-mcp, static/dynamic hand-off, tool order, troubleshooting)`, mimeType: 'text/markdown' },
      async (uri) => {
        try {
          return { contents: [{ uri: uri.href, mimeType: 'text/markdown', text: readSkill(skill) }] };
        } catch (err) {
          return { contents: [{ uri: uri.href, mimeType: 'text/plain', text: `Skill ${skill} is not available: ${String(err)}` }] };
        }
      }
    );
  }

  // Static: frida://scripts
  server.registerResource(
    'frida-scripts-catalog',
    'frida://scripts',
    { description: 'Catalog of available pre-built Frida scripts', mimeType: 'application/json' },
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
  server.registerResource(
    'frida-script-detail',
    new ResourceTemplate('frida://scripts/{name}', { list: undefined }),
    { description: 'Details of a specific pre-built script', mimeType: 'application/json' },
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

  // Template: frida://scripts/{name}/source — the generated classic-JS body of a template,
  // as a worked example the AI can read and adapt. Generated with default options.
  server.registerResource(
    'frida-script-source',
    new ResourceTemplate('frida://scripts/{name}/source', { list: undefined }),
    { description: 'Generated classic-JS source of a pre-built script (worked example), with its options', mimeType: 'text/plain' },
    async (uri, variables) => {
      const registry = getScriptRegistry();
      const template = registry.get(String(variables.name));
      if (!template) {
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify({ error: 'Script not found' }) }] };
      }
      const header = [
        `// Prebuilt script: ${template.name}`,
        `// ${template.description}`,
        `// Platforms: ${template.platforms.join(', ')} | category: ${template.category} | riskTier: ${template.riskTier}`,
        template.options ? `// Options: ${JSON.stringify(template.options)}` : '// Options: none',
        '// Runs after the agent preamble (findExport/hookNative/javaPerform/objcClassNames/reportSummary);',
        '// reads its options from __FRIDA_MCP__.options. Run via run_prebuilt_script, or adapt and run with execute_script.',
        '',
      ].join('\n');
      return { contents: [{ uri: uri.href, mimeType: 'text/plain', text: header + template.generate({}) }] };
    }
  );

  // Static: frida://recipes — purpose-indexed library catalog.
  server.registerResource(
    'frida-recipes-catalog',
    'frida://recipes',
    { description: 'Purpose-indexed library of classic-JS Frida recipes (custom crypto-key capture, native/JNI hooks, classloader/intent/WebView, iOS Keychain)', mimeType: 'application/json' },
    async (uri) => {
      const recipes = listRecipes().map((r) => ({
        name: r.name, title: r.title, purpose: r.purpose,
        platforms: r.platforms, tags: r.tags,
      }));
      return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(recipes) }] };
    }
  );

  // Template: frida://recipes/{name} — one recipe with its classic-JS source and usage.
  server.registerResource(
    'frida-recipe-detail',
    new ResourceTemplate('frida://recipes/{name}', { list: undefined }),
    { description: 'A single recipe: classic-JS source, options and usage guidance', mimeType: 'application/json' },
    async (uri, variables) => {
      const recipe = getRecipe(String(variables.name));
      if (!recipe) {
        return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify({ error: 'Recipe not found' }) }] };
      }
      return {
        contents: [{
          uri: uri.href, mimeType: 'application/json',
          text: JSON.stringify({
            name: recipe.name, title: recipe.title, purpose: recipe.purpose,
            platforms: recipe.platforms, tags: recipe.tags, options: recipe.options,
            usage: recipe.usage, source: recipe.source,
          }),
        }],
      };
    }
  );
}
