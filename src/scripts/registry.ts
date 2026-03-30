import type { ScriptTemplate } from '../types.js';
import { sslPinningBypassTemplate } from './ssl-pinning-bypass.js';
import { rootJailbreakBypassTemplate } from './root-jailbreak-bypass.js';
import { classEnumerationTemplate } from './class-enumeration.js';
import { methodHookTemplate } from './method-hook.js';
import { cryptoMonitorTemplate } from './crypto-monitor.js';
import { networkInspectorTemplate } from './network-inspector.js';
import { keychainPrefsTemplate } from './keychain-prefs.js';
import { filesystemMonitorTemplate } from './filesystem-monitor.js';

class ScriptRegistry {
  private templates: Map<string, ScriptTemplate> = new Map();

  register(template: ScriptTemplate): void {
    this.templates.set(template.name, template);
  }

  get(name: string): ScriptTemplate | undefined {
    return this.templates.get(name);
  }

  listAll(): ScriptTemplate[] {
    return Array.from(this.templates.values());
  }
}

let registryInstance: ScriptRegistry | null = null;

export function getScriptRegistry(): ScriptRegistry {
  if (!registryInstance) {
    registryInstance = new ScriptRegistry();
    registryInstance.register(sslPinningBypassTemplate);
    registryInstance.register(rootJailbreakBypassTemplate);
    registryInstance.register(classEnumerationTemplate);
    registryInstance.register(methodHookTemplate);
    registryInstance.register(cryptoMonitorTemplate);
    registryInstance.register(networkInspectorTemplate);
    registryInstance.register(keychainPrefsTemplate);
    registryInstance.register(filesystemMonitorTemplate);
  }
  return registryInstance;
}
