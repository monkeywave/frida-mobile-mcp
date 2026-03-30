import { getMobileMcpClient } from './client.js';
import { log } from '../helpers/logger.js';

export interface MobileMcpProxy {
  callTool(name: string, args: Record<string, unknown>): Promise<unknown>;
  listTools(): Promise<Array<{ name: string; description?: string }>>;
}

let proxyInstance: MobileMcpProxy | null = null;
let toolCache: Array<{ name: string; description?: string }> | null = null;

class MobileMcpProxyImpl implements MobileMcpProxy {
  async callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
    const client = await getMobileMcpClient();
    try {
      const result = await client.callTool({ name, arguments: args });
      return result;
    } catch (err) {
      log('error', `mobile-mcp tool call failed: ${name}`, { error: String(err) });
      throw err;
    }
  }

  async listTools(): Promise<Array<{ name: string; description?: string }>> {
    if (toolCache) return toolCache;

    const client = await getMobileMcpClient();
    const result = await client.listTools();
    toolCache = result.tools.map((t) => ({
      name: t.name,
      description: t.description,
    }));
    return toolCache;
  }
}

export async function getMobileMcpProxy(): Promise<MobileMcpProxy> {
  if (!proxyInstance) {
    proxyInstance = new MobileMcpProxyImpl();
  }
  return proxyInstance;
}
