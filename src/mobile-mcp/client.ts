import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { log } from '../helpers/logger.js';
import { getState } from '../state.js';

const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1000;

let client: Client | null = null;
let transport: StdioClientTransport | null = null;
let connecting = false;

export async function getMobileMcpClient(): Promise<Client> {
  if (client) return client;
  if (connecting) {
    // Wait for existing connection attempt
    await new Promise((resolve) => setTimeout(resolve, 1000));
    if (client) return client;
    throw new Error('mobile-mcp connection in progress');
  }

  connecting = true;
  let lastError: unknown;
  try {
    const state = getState();
    const config = state.config.mobileMcp;

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        log('info', `Spawning mobile-mcp (attempt ${attempt}/${MAX_RETRIES}): ${config.command} ${config.args.join(' ')}`);

        transport = new StdioClientTransport({
          command: config.command,
          args: config.args,
        });

        client = new Client(
          { name: 'frida-mobile-mcp', version: '0.1.0' },
          { capabilities: {} }
        );

        await client.connect(transport);
        log('info', 'Connected to mobile-mcp');

        return client;
      } catch (err) {
        lastError = err;
        client = null;
        try { await transport?.close(); } catch { /* ignore */ }
        transport = null;
        log('warn', `mobile-mcp connection attempt ${attempt}/${MAX_RETRIES} failed: ${err instanceof Error ? err.message : String(err)}`);

        if (attempt < MAX_RETRIES) {
          const delay = BASE_DELAY_MS * Math.pow(2, attempt - 1);
          await new Promise((resolve) => setTimeout(resolve, delay));
        }
      }
    }

    throw lastError;
  } finally {
    connecting = false;
  }
}

export async function disconnectMobileMcp(): Promise<void> {
  if (client) {
    try { await client.close(); } catch { /* ignore */ }
    client = null;
  }
  if (transport) {
    try { await transport.close(); } catch { /* ignore */ }
    transport = null;
  }
}

export function isMobileMcpConnected(): boolean {
  return client !== null;
}
