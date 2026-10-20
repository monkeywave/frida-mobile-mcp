import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { Client } from '@modelcontextprotocol/client';
import { log } from '../helpers/logger.js';
import { getPackageVersion } from '../helpers/version.js';
import { getState } from '../state.js';

const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1000;

type DisconnectListener = () => void;

let client: Client | null = null;
let transport: StdioClientTransport | null = null;
let connectPromise: Promise<Client> | null = null;
const disconnectListeners = new Set<DisconnectListener>();

/**
 * Get the shared mobile-mcp client, spawning it on first use.
 * Concurrent callers share a single in-flight connection attempt.
 */
export async function getMobileMcpClient(): Promise<Client> {
  if (client) return client;
  if (!connectPromise) {
    connectPromise = connectWithRetry().finally(() => {
      connectPromise = null;
    });
  }
  return connectPromise;
}

/** Register a callback that runs whenever the mobile-mcp connection goes away. */
export function onMobileMcpDisconnect(listener: DisconnectListener): () => void {
  disconnectListeners.add(listener);
  return () => disconnectListeners.delete(listener);
}

export async function disconnectMobileMcp(): Promise<void> {
  const activeClient = client;
  const activeTransport = transport;
  resetConnection();

  if (activeClient) {
    try { await activeClient.close(); } catch { /* ignore */ }
  }
  if (activeTransport) {
    try { await activeTransport.close(); } catch { /* ignore */ }
  }
}

export function isMobileMcpConnected(): boolean {
  return client !== null;
}

async function connectWithRetry(): Promise<Client> {
  const config = getState().config.mobileMcp;
  let lastError: unknown;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      log('info', `Spawning mobile-mcp (attempt ${attempt}/${MAX_RETRIES}): ${config.command} ${config.args.join(' ')}`);
      return await connectOnce(config.command, config.args);
    } catch (err) {
      lastError = err;
      log('warn', `mobile-mcp connection attempt ${attempt}/${MAX_RETRIES} failed: ${err instanceof Error ? err.message : String(err)}`);
      if (attempt < MAX_RETRIES) {
        await delay(BASE_DELAY_MS * Math.pow(2, attempt - 1));
      }
    }
  }

  throw lastError;
}

async function connectOnce(command: string, args: string[]): Promise<Client> {
  const newTransport = new StdioClientTransport({ command, args });
  const newClient = new Client(
    { name: 'frida-mobile-mcp', version: getPackageVersion() },
    { capabilities: {} }
  );

  try {
    await newClient.connect(newTransport);
  } catch (err) {
    try { await newTransport.close(); } catch { /* ignore */ }
    throw err;
  }

  newClient.onclose = () => {
    if (client !== newClient) return;
    log('warn', 'mobile-mcp connection closed');
    resetConnection();
  };
  newClient.onerror = (err) => {
    log('warn', `mobile-mcp transport error: ${err instanceof Error ? err.message : String(err)}`);
  };

  client = newClient;
  transport = newTransport;
  log('info', 'Connected to mobile-mcp');
  return newClient;
}

function resetConnection(): void {
  const wasConnected = client !== null;
  client = null;
  transport = null;
  if (wasConnected) {
    notifyDisconnect();
  }
}

function notifyDisconnect(): void {
  for (const listener of disconnectListeners) {
    try { listener(); } catch { /* listener errors must not break teardown */ }
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
