import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

vi.mock('frida', () => ({
  default: {
    getDeviceManager: () => ({}),
    Cancellable: { withTimeout: () => ({ isCancelled: false }) },
  },
}));

vi.mock('../../src/helpers/logger.js', () => ({
  log: vi.fn(),
  initLogger: vi.fn(),
  audit: vi.fn(),
}));

import {
  DEFAULT_FRITAP_VERSION,
  FRITAP_AGENT_FILENAME,
  toFritapTag,
  fritapDownloadUrl,
  fritapCacheDir,
  isValidFritapBundle,
  locateFritapAgent,
  buildFritapConfigBatch,
  fritapHandshakeReply,
  isFritapHandshakeRequest,
  configureFritapAgent,
  readFritapAbiVersion,
  gracefulDetachFritap,
} from '../../src/fritap/agent-loader.js';
import { PINNED_AGENT_SHA256 } from '../../src/fritap/constants.js';
import { FritapAgentUnavailableError } from '../../src/helpers/errors.js';
import { sha256Hex } from '../../src/helpers/sanitize.js';

const VALID_BUNDLE = '📦\n123 /agent/fritap_agent.js\n✄\nvar a=1;';
const NOT_A_BUNDLE = 'var a=1;';
const VALID_BUNDLE_SHA256 = sha256Hex(VALID_BUNDLE);

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fritap-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeTmp(name: string, content: string): string {
  const file = path.join(tmpDir, name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, 'utf8');
  return file;
}

async function expectUnavailable(promise: Promise<unknown>): Promise<FritapAgentUnavailableError> {
  let caught: unknown;
  try {
    await promise;
  } catch (err) {
    caught = err;
  }
  expect(caught).toBeInstanceOf(FritapAgentUnavailableError);
  const error = caught as FritapAgentUnavailableError;
  expect(error.code).toBe('FRITAP_AGENT_UNAVAILABLE');
  expect(error.category).toBe('capability');
  return error;
}

describe('helpers', () => {
  it('toFritapTag prefixes bare semver with v and leaves tags and branches alone', () => {
    expect(toFritapTag('2.5.2')).toBe('v2.5.2');
    expect(toFritapTag('v2.5.2')).toBe('v2.5.2');
    expect(toFritapTag('main')).toBe('main');
  });

  it('fritapDownloadUrl points at the raw GitHub bundle for the tag', () => {
    expect(fritapDownloadUrl('v2.5.2')).toBe(
      'https://raw.githubusercontent.com/fkie-cad/friTap/v2.5.2/friTap/fritap_agent.js'
    );
  });

  it('fritapCacheDir honours XDG_CONFIG_HOME', () => {
    expect(fritapCacheDir('v2.5.2', { XDG_CONFIG_HOME: '/x' })).toBe(path.join('/x', 'frida-mobile-mcp', 'fritap', 'v2.5.2'));
  });

  it('isValidFritapBundle requires the frida-compile marker', () => {
    expect(isValidFritapBundle(VALID_BUNDLE)).toBe(true);
    expect(isValidFritapBundle(NOT_A_BUNDLE)).toBe(false);
  });
});

describe('locateFritapAgent', () => {
  it('loads from FRITAP_AGENT_PATH with origin env and version unknown', async () => {
    const file = writeTmp('env/fritap_agent.js', VALID_BUNDLE);
    const located = await locateFritapAgent({ env: { FRITAP_AGENT_PATH: file }, skipPython: true });
    expect(located.origin).toBe('env');
    expect(located.version).toBe('unknown');
    expect(located.path).toBe(file);
    expect(located.source).toBe(VALID_BUNDLE);
  });

  it('rejects when FRITAP_AGENT_PATH points to a non-bundle file', async () => {
    const file = writeTmp('env/plain.js', NOT_A_BUNDLE);
    await expectUnavailable(locateFritapAgent({ env: { FRITAP_AGENT_PATH: file }, skipPython: true }));
  });

  it('hits the cache with the default version', async () => {
    const cacheDir = path.join(tmpDir, 'cache');
    writeTmp(path.join('cache', FRITAP_AGENT_FILENAME), VALID_BUNDLE);
    // The default tag has a built-in pin, so the fake bundle needs a matching override.
    const located = await locateFritapAgent({ skipPython: true, cacheDir, env: { FRITAP_AGENT_SHA256: VALID_BUNDLE_SHA256 }, allowDownload: false });
    expect(located.origin).toBe('cache');
    expect(located.version).toBe(DEFAULT_FRITAP_VERSION);
    expect(located.version).toBe('v2.5.2');
    expect(located.path).toBe(path.join(cacheDir, FRITAP_AGENT_FILENAME));
    expect(located.source).toBe(VALID_BUNDLE);
  });

  it('uses FRITAP_VERSION from env as the version tag', async () => {
    const cacheDir = path.join(tmpDir, 'cache');
    writeTmp(path.join('cache', FRITAP_AGENT_FILENAME), VALID_BUNDLE);
    const located = await locateFritapAgent({
      skipPython: true,
      cacheDir,
      env: { FRITAP_VERSION: '2.4.0' },
      allowDownload: false,
    });
    expect(located.version).toBe('v2.4.0');
    expect(located.origin).toBe('cache');
  });

  it('derives the cache dir from the FRITAP_VERSION tag when no cacheDir is given', async () => {
    const xdg = path.join(tmpDir, 'xdg');
    writeTmp(path.join('xdg', 'frida-mobile-mcp', 'fritap', 'v2.4.0', FRITAP_AGENT_FILENAME), VALID_BUNDLE);
    const located = await locateFritapAgent({
      skipPython: true,
      env: { FRITAP_VERSION: '2.4.0', XDG_CONFIG_HOME: xdg },
      allowDownload: false,
    });
    expect(located.version).toBe('v2.4.0');
    expect(located.origin).toBe('cache');
    expect(located.path).toBe(path.join(xdg, 'frida-mobile-mcp', 'fritap', 'v2.4.0', FRITAP_AGENT_FILENAME));
  });

  it('rejects with the searched paths when nothing is found and download is disabled', async () => {
    const cacheDir = path.join(tmpDir, 'empty-cache');
    const error = await expectUnavailable(
      locateFritapAgent({ skipPython: true, cacheDir, env: {}, allowDownload: false })
    );
    expect(Array.isArray(error.context.searched)).toBe(true);
    expect(error.context.searched).toContain(path.join(cacheDir, FRITAP_AGENT_FILENAME));
  });

  it('downloads into the cache and serves the cache on the next call', async () => {
    const cacheDir = path.join(tmpDir, 'dl-cache');
    const fetchImpl = vi.fn(async () => new Response(VALID_BUNDLE, { status: 200 }));

    const downloaded = await locateFritapAgent({
      allowDownload: true,
      skipPython: true,
      cacheDir,
      env: { FRITAP_AGENT_SHA256: VALID_BUNDLE_SHA256 },
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(downloaded.origin).toBe('download');
    expect(downloaded.version).toBe('v2.5.2');
    expect(downloaded.source).toBe(VALID_BUNDLE);

    const cachedFile = path.join(cacheDir, FRITAP_AGENT_FILENAME);
    expect(downloaded.path).toBe(cachedFile);
    expect(fs.readFileSync(cachedFile, 'utf8')).toBe(VALID_BUNDLE);

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl.mock.calls[0][0]).toBe(fritapDownloadUrl('v2.5.2'));

    const cached = await locateFritapAgent({ allowDownload: false, skipPython: true, cacheDir, env: { FRITAP_AGENT_SHA256: VALID_BUNDLE_SHA256 } });
    expect(cached.origin).toBe('cache');
    expect(cached.source).toBe(VALID_BUNDLE);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('pins the v2.5.2 agent by sha256', () => {
    expect(PINNED_AGENT_SHA256['v2.5.2']).toMatch(/^[0-9a-f]{64}$/);
  });

  it('discards a download whose sha256 differs from the built-in pin', async () => {
    const cacheDir = path.join(tmpDir, 'pin-cache');
    const fetchImpl = vi.fn(async () => new Response(VALID_BUNDLE, { status: 200 }));
    const error = await expectUnavailable(
      locateFritapAgent({
        allowDownload: true, skipPython: true, cacheDir, env: {},
        fetchImpl: fetchImpl as unknown as typeof fetch,
      })
    );
    expect(error.message).toContain('sha256 mismatch');
    expect(error.message).toContain('FRITAP_AGENT_SHA256');
    expect(fs.existsSync(path.join(cacheDir, FRITAP_AGENT_FILENAME))).toBe(false);
  });

  it('rejects when FRITAP_AGENT_SHA256 does not match the download', async () => {
    const cacheDir = path.join(tmpDir, 'env-mismatch');
    const fetchImpl = vi.fn(async () => new Response(VALID_BUNDLE, { status: 200 }));
    await expectUnavailable(
      locateFritapAgent({
        allowDownload: true, skipPython: true, cacheDir,
        env: { FRITAP_AGENT_SHA256: 'a'.repeat(64) },
        fetchImpl: fetchImpl as unknown as typeof fetch,
      })
    );
    expect(fs.existsSync(path.join(cacheDir, FRITAP_AGENT_FILENAME))).toBe(false);
  });

  it('applies a bare FRITAP_AGENT_SHA256 pin to the selected non-default tag (case-insensitive)', async () => {
    const cacheDir = path.join(tmpDir, 'tag-pin');
    const fetchImpl = vi.fn(async () => new Response(VALID_BUNDLE, { status: 200 }));
    const located = await locateFritapAgent({
      allowDownload: true, skipPython: true, cacheDir, version: 'v9.9.9',
      env: { FRITAP_AGENT_SHA256: VALID_BUNDLE_SHA256.toUpperCase() },
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(located.version).toBe('v9.9.9');
    expect(fs.existsSync(path.join(cacheDir, FRITAP_AGENT_FILENAME))).toBe(true);
  });

  it('accepts an unpinned tag with no override (warns only)', async () => {
    const cacheDir = path.join(tmpDir, 'unpinned');
    const fetchImpl = vi.fn(async () => new Response(VALID_BUNDLE, { status: 200 }));
    const located = await locateFritapAgent({
      allowDownload: true, skipPython: true, cacheDir, version: 'v9.9.9', env: {},
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(located.origin).toBe('download');
  });

  it('serves a cached bundle that matches the pin without downloading', async () => {
    const cacheDir = path.join(tmpDir, 'pinned-cache');
    writeTmp(path.join('pinned-cache', FRITAP_AGENT_FILENAME), VALID_BUNDLE);
    const fetchImpl = vi.fn(async () => new Response(VALID_BUNDLE, { status: 200 }));
    const located = await locateFritapAgent({
      allowDownload: true, skipPython: true, cacheDir,
      env: { FRITAP_AGENT_SHA256: VALID_BUNDLE_SHA256 },
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(located.origin).toBe('cache');
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('ignores a cached bundle that does not match the pin and re-downloads it', async () => {
    const cacheDir = path.join(tmpDir, 'tampered-cache');
    const tampered = VALID_BUNDLE + '\n/* tampered */';
    writeTmp(path.join('tampered-cache', FRITAP_AGENT_FILENAME), tampered);
    const fetchImpl = vi.fn(async () => new Response(VALID_BUNDLE, { status: 200 }));
    const located = await locateFritapAgent({
      allowDownload: true, skipPython: true, cacheDir,
      env: { FRITAP_AGENT_SHA256: VALID_BUNDLE_SHA256 },
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(located.origin).toBe('download');
    expect(located.source).toBe(VALID_BUNDLE);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fs.readFileSync(path.join(cacheDir, FRITAP_AGENT_FILENAME), 'utf8')).toBe(VALID_BUNDLE);
  });

  it('treats a mismatching cache entry as absent when download is disabled', async () => {
    const cacheDir = path.join(tmpDir, 'tampered-offline');
    writeTmp(path.join('tampered-offline', FRITAP_AGENT_FILENAME), VALID_BUNDLE);
    await expectUnavailable(
      locateFritapAgent({ allowDownload: false, skipPython: true, cacheDir, env: { FRITAP_AGENT_SHA256: 'b'.repeat(64) } })
    );
  });

  it('does not verify FRITAP_AGENT_PATH bundles (local trust)', async () => {
    const file = writeTmp('local/fritap_agent.js', VALID_BUNDLE);
    const located = await locateFritapAgent({
      skipPython: true, env: { FRITAP_AGENT_PATH: file, FRITAP_AGENT_SHA256: 'c'.repeat(64) },
    });
    expect(located.origin).toBe('env');
  });

  it('rejects a downloaded body that is not a bundle and does not cache it', async () => {
    const cacheDir = path.join(tmpDir, 'bad-cache');
    const fetchImpl = vi.fn(async () => new Response(NOT_A_BUNDLE, { status: 200 }));
    await expectUnavailable(
      locateFritapAgent({
        allowDownload: true,
        skipPython: true,
        cacheDir,
        env: {},
        fetchImpl: fetchImpl as unknown as typeof fetch,
      })
    );
    expect(fs.existsSync(path.join(cacheDir, FRITAP_AGENT_FILENAME))).toBe(false);
  });

  it('rejects with the HTTP status when the download fails', async () => {
    const cacheDir = path.join(tmpDir, '404-cache');
    const fetchImpl = vi.fn(async () => new Response('nope', { status: 404, statusText: 'Not Found' }));
    const error = await expectUnavailable(
      locateFritapAgent({
        allowDownload: true,
        skipPython: true,
        cacheDir,
        env: {},
        fetchImpl: fetchImpl as unknown as typeof fetch,
      })
    );
    expect(error.message).toContain('404');
  });
});

describe('buildFritapConfigBatch', () => {
  it('uses friTap defaults when no options are given', () => {
    const batch = buildFritapConfigBatch({});
    expect(batch.pcap_enabled).toBe(false);
    expect(batch.keylog_enabled).toBe(true);
    expect(batch.spawned).toBe(false);
    expect(batch.patterns).toBeNull();
    expect(batch.offsets).toBeNull();
    expect(batch.protocol_select).toBe('tls');
    expect(batch.experimental).toBe(false);
  });

  it('maps options and JSON-encodes object patterns', () => {
    const batch = buildFritapConfigBatch({ fullCapture: true, spawned: true, patterns: { a: 1 } });
    expect(batch.pcap_enabled).toBe(true);
    expect(batch.spawned).toBe(true);
    expect(batch.patterns).toBe('{"a":1}');
    expect(typeof batch.patterns).toBe('string');
  });

  it('keeps string patterns and offsets as-is', () => {
    const batch = buildFritapConfigBatch({ patterns: '{"x":2}', offsets: '{"y":3}' });
    expect(batch.patterns).toBe('{"x":2}');
    expect(batch.offsets).toBe('{"y":3}');
  });
});

describe('handshake replies', () => {
  it('answers config_batch with the config batch', () => {
    const reply = fritapHandshakeReply('config_batch', {});
    expect(reply?.type).toBe('config_batch');
    expect(reply?.payload).toMatchObject({ pcap_enabled: false });
  });

  it('answers anti with antiroot', () => {
    expect(fritapHandshakeReply('anti', { antiRoot: true })).toEqual({ type: 'antiroot', payload: true });
    expect(fritapHandshakeReply('anti', {})).toEqual({ type: 'antiroot', payload: false });
  });

  it('answers legacy channels with the same type name', () => {
    expect(fritapHandshakeReply('experimental', {})).toEqual({ type: 'experimental', payload: false });
    expect(fritapHandshakeReply('defaultFD', {})).toEqual({ type: 'defaultFD', payload: false });
  });

  it('returns null for non-handshake payloads, including prototype names', () => {
    expect(fritapHandshakeReply({ contentType: 'keylog' }, {})).toBeNull();
    expect(fritapHandshakeReply(42, {})).toBeNull();
    expect(fritapHandshakeReply(undefined, {})).toBeNull();
    expect(fritapHandshakeReply('hello', {})).toBeNull();
    expect(fritapHandshakeReply('constructor', {})).toBeNull();
    expect(fritapHandshakeReply('toString', {})).toBeNull();
  });

  it('isFritapHandshakeRequest recognises the handshake channel names', () => {
    expect(isFritapHandshakeRequest('config_batch')).toBe(true);
    expect(isFritapHandshakeRequest('anti')).toBe(true);
    expect(isFritapHandshakeRequest('socket_tracing')).toBe(true);
    expect(isFritapHandshakeRequest('hello')).toBe(false);
    expect(isFritapHandshakeRequest({})).toBe(false);
  });
});

describe('configureFritapAgent', () => {
  type Handler = (message: { type: string; payload?: unknown }) => void;

  function fakeScript() {
    const handlers: Handler[] = [];
    const script = {
      message: { connect: vi.fn((handler: Handler) => handlers.push(handler)) },
      post: vi.fn(),
    };
    const emit = (message: { type: string; payload?: unknown }) => handlers.forEach((h) => h(message));
    return { script, emit };
  }

  it('posts replies in order and resolves configured after config_batch', async () => {
    const { script, emit } = fakeScript();
    const state = configureFritapAgent(script as any, { antiRoot: true });
    expect(script.message.connect).toHaveBeenCalledTimes(1);

    emit({ type: 'send', payload: 'config_batch' });
    emit({ type: 'send', payload: 'anti' });

    expect(script.post).toHaveBeenCalledTimes(2);
    expect(script.post.mock.calls[0][0].type).toBe('config_batch');
    expect(script.post.mock.calls[0][0].payload).toMatchObject({ pcap_enabled: false, keylog_enabled: true });
    expect(script.post.mock.calls[1][0]).toEqual({ type: 'antiroot', payload: true });
    expect(state.answered).toEqual(['config_batch', 'anti']);
    await expect(state.configured).resolves.toBeUndefined();
  });

  it('ignores non-handshake sends and non-send messages', () => {
    const { script, emit } = fakeScript();
    const state = configureFritapAgent(script as any, {});

    emit({ type: 'send', payload: { contentType: 'keylog', keylog: 'CLIENT_RANDOM aa bb' } });
    emit({ type: 'error', payload: 'config_batch' });
    emit({ type: 'send', payload: 'hello' });

    expect(script.post).not.toHaveBeenCalled();
    expect(state.answered).toEqual([]);
  });
});

describe('optional rpc exports', () => {
  it('readFritapAbiVersion returns the number from agentAbiVersion', async () => {
    const script = { exports: { agentAbiVersion: async () => 2 } };
    await expect(readFritapAbiVersion(script as any)).resolves.toBe(2);
  });

  it('readFritapAbiVersion returns null when the export is missing', async () => {
    await expect(readFritapAbiVersion({ exports: {} } as any)).resolves.toBeNull();
  });

  it('readFritapAbiVersion returns null when the rpc rejects', async () => {
    const script = { exports: { agentAbiVersion: async () => { throw new Error('rpc failed'); } } };
    await expect(readFritapAbiVersion(script as any)).resolves.toBeNull();
  });

  it('readFritapAbiVersion returns null for a non-number result', async () => {
    const script = { exports: { agentAbiVersion: async () => 'two' } };
    await expect(readFritapAbiVersion(script as any)).resolves.toBeNull();
  });

  it('gracefulDetachFritap calls gracefulDetach when present', async () => {
    const gracefulDetach = vi.fn(async () => undefined);
    await gracefulDetachFritap({ exports: { gracefulDetach } } as any);
    expect(gracefulDetach).toHaveBeenCalledTimes(1);
  });

  it('gracefulDetachFritap resolves when the export is missing', async () => {
    await expect(gracefulDetachFritap({ exports: {} } as any)).resolves.toBeUndefined();
  });
});
