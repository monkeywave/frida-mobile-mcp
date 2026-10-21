# frida-mobile-mcp

[![npm](https://img.shields.io/npm/v/frida-mobile-mcp.svg)](https://www.npmjs.com/package/frida-mobile-mcp)
[![CI](https://github.com/monkeywave/frida-mobile-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/monkeywave/frida-mobile-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node >=22.12](https://img.shields.io/badge/node-%3E%3D22.12-brightgreen.svg)](package.json)

An MCP server that gives AI agents dynamic instrumentation of Android and iOS apps through Frida 17. It exposes 40 tools: high-level ones that manage devices, sessions and scripts for you (explore an app, hook a Java/ObjC/native method, trace calls, bypass SSL pinning, capture TLS keys and plaintext with friTap, run prebuilt analysis scripts, validate custom scripts) and low-level primitives (spawn/attach, module and symbol enumeration, address resolution, control-flow analysis, memory dumps). Addresses use the same `module+0xoffset` notation as Ghidra/IDA so results move between static and dynamic tools without conversion, and every result carries an evidence envelope (`evidence_id`, `limitations`, `coverage`). Optional UI automation goes through [mobile-mcp](https://github.com/mobile-next/mobile-mcp).

## Quick start

```bash
npx frida-mobile-mcp                      # stdio MCP server (default `serve` command)
frida-mobile-mcp doctor                   # check Node, frida-node, adb, devices, frida-server, bridge bundles
frida-mobile-mcp setup --client cursor    # write the server into a client config (claude-code, claude-desktop, cursor, vscode, windsurf, codex)
```

Claude Code:

```bash
claude mcp add frida -- npx -y frida-mobile-mcp
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "frida": {
      "command": "npx",
      "args": ["-y", "frida-mobile-mcp"],
      "env": { "FRIDA_DEVICE_ID": "emulator-5554" }
    }
  }
}
```

Per-client instructions, HTTP mode and remote frida-server setup are in [docs/clients.md](docs/clients.md). A Claude Desktop extension manifest (`manifest.json`, MCPB) and an MCP registry entry (`server.json`) ship in the repo.

## Requirements

- Node.js >= 22.12 (CI runs 22 and 24 on Linux, macOS and Windows). `npm install` runs the `frida` package's install script, which downloads the native frida-node prebuild.
- A device or emulator running **frida-server 17.x**. This package depends on frida-node `^17.24.3`; frida-server on the device must have the same major version (17) and ideally the same minor version. `frida-mobile-mcp doctor` prints both versions and flags mismatches.
- Android: download the matching `frida-server-17.x.y-android-<arch>.xz` from <https://github.com/frida/frida/releases>, then

  ```bash
  xz -d frida-server-17.24.3-android-arm64.xz
  adb push frida-server-17.24.3-android-arm64 /data/local/tmp/frida-server
  adb shell "chmod 755 /data/local/tmp/frida-server"
  adb shell "su -c '/data/local/tmp/frida-server &'"
  ```

- iOS: a jailbroken device with the matching Frida package from the Frida Cydia/Sileo repository. Non-jailbroken devices need the app repackaged with the Frida Gadget; the server then attaches to the gadget-enabled process like any other.
- Optional: `pip install friTap` for `capture_tls` (otherwise the pinned agent is downloaded on first use), and network access for `npx -y @mobilenext/mobile-mcp@latest` on first `mobile_action`.

## What is new for Frida 17

- **Bridges are bundled.** Frida 17 no longer ships the Java/ObjC bridges in the GumJS runtime. `npm run build:bridges` bundles `frida-java-bridge` and `frida-objc-bridge` into `dist/bridges/{java,objc}.js`; the server injects the right one by platform (Java on Android, ObjC on iOS/macOS) ahead of every script.
- **Legacy scripts still work.** `execute_script` runs classic (non-module) scripts through `Script.evaluate`, so a `Java.perform(...)` script written for Frida 16 runs unchanged and keeps its own line numbers in errors. ES modules (`import Java from "frida-java-bridge"`, JS or TS) are compiled on the host with the Frida Compiler; frida-compile bundles (starting with the `📦` marker) are loaded as-is.
- **Removed APIs are linted.** `validate_script` flags the static `Module.findExportByName`/`findBaseAddress`/`enumerateExports`, `Memory.readX`/`writeX` and `*Sync` enumerators that throw on Frida 17 and suggests the Module-instance / `NativePointer` replacements. Generated scripts get `findExport(lib, name)` and `hookNative(lib, name, callbacks)` helpers from the agent preamble, and template options as `__FRIDA_MCP__.options`.
- `analyze_native_function` uses `Process.findFunctionRange` and the Frida 17.12+ `ControlFlowGraph` (with a linear-disassembly fallback reported in `limitations`).

## Tool reference

### Tier 1: high-level tools

| Tool | Description |
|------|-------------|
| `get_status` | Connected devices, active sessions (platform, script count, last activity), hooks, traces and recent detaches/crashes. Run first and after a session is lost. |
| `frida_help` | Topic help: overview, hooking, tracing, memory, scripts, native, tls, mobile, examples, advanced, script_catalog. |
| `detect_app_technologies` | Fingerprint libraries, frameworks and security mechanisms; returns recommended script targets. |
| `explore_app` | Spawn an app suspended, instrument, resume; returns pid, platform, modules and a filtered class list. |
| `search_classes_and_methods` | Regex search over classes (and methods with `include_methods`) in a running app. |
| `hook_method` | Hook Java (`com.example.Class.method`), ObjC (`-[Class sel:]`) or native targets (`libssl.so!SSL_read`, `libfoo.so+0x1234`, `0x7f...`, `!open`) with auto session management; backtraces as `module+0xoff (symbol)`. |
| `trace_method` | frida-trace style tracing of glob patterns (`com.example.net.*`, `-[NSURL*]`, `libssl.so!SSL_*`) for a duration. |
| `execute_script` | Run a custom script: classic JS (bridges injected), ES module JS/TS (compiled with the Frida Compiler) or a frida-compile bundle. `timeout_ms` bounds the initial run. Requires `allowCustomScripts`. |
| `validate_script` | Syntax, type and Frida 17 removed-API check without a device. Use before `execute_script`. |
| `run_prebuilt_script` | Run one of the 8 prebuilt scripts below; call without `script_name` to list them. |
| `bypass_ssl_pinning` | One-click pinning bypass (Android: TrustManager, OkHttp CertificatePinner, Conscrypt; iOS: SecTrust, ATS, BoringSSL). |
| `capture_tls` | friTap: TLS session keys (NSS key log) and optional decrypted plaintext / synthetic pcap for OpenSSL/BoringSSL, Conscrypt, NSS, GnuTLS, wolfSSL, mbedTLS, Secure Transport and more. |
| `read_memory` | Read up to 4 MB at any address notation; returns hex plus absolute address and `module+offset`. |
| `write_memory` | Write hex bytes to memory. Disabled unless `memoryWriteEnabled`. |
| `scan_memory` | Byte-pattern scan (`48 89 5c 24 ?? 57`), optionally limited to a module. |
| `get_messages` | Buffered hook invocations, trace hits, `send()` output and errors; `since` paginates. |
| `stop_instrumentation` | Remove all hooks, scripts and traces on a target and detach. |
| `mobile_action` | Gateway to mobile-mcp UI automation (screenshot, elements, tap, swipe, type, launch app, list apps). |

### Tier 2: advanced primitives

| Tool | Description |
|------|-------------|
| `list_devices` | Local, USB and remote Frida devices (frida-ls-devices). |
| `select_device` | Select the active device by ID, type or remote host. |
| `get_device_info` | OS version, architecture and system parameters. |
| `list_processes` | Running processes (frida-ps). |
| `list_applications` | Installed and running applications. |
| `get_frontmost_application` | Foreground application. |
| `spawn_process` | Spawn suspended for early instrumentation; resume with `resume_process`. |
| `attach_process` | Attach to a running process by PID or name. |
| `resume_process` | Resume a suspended process. |
| `kill_process` | Kill a process. |
| `detach_session` | Detach a session and unload its scripts. |
| `list_sessions` | Sessions managed by this server. |
| `enumerate_modules` | Loaded modules with name, base, end, size, path; regex `filter`. |
| `enumerate_exports` | Exports of a module, paginated. |
| `enumerate_imports` | Imports of a module with the providing module, paginated. |
| `enumerate_symbols` | Symbols including non-exported/debug symbols; regex filter and paging inside the agent (Linux, Android, iOS, macOS). |
| `resolve_address` | Translate `0x7f...` to `module+0xoffset` (+ nearest symbol) and `module+0xoff` / `module!sym` to an absolute address. |
| `analyze_native_function` | Function range, basic blocks and edges, first instructions; addresses as absolute and `module+0xoffset`. |
| `dump_module_memory` | Dump a module base-relative to a host file (under cwd, the temp dir or `~/.config/frida-mobile-mcp/dumps`) for raw import into Ghidra/IDA. |
| `list_threads` | Threads with id, name, state, current pc as `module+0xoffset`; optional 8-frame backtraces. |
| `hook_function` | Low-level `Interceptor` hook on a `session_id` with optional custom `on_enter`/`on_leave` bodies (custom bodies need `allowCustomScripts`). |
| `unhook_function` | Remove a hook by ID. |

### mobile_action gateway

`mobile_action({ action, params })` forwards to a lazily spawned mobile-mcp process (`npx -y @mobilenext/mobile-mcp@latest` by default, configurable via `mobileMcp`, disabled with `--no-mobile-mcp`). Call it without `action` to list the available actions. All Frida tools work without it; when it cannot start the error is `MOBILE_MCP_UNAVAILABLE`.

The server also exposes `frida://` resources (version, devices, processes, apps, sessions, messages, script catalog) and three workflow prompts (`explore_app`, `security_audit`, `trace_functionality`).

## Prebuilt scripts

| Script | Purpose |
|--------|---------|
| `ssl_pinning_bypass` | Bypass certificate pinning (TrustManager, OkHttp, Conscrypt, WebView; SecTrust, ATS, BoringSSL, AFNetworking) |
| `root_jailbreak_bypass` | Bypass root/jailbreak detection (Java, SystemProperties, native fopen/access/stat, canOpenURL, sysctl) |
| `class_enumeration` | List loaded Java/ObjC classes with a regex filter, optionally with methods |
| `method_hook` | Generic method hook with argument and return value logging |
| `crypto_monitor` | javax.crypto, CommonCrypto and OpenSSL calls |
| `network_inspector` | Sockets, DNS, UDP and SSL_read/SSL_write plaintext |
| `keychain_prefs` | iOS Keychain and Android SharedPreferences access |
| `filesystem_monitor` | File I/O and SQLite |

## Address notation and evidence envelope

Every tool that takes or returns a native address uses one vocabulary:

| Form | Meaning | Example |
|------|---------|---------|
| `module!symbol` | export or ELF/Mach-O symbol | `libssl.so!SSL_write` |
| `module+0xOFFSET` | offset from the module base (Ghidra/IDA RVA); decimal `libfoo.so+4660` also accepted | `libfoo.so+0x1a2b0` |
| `0xADDRESS` | absolute runtime address | `0x7f3a1c2b1234` |
| `symbol` / `!symbol` | global export searched across all modules | `!open` |

Results prefer `module+0xoffset` so a static tool can decompile at image base + offset; absolute addresses appear only outside known modules and come with a `limitations` entry.

Every successful call returns `result`, `evidence_id` (UUID, also written to the audit log), `limitations[]`, `coverage` (`complete` | `unknown`), `session_context` and `suggested_next`. Errors carry `code`, `category`, `retryable`, `remediation` and `recovery_actions`. Field semantics and the error-code table are in [docs/interop.md](docs/interop.md); the agent workflow around them is in [skills/mobile-dynamic-analysis/SKILL.md](skills/mobile-dynamic-analysis/SKILL.md).

## Working with static tools

frida-mobile-mcp is built to run next to ReVa (Ghidra), ida-pro-mcp (IDA Pro) and REA: the static side answers what the code says, this server answers what it does at runtime. A static tool finds `libfoo.so+0x1234`; `hook_method` or `analyze_native_function` take that string as-is; backtraces and `resolve_address` give offsets back in the same form for decompilation. `enumerate_modules` returns `base`/`end` for rebasing a Ghidra/IDA project, `dump_module_memory` writes a base-relative image of an unpacked library for raw import, and `capture_tls` shows the bytes a statically found wrapper actually puts on the wire. A three-server client configuration and a full static -> dynamic -> static walkthrough are in [docs/interop.md](docs/interop.md).

## HTTP transport

```bash
frida-mobile-mcp --transport http --port 3000                 # loopback (127.0.0.1), token optional
FRIDA_MCP_HTTP_TOKEN=<token> frida-mobile-mcp --transport http --host 0.0.0.0 --port 3000
```

Streamable HTTP endpoint at `/mcp` with one MCP session per client (`Mcp-Session-Id`); `DELETE /mcp` with that header ends the session. The server binds to loopback by default; a Bearer token (`--http-token` or `FRIDA_MCP_HTTP_TOKEN`) is mandatory when `--host` is not a loopback address and the server refuses to start without one. `Host` and `Origin` headers are validated against the bound host (DNS-rebinding protection). There is no TLS; use a reverse proxy or SSH tunnel across networks. `--port 0` picks a free port; the bound URL is printed as a JSON line on stderr. Full curl examples: [docs/clients.md](docs/clients.md#http-mode).

## Library usage

```ts
import { McpServer } from '@modelcontextprotocol/server';
import { createServer, registerFridaTools, createSessionServer } from 'frida-mobile-mcp';

const server = createServer({ allowCustomScripts: false });      // ready-made McpServer with every tool
// or add the tools to your own server:
const mine = new McpServer({ name: 'my-agent', version: '1.0.0' });
const deviceManager = registerFridaTools(mine, { resources: true, prompts: false });
// or one server per HTTP session:
const perSession = createSessionServer();
```

Also exported: `scriptRegistry`, `DeviceManager`, `composeAgentSource`/`createAgentScript`, `findRemovedApis`, `loadBridgeSource`, `startHttpServer`, `createStdioTransport`, `loadConfig`, `ensureState` and the types (`dist/lib.d.ts`).

## Configuration

Config file `~/.config/frida-mobile-mcp/config.json` (merged over defaults, then CLI flags, then environment):

```json
{
  "allowCustomScripts": false,
  "memoryWriteEnabled": false,
  "allowedDevices": [],
  "maxSessions": 4,
  "sessionTimeoutMinutes": 30,
  "maxMessageBuffer": 1000,
  "auditLogPath": "~/.config/frida-mobile-mcp/audit.jsonl",
  "mobileMcp": { "enabled": true, "command": "npx", "args": ["-y", "@mobilenext/mobile-mcp@latest"] },
  "rateLimits": { "scriptsPerMinute": 10, "memoryReadsPerMinute": 60, "sessionsPerMinute": 5 }
}
```

| Variable | Default | Description |
|----------|---------|-------------|
| `FRIDA_DEVICE_ID` | first USB device | Device to use; same as `--device` |
| `FRIDA_MCP_ALLOW_CUSTOM_SCRIPTS` | unset | `1`/`true` enables `execute_script` and custom `hook_function` bodies; same as `--allow-custom-scripts` |
| `FRIDA_MCP_MEMORY_WRITE` | unset | `1`/`true` enables `write_memory`; same as `--allow-memory-write` |
| `FRIDA_MCP_DEBUG` | unset | `1` enables debug logging on stderr; same as `--debug` |
| `FRIDA_MCP_REMOTE` | unset | `host[:port]` of a frida-server added as a remote device at startup (port 27042) |
| `FRIDA_MCP_HTTP_TOKEN` | unset | Bearer token for the HTTP transport; same as `--http-token` |
| `FRIDA_MCP_SCHEMA_PROFILE` | `full` | `compact` shortens tool schemas for small context windows |
| `FRIDA_MCP_MAX_RESPONSE_CHARS` | `25000` | Truncation limit for a single tool response |
| `FRIDA_MCP_RUNTIME` | Frida default | `qjs` or `v8` script runtime for injected agents |
| `FRIDA_MCP_BRIDGES_DIR` | `dist/bridges` | Directory with the bundled `java.js`/`objc.js` bridges |
| `FRIDA_MCP_COMPILER_PROJECT_DIR` | `$TMPDIR/frida-mobile-mcp/compiler-project` | Project dir the Frida Compiler uses for ES module scripts |
| `FRITAP_AGENT_PATH` | unset | Path to a `fritap_agent.js` bundle for `capture_tls` |
| `FRITAP_VERSION` | `v2.5.2` | friTap tag to download when no local agent is found |

## Security guardrails

- `execute_script` and custom `hook_function` handler bodies are refused with `CUSTOM_SCRIPTS_DISABLED` unless `allowCustomScripts` is on; prebuilt scripts and typed hook tools never need it.
- `write_memory` is refused with `MEMORY_WRITE_DISABLED` unless `memoryWriteEnabled` is on.
- `allowedDevices` restricts which device IDs may be used (empty = any).
- Rate limits per minute for script loads, memory reads/scans and attach/spawn (`RATE_LIMIT_EXCEEDED`, retryable); `maxSessions` and `sessionTimeoutMinutes` cap concurrent and idle sessions.
- Every tool call is appended to the JSONL audit log at `auditLogPath` with its `evidence_id`.
- `dump_module_memory` only writes under the current directory, the OS temp directory or `~/.config/frida-mobile-mcp/dumps`.
- HTTP transport: loopback bind by default, token required off-loopback, Host/Origin validation.

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## Troubleshooting

- **Version mismatch** (`unable to connect to remote frida-server`, protocol/"unexpected message" errors, timeouts while `adb devices` works): frida-server on the device must be 17.x matching frida-node. Run `frida-mobile-mcp doctor`, then push the matching release (see Requirements).
- **"Timeout was reached" / app killed after spawn**: Android kills a spawned app that stays suspended for more than ~10 s (Frida >= 17.6 cannot disable the launch timeout). `explore_app` resumes before class enumeration for this reason; with `spawn_process`, call `resume_process` promptly. If spawning is slow, launch the app first and attach (`spawn: false` / `attach_process`).
- **No Java messages right after hooking**: Java hooks install inside `Java.perform`, which runs once the ART VM is up. Poll `get_messages` again after a few seconds. "Java is not available" means a native-only process; use `hook_function`, `enumerate_exports` or `analyze_native_function`.
- **`Frida java bridge bundle not found`**: run `npm run build:bridges` (part of `npm run build` and `pretest`) or point `FRIDA_MCP_BRIDGES_DIR` at a directory with `java.js`/`objc.js`.
- **`npm install` fails downloading the frida prebuild**: the `frida` package fetches its native binding in an install script; make sure install scripts are allowed (`npm ci --foreground-scripts` shows the download) and GitHub releases are reachable.
- **Two devices attached**: set `FRIDA_DEVICE_ID`/`--device`, pass `device` to the tool, or `select_device`; with `allowedDevices` set an unlisted device yields `DEVICE_NOT_FOUND`.
- **`SESSION_LOST` / "script destroyed"**: the app crashed or was detached; `get_status` shows `recent_detaches`. Re-running the hook tool creates a fresh session; frequent crashes right after hooking point to anti-Frida checks (`root_jailbreak_bypass`, `capture_tls({ anti_root: true })`).
- **`FRITAP_AGENT_UNAVAILABLE`**: `pip install friTap`, set `FRITAP_AGENT_PATH`, or allow the download (`allow_download: true`).

## Development

```bash
npm ci --foreground-scripts   # installs deps and the frida prebuild
npm run build                 # build:bridges (rollup bundles of the Java/ObjC bridges) + tsc
npm run lint                  # tsc --noEmit
npm test                      # vitest (pretest rebuilds the bridges); device suites are skipped
npm run dev                   # tsc --watch
```

Device end-to-end tests opt in through environment variables:

```bash
FRIDA_MCP_E2E_DEVICE=emulator-5556 FRIDA_MCP_E2E_TARGET=com.example.rc4demo npx vitest run test/e2e
FRIDA_E2E=1 FRIDA_DEVICE_ID=emulator-5556 npx vitest run test/fritap/capture-tls.e2e.test.ts
```

Commits follow Conventional Commits (`feat:`, `fix:`, `docs:`, ...); release-please opens the release PR, maintains `CHANGELOG.md` and the `publish` job in `release.yml` publishes to npm via OIDC trusted publishing. See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md).

## License

[MIT](LICENSE)
