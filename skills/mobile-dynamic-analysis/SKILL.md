---
name: mobile-dynamic-analysis
description: Dynamic analysis of Android and iOS apps with Frida through the frida-mobile-mcp server. Use this skill when a question cannot be answered from static artifacts alone - runtime argument and return values, decrypted buffers, which code path is actually taken, anti-tamper or root/jailbreak checks, and TLS plaintext or TLS key capture (capture_tls, backed by friTap). It also covers the loop between static reverse-engineering MCP servers (REA, ReVa/Ghidra, IDA MCP) and runtime hooks using the shared module+0xoffset address notation, the recommended tool order, guardrail flags, the evidence/error envelope, and troubleshooting of common Frida failures.
---

# Mobile dynamic analysis with frida-mobile-mcp

frida-mobile-mcp is an MCP server on top of frida-node 17. It exposes Frida
device, process, session, hooking, memory and TLS-capture operations as tools.
Every tool auto-manages device selection and sessions: give it the app bundle
ID (`com.example.app`), a process name or a PID string and it attaches or
spawns as needed.

Registered tools: `get_status`, `frida_help`, `explore_app`,
`detect_app_technologies`, `search_classes_and_methods`, `hook_method`,
`hook_function`, `unhook_function`, `trace_method`, `run_prebuilt_script`,
`bypass_ssl_pinning`, `execute_script`, `read_memory`, `write_memory`,
`scan_memory`, `enumerate_modules`, `enumerate_exports`, `get_messages`,
`stop_instrumentation`, `mobile_action`, `list_devices`, `select_device`,
`get_device_info`, `list_processes`, `list_applications`,
`get_frontmost_application`, `spawn_process`, `attach_process`,
`resume_process`, `kill_process`, `detach_session`, `list_sessions`,
`capture_tls` (friTap) and `analyze_native_function` (native function analysis
that returns `module+0xoffset` addresses).

`frida_help({ topic })` returns in-server documentation; topics are
`overview, hooking, tracing, memory, scripts, mobile, examples, advanced,
script_catalog`.

## 1. When to use frida-mobile-mcp instead of static tools

Static servers answer "what does the code say". Examples:

- REA: `inspect_android_package`, `project_apple_application_graph`
- ReVa / Ghidra: `decompile`, `get-functions`, cross references, strings
- IDA MCP: decompile, rename, list functions, xrefs

Reach for frida-mobile-mcp (dynamic) when you need:

- Runtime values: real arguments, return values, object state, backtraces.
- Decrypted data: buffers after `AES.doFinal`, after `SSL_read`, before
  `SSL_write`, decoded config blobs, JWTs after signing.
- Which branch is actually taken: hook the decision function and read the
  retval instead of reasoning about every path.
- Anti-tamper behaviour: root/jailbreak detection, debugger checks, Frida
  detection, certificate pinning - observe and neutralise them
  (`run_prebuilt_script`, `bypass_ssl_pinning`).
- TLS plaintext and session keys: `capture_tls` (friTap) gives NSS key logs
  and decrypted records regardless of the TLS library the app ships.
- Reachability: confirm a statically found function is ever called, and from
  where, with `hook_function` + `log_backtrace`.

Stay static when a disassembler already answers the question, when no device
or emulator is available, or when the app refuses to run under
instrumentation and the goal does not justify bypass work.

## 2. The static -> dynamic -> static loop

Disassemblers work on image-base-relative offsets. Frida works on runtime
addresses randomised by ASLR. The bridge is the address notation contract:

| Kind            | Notation                                   | Example                                   |
|-----------------|--------------------------------------------|-------------------------------------------|
| Native          | `<module>+0x<hex offset from module base>` | `libfoo.so+0x1234`                        |
| Native symbol   | `<module>!<symbol>`                        | `libssl.so!SSL_write`                     |
| Java (Android)  | `com.pkg.Class.method(sig)`                | `com.example.net.Api.sign(java.lang.String)` |
| Objective-C     | `-[Class selector]` / `+[Class selector]`  | `-[NSURLSession dataTaskWithRequest:]`    |

The loop:

1. Static: Ghidra/IDA shows an interesting function at `libfoo.so+0x1234`
   (offset = function address - image base shown in the disassembler).
2. Dynamic, native: `hook_method({ target: "com.example.app",
   method: "libfoo.so+0x1234", log_backtrace: true })` (decimal
   `libfoo.so+4660` also works). Dynamic, Java/ObjC: `hook_method({ target,
   method: "com.pkg.Class.method" })`. `hook_method` creates or reuses the
   session for you. `hook_function({ session_id, target: "libfoo.so+0x1234",
   on_enter?, on_leave? })` is the low-level variant on an existing session
   (from `list_sessions` or a previous result); custom handler bodies need
   `allowCustomScripts`.
3. Runtime args, retvals and backtraces come back as `module+0xoff` so they
   can be pasted straight into the static tool: ask ReVa to `decompile` at
   image base + offset, or IDA to jump to that offset.
4. Repeat for callers found in the backtrace.

ASLR rules:

- Never paste absolute runtime addresses (`0x7f3a1c2b1234`) into Ghidra or
  IDA. They differ per launch.
- If a tool gives you an absolute address, call `enumerate_modules` to get the
  module base and compute `addr - base` yourself, or prefer tools that already
  return `module+0x` (hook output, `analyze_native_function`).
- Tools that accept addresses take both forms; tools that return addresses
  prefer `module+0x`.

## 3. Recommended tool order

`get_status` -> `explore_app` -> `detect_app_technologies` ->
`run_prebuilt_script` -> `hook_method` / `hook_function` -> `get_messages` ->
`stop_instrumentation`.

Example for the Android app `com.example.app`:

```json
{"tool": "get_status", "args": {}}
{"tool": "explore_app", "args": {"target": "com.example.app"}}
{"tool": "detect_app_technologies", "args": {"target": "com.example.app"}}
{"tool": "run_prebuilt_script", "args": {"script_name": "ssl_pinning_bypass", "target": "com.example.app"}}
{"tool": "search_classes_and_methods", "args": {"target": "com.example.app", "pattern": "Crypto|Sign", "include_methods": true}}
{"tool": "hook_method", "args": {"target": "com.example.app", "method": "com.example.crypto.Signer.sign", "log_args": true, "log_retval": true, "log_backtrace": true}}
{"tool": "hook_method", "args": {"target": "com.example.app", "method": "libfoo.so+0x1234", "log_backtrace": true}}
{"tool": "get_messages", "args": {"session_id": "<session_id from hook result>", "limit": 50}}
{"tool": "stop_instrumentation", "args": {"target": "com.example.app"}}
```

Notes:

- `explore_app` accepts `class_filter` (regex); it defaults to the package
  pattern. `search_classes_and_methods` caps at `limit` (default 50).
- Prebuilt scripts: `ssl_pinning_bypass`, `root_jailbreak_bypass`,
  `class_enumeration`, `method_hook`, `crypto_monitor`, `network_inspector`,
  `keychain_prefs`, `filesystem_monitor`. Call `run_prebuilt_script` without
  `script_name` to list them with their options.
- `trace_method` takes wildcard patterns (`com.example.*.encrypt*`) and runs
  for `duration_seconds` (default 10) - use it to find candidates, then
  `hook_method` for the ones that matter.
- `get_messages` paginates with `since` (message index) and `limit`; filter
  with `script_id`. Hook invocations are capped at 1000 per hook and the
  session buffer at `maxMessageBuffer` (default 1000).
- `stop_instrumentation` by `session_id`, by `target`, or `all: true`.
- Use `response_format: "json"` on any tool when you need the untruncated
  structured payload; default output is TOON, `markdown` is also available.
- `mobile_action` proxies UI automation to mobile-mcp (tap, type, screenshot,
  launch). Use it to drive the app to the code path you are hooking.

## 4. capture_tls (friTap)

Captures TLS session keys and decrypted plaintext from an app using the friTap
agent, independent of the TLS library (BoringSSL, OpenSSL, NSS, GnuTLS,
mbedTLS, Conscrypt, Flutter/Dart, Cronet, ...).

Arguments:

| Arg                | Default | Meaning |
|--------------------|---------|---------|
| `target`           | -       | Bundle ID, process name or PID string |
| `device`           | auto    | Device ID |
| `keylog_path`      | auto    | Where to write the NSS key log |
| `pcap_path`        | none    | Best-effort pcap of decrypted records (see below) |
| `spawn`            | `true`  | Spawn suspended -> load friTap agent -> configure -> resume, so the first TLS handshakes are caught. `false` attaches to the running process |
| `anti_root`        | `false` | Enable friTap anti-root/anti-detection helpers |
| `full_capture`     | `false` | Capture all traffic of the process, not only TLS |
| `duration_seconds` | `0`     | `0` = keep running until `stop_instrumentation`; max 600 |
| `allow_download`   | `true`  | Fetch the pinned friTap agent bundle from GitHub into `~/.config/frida-mobile-mcp/fritap/<version>/` when `pip install friTap` is not present |

Output: `session_id`, `script_id`, `agent_version`, `keylog_path`, `hooks`
(initial summary messages reporting which TLS libraries were hooked).

- Key log: NSS key log format (`CLIENT_RANDOM <client_random> <secret>`).
  Load it in Wireshark via Preferences -> Protocols -> TLS ->
  `(Pre)-Master-Secret log filename`, or `tls.keylog_file` in `tshark -o`.
- Plaintext: decrypted records are buffered into session messages. Poll
  `get_messages({ session_id })`; records have type `fritap_datalog` with a
  hex dump plus a UTF-8 preview, capped per record and by the session buffer.
- pcap: full pcap writing (with TCP/IP framing) needs the friTap Python CLI:
  `fritap -m -p out.pcap -k keys.log -s com.example.app`. The MCP tool writes
  only a best-effort pcap of decrypted records, and only when `pcap_path` is
  given.

Agent discovery order: `FRITAP_AGENT_PATH` env -> installed `friTap` Python
package (`fritap_agent.js` next to `friTap/__init__.py`) -> cached download
`~/.config/frida-mobile-mcp/fritap/<version>/fritap_agent.js` fetched from
`https://raw.githubusercontent.com/fkie-cad/friTap/<tag>/friTap/fritap_agent.js`
(default tag `v2.5.2`; `FRITAP_VERSION` pins another tag).

Error `FRITAP_AGENT_UNAVAILABLE`: run `pip install friTap`, or set
`FRITAP_AGENT_PATH=/path/to/fritap_agent.js`, or allow the download.

Typical sequence: `capture_tls({ target: "com.example.app" })` -> drive the app
with `mobile_action` -> `get_messages` for `fritap_datalog` -> open
`keylog_path` in Wireshark alongside a device-side capture (`tcpdump`,
`androidtcpdump`) -> `stop_instrumentation`.

## 5. Guardrail flags and configuration

Config file: `~/.config/frida-mobile-mcp/config.json` (merged over defaults,
then CLI overrides, then env). Defaults from `src/config.ts`:

| Flag                    | Default | Effect |
|-------------------------|---------|--------|
| `allowCustomScripts`    | `false` | `execute_script` and custom `on_enter`/`on_leave` bodies are refused with `CUSTOM_SCRIPTS_DISABLED`. Enable in config or `FRIDA_MCP_ALLOW_CUSTOM_SCRIPTS=1` |
| `memoryWriteEnabled`    | `false` | `write_memory` is refused with `MEMORY_WRITE_DISABLED`. Enable in config or `FRIDA_MCP_MEMORY_WRITE=1` |
| `allowedDevices`        | `[]`    | Empty = any device; otherwise only listed device IDs may be used |
| `maxSessions`           | `4`     | Concurrent Frida sessions; clean up with `stop_instrumentation` |
| `sessionTimeoutMinutes` | `30`    | Idle sessions are detached |
| `maxMessageBuffer`      | `1000`  | Per-session message ring buffer |
| `rateLimits.scriptsPerMinute`     | `10` | Script loads per minute |
| `rateLimits.memoryReadsPerMinute` | `60` | `read_memory` / `scan_memory` per minute |
| `rateLimits.sessionsPerMinute`    | `5`  | Attach/spawn per minute |
| `auditLogPath`          | `~/.config/frida-mobile-mcp/audit.jsonl` | Every tool call is appended as JSONL (tool, params, duration, outcome) |
| `mobileMcp`             | `npx -y @mobilenext/mobile-mcp@latest` | Backend for `mobile_action`; `enabled: false` disables it |

Environment variables: `FRIDA_DEVICE_ID` (preselect a device, e.g.
`emulator-5556`; also set by the `--device` CLI option), `FRIDA_MCP_DEBUG=1`
(debug logging to stderr), `FRIDA_MCP_RUNTIME=v8|qjs` (agent script runtime),
`FRITAP_AGENT_PATH`, `FRITAP_VERSION`.

Prefer prebuilt scripts and typed hook tools over `execute_script`; they do
not need `allowCustomScripts` and their output is structured.

## 6. Troubleshooting

frida-server version mismatch
: frida-node 17.x needs frida-server 17.x on the device. Symptoms: "unable to
  communicate with remote frida-server", protocol or "unexpected message"
  errors, `list_processes` failing although `adb devices` works. Fix: download
  the matching `frida-server-17.x.y-android-<arch>` from the Frida GitHub
  releases, `adb push` it to `/data/local/tmp/`, `chmod 755`, and run it as
  root. Check with `get_device_info` / `frida --version` on the host.

Android spawn launch timeout (`FRIDA_TIMEOUT` on spawn)
: The app is slow to start, zygote is busy, or the launcher activity is
  blocked. Launch the app first with `mobile_action` (or manually) and call
  the tool with `spawn: false`, or use `attach_process` on the PID from
  `list_processes`. Early-init hooks are lost that way; for TLS use
  `capture_tls` with `spawn: true` once the emulator is warm.

`Java.perform` deferral / no Java messages
: Java hooks are installed inside `Java.perform`, which runs only once the ART
  VM is up. With spawn, the first messages arrive after resume: wait a few
  seconds and poll `get_messages` again. "Java is not available" means the
  process has no ART/JVM yet (too early) or is native-only (Flutter, Unity
  native, game engines): use `hook_function`, `enumerate_exports` and
  `analyze_native_function` instead.

"script destroyed" / session detached
: The app crashed, was killed, or was detached by the OS. Check
  `get_status` (`recent_detaches`, and `session_context.last_detach` on every result) and `list_sessions`. Re-run the hook
  tool; it creates a fresh session. Frequent crashes right after hooking point
  to anti-Frida checks: try `run_prebuilt_script({ script_name:
  "root_jailbreak_bypass" })` or `capture_tls({ anti_root: true })`.

Rate limiting (`RATE_LIMIT_EXCEEDED`)
: Retryable. Wait a minute or batch work: one `trace_method` instead of many
  `hook_method` calls, pagination on `get_messages` instead of re-reading.

No device / wrong device
: `list_devices`, then `select_device` or set `FRIDA_DEVICE_ID`. With
  `allowedDevices` configured, an unlisted device is a `DEVICE_NOT_FOUND`.

`mobile_action` fails with `MOBILE_MCP_UNAVAILABLE`
: mobile-mcp could not be started (`npx` missing, no network for the first
  download, or `mobileMcp.enabled: false`). Drive the UI manually and keep
  using the Frida tools.

Read the envelope before retrying
: Every result carries `evidence_id`, `limitations[]` and
  `coverage.status`. `coverage.status: "unknown"` with a limitation such as
  "class enumeration truncated at 50" means the answer is partial; raise
  `limit`, narrow the filter, or page with `since` before concluding that
  something does not exist.

## 7. Evidence and error envelope

Every successful tool result has this shape (in both text content and
`structuredContent`):

```json
{
  "result": { "...tool specific..." },
  "evidence_id": "6f0c0b5e-1c1e-4f1b-9d8c-6b5c2a1e0f3d",
  "limitations": ["output truncated to 50 messages; use since/limit"],
  "coverage": { "status": "complete" },
  "session_context": { "device": "emulator-5556", "platform": "android", "active_sessions": ["..."], "active_hooks": 2, "active_scripts": 3 },
  "suggested_next": [{ "tool": "get_messages", "args": { "session_id": "..." }, "reason": "Retrieve intercepted calls" }]
}
```

- `evidence_id` is a UUID per tool call; cite it when reporting findings so a
  reviewer can locate the call in the audit log.
- `limitations` lists what the tool could not do; `coverage.status` is
  `complete` or `unknown` (with an optional `note`).
- `suggested_next` is advisory; the recommended order in section 3 still
  applies.

Errors are returned as:

```json
{ "error": { "code": "CUSTOM_SCRIPTS_DISABLED", "category": "authorization",
             "message": "...", "retryable": false,
             "remediation": "Set allowCustomScripts: true in config.json",
             "recovery_actions": [{ "tool": "run_prebuilt_script", "reason": "..." }],
             "context": { "tool": "execute_script" } } }
```

`category` is one of `request | authorization | capability | timeout |
resource | provider`. Retry only when `retryable` is true (`RATE_LIMIT_EXCEEDED`,
`RPC_TIMEOUT`, `FRIDA_TIMEOUT`); otherwise apply `remediation` or one of the
`recovery_actions` first. See `docs/interop.md` for the full code table.
