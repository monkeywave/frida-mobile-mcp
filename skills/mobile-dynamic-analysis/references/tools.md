# Tool reference and RASP evasion

Detail for `SKILL.md`. Read this when you need option-level behaviour of a
tool, the prebuilt script list, the Frida 17.26 realm and Stalker features, or
the anti-Frida (RASP) playbook.

## Usage notes per tool

- Before hooking a Java method, call `describe_class` for the exact method
  overloads with parameter/return types and a hook-ready `signature`; pass that
  string to `hook_method` as `evidence: { class, signature }` to instrument a
  single overload (otherwise every overload is hooked). A static-analysis offset
  becomes a hook via `hook_method` `evidence: { module, offset }`.
- To author a custom script, follow the `write_frida_script` prompt and read
  `frida_help({ topic: "script_api" })`. `search_recipes` returns ready-made
  classic-JS snippets (custom crypto-key capture incl. hand-rolled RC4 like
  `Rc4Client`, native/JNI hooks, classloader/intent/WebView, iOS Keychain) to
  adapt and run with `execute_script`; keep useful ones with `save_script` /
  `run_saved_script` and hand off a standalone CLI file with `export_script`.
- `explore_app` accepts `class_filter` (regex); it defaults to the package
  pattern. `search_classes_and_methods` caps at `limit` (default 50).
- Two ways past the "I hooked it but nothing fired" wall. **Recognition**:
  `find_secrets_in_memory` scans the heap for the *structure* of a key (RC4
  S-box, AES key schedule, high-entropy buffers, PEM/DER, JWT) and recovers it
  without reaching the code that uses it — confirm a hit with `read_memory`.
  **Reachability**: `trace_coverage` arms cheap entry-hooks over a scope
  (`com.example.*`, `libfoo.so!*`) and, alternated with `trigger_and_wait`,
  shows which targets are still COLD so you know where to keep driving.
  `monitor_crypto` hooks every likely crypto sink at once when you don't know
  the exact method. `find_secrets_in_memory` recognizes RC4 / AES (enc+dec, any
  mode) / ChaCha20 / Salsa20 key structures, not just RC4.
- To close the loop automatically, the `hunt_secrets` prompt chains
  discover_crypto -> monitor_crypto + trace_coverage -> `drive_coverage`
  (autonomously taps the UI toward the cold crypto path, stopping when a key
  fires) -> find_secrets_in_memory -> `generate_memory_pattern`, which emits a
  reusable anchor+offset signature you can re-run with `scan_memory` or hand to
  friTap through `capture_tls` (`patterns`/`offsets`).
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
- `stop_instrumentation` by `session_id`, by `target`, or `all: true`. Skips
  eternalized scripts; it, `unload_script` and `detach_session` return
  `fritap_captures[]` (final friTap stats incl. `per_library`).
- `get_messages` cursor (`last_index` / `next_offset`) points after the last
  message returned; `truncated` and `remaining` say whether more is buffered.
- Teardown order: frida-java-bridge instances patch shared ART entry routines
  and must be reverted newest-first. All bulk teardown (`stop_instrumentation`,
  `detach_session`, session expiry, shutdown) does this. `unload_script` on an
  older Java-bridge script fails with `UNLOAD_ORDER_UNSAFE` (lists the newer
  scripts); pass `cascade: true` to unload them first (`cascaded_scripts`).
- `read_memory` / `write_memory` on unmapped or `0x0` addresses return
  `INVALID_ADDRESS`.
- Use `response_format: "json"` on any tool when you need the untruncated
  structured payload; default output is TOON, `markdown` is also available.
- `mobile_action` proxies UI automation to mobile-mcp (tap, type, screenshot,
  launch). Use it to drive the app to the code path you are hooking.

## Frida 17.26 features

### Emulated realm (ARM libraries in x86/x86_64 emulator apps)

`spawn_process` and `attach_process` accept `realm: 'native' | 'emulated'`
(default `'native'`). On an x86/x86_64 Android emulator, apps that ship only
ARM libraries run under native-bridge translation (Houdini/libndk). Use
`realm: 'emulated'` to hook those ARM libraries; the session records the realm
and the result echoes it. Requires Frida >= 17.26 on the device (matching
frida-server; node bundles 17.26.2, so run frida-server 17.26.x).
`spawn_process` kills the spawned process if the attach fails.
When a tool targets an app that is not running, it is spawned and resumed
*before* the attach (Android kills apps not resumed within ~10 s of a spawn).
Explicit spawn-suspended paths keep spawn -> attach -> load -> resume.

### trace_coverage engines

`trace_coverage` takes `engine: 'hooks' | 'stalker'` (default `'hooks'`).

- `hooks`: persistent entry-hooks over `scope`; alternate with
  `trigger_and_wait` to watch the cold set shrink (see notes above).
- `stalker`: a time-boxed basic-block map of one native module, returned as
  `module+0xoffset` blocks that paste straight into Ghidra/IDA. CPU heavy.

Stalker parameters:

| Arg               | Default | Meaning |
|-------------------|---------|---------|
| `module`          | -       | Required for stalker: module whose blocks are recorded (`libfoo.so`) |
| `offset_range`    | whole module | `{ start, size }`: restrict to `[module+start, module+start+size)`; `start` is hex string or number |
| `thread`          | `main`  | `'main'` or a numeric thread id. Main often yields 0 blocks (native work runs on workers): call `list_threads` and pass the worker tid |
| `duration_seconds`| `10`    | Recording window, max `120`; drive the app meanwhile |
| `max_blocks`      | `5000`  | Stop early at this many unique blocks, max `100000` |

The response lists at most 1000 blocks; `blocks_count` is the full count. When
`max_blocks` is hit a limitation notes that later blocks are missing.

## Defeating RASP / anti-Frida detection

The prebuilt bypasses (`run_prebuilt_script`, `bypass_ssl_pinning`) defeat the app's own checks (root/jailbreak,
SSL pinning, iOS anti-debug). Modern RASP (Talsec freeRASP, Guardsquare,
PairIP, Promon SHIELD, Appdome) additionally fingerprints **Frida itself**:
it scans `/proc/self/maps` for `frida-agent`/`libgadget`, reads thread names
(`gum-js-loop`, `pool-frida`), probes the `:27042` port / D-Bus handshake,
reads `/proc/self/status` TracerPid, and on iOS walks the dyld image list for
`FridaGadget`. Attack this in four layers (`frida_help({ topic: "evasion" })`
has the condensed version).

**Honest limitation.** Native detection in `.init_array` / `JNI_OnLoad` runs at
`dlopen`, before any attach-time script loads — even spawned suspended. The
attach model cannot instrument a constructor that already ran. The only full
answer to that class is frida-gadget embedded in a repackaged app (layer 3).

1. **In-process spoofing (attach model).** `run_prebuilt_script({ script_name:
   "anti_frida_evasion", target })` in `mode=report` (default) logs every probe
   the app makes; `mode=spoof` (needs `memoryWriteEnabled`) scrubs the Frida
   signatures out of what it reads from `/proc/self/{maps,status,task}`, zeroes
   TracerPid, blanks matched thread names, and rewrites iOS dyld image names.
   `aggressive=true` also hooks the hot `read()`/`strstr()` (raw `open()+read()`
   maps reads) at some stability cost. `watch_loads({ spoof: true })` applies
   the same scrub scoped to the `/proc` reads it watches. In-process scrubbing
   cannot change thread names it does not own, free `:27042`, or hide the
   agent's own file-backed mapping — that is layers 2–4.

2. **A quieter frida-server (Android).** `frida_server_start` accepts a custom
   `name` and `port`; run it as e.g. `/data/local/tmp/fs-$RANDOM` on
   `127.0.0.1:1337` so a `:27042` port scan and an `re.frida.server` name scan
   both miss. Reach the non-default port with `adb_forward` +
   `FRIDA_MCP_REMOTE=127.0.0.1:1337`. A patched/renamed build (strongR-frida,
   hluda) also renames the server's internal threads and pipe/D-Bus strings
   that a vanilla server leaks.

3. **frida-gadget (pre-`main`, no server port).** `frida-mobile-mcp gadget`
   (a CLI command — it needs app repackaging, so it is not a session tool)
   writes the gadget `config.json` and prints the APK/IPA steps.
   `gadget --interaction script --script /data/local/tmp/agent.js` runs fully
   on-device with **no listening port at all**; `gadget --interaction listen
   --port 1337 --on-load wait` blocks the app at launch until a client attaches
   (`FRIDA_MCP_REMOTE=127.0.0.1:1337`). This is the fix for the `.init_array`
   limitation above.

4. **Hide the tracer at the OS level (device-side, out of band).** Use
   **Magisk DenyList + Shamiko** (or Zygisk) to hide root/Magisk from the
   target, defeating RASP that keys off root/Zygisk presence before it even
   looks for Frida. Avoid the default `/data/local/tmp/frida-server` path/name,
   and run app-scoped/non-root where the target allows it.

Order: observe first (`anti_frida_evasion` report, or `watch_loads`), spoof only
the vectors the app actually uses, escalate to the gadget if you are caught
before `main`, and add layers 2 + 4 if maps/thread-name scans still catch you.

## Example call sequence (Android)

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

## Environment variables

Environment variables: `FRIDA_DEVICE_ID` (preselect a device, e.g.
`emulator-5556`; also set by the `--device` CLI option), `FRIDA_MCP_DEBUG=1`
(debug logging to stderr), `FRIDA_MCP_RUNTIME=v8|qjs` (agent script runtime),
`FRITAP_AGENT_PATH`, `FRITAP_VERSION`. Context-budget and remote controls:
`FRIDA_MCP_TOOL_PROFILE=core` (register only the core tool set),
`FRIDA_MCP_TOOLS_EXCLUDE=<globs>` (e.g. `adb_*,frida_server_*`),
`FRIDA_MCP_SCHEMA_PROFILE=compact` (shorter tool schemas),
`FRIDA_MCP_REMOTE_TOKEN` and `FRIDA_MCP_REMOTE_CERT` (auth token and TLS
certificate for a remote frida-server).

## Additional troubleshooting

`Java.perform` deferral / no Java messages
: Java hooks are installed inside `Java.perform`, which runs only once the ART
  VM is up. With spawn, the first messages arrive after resume: wait a few
  seconds and poll `get_messages` again. "Java is not available" means the
  process has no ART/JVM yet (too early) or is native-only (Flutter, Unity
  native, game engines): use `hook_function`, `enumerate_exports` and
  `analyze_native_function` instead.

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

## Running next to REA (Reverse Engineer Anything)

REA (morluto/rea) is a static-first server: Android package and method
inspection (`inspect_android_package`, `inspect_android_method`,
`trace_android_references`), ADB acquisition (`pull_adb_package`) and a generic
Frida lane (`start_frida_session`, `load_frida_script`) without the Java or
ObjC bridges. Run both side by side and route by question:

- Android/iOS runtime questions go to this server: bridges, prebuilt scripts,
  `capture_tls`, memory, UI driving.
- Use REA's Frida tools only for desktop binaries.
- Never hold the same PID in both servers' sessions.
- Pick one side for adb tasks (REA `pull_adb_package` or this server's
  `adb_*` / `get_app_info`); do not mix them in one flow.

Keep the combined tool list small with
`FRIDA_MCP_TOOL_PROFILE=core`, `FRIDA_MCP_TOOLS_EXCLUDE=adb_*,frida_server_*`
and `FRIDA_MCP_SCHEMA_PROFILE=compact`.

Evidence: cite REA's and this server's `evidence_id` values side by side in one
finding ledger. The APK sha256 from `get_app_info` ties the static and dynamic
halves together; if it differs from REA's, stop and re-pull.

Hand-off sequence: `get_app_info` -> REA `inspect_android_package` ->
`describe_class` -> `hook_method({ evidence: { class, signature } })` ->
`trigger_and_wait` -> `get_messages` -> `export_evidence_bundle`.

See `docs/rea.md` for the full integration guide.

## Tool catalog

Registered tools: `get_status`, `frida_help`, `explore_app`,
`detect_app_technologies`, `search_classes_and_methods`, `hook_method`,
`hook_function`, `unhook_function`, `trace_method`, `trace_coverage`,
`drive_coverage`, `discover_crypto`, `monitor_crypto`,
`find_secrets_in_memory`, `generate_memory_pattern`,
`run_prebuilt_script`,
`bypass_ssl_pinning`, `execute_script`, `read_memory`, `write_memory`,
`scan_memory`, `enumerate_modules`, `enumerate_exports`, `get_messages`,
`stop_instrumentation`, `mobile_action`, `list_devices`, `select_device`,
`get_device_info`, `list_processes`, `list_applications`,
`get_frontmost_application`, `spawn_process`, `attach_process`,
`resume_process`, `kill_process`, `detach_session`, `list_sessions`,
`capture_tls` (friTap) and `analyze_native_function` (native function analysis
that returns `module+0xoffset` addresses). Class and load inspection:
`describe_class` (overloads and hook-ready signatures), `trigger_and_wait`,
`watch_loads`. Script lifecycle: `unload_script` (drop one script, keep the
session), `eternalize_script` (pin a script so it survives detach, fire and
forget), `validate_script` (syntax/type/Frida 17 lint without a device),
`save_script`, `list_saved_scripts`, `run_saved_script`, `export_script`,
`search_recipes`. Native inspection: `enumerate_imports`, `enumerate_symbols`,
`resolve_address` (absolute address <-> `module+0xoffset`), `list_threads`,
`dump_module_memory` (dump a loaded module to a host file for Ghidra/IDA),
`inject_library` (inject a host `.so`/`.dylib`; needs `allowNativeInjection`).
Artifact and evidence: `get_app_info` (installed version, flags and per-APK
sha256; optional `pull_to`), `get_evidence` (fetch a persisted tool result by
`evidence_id`), `export_evidence_bundle` (JSON or Markdown report). Operational / stealth tools (Android,
via adb): `frida_server_status`, `frida_server_install`, `frida_server_start`,
`frida_server_stop`, `adb_shell`, `adb_logcat`, `adb_pull`, `adb_push`,
`adb_forward`, `spawn_gating`, `child_gating`, plus the `anti_frida_evasion`
prebuilt script and the `frida-mobile-mcp gadget` CLI command (section 8).
