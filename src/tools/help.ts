import { z } from 'zod';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { responseFormatSchema } from '../constants.js';

const TOPIC_LIST = 'overview, hooking, tracing, memory, scripts, native, tls, mobile, examples, advanced, evasion, script_catalog, script_api, recipes, interop';

const HELP_TOPICS: Record<string, string> = {
  overview: `# frida-mobile-mcp: Mobile Frida MCP Server

## What is this?
A server that lets AI agents dynamically instrument and explore mobile apps on Android and iOS using Frida 17.

## Quick Start
1. \`get_status\` — See connected devices, sessions and recent detaches
2. \`detect_app_technologies\` — **Run this first!** Fingerprint the app's tech stack and get tailored script recommendations
3. \`explore_app\` — Launch an app and get initial context (modules, classes)
4. \`hook_method\` — Hook a Java, ObjC or native method to intercept calls
5. \`trace_method\` — Trace function calls for a duration
6. \`bypass_ssl_pinning\` — One-click SSL pinning bypass
7. \`capture_tls\` — TLS keys and plaintext via friTap (no pinning bypass needed)

## Tool Categories
- **Exploration**: explore_app, detect_app_technologies, search_classes_and_methods, describe_class, discover_crypto
- **Artifact identity**: get_app_info (version, debuggable, every APK with on-device sha256/size; \`pull_to\` pulls and hash-verifies them for REA \`inspect_android_package\` / jadx)
- **Evidence**: get_evidence (re-read a persisted tool result by \`evidence_id\`), export_evidence_bundle (JSON or Markdown bundle of persisted results, inline or to a file)
- **Instrumentation**: hook_method, trace_method, trace_coverage (reachability map), execute_script, validate_script, run_prebuilt_script
- **Observation**: watch_loads (late-loaded libs/classes + anti-Frida probes), trigger_and_wait (do a UI action, then wait for the hooks it fires)
- **Secret recovery**: find_secrets_in_memory (RC4/AES/ChaCha/key structures in the heap), generate_memory_pattern (turn a found secret into a reusable friTap pattern), monitor_crypto (wide-net crypto-sink hooking)
- **Reachability**: trace_coverage (covered-vs-cold map), drive_coverage (autonomously tap the UI toward uncovered code)
- **Security / TLS**: bypass_ssl_pinning, capture_tls
- **Memory**: read_memory, write_memory, scan_memory
- **Native analysis** (topic \`native\`): enumerate_modules, enumerate_exports, enumerate_imports, enumerate_symbols, resolve_address, analyze_native_function, dump_module_memory, list_threads
- **Device / frida-server** (Android, via adb): frida_server_status, frida_server_install, frida_server_start, frida_server_stop — provision and control the device-side frida-server (custom port/name for stealth)
- **Raw adb** (Android): adb_shell (needs allowAdbShell), adb_logcat, adb_pull, adb_push, adb_forward
- **Mobile UI**: mobile_action (tap, swipe, screenshot, elements via mobile-mcp)
- **Knowledge & library**: search_recipes (purpose-indexed classic-JS recipes), save_script, list_saved_scripts, run_saved_script, export_script (standalone \`frida -U -l\` file) — see topics \`recipes\` and \`script_api\`
- **Management**: get_status, get_messages, stop_instrumentation, unload_script, frida_help
- **Next to REA / ReVa / IDA** (topic \`interop\`): routing rules, evidence mapping, context-budget env vars and an APK -> static -> hook -> report walkthrough

## Finding the right hook target (crypto example)
1. \`discover_crypto\` — ranked candidate classes/symbols (does NOT assume javax.crypto; finds custom Java like \`Rc4Client\` and native symbols).
2. \`hook_method\` on the top candidate, or \`monitor_crypto\` to hook EVERY likely crypto sink at once (a wide net when you don't know the exact method).
3. \`trigger_and_wait\` — drive the app (a tap/launch) and confirm the hook fired; if nothing fires, check \`get_status\` hook liveness and re-run \`discover_crypto\`.
4. \`watch_loads\` if the implementation loads later (native \`.so\` or dynamic dex) or the app runs anti-Frida checks.

## When you cannot reach the code
- \`find_secrets_in_memory\` — recover keys by their STRUCTURE in the heap without ever reaching the function that uses them: RC4 S-box (byte[] or Java int[256]), AES key schedule (encryption AND decryption — and MODE-INDEPENDENT: one schedule backs CBC/CTR/GCM/XTS), ChaCha20/Salsa20 (found by the "expand 32-byte k" sigma constant), high-entropy buffers, PEM/DER, JWT. Raw-key-only ciphers (AES-NI) fall back to high_entropy_key + monitor_crypto. Confirm a hit with \`read_memory\`; turn it into a reusable signature with \`generate_memory_pattern\`.
- \`generate_memory_pattern\` — emit an anchor byte-pattern + offset-to-key for a found secret, usable by \`scan_memory\` and as a friTap ms_agent anchor / \`--offsets\` entry (feed it back via \`capture_tls\` patterns/offsets).
- \`trace_coverage\` — arm a broad set of entry-hooks (a class, \`com.example.*\`, \`libfoo.so!*\`) and alternate \`trigger_and_wait\` with \`trace_coverage { report_only: true }\` to watch the COLD (unreached) set shrink as you drive the app.
- \`drive_coverage\` — once hooks are armed (e.g. \`monitor_crypto\`), autonomously tap the UI breadth-first to reach uncovered code; it stops the moment a crypto/secret signal fires. The \`hunt_secrets\` prompt chains the whole flow.
- **Advanced primitives** (topic \`advanced\`): devices, processes, sessions, hook_function/unhook_function

## Response Format
All tools default to **TOON** (Token-Oriented Object Notation) — ~40% fewer tokens than JSON with equal or better LLM comprehension. Pass \`response_format: "markdown"\` for human-readable output or \`response_format: "json"\` for raw structured data.

## Evidence envelope
Every result carries \`evidence_id\`, \`limitations[]\`, \`coverage.status\` (complete | unknown), \`session_context\` and \`suggested_next\`. Read \`limitations\` before concluding that something does not exist.

## Tip
Most tools auto-manage device selection and sessions. Just provide the app bundle ID or name.
Topics: ${TOPIC_LIST}`,

  hooking: `# Method Hooking Guide

## hook_method
The simplest way to intercept method calls. Auto-manages device, session, and script lifecycle.

### Method Pattern Syntax
- **Java (Android)**: \`com.example.MyClass.myMethod\`
- **Objective-C (iOS)**: \`-[NSURLSession dataTaskWithRequest:]\` or \`+[MyClass staticMethod]\`
- **Native**: any address notation (see topic \`native\`):
  - \`libssl.so!SSL_read\` — module export
  - \`libfoo.so+0x1234\` or \`libfoo.so+4660\` — module-relative offset, as shown by Ghidra/IDA
  - \`0x7f1234567890\` — absolute runtime address
  - \`!open\` — global export searched across all modules

### Examples
- Hook a login method: \`hook_method({ target: "com.example.app", method: "com.example.auth.LoginManager.login" })\`
- Hook iOS networking: \`hook_method({ target: "MyApp", method: "-[NSURLSession dataTaskWithRequest:]" })\`
- Hook native SSL: \`hook_method({ target: "com.example.app", method: "libssl.so!SSL_write" })\`
- Hook a Ghidra offset: \`hook_method({ target: "com.example.app", method: "libfoo.so+0x1a2b0", log_backtrace: true })\`

### Options
- \`log_args: true\` — Log method arguments (default: true)
- \`log_retval: true\` — Log return value (default: true)
- \`log_backtrace: false\` — Log call stack (default: false); native frames are reported as \`module+0xoff (symbol)\`

### Interceptor options (native hooks, Frida 17.10+)
\`interceptor_options\` tunes how Frida writes the inline hook. It is passed through as \`Interceptor.attach({ target, ...options }, callbacks)\` and applies to native targets of \`hook_method\`, \`trace_method\` and every \`hook_function\` target; Java/ObjC hooks ignore it and say so in \`limitations\`. Omit it to keep Frida's defaults (or a script-level \`Interceptor.defaults\`).
- \`scenario\`: \`"online"\` (default, other threads may be mid-call) or \`"offline"\` (no call can be in flight, e.g. spawned but not yet resumed)
- \`relocation\`: \`"checked"\` (default, verifies prologue/back-branch constraints), \`"unchecked"\` (skip the checks) or \`"forced"\` (also allow writing past the end of the function)
- \`scratchRegister\`: register the trampoline may clobber, e.g. \`"x16"\` (arm64 and mips only)
- \`redirectSpaceHint\`: upper bound in bytes for the redirect (default: a full redirect, 16 bytes on arm64)
Example: \`hook_method({ target: "com.example.app", method: "libfoo.so+0x1a2b0", interceptor_options: { relocation: "unchecked", scratchRegister: "x16" } })\` when the checked relocation refuses a hand-rolled prologue.

### Retrieving Results
After hooking, use \`get_messages\` to retrieve intercepted calls with their arguments and return values.
Java hooks are installed inside \`Java.perform\`, which runs once the ART VM is up: with a spawned app the first messages arrive a few seconds after resume.

### Reusing a session
Pass \`session_id\` to hook into a session that already exists (e.g. from \`explore_app\`, \`spawn_process\` or an earlier \`hook_method\`): \`hook_method({ session_id: "<id from explore_app>", method: "com.example.auth.LoginManager.login" })\`. With \`session_id\` the \`target\` is optional and nothing new is spawned or attached. Every hook result includes a \`script_id\` identifying the script that holds the hook.

### Removing a single hook
\`unload_script({ session_id, script_id })\` unloads just that hook's script and keeps the session attached (its hooks and traces are dropped from the server state). Use \`stop_instrumentation\` instead to tear down the whole session with all of its scripts.

### Low-level alternative
\`hook_function\` (topic \`advanced\`) takes an existing \`session_id\` and optional custom \`on_enter\`/\`on_leave\` bodies (requires \`allowCustomScripts\`).`,

  tracing: `# Function Tracing Guide

## trace_method
Simplified frida-trace equivalent. Traces function calls matching a pattern for a specified duration.

### Usage
\`trace_method({ target: "com.example.app", method: "com.example.network.*", duration_seconds: 10 })\`
\`trace_method\` also accepts \`session_id\` instead of \`target\` to trace inside an existing session without spawning; the result includes a \`script_id\` that \`unload_script\` can remove later.

### Patterns
- Glob patterns: \`com.example.network.*\` matches all methods in the class
- ObjC: \`-[NSURL*]\`
- Multiple methods: provide an array of patterns
- Native functions: \`libssl.so!SSL_*\` traces all SSL functions

### Output
Returns all captured invocations with timestamps, arguments, return values, and optional backtraces.`,

  memory: `# Memory Operations Guide

All memory tools accept an address in any notation: \`"0x7fff12345678"\` (absolute), \`"libfoo.so+0x1234"\` or \`"libfoo.so+4660"\` (module-relative offset), \`"libssl.so!SSL_read"\` (module export), \`"!open"\` (global export).

## read_memory
Read raw bytes from a target process memory.
- Requires an active session (use explore_app or hook_method first)
- Max read size: 4MB per call
- Returns hex-encoded bytes plus the resolved absolute address and \`module+offset\` (rva)

## write_memory
Write bytes to process memory. **Disabled by default** for safety.
Enable via config: \`memoryWriteEnabled: true\` (or \`FRIDA_MCP_MEMORY_WRITE=1\` / \`--allow-memory-write\`)

## scan_memory
Search for byte patterns in memory.
Pattern format: \`"48 89 5c 24 ?? 57"\` (Frida Memory.scan format, ?? = wildcard)
Optional: specify a module to limit scan scope.

## dump_module_memory
Dump a whole loaded module (e.g. an unpacked/decrypted library) to a base-relative file on the host for import into Ghidra/IDA. See topic \`native\`.`,

  scripts: `# Scripts: Pre-built Library and Custom Scripts

## Pre-built scripts (use run_prebuilt_script)

### Security Bypass
- \`ssl_pinning_bypass\` — Bypass SSL certificate pinning (Android: TrustManager, OkHttp, Conscrypt, WebView; iOS: SecTrust/ATS, BoringSSL, AFNetworking)
- \`root_jailbreak_bypass\` — Bypass root/jailbreak detection (iOS \`bypass_debugger\` option strips P_TRACED)

### Enumeration
- \`class_enumeration\` — List all loaded Java/ObjC classes with regex filter

### Monitoring
- \`method_hook\` — Generic method hook (Java/ObjC methods or a native \`target\`) with argument and return value logging
- \`crypto_monitor\` — Monitor crypto API calls (javax.crypto, CommonCrypto, OpenSSL)
- \`network_inspector\` — Monitor network socket operations and TLS (plaintext with \`log_data\`)
- \`keychain_prefs\` — Monitor iOS Keychain / Android SharedPreferences access
- \`filesystem_monitor\` — Monitor file system I/O operations

### Anti-detection
- \`anti_frida_evasion\` — Observe (\`mode=report\`, default) or neutralize (\`mode=spoof\`, needs memoryWriteEnabled) the native checks RASP uses to find Frida: /proc/self/{maps,status,task} reads, strstr "frida" greps, thread-name/dlopen probes, iOS dyld image scans. Pair with \`watch_loads\` (anti-Frida probe detection) and \`root_jailbreak_bypass\`.

### Usage
\`run_prebuilt_script({ script_name: "ssl_pinning_bypass", target: "com.example.app" })\`
\`run_prebuilt_script()\` — Lists all available scripts when called without arguments.

## Custom scripts (execute_script, requires allowCustomScripts: true)
Three source kinds are detected automatically (override with \`source_kind\`):
- **classic** — plain (non-module) JavaScript. The \`Java\` and \`ObjC\` globals are injected by platform (Java on Android, ObjC on iOS/macOS; override with \`bridges\`), so legacy \`Java.perform()\` scripts keep working with their own line numbers. The script runs via \`Script.evaluate\`.
- **esm** — ES modules (import/export, JS or TS), e.g. \`import Java from "frida-java-bridge"\`. Compiled on the host with the Frida Compiler; bridges come from the imports, so \`bridges\` is ignored.
- **bundle** — frida-compile output (source starts with the 📦 marker). Loaded as-is.

Results are sent with \`send()\` and read with \`get_messages\`. \`persistent: true\` keeps the script loaded; \`timeout_ms\` bounds the initial run (default 30000 for one-shot scripts, 0 for persistent ones); overruns fail with \`SCRIPT_TIMEOUT\` and the partial messages.

### Frida 17 rules
Static \`Module.findExportByName\`, \`Module.findBaseAddress\`, \`Module.enumerateExports\`, \`Memory.readX\`/\`writeX\` and the \`*Sync\` enumerators were removed. Use \`Process.getModuleByName(lib).findExportByName(name)\`, \`Module.findGlobalExportByName(name)\`, \`NativePointer#readX()\` and \`Process.enumerateModules()\`. The preamble provides \`findExport(lib, name)\` and \`hookNative(lib, name, callbacks)\` helpers and exposes template options as \`__FRIDA_MCP__.options\`.

## validate_script
Check a script without a device before execute_script: classic scripts get a syntax check plus a lint for the removed Frida 17 APIs above; ES modules are compiled (\`strict: true\` runs a full TypeScript type check); bundles are accepted as-is.`,

  native: `# Native Analysis Guide

## Address notation (shared with Ghidra / IDA / ReVa / REA)
| Form | Meaning | Example |
|------|---------|---------|
| \`module!symbol\` | export or ELF/Mach-O symbol | \`libssl.so!SSL_write\` |
| \`module+0xOFFSET\` | offset from the module base (Ghidra/IDA RVA); decimal also accepted | \`libfoo.so+0x1a2b0\` |
| \`0xADDRESS\` | absolute runtime address | \`0x7f3a1c2b1234\` |
| \`symbol\` / \`!symbol\` | global export searched across all modules | \`!open\` |

Tools that return addresses prefer \`module+0xoff\` so a static tool can decompile at image base + offset without conversion. Never feed an absolute runtime address to a disassembler.

## Tools (all need a \`session_id\` from explore_app / attach_process / spawn_process)
- \`enumerate_modules\` — loaded modules with name, base, end, size, path; optional regex \`filter\`. Use base/end to rebase a Ghidra/IDA project.
- \`enumerate_exports\` — exports of a module (paginated offset/limit); hook results with \`module!name\`.
- \`enumerate_imports\` — imports of a module, each with the providing module when known.
- \`enumerate_symbols\` — symbols incl. non-exported/debug symbols; regex \`filter\` and paging run inside the agent.
- \`resolve_address\` — translate \`0x7f...\` to \`module+0xoff\` (+ nearest symbol) and back.
- \`analyze_native_function\` — function range, basic blocks and edges (Frida 17.12+ ControlFlowGraph, linear fallback noted in \`limitations\`), first instructions.
- \`dump_module_memory\` — dump a module base-relative to a host file (under cwd, the temp dir or ~/.config/frida-mobile-mcp/dumps) for Ghidra/IDA raw import at the returned \`base\`.
- \`list_threads\` — threads with state and current pc as \`module+0xoff\`; \`backtraces: true\` adds an 8-frame symbolised backtrace each.
- \`read_memory\` / \`scan_memory\` — accept the same notation (topic \`memory\`).

## Typical loop
1. Static tool finds \`libfoo.so+0x1234\`
2. \`hook_method({ target, method: "libfoo.so+0x1234", log_backtrace: true })\`
3. \`get_messages\` → backtrace frames as \`libfoo.so+0x...\`
4. Hand those offsets back to the static tool for decompilation
See docs/interop.md for the full static -> dynamic -> static walkthrough.`,

  tls: `# TLS Capture (capture_tls, backed by friTap)

\`capture_tls\` loads the friTap agent into the target to extract TLS session keys (NSS key log format) and, optionally, decrypted plaintext — whatever TLS library the app uses (OpenSSL/BoringSSL, Conscrypt, NSS, GnuTLS, wolfSSL, mbedTLS, Secure Transport, ...). No pinning bypass or MITM proxy is needed.

## Usage
\`capture_tls({ target: "com.example.app", keylog_path: "/tmp/keys.log" })\`
\`capture_tls({ target: "com.example.app", full_capture: true, duration_seconds: 60 })\`

## Arguments
- \`spawn\` (default true) — spawn suspended, load friTap, resume so early handshakes are caught; \`false\` attaches to the running process
- \`keylog_path\` — append \`CLIENT_RANDOM ...\` lines (Wireshark: tls.keylog_file)
- \`full_capture\` — also buffer decrypted records as \`fritap_datalog\` messages for \`get_messages\`
- \`pcap_path\` — write decrypted records as a synthetic TCP pcap (implies full_capture)
- \`anti_root\` — install friTap anti-root hooks (Android)
- \`duration_seconds\` — 0 keeps running until \`stop_instrumentation\` (max 600)
- \`allow_download\` (default true) — fetch the pinned friTap agent from GitHub when not installed

## Agent discovery
1. \`FRITAP_AGENT_PATH\` → 2. \`pip install friTap\` (fritap_agent.js in the package) → 3. cached download (\`FRITAP_VERSION\` overrides the tag).
Missing agent → \`FRITAP_AGENT_UNAVAILABLE\` with remediation.`,

  mobile: `# Mobile UI Automation (via mobile-mcp)

## mobile_action Gateway
All mobile UI interactions go through the \`mobile_action\` tool.

### Common Actions
- \`mobile_action({ action: "mobile_take_screenshot" })\` — Take a screenshot
- \`mobile_action({ action: "mobile_list_elements_on_screen" })\` — Get UI element hierarchy
- \`mobile_action({ action: "mobile_click_on_screen_at_coordinates", params: { x: 100, y: 200 } })\` — Tap
- \`mobile_action({ action: "mobile_swipe_on_screen", params: { direction: "up" } })\` — Swipe
- \`mobile_action({ action: "mobile_type_keys", params: { text: "hello" } })\` — Type text
- \`mobile_action({ action: "mobile_launch_app", params: { appId: "com.example.app" } })\` — Launch app
- \`mobile_action({ action: "mobile_list_apps" })\` — List installed apps
- \`mobile_action()\` — List all available actions

### Prerequisites
mobile-mcp is spawned automatically on first use (\`npx -y @mobilenext/mobile-mcp@latest\` by default; configurable via \`mobileMcp\` in the config file, disable with \`--no-mobile-mcp\`).

### Combining with Frida
The real power is combining UI automation with instrumentation:
1. Hook a method with \`hook_method\`
2. Trigger the UI action with \`mobile_action\`
3. Check what was intercepted with \`get_messages\``,

  examples: `# Example Workflows

## 1. Explore an Unknown App
\`\`\`
get_status()                                    # Check devices
explore_app({ target: "com.example.app" })     # Launch + enumerate
search_classes_and_methods({ target: "com.example.app", pattern: "Login" })
hook_method({ target: "com.example.app", method: "com.example.auth.LoginManager.login" })
mobile_action({ action: "mobile_take_screenshot" })  # See the app
mobile_action({ action: "mobile_click_on_screen_at_coordinates", params: { x: 200, y: 500 } })
get_messages({ session_id: "..." })            # Check intercepted data
\`\`\`

## 2. SSL Traffic Analysis
\`\`\`
bypass_ssl_pinning({ target: "com.example.app" })
run_prebuilt_script({ script_name: "network_inspector", target: "com.example.app" })
# Interact with the app to trigger network calls
get_messages({ session_id: "..." })
\`\`\`
Or skip the bypass and read plaintext directly:
\`\`\`
capture_tls({ target: "com.example.app", full_capture: true })
get_messages({ session_id: "..." })            # fritap_datalog records
\`\`\`

## 3. Security Audit
\`\`\`
explore_app({ target: "com.example.app" })
bypass_ssl_pinning({ target: "com.example.app" })
run_prebuilt_script({ script_name: "crypto_monitor", target: "com.example.app" })
run_prebuilt_script({ script_name: "keychain_prefs", target: "com.example.app" })
# Navigate through the app
get_messages({ session_id: "..." })
\`\`\`

## 4. Reverse Engineering a Feature
\`\`\`
explore_app({ target: "com.example.app" })
search_classes_and_methods({ target: "com.example.app", pattern: "Payment", include_methods: true })
describe_class({ session_id, class_name: "com.example.payment.PaymentClient" })  # exact overloads + signatures
hook_method({ session_id, evidence: { class: "com.example.payment.PaymentClient", signature: "pay(java.lang.String, long)" } })
trace_method({ target: "com.example.app", method: "com.example.payment.*", duration_seconds: 15 })
# Trigger the payment flow in the app
\`\`\`

## 5. Native Function from Ghidra
\`\`\`
explore_app({ target: "com.example.app" })                       # session_id
enumerate_modules({ session_id, filter: "libfoo" })             # base for rebasing
resolve_address({ session_id, target: "libfoo.so+0x1234" })      # absolute + nearest symbol
analyze_native_function({ session_id, target: "libfoo.so+0x1234" })
hook_method({ target: "com.example.app", method: "libfoo.so+0x1234", log_backtrace: true })
get_messages({ session_id })                                     # args + module+0xoff backtrace
\`\`\``,

  advanced: `# Advanced (Tier 2) Tools

These tools provide fine-grained control when the high-level tools don't fit your needs.

## Device Management
- \`list_devices\` — Enumerate all Frida-visible devices (frida-ls-devices equivalent)
- \`select_device\` — Explicitly select the active device by ID, type, or remote host
- \`get_device_info\` — Get detailed system parameters (OS, arch, version)

## Process Management
- \`list_processes\` — List running processes (frida-ps equivalent)
- \`list_applications\` — List installed/running applications with metadata
- \`get_frontmost_application\` — Get the currently foreground app

## Session Lifecycle
- \`spawn_process\` — Spawn a process in suspended state for early instrumentation (resume within ~10 s on Android or the OS kills it)
- \`attach_process\` — Attach to an already running process
- \`resume_process\` — Resume a suspended process
- \`kill_process\` — Kill a process on the device
- \`detach_session\` — Detach from a specific Frida session
- \`list_sessions\` — List all active Frida sessions
- \`spawn_gating\` — Enable/disable/list device-wide spawn gating; holds newly spawned (incl. child/isolated) processes suspended so RASP checks in them can be instrumented. Release with \`resume_process\`.
- \`child_gating\` — Enable/disable child gating on a session so forked/exec'd children are held for instrumentation
- \`eternalize_script\` — Pin a loaded script in the target so it survives detach (fire-and-forget: no more messages/unload afterwards). Leave a bypass/monitor running while you free the session.

## Native Injection
- \`inject_library\` — Inject a native library (.so/.dylib) from the host into a process via Frida's injector, independent of the JS engine (a prebuilt gadget/agent or custom .so). Runs arbitrary native code, so it needs allowNativeInjection (a capability separate from allowCustomScripts) and an architecture-matched library.

## Module Inspection
- \`enumerate_modules\` — List loaded shared libraries/modules (name, base, end, size, path)
- \`enumerate_exports\` — List exports (functions/variables) of a specific module
- \`enumerate_imports\` — List imports of a module with the providing module
- \`enumerate_symbols\` — List symbols incl. non-exported/debug symbols (Linux/Android/iOS/macOS)

## Native Analysis (topic \`native\`)
- \`resolve_address\` — Translate absolute addresses <-> module+0xoffset / module!symbol
- \`analyze_native_function\` — Function range, basic blocks/edges, first instructions
- \`dump_module_memory\` — Dump a module to a base-relative file for Ghidra/IDA
- \`list_threads\` — Threads with current pc and optional backtraces

## Low-level Hooking
- \`hook_function\` — Install a hook with custom onEnter/onLeave JavaScript handlers (custom bodies need allowCustomScripts)
- \`unhook_function\` — Remove a specific hook by ID

## Device / frida-server (Android, via adb)
- \`frida_server_status\` — Running PIDs + device ABI + the matching frida-server .xz asset URL to download
- \`frida_server_install\` — Push a local (decompressed) frida-server binary and chmod it (adb push + chmod 755)
- \`frida_server_start\` — Start it daemonized with a custom listen address/port and binary name (non-default port evades :27042 scans); respects allowedDevices
- \`frida_server_stop\` — Signal the matching process to stop (pkill, optionally via su)

## Raw adb (Android)
- \`adb_shell\` — Run an arbitrary device shell command (DISABLED unless allowAdbShell is set; arbitrary execution)
- \`adb_logcat\` — Dump the last N logcat lines (one-shot), optional tag:priority filters, or clear the buffer
- \`adb_pull\` / \`adb_push\` — Move files between host and device
- \`adb_forward\` — Add/remove/list port forwards (reach frida-server on a non-default device port)
All raw adb tools enforce allowedDevices and target the sole attached device when \`device\` is omitted.`,

  evasion: `# Defeating anti-Frida / RASP detection

Modern RASP (Talsec freeRASP, Guardsquare, PairIP, Promon SHIELD, Appdome) fingerprints
**Frida itself**, not just the app's own root/pinning checks. It scans \`/proc/self/maps\` for
\`frida-agent\`/\`libgadget\`, reads thread names (\`gum-js-loop\`, \`pool-frida\`), probes the
\`:27042\` port / D-Bus handshake, reads \`/proc/self/status\` TracerPid, and on iOS walks the
dyld image list for \`FridaGadget\`. The server fights this on four layers; use them together.

## Honest limitation (read first)
Native detection in \`.init_array\` / \`JNI_OnLoad\` runs at \`dlopen\` time — **before** any
attach-time script loads, even when you spawn suspended. The attach model cannot instrument a
constructor that already ran. The only full answer to that class is **frida-gadget embedded in
a repackaged app** (layer 3). The in-process script (layer 1) covers detection that runs later,
at or after startup.

## Layer 1 — in-process spoofing (attach model)
- \`anti_frida_evasion\` prebuilt script — \`mode=report\` (default, observe-only) logs every
  probe; \`mode=spoof\` (needs memoryWriteEnabled) scrubs the Frida signatures out of what the
  target reads from \`/proc/self/{maps,status,task}\`, zeroes TracerPid, blanks matched thread
  names, and on iOS rewrites dyld image names. \`aggressive=true\` also hooks the very hot
  \`read()\`/\`strstr()\` (covers raw \`open()+read()\` maps reads) at the cost of stability.
  \`run_prebuilt_script({ script_name: "anti_frida_evasion", target, options: { mode: "spoof" } })\`.
- \`watch_loads({ spoof: true })\` — the same scrub, scoped to the \`/proc\` reads it already
  watches; good when you're also watching late loads. Use the full script for thread
  names / iOS dyld / strstr.
- These do **not** change thread names, free the \`:27042\` port, or hide the agent mapping
  itself — layers 2–4 cover what in-process scrubbing cannot.

## Layer 2 — a quieter frida-server (device tools, Android)
- \`frida_server_start\` takes a custom \`name\` and \`port\` — run the server as e.g.
  \`/data/local/tmp/fs-$RANDOM\` on \`127.0.0.1:1337\` so a \`:27042\` port scan and a
  \`re.frida.server\` name scan both miss.
- Reach the non-default port from this server with \`adb_forward\` +
  \`FRIDA_MCP_REMOTE=127.0.0.1:1337\` (the device resolver connects over the forward).
- A **patched/renamed frida-server build** (e.g. strongR-frida, hluda) additionally renames the
  internal threads and pipe/D-Bus strings that a vanilla server leaks — worth it against RASP
  that greps thread names and \`/proc\` maps for \`frida\`/\`gum\`.

## Layer 3 — frida-gadget (pre-\`main\` coverage, no server port)
\`frida-mobile-mcp gadget\` (CLI, not a session tool — it needs app repackaging) generates the
gadget \`config.json\` and prints the APK/IPA repackaging steps:
- \`gadget --interaction script --script /data/local/tmp/agent.js\` — fully on-device, **no
  listening port at all** (nothing to fingerprint), agent runs from \`.init_array\`.
- \`gadget --interaction listen --port 1337 --on-load wait\` — the app blocks at launch until a
  client attaches; then set \`FRIDA_MCP_REMOTE=127.0.0.1:1337\`.
This is the honest fix for the \`.init_array\`/\`JNI_OnLoad\` limitation above.

## Layer 4 — hide the tracer at the OS level (device-side, out of band)
What in-process scrubbing can't fully cover (the agent's own file-backed mapping, ptrace state):
- **Magisk DenyList + Shamiko** (or Zygisk) to hide root/Magisk from the target process, so RASP
  that keys off root presence and the Zygisk/Magisk footprint is defeated before it looks for
  Frida at all.
- Run the server as a non-root, app-scoped process where possible, and avoid the default
  \`/data/local/tmp/frida-server\` path/name.
See the \`mobile-dynamic-analysis\` skill ("Defeating RASP / anti-Frida detection") for the full
device-side setup.

## Suggested order
1. \`watch_loads\` (report) or \`anti_frida_evasion\` (report) — see **which** vectors the app uses.
2. Spoof only those: \`anti_frida_evasion\` spoof (+ aggressive if it reads maps via \`read()\`).
3. Still caught pre-\`main\`? Switch to \`gadget\`. Still caught on maps/threads? Layer 2 + 4.`,

  script_catalog: `# Task-Oriented Script Catalog

## "I want to intercept HTTPS traffic"
1. \`detect_app_technologies\` → identify HTTP client library
2. \`capture_tls\` → TLS keys + plaintext without touching pinning (topic \`tls\`), or
3. \`bypass_ssl_pinning\` → disable certificate pinning, then \`network_inspector\` → monitor network operations, DNS, TLS
4. \`get_messages\` → read captured data

## "I want to find where the app stores credentials"
1. \`keychain_prefs\` → monitor Keychain/SharedPreferences access
2. \`filesystem_monitor\` → monitor file I/O and SQLite
3. \`crypto_monitor\` → detect key derivation and encryption

## "The app detects root/jailbreak and crashes"
1. \`root_jailbreak_bypass\` (run BEFORE app starts via spawn)
2. \`get_messages\` → check which detection methods were triggered
3. If still detected: use \`class_enumeration\` to find custom detection

## "I want to understand what an app does"
1. \`detect_app_technologies\` → map the app's tech stack
2. \`explore_app\` → enumerate classes and modules
3. \`class_enumeration\` with include_methods:true → deep class analysis
4. \`method_hook\` → hook specific methods for dynamic analysis

## "Ghidra/IDA gave me an offset"
1. \`resolve_address\` / \`analyze_native_function\` with \`libfoo.so+0x1234\` (topic \`native\`)
2. \`hook_method\` with the same target and \`log_backtrace: true\`
3. \`dump_module_memory\` if the library is packed or decrypted at runtime

## detect_app_technologies
Run this first! It fingerprints 20+ libraries and recommends which scripts to use with optimal targets.`,

  script_api: `# Writing Frida scripts for this server (the agent API)

Scripts you run with \`execute_script\` (and every prebuilt template / recipe) run as a
**classic Frida 17 agent** inside the target. Before your body runs, this server prepends a
**preamble** (src/agent/preamble.ts) that gives you a small, stable API. Author new scripts
against it.

## \`__FRIDA_MCP__\`
A global holding your call's context and options as a **JSON literal** (never spliced into
code), so user input can't become code:
- \`__FRIDA_MCP__.name\` — the script name
- \`__FRIDA_MCP__.platform\` — "android" | "ios" | ...
- \`__FRIDA_MCP__.options\` — the object you passed; read every parameter from here

## Preamble helpers (classic JS, always present)
- \`findExport(lib, name)\` — Frida 17 export lookup. \`lib\` null/'' → \`Module.findGlobalExportByName(name)\`; else \`Process.findModuleByName(lib).findExportByName(name)\`. Returns a NativePointer or null.
- \`hookNative(lib, name, callbacks, options?)\` — resolve + \`Interceptor.attach\` with bookkeeping; the optional 4th arg carries Frida 17.10 options ({ scenario, relocation, scratchRegister, redirectSpaceHint }).
- \`javaPerform(fn)\` — Promise-returning \`Java.perform\` (use in rpc.exports; frida awaits the promise). Rejects cleanly if the Java bridge is absent.
- \`objcClassNames()\` — flattened \`ObjC.enumerateLoadedClassesSync()\`.
- \`reportSummary(name?)\` — send the \`init_complete\` summary (hooks attempted/installed/skipped/errors).
- \`recordHookError(target, e)\` — record an install error into the summary.
- The \`Java\` / \`ObjC\` globals are always defined: a real bridge when injected, else \`{ available: false }\`, so \`if (Java.available)\` never throws a ReferenceError.

## The send() convention
Report results with \`send({ type: '...', ... })\`; read them back with \`get_messages\`. Agent
\`console.log/warn/error\` is captured into the message buffer too (never to stdout). Throwns
surface with full fidelity (stack/file/line/column).

## Frida 17 instance API (the removed statics are rejected by validate_script)
- \`Module.findExportByName(...)\`  → \`Process.getModuleByName(lib).findExportByName(name)\` or \`findExport(lib, name)\`
- \`Module.findBaseAddress(...)\`   → \`Process.getModuleByName(lib).base\`
- \`Module.enumerateExports/Imports/Symbols(...)\` → the same methods on a **Module instance**
- \`Memory.readX()/writeX()\`       → \`NativePointer#readX()/writeX()\`
- \`Process.enumerateXSync()\`      → \`Process.enumerateX()\` (returns an array)

## Java / ObjC idioms & pitfalls
- Resolve app classes across every class loader (plugin/split-dex/packed), not just the default one — \`describe_class\` and \`hook_method\` already do this; in a recipe, use the shared \`useInAnyLoader\` lookup.
- Hook a **single overload** by argument types (\`overload('[B', 'java.lang.String')\`) — see \`describe_class\` for exact signatures and \`hook_method\`'s \`evidence: { class, signature }\`.
- **10 s suspend limit:** Android kills a spawned process left suspended > ~10 s; resume before anything that waits on \`Java.perform\`.
- **Lazy loading:** native \`.so\` and dynamic dex load late — if a class/export isn't there yet, use \`watch_loads\` then retry.

See topic \`recipes\` for ready-made, adaptable examples, and \`validate_script\` to check a draft without a device.`,

  recipes: `# Recipe library (purpose-indexed, classic JS)

\`search_recipes\` returns ready-to-run classic-JS snippets you adapt and run with
\`execute_script\`. Each recipe reads its parameters from \`__FRIDA_MCP__.options\` and reports
via \`send({ type, ... })\` (see topic \`script_api\`). Browse them as the \`frida://recipes\`
resource, or one at a time as \`frida://recipes/{name}\`.

## What's in the library
- **custom-java-crypto-key** — dump byte[]/String args + return of an app-defined crypto class (e.g. a hand-rolled RC4/AES helper that never touches javax.crypto). The rc4demo case.
- **javax-crypto-key** — key/IV from the standard JCE (SecretKeySpec/IvParameterSpec/Cipher.init).
- **native-export-hook** — attach to a native export by name and log its args.
- **jni-register-natives** — reveal natives bound dynamically via JNI RegisterNatives.
- **custom-classloader-enum** — list class loaders and the classes each exposes.
- **intent-deeplink-trace** — log the Intents/deep links each Activity receives.
- **webview-bridge** — report objects exposed to page JS via addJavascriptInterface.
- **ios-keychain-trace** — log SecItem* Keychain access.
- **android-keystore-usage** — observe Android Keystore key USAGE (KeyStore.getKey, Cipher.init, KeyGenParameterSpec, Signature); hardware-backed keys cannot be extracted, only their use observed.
- **string-decryptor-harness** — hook one app-defined string-decryptor method and dump every plaintext it returns (deobfuscation).

## Save / run / export
- \`save_script\` — store an adapted script under ~/.config/frida-mobile-mcp/scripts (needs allowCustomScripts).
- \`list_saved_scripts\` — list what you've saved.
- \`run_saved_script\` — run a saved script by name against a target.
- \`export_script\` — emit a **standalone classic .js** that runs under the plain \`frida -U -f <pkg> -l file.js\` CLI (preamble + your source; bridges are provided by the frida-tools CLI, not bundled).`,

  interop: `# Running next to REA, ReVa (Ghidra) and IDA

Static servers answer what the code says; this server answers what it does at runtime. Full guide: docs/rea.md and docs/interop.md.

## Routing rules
- **Mobile app at runtime -> this server**: Java/ObjC bridges, prebuilt scripts, TLS keys (\`capture_tls\`), memory (\`read_memory\`, \`find_secrets_in_memory\`), UI driving (\`mobile_action\`, \`trigger_and_wait\`).
- **Static questions -> REA** (\`inspect_android_package\`, \`search_android_classes\`, \`inspect_android_method\`, \`trace_android_references\`) or ReVa/IDA (\`decompile\`).
- **Desktop binaries -> REA's Frida lane** (\`start_frida_session\`, \`load_frida_script\`, \`instrument_with_frida\`). REA sessions have no Java/ObjC bridge, so mobile apps belong here.
- **Never hold one PID in sessions of both servers.** \`stop_instrumentation\` here (or REA \`close_frida_session\`) before the other side attaches.
- **Both need frida-server 17.x** on the device; REA never installs it (\`frida_server_status\` / \`frida_server_install\` / \`frida_server_start\` here).
- **Pick one side for ADB**: REA \`list_adb_devices\` / \`pull_adb_package\` overlap with \`adb_*\` / \`frida_server_*\` here.

## Context budget (env)
- \`FRIDA_MCP_TOOL_PROFILE=core\`: core tool set only
- \`FRIDA_MCP_TOOLS_EXCLUDE=adb_*,frida_server_*\`: hide what REA covers
- \`FRIDA_MCP_SCHEMA_PROFILE=compact\`: first-sentence descriptions (core + compact = 17% of the full catalog)
- \`get_status\` reports \`hidden_tools\`.

## Evidence mapping (REA -> this server)
- \`normalized_result\` -> \`result\`; \`evidence_id\` -> \`evidence_id\` (also \`_meta.evidence_id\`); \`raw_result\`, \`limitations\` same names
- \`coverage { scope, status, next_offset }\` -> \`coverage { status: complete|partial|unknown, scope?, next_offset?, truncated? }\`
- \`_meta.provenance\` -> same object \`{ untrusted_content: true, source: "analysis_target" }\` on target-derived tools; effect flags -> \`_meta.effects\`
- \`source_sha256\` -> \`source_sha256\` (\`execute_script\`), stored as \`script_sha256\` in the evidence record
- \`details.partial_observation\` -> \`error.details.partial_observation\`
- REA \`export_evidence_bundle\` -> \`export_evidence_bundle\` (JSON/Markdown), \`get_evidence\`, \`frida://evidence/{id}\`
- Errors: \`INVALID_ARGUMENT\` -> invalid_request, \`*_DISABLED\` / \`DEVICE_NOT_FOUND\` -> capability_unavailable, \`RPC_TIMEOUT\` / \`FRIDA_TIMEOUT\` -> provider_timeout, \`RATE_LIMIT_EXCEEDED\` -> resource_constraint, \`SESSION_LOST\` -> unavailable

## Walkthrough: APK -> static -> hook -> report
1. \`get_app_info({ target, pull_to: "/tmp/apks" })\`: every APK with on-device sha256, pulled and hash-verified (artifact identity).
2. REA \`inspect_android_package\` on the pulled base.apk (or REA \`pull_adb_package\`, then compare the hash).
3. REA \`inspect_android_method\` on the candidate method.
4. \`describe_class({ session_id, class_name })\`: loaded overloads with a hook-ready \`signature\`.
5. \`hook_method({ target, evidence: { class, signature } })\`: hook exactly that overload.
6. \`trigger_and_wait({ session_id, action, params })\`: drive the UI until the hook fires.
7. \`get_messages({ session_id })\`: arguments, return value, backtrace.
8. \`capture_tls({ target, keylog_path })\`: confirm the result on the wire.
9. \`export_evidence_bundle({ session_id, format: "markdown", out_path })\`: plus REA's own \`export_evidence_bundle\`.
10. Finding ledger: cite the REA evidence_id (static), this server's evidence_ids (runtime) and the APK sha256 from \`get_app_info\`.`,
};

export function registerHelpTool(server: McpServer): void {
  server.registerTool(
    'frida_help',
    {
      title: 'Frida Help',
      description: `Get help on how to use frida-mobile-mcp tools. Use this to learn about available capabilities, method hooking patterns, address notation, script kinds (classic/esm/bundle), TLS capture and example workflows. Topics: ${TOPIC_LIST}.`,
      inputSchema: z.object({
        topic: z.string()
          .optional()
          .describe(`Help topic: ${TOPIC_LIST}. Default: overview`),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ topic, response_format }) => {
      const selectedTopic = topic || 'overview';
      const content = HELP_TOPICS[selectedTopic];

      if (!content) {
        const available = Object.keys(HELP_TOPICS).join(', ');
        return formatToolResponse(
          buildResult(
            { message: `Unknown topic "${selectedTopic}". Available topics: ${available}` },
            [{ tool: 'frida_help', args: { topic: 'overview' }, reason: 'Start with the overview' }]
          ), response_format
        );
      }

      return formatToolResponse(
        buildResult(
          { topic: selectedTopic, content },
          selectedTopic === 'overview'
            ? [
                { tool: 'get_status', reason: 'Check connected devices' },
                { tool: 'explore_app', reason: 'Start exploring an app' },
              ]
            : [
                { tool: 'frida_help', args: { topic: 'overview' }, reason: 'Back to overview' },
              ]
        ), response_format
      );
    }
  );
}
