# Interoperability with static-analysis MCP servers

frida-mobile-mcp is designed to sit next to static reverse-engineering MCP
servers such as ReVa (Ghidra), ida-pro-mcp (IDA Pro) and REA. The static side
answers "what does the code say", the dynamic side answers "what does the
code do at runtime". This document describes the shared conventions that make
the hand-off between them mechanical: client configuration, the address
notation contract, the evidence and error envelope, the friTap-backed
`capture_tls` tool, and a full static -> dynamic -> static walkthrough.

## 1. Three-server client configuration

An MCP client `mcpServers` map with all three servers, plus REA. ReVa listens on
streamable HTTP; ida-pro-mcp, REA and frida-mobile-mcp are stdio servers.

```json
{
  "mcpServers": {
    "reva": {
      "type": "http",
      "url": "http://127.0.0.1:8080/mcp/message"
    },
    "ida-pro-mcp": {
      "command": "ida-pro-mcp",
      "args": []
    },
    "rea": {
      "command": "npx",
      "args": ["-y", "rea-agents@latest", "mcp"]
    },
    "frida-mobile-mcp": {
      "command": "npx",
      "args": ["-y", "frida-mobile-mcp"],
      "env": {
        "FRIDA_DEVICE_ID": "emulator-5556"
      }
    }
  }
}
```

Notes:

- Clients that cannot talk to remote HTTP servers directly can bridge ReVa
  through `mcp-remote` as a stdio server:

  ```json
  "reva": {
    "command": "npx",
    "args": ["-y", "mcp-remote", "http://127.0.0.1:8080/mcp/message"]
  }
  ```

- ida-pro-mcp may also be launched as `uvx ida-pro-mcp` or through its
  installer-generated wrapper; check that project's README for the exact
  command and for the IDA plugin side that must be running.
- REA (npm `rea-agents`) can also be added with
  `claude mcp add rea -- npx -y rea-agents@latest mcp`. Next to REA, trim this
  server's catalog with `FRIDA_MCP_TOOL_PROFILE=core`,
  `FRIDA_MCP_TOOLS_EXCLUDE=adb_*,frida_server_*` and
  `FRIDA_MCP_SCHEMA_PROFILE=compact`; see [rea.md](rea.md).
- `FRIDA_DEVICE_ID` preselects the Frida device so no tool has to pass
  `device`. Other useful env vars: `FRIDA_MCP_DEBUG=1`,
  `FRIDA_MCP_RUNTIME=v8|qjs`, `FRIDA_MCP_ALLOW_CUSTOM_SCRIPTS=1`,
  `FRIDA_MCP_MEMORY_WRITE=1`, `FRITAP_AGENT_PATH`, `FRITAP_VERSION`.
  Persistent settings live in `~/.config/frida-mobile-mcp/config.json`.

## 2. Address notation contract

Static tools reason about image-base-relative offsets; Frida sees ASLR
randomised runtime addresses. frida-mobile-mcp therefore standardises on one
notation at the tool boundary:

| Kind            | Form                                      | Example                                 |
|-----------------|-------------------------------------------|-----------------------------------------|
| Native offset   | `<module>+0x<hex offset from module base>` | `libssl.so+0x1a2b0`                     |
| Native symbol   | `<module>!<symbol>` (fallback)             | `libssl.so!SSL_write`                   |
| Java            | `com.pkg.Class.method` (optionally with signature) | `com.example.net.Api.sign(java.lang.String)` |
| Objective-C     | `-[Class selector]` / `+[Class selector]`  | `-[NSURLSession dataTaskWithRequest:]`  |

Rules:

- Module names are lower-case as reported by Frida (`Process.enumerateModules`),
  for example `libssl.so`, `libflutter.so`, `CoreFoundation`.
- Offsets are hex with a `0x` prefix and are relative to the module base, so
  `libssl.so+0x1a2b0` is the same function in Ghidra (image base + 0x1a2b0),
  in IDA (`ida_nalt.get_imagebase() + 0x1a2b0`) and in Frida
  (`Module.findBaseAddress("libssl.so").add(0x1a2b0)`).
- Tools that accept addresses (`hook_method` native targets, `hook_function`
  `target`, `read_memory`, `scan_memory`, `analyze_native_function`) accept
  both an absolute runtime address (`0x7f3a1c2b1234`) and the `module+0x`
  form (hex `libfoo.so+0x1234` or decimal `libfoo.so+4660`). `hook_method`
  auto-manages the session from an app target; `hook_function` needs an
  existing `session_id` and is the low-level variant with optional custom
  `on_enter`/`on_leave` bodies (requires `allowCustomScripts`).
- Tools that return addresses (`hook_function` backtraces,
  `analyze_native_function`, `enumerate_exports`, `scan_memory` matches)
  prefer `module+0x` so a static tool can be asked to decompile at
  image base + offset without any conversion. Absolute addresses are only
  returned when the address falls outside any known module (JIT regions,
  anonymous mappings), and such results carry a `limitations` entry.
- Symbol form `module!symbol` is the fallback when the export is known but
  the offset is not; frida-mobile-mcp resolves it through the module's `findExportByName()` (Frida 17 instance API)
  and reports the resolved `module+0x` in the result.
- Never feed an absolute runtime address to a disassembler. Use
  `enumerate_modules` to obtain the base and subtract if a conversion is
  unavoidable.

### 2.1 Hook by evidence

`hook_method` and `hook_function` accept an `evidence` object in place of
`method` / `target`, so a static finding becomes a hook without rewriting it
by hand. Pass exactly one of `method`/`target` or `evidence`.

| Evidence                                  | Becomes                         | Notes |
|-------------------------------------------|---------------------------------|-------|
| `{ module, offset }`                      | `module+0x<offset>`             | `offset` is image-base-relative (RVA): the address Ghidra/IDA show minus the image base. Hex string `"0x1234"`, decimal string or number. **Not** a raw on-disk file offset; there is no section translation. |
| `{ module, address, image_base }`         | `module+0x<address-image_base>` | Copy the address exactly as the static tool shows it plus the base it used (Ghidra ELF default `0x100000`, IDA usually `0x0`). |
| `{ class, signature }` (Java)             | `class.name(src types)`         | `hook_method` only. Hooks the **one** overload whose parameter types match. |
| `{ class, method, signature }` (Java)     | same                            | For signatures without a name, e.g. `(byte[])`. Constructors: `$init` / `<init>`. |

Java signatures are accepted in every common notation and normalised to the
`Class#getName()` form Frida reports in `overload.argumentTypes[i].className`
(`int`, `java.lang.String`, `[B`, `[Ljava.lang.String;`):

| Source of the signature | Example |
|-------------------------|---------|
| jadx / `describe_class` (Java source form) | `encrypt(byte[], java.lang.String)` |
| Frida / `Class#getName()` form             | `encrypt([B,java.lang.String)` |
| Java declaration (modifiers, return type, parameter names, generics and annotations are dropped) | `public static byte[] encrypt(byte[] data, String key)` |
| JVM descriptor (smali, Ghidra, JEB)        | `encrypt([BLjava/lang/String;)[B`, `([B)V` |

The same signature may also be appended to a plain `hook_method` `method`:
`com.example.Rc4Client.encrypt(byte[], java.lang.String)` hooks one overload,
`com.example.Rc4Client.encrypt` keeps hooking all of them. Unqualified class
names (`String`, `String[]`) match the runtime type by simple name; varargs
`String...` is `String[]`; the return type is informational and not used for
matching.

When no overload matches, the hook is not installed: its liveness reports
`reason: "OVERLOAD_MISMATCH"`, `class_resolved: true` and
`availableOverloads` (the existing overloads in source form) so the
signature can be corrected without guessing. A matched hook reports
`overloads_matched: 1`.

## 3. Evidence and error envelope

Every successful tool call returns the same envelope, both as text content
(TOON by default, `markdown` or `json` via `response_format`) and as
`structuredContent`:

| Field             | Type                                                 | Purpose |
|-------------------|------------------------------------------------------|---------|
| `result`          | tool specific                                        | The payload |
| `evidence_id`     | `string` (UUID per tool call)                        | Stable reference for reports and for the audit log at `~/.config/frida-mobile-mcp/audit.jsonl` |
| `limitations`     | `string[]`                                           | What the tool could not do (truncation, missing bridge, partial enumeration) |
| `coverage`        | `{ status: 'complete' \| 'partial' \| 'unknown', note?: string }` | Whether the result is exhaustive for the question asked |
| `coverage.scope` / `coverage.next_offset` / `coverage.truncated` | optional `string` / `number` / `boolean` | What was scanned, the cursor to continue a partial result, and whether items were dropped (limit, eviction, response trimming); REA's top-level `truncated` maps to `coverage.truncated` |
| `raw_result`      | optional                                             | Untransformed provider output when the tool normalised it |
| `session_context` | object                                               | Current device, platform, active sessions/hooks/scripts |
| `suggested_next`  | `{ tool, args?, reason }[]`                          | Advisory follow-up calls |
| `_meta.evidence_id` | `string` (same UUID; on errors also `error.evidence_id`) | Protocol-level copy of the id, present on every response including errors |
| `_meta.provenance` | object, target-derived tools only                   | Marks the result as derived from the instrumented target (untrusted data); same object as REA: `{ untrusted_content: true, source: "analysis_target" }` |
| `_meta.effects`   | object on every tool definition (`tools/list`)       | Side-effect flags `executesForeignCode`, `mutatesTarget`, `launchesProcess`, `accessesNetwork`, `writesFilesystem`, `mutatesDevice`, `idempotent` (REA's names) plus `targetDerived` |
| `error.details.partial_observation` | optional, errors only               | What was observed before the failure (REA `details.partial_observation`) |
| retrieval         | tools and resources                                  | `get_evidence({ evidence_id })`, `export_evidence_bundle` (JSON or Markdown, inline or `out_path`), `frida://evidence` and `frida://evidence/{id}` |

Every response, errors included, is persisted to the evidence store
(`~/.config/frida-mobile-mcp/evidence` by default, `FRIDA_MCP_EVIDENCE=0`
disables it) and can be re-read by its `evidence_id` with `get_evidence`,
exported with `export_evidence_bundle`, or read as the
`frida://evidence/{id}` resource (`frida://evidence` lists the latest 100).

Errors are returned with `isError: true` and this shape:

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "category": "resource",
    "message": "Script rate limit exceeded (10/min)",
    "retryable": true,
    "remediation": "Wait before loading more scripts or raise rateLimits.scriptsPerMinute",
    "recovery_actions": [{ "action": "wait", "message": "Retry after 60 seconds" }],
    "context": { "tool": "hook_method", "limit": 10 }
  }
}
```

Code to category mapping:

| Code                                                                 | Category        | Retryable | REA nearest code |
|----------------------------------------------------------------------|-----------------|-----------|------------------|
| `RATE_LIMIT_EXCEEDED`                                                | `resource`      | yes       | `resource_constraint` |
| `CUSTOM_SCRIPTS_DISABLED`, `MEMORY_WRITE_DISABLED`                   | `authorization` | no        | `capability_unavailable` |
| `DEVICE_NOT_FOUND`, `MOBILE_MCP_UNAVAILABLE`, `FRITAP_AGENT_UNAVAILABLE` | `capability` | no        | `capability_unavailable` |
| `RPC_TIMEOUT`, `FRIDA_TIMEOUT`                                       | `timeout`       | yes       | `provider_timeout` |
| `SESSION_NOT_FOUND`, `INVALID_ARGUMENT`, `SCRIPT_NOT_FOUND`, `PROCESS_NOT_FOUND` | `request` | no | `invalid_request` (`target_required` for `SESSION_NOT_FOUND` / `PROCESS_NOT_FOUND`) |
| `FRIDA_ERROR`, `SCRIPT_ERROR`, `SESSION_LOST`                        | `provider`      | no        | `unavailable` |

The full code list (including `ADB_SHELL_DISABLED`, `NATIVE_INJECTION_DISABLED`,
`CLASS_NOT_LOADED`, `EVIDENCE_NOT_FOUND`, `SESSION_LIMIT_REACHED`) and its REA
mapping are in [rea.md section 6](rea.md#6-evidence-across-both-servers). REA's
`evidence_integrity_mismatch`, `unreadable_output` and `cancelled` have no
counterpart here.

A client or orchestrating agent should retry only `retryable` errors, apply
`remediation` for `authorization` and `capability` errors (these need a config
change or an installation, not another attempt), and re-establish the session
for `provider` errors (`SESSION_LOST` means the app died or detached; the next
hook call creates a fresh session).

## 4. The friTap tool: capture_tls

`capture_tls` loads the friTap agent (fkie-cad/friTap) into the target process
to extract TLS session keys and decrypted plaintext from whatever TLS library
the app uses (BoringSSL, OpenSSL, NSS, GnuTLS, mbedTLS, Conscrypt, Flutter/Dart,
Cronet, ...), without needing pinning bypasses or a MITM proxy.

Arguments:

| Arg                | Default | Meaning |
|--------------------|---------|---------|
| `target`           | -       | Bundle ID, process name or PID string |
| `device`           | auto    | Device ID |
| `keylog_path`      | omitted | NSS key log output path; when omitted, keys are only buffered as `get_messages` records |
| `pcap_path`        | none    | Best-effort pcap of decrypted records |
| `spawn`            | `true`  | Spawn suspended -> load agent -> configure -> resume, so early handshakes are caught; `false` attaches to the running process |
| `anti_root`        | `false` | Enable friTap anti-root/anti-detection helpers |
| `full_capture`     | `false` | Also buffer decrypted TLS plaintext records (and write a pcap when `pcap_path` is set), not only keys |
| `duration_seconds` | `0`     | `0` keeps running until `stop_instrumentation`; max 600 |
| `allow_download`   | `true`  | Permit fetching the pinned agent bundle from GitHub |

Output: `session_id`, `script_id`, `agent_version`, `keylog_path` and `hooks`
(the initial summary messages naming the TLS libraries that were hooked).

- The key log is NSS key log format (`CLIENT_RANDOM <random> <secret>`) and
  loads directly into Wireshark (`tls.keylog_file`) to decrypt a parallel
  device-side packet capture.
- Plaintext records are buffered into session messages. Read them with
  `get_messages({ session_id })`; each has type `fritap_datalog` with a hex
  dump and a UTF-8 preview, capped per record and by `maxMessageBuffer`.
- Full pcap writing with proper TCP/IP framing needs the friTap Python CLI:
  `fritap -m -p out.pcap -k keys.log -s com.example.app`. The MCP tool writes
  only a best-effort pcap of decrypted records and only when `pcap_path` is set.

Agent discovery order:

1. `FRITAP_AGENT_PATH` environment variable pointing at a `fritap_agent.js`.
2. The installed `friTap` Python package (`pip install friTap`):
   `fritap_agent.js` next to `friTap/__init__.py`.
3. The cached download `~/.config/frida-mobile-mcp/fritap/<version>/fritap_agent.js`,
   fetched from
   `https://raw.githubusercontent.com/fkie-cad/friTap/<tag>/friTap/fritap_agent.js`.
   The default tag is `v2.5.2`; `FRITAP_VERSION` overrides it; the download
   happens only when `allow_download` is true.

If none succeeds the tool returns `FRITAP_AGENT_UNAVAILABLE` (category
`capability`) with the remediation `pip install friTap` or
`FRITAP_AGENT_PATH=/path/to/fritap_agent.js`.

Worked example: correlating plaintext with a statically found wrapper.

1. In Ghidra (ReVa `decompile`), a function at `libfoo.so+0x4210` builds a
   request buffer and calls `SSL_write`. Static analysis cannot show the
   final serialised bytes because they depend on runtime state.
2. `capture_tls({ target: "com.example.app" })` -> drive the app ->
   `get_messages({ session_id })` returns `fritap_datalog` records with the
   plaintext request, including the header the wrapper assembles.
3. `hook_method({ target: "com.example.app", method: "libfoo.so+0x4210",
   log_args: true, log_backtrace: true })` -> the hook's
   invocation timestamps and argument pointers line up with the
   `fritap_datalog` records, confirming the wrapper is the producer; the
   backtrace lists the callers as `libfoo.so+0x...` entries.
4. Ask ReVa to `decompile` each caller offset to document the call chain.

## 5. Static -> dynamic -> static walkthrough

Goal: understand how `com.example.app` signs API requests.

For the REA-specific version (artifact identity with `get_app_info`, REA
`inspect_android_method`, hook by signature, evidence bundles from both
servers) see [rea.md section 7](rea.md#7-walkthrough-apk---static---hook---report).

1. Static (REA): `inspect_android_package` on the APK lists native libraries
   (`libfoo.so`) and the Java class `com.example.net.Api` with a `sign`
   method that declares a `native` counterpart.
2. Static (ReVa or IDA): `get-functions` / `decompile` on `libfoo.so` finds
   `Java_com_example_net_Api_sign` at `libfoo.so+0x3f80` calling an unnamed
   helper at `libfoo.so+0x1234` that looks like HMAC with a key derived at
   runtime.
3. Dynamic (frida-mobile-mcp):
   - `get_status` -> `explore_app({ target: "com.example.app" })` ->
     `detect_app_technologies` (confirms OkHttp + native crypto).
   - `hook_method({ target: "com.example.app", method:
     "com.example.net.Api.sign", log_backtrace: true })` captures the input
     string and the returned signature.
   - `hook_method({ target: "com.example.app", method: "libfoo.so+0x1234",
     log_backtrace: true })` captures the key pointer and
     length; `read_memory` at the pointer dumps the derived key.
   - `capture_tls({ target: "com.example.app" })` shows the signed request
     on the wire so the header name and encoding are confirmed.
   - `get_messages` -> collect `evidence_id` values -> `stop_instrumentation`.
4. Static again: backtraces reference `libfoo.so+0x2a10` as the key
   derivation site. `decompile` at image base + 0x2a10 in Ghidra, now with
   the known key material, and rename the function. In IDA, `uvx ida-pro-mcp`
   tools can apply the same rename so both databases stay consistent.
5. Report: cite the `evidence_id` of each hook result and the
   `limitations`/`coverage` fields so a reviewer can tell which claims are
   backed by runtime observation and which remain static inference.
