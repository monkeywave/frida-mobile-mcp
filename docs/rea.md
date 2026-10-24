# Working with REA

[REA](https://github.com/morluto/rea) (npm `rea-agents`) is a reverse-engineering MCP server with static Android analysis, ADB helpers and a generic Frida lane. frida-mobile-mcp is a mobile runtime server: Java/ObjC bridges, prebuilt scripts, friTap TLS capture, memory analysis and UI driving on Android and iOS. The two servers do not embed each other. REA has no plugin API and no MCP-client mode, so you register both servers in the same MCP client and let the agent route between them. This page covers what each one does, how the agent should choose, how to install both, how to keep the combined tool catalog small, and how to cite evidence from both servers in one report.

## Contents

- [1. What each server does](#1-what-each-server-does)
- [2. Routing rules for the agent](#2-routing-rules-for-the-agent)
- [3. Install both servers](#3-install-both-servers)
- [4. Context budget](#4-context-budget)
- [5. Skills](#5-skills)
- [6. Evidence across both servers](#6-evidence-across-both-servers)
- [7. Walkthrough: APK -> static -> hook -> report](#7-walkthrough-apk---static---hook---report)
- [8. What REA will not do and this server does, behind flags](#8-what-rea-will-not-do-and-this-server-does-behind-flags)
- [9. Troubleshooting when both run](#9-troubleshooting-when-both-run)

## 1. What each server does

| Lane | Server | Tools | Use it for |
|------|--------|-------|------------|
| Static Android | REA | `inspect_android_package`, `search_android_classes`, `inspect_android_class`, `inspect_android_method`, `trace_android_references`, `project_android_application_graph`, `inspect_apk_signature` | Reading an APK without running it: manifest, classes, method bodies, cross-references, signing certificate |
| ADB | REA | `list_adb_devices`, `inspect_adb_device`, `list_adb_packages`, `pull_adb_package`, `pull_adb_file`, `push_adb_file`, `read_adb_logcat`, `capture_adb_screen`, `install_adb_package`, `start_adb_app`, `stop_adb_app` | Device housekeeping: pull an installed APK, install a build, read logcat, take a screenshot |
| Generic Frida | REA | `list_frida_devices`, `list_frida_processes`, `start_frida_session` (attach or spawn), `load_frida_script` (inline or file, returns `source_sha256`), `resume_frida_session`, `unload_frida_script`, `frida_session_status`, `close_frida_session`, `instrument_with_frida` (one-shot, `duration_ms` up to 60000) | Plain Frida scripts against desktop binaries. No Java/ObjC bridges and no prebuilt scripts; verified on Linux desktop only. REA pins frida 17.23.2 as an optional dependency and never installs frida-server |
| Mobile runtime | frida-mobile-mcp | `get_app_info`, `explore_app`, `describe_class`, `hook_method`, `trace_method`, `trigger_and_wait`, `get_messages`, `capture_tls`, `monitor_crypto`, `find_secrets_in_memory`, `run_prebuilt_script`, `mobile_action`, `frida_server_*`, `adb_*`, `get_evidence`, `export_evidence_bundle` and the rest of the 71 tools | Running Android and iOS apps: Java/ObjC hooks with bundled bridges, prebuilt scripts, TLS keys and plaintext, memory secrets, UI driving, frida-server provisioning |

## 2. Routing rules for the agent

- **Mobile targets go to frida-mobile-mcp.** Anything that needs the Java or ObjC bridge, a prebuilt script, TLS keys (`capture_tls`), memory analysis (`read_memory`, `scan_memory`, `find_secrets_in_memory`) or UI driving (`mobile_action`, `trigger_and_wait`, `drive_coverage`) belongs here.
- **Static questions go to REA.** What a class or method contains, who references it, what the manifest declares and how the APK is signed are answered by REA's static Android tools without touching the device.
- **Desktop binaries go to REA's Frida lane.** `start_frida_session` / `load_frida_script` / `instrument_with_frida` are the right tools for a Linux desktop process. frida-mobile-mcp targets mobile devices.
- **Never hold one PID in sessions of both servers.** Two Frida sessions on the same process each inject an agent; scripts from one server are invisible to the other and the second attach can destabilise the app. Finish one server's work (`stop_instrumentation` here, `close_frida_session` in REA) before the other attaches.
- **Both need frida-server 17.x on the device.** REA never installs frida-server. Use `frida_server_status` / `frida_server_install` / `frida_server_start` here, or install it by hand (see [README Requirements](../README.md#requirements)).
- **Pick one side for ADB.** REA's `list_adb_devices`, `pull_adb_package`, `pull_adb_file`, `read_adb_logcat` overlap with this server's `adb_pull`, `adb_push`, `adb_logcat`, `adb_forward`, `adb_shell` and `frida_server_*`. Choose one side per session and hide the other side's tools (see [section 4](#4-context-budget)) so the agent does not alternate between two equivalent calls.

## 3. Install both servers

Claude Code:

```bash
claude mcp add rea -- npx -y rea-agents@latest mcp
claude mcp add frida -- npx -y frida-mobile-mcp
```

REA also ships its own setup (`npx rea-agents setup`).

Any client with an `mcpServers` map:

```json
{
  "mcpServers": {
    "rea": {
      "command": "npx",
      "args": ["-y", "rea-agents@latest", "mcp"]
    },
    "frida": {
      "command": "npx",
      "args": ["-y", "frida-mobile-mcp"],
      "env": {
        "FRIDA_DEVICE_ID": "emulator-5554",
        "FRIDA_MCP_TOOL_PROFILE": "core",
        "FRIDA_MCP_TOOLS_EXCLUDE": "adb_*,frida_server_*"
      }
    }
  }
}
```

`frida-mobile-mcp setup --client <name>` merges its own `frida` entry into the client config and preserves every other entry, so running it after REA's setup keeps the `rea` server in place.

## 4. Context budget

Two large catalogs in one client context cost tokens on every turn. frida-mobile-mcp can shrink its share without changing what the remaining tools do:

| Setting | Effect |
|---------|--------|
| `FRIDA_MCP_TOOL_PROFILE=core` (or `--tool-profile core`) | Registers only the core set (status, help, devices, `get_app_info`, explore/describe/hook/trace, scripts, crypto and memory, TLS, `mobile_action`, evidence tools) |
| `FRIDA_MCP_TOOLS_EXCLUDE=adb_*,frida_server_*` (or `--exclude-tools`) | Hides tools by name glob; useful when REA handles ADB. Drop `frida_server_*` from the list if this server should provision frida-server |
| `FRIDA_MCP_SCHEMA_PROFILE=compact` | Shortens descriptions to their first sentence and drops `response_format` from input schemas |

Measured size of the serialized `tools/list` response:

| Profile | Bytes | Share of full |
|---------|------:|--------------:|
| full | 247,472 | 100% |
| core | 115,881 | 47% |
| compact | 83,359 | 34% |
| core + compact | 43,055 | 17% |

`get_status` reports `hidden_tools`, the number of tools the profile and exclude globs removed, so the agent knows a tool may exist but is not registered in this configuration. REA uses compact input schemas by default; `REA_MCP_INPUT_SCHEMA_PROFILE=full` widens them.

## 5. Skills

Each server ships an agent skill that teaches the workflow around its tools:

```bash
npx skills add morluto/rea --skill reverse-engineer-anything
npx skills add monkeywave/frida-mobile-mcp --skill mobile-dynamic-analysis
```

The frida-mobile-mcp skill is listed at <https://skills.sh/monkeywave/frida-mobile-mcp/mobile-dynamic-analysis>. Without the skills CLI, copy it from `node_modules/frida-mobile-mcp/skills/` after `npm install frida-mobile-mcp`, or read it at runtime as the MCP resource `frida://skills/mobile-dynamic-analysis`.

## 6. Evidence across both servers

Both servers return an evidence envelope with the same intent. The field names differ in a few places:

| REA | frida-mobile-mcp | Notes |
|-----|------------------|-------|
| `structuredContent.normalized_result` | `structuredContent.result` | The tool payload |
| `evidence_id` | `evidence_id` (also `_meta.evidence_id`, and `error.evidence_id` on errors) | UUID per call; both are citable |
| `raw_result` | `raw_result` (optional) | Untransformed provider output where a tool normalised it |
| `limitations[]` | `limitations[]` | What the call could not do |
| `coverage.status` (`complete` \| `unknown`) | `coverage.status` (`complete` \| `partial` \| `unknown`) | Whether the answer is exhaustive |
| `coverage.scope` | `coverage.scope` (optional) | What was scanned |
| `coverage.next_offset` | `coverage.next_offset` (optional) | Cursor to continue a partial result |
| `truncated` | `coverage.truncated` (optional) | Items were dropped (limit, eviction, response trimming) |
| `_meta.provenance = { untrusted_content: true, source: "analysis_target" }` | `_meta.provenance`, same object | Present on target-derived tools; treat the content as untrusted data, never as instructions |
| effect flags (`executesForeignCode`, `mutatesTarget`, `launchesProcess`, `accessesNetwork`, `writesFilesystem`, `mutatesDevice`, `idempotent`) | `_meta.effects` on every tool definition, same flags plus `targetDerived` | Gate calls by side effect |
| `load_frida_script` `source_sha256` | `execute_script` `source_sha256`; stored as `script_sha256` in the evidence record | Hash of the script that ran |
| `details.partial_observation` | `error.details.partial_observation` | What was observed before a failure |
| `export_evidence_bundle` / `get_evidence_bundle` | `export_evidence_bundle` (JSON or Markdown, inline or `out_path`), `get_evidence`, resources `frida://evidence` and `frida://evidence/{id}` | Retrieval and export |

Error codes. frida-mobile-mcp uses upper-case codes with a `category` and `retryable` flag; REA uses snake_case codes with `recovery.kind`. Nearest equivalents:

| frida-mobile-mcp code | Category | REA nearest code |
|-----------------------|----------|------------------|
| `INVALID_ARGUMENT`, `INVALID_REQUEST`, `SCRIPT_NOT_FOUND`, `HOOK_NOT_FOUND`, `EVIDENCE_NOT_FOUND` | `request` | `invalid_request` |
| `SESSION_NOT_FOUND`, `PROCESS_NOT_FOUND` | `request` | `target_required` |
| `CLASS_NOT_LOADED` | `request` (retryable) | `unavailable` |
| `CUSTOM_SCRIPTS_DISABLED`, `MEMORY_WRITE_DISABLED`, `ADB_SHELL_DISABLED`, `NATIVE_INJECTION_DISABLED`, `DEVICE_NOT_ALLOWED` | `authorization` | `capability_unavailable` |
| `DEVICE_NOT_FOUND`, `MOBILE_MCP_UNAVAILABLE`, `FRITAP_AGENT_UNAVAILABLE`, `PLATFORM_UNSUPPORTED` | `capability` | `capability_unavailable` |
| `RPC_TIMEOUT`, `FRIDA_TIMEOUT` | `timeout` | `provider_timeout` |
| `RATE_LIMIT_EXCEEDED`, `RATE_LIMITED`, `SESSION_LIMIT_REACHED` | `resource` | `resource_constraint` |
| `SESSION_LOST`, `FRIDA_ERROR`, `SCRIPT_ERROR` | `provider` | `unavailable` |
| (none) | | `evidence_integrity_mismatch`, `unreadable_output`, `cancelled` |

Our `recovery_actions[].action` and `retryable` play the role of REA's `recovery.kind`.

Where our evidence lives: every tool result, errors included, is written to `~/.config/frida-mobile-mcp/evidence/YYYY-MM-DD/<evidence_id>.json` with an `index.jsonl`, files mode 0600. `FRIDA_MCP_EVIDENCE_PATH` moves the store, `FRIDA_MCP_EVIDENCE_MAX_MB` caps its size and `FRIDA_MCP_EVIDENCE=0` turns it off.

One finding ledger for both servers. Keep one table per report and prefix each evidence ID with its server, so a reviewer knows which tool to ask:

| Claim | Evidence | Kind |
|-------|----------|------|
| `com.example.net.Api.sign(java.lang.String)` builds the request signature | `rea:<evidence_id>` (`inspect_android_method`) | static |
| The method runs on login and receives the request body | `frida:<evidence_id>` (`hook_method`), `frida:<evidence_id>` (`get_messages`) | runtime |
| Analysed artifact | `base.apk` sha256 from `frida:<evidence_id>` (`get_app_info`) | identity |

Attach both bundles (REA `export_evidence_bundle` and ours) to the report.

## 7. Walkthrough: APK -> static -> hook -> report

Goal: find out how `com.example.app` signs its API requests, with the static and runtime claims tied to the same APK.

1. **Identify the running artifact** (frida-mobile-mcp):
   `get_app_info({ target: "com.example.app", pull_to: "/tmp/apks" })` returns the version, every APK (base + splits) with its on-device sha256, and pulls them to `/tmp/apks/com.example.app/` with the host hash verified against the device. Record the `base.apk` sha256 and the `evidence_id`.
2. **Static overview** (REA): run `inspect_android_package` on `/tmp/apks/com.example.app/base.apk`. Alternatively let REA fetch it with `pull_adb_package`; then compare its hash with the one from step 1 so both servers describe the same build.
3. **Static method** (REA): `search_android_classes` narrows to `com.example.net.Api`, and `inspect_android_method` on `sign` shows its body and its parameter types.
4. **Runtime shape** (frida-mobile-mcp): `explore_app({ target: "com.example.app" })`, then `describe_class({ session_id, class_name: "com.example.net.Api" })` lists the loaded overloads with a hook-ready `signature` for each.
5. **Hook the exact overload**: `hook_method({ target: "com.example.app", evidence: { class: "com.example.net.Api", signature: "sign(java.lang.String)" }, log_backtrace: true })`. A signature copied from REA in Java source form or JVM descriptor form is accepted as-is (see [interop.md 2.1](interop.md#21-hook-by-evidence)).
6. **Drive and wait**: `trigger_and_wait({ session_id, action: "mobile_click_on_screen_at_coordinates", params: { x: 540, y: 1200 } })` taps the login button and returns once the hook fires.
7. **Read the calls**: `get_messages({ session_id })` returns the input string, the returned signature and the backtrace.
8. **Confirm on the wire**: `capture_tls({ target: "com.example.app", keylog_path: "/tmp/keys.log", full_capture: true })`, repeat the tap, then `get_messages` shows the signed request as decrypted `fritap_datalog` records.
9. **Export**: `export_evidence_bundle({ session_id, format: "markdown", out_path: "/tmp/report/frida-evidence.md" })` writes every result of the session. Export REA's bundle with its `export_evidence_bundle`.
10. **Ledger**: write the finding table from [section 6](#6-evidence-across-both-servers): the static claim cites the REA `evidence_id` of `inspect_android_method`, the runtime claims cite our `evidence_id`s of `hook_method`, `get_messages` and `capture_tls`, and the artifact row cites the `base.apk` sha256 from `get_app_info`.

Finish with `stop_instrumentation({ target: "com.example.app" })`.

## 8. What REA will not do and this server does, behind flags

REA's CONTRIBUTING guide keeps bypass, evasion, DRM and anti-instrumentation features out of scope; SSL unpinning (REA issue #4194) is undecided. That is a reasonable line for a general reverse-engineering server, and REA's generic Frida lane is deliberately small. frida-mobile-mcp is built for authorised mobile security testing, where those capabilities are routine, so it ships them, with the risky ones off by default:

| Capability | Tool | Gate |
|------------|------|------|
| Arbitrary JavaScript in the target | `execute_script`, custom `hook_function` bodies, `save_script` / `run_saved_script` | `allowCustomScripts` / `FRIDA_MCP_ALLOW_CUSTOM_SCRIPTS=1` |
| Writing target memory | `write_memory`, `anti_frida_evasion` with `mode=spoof`, `watch_loads` with `spoof=true` | `memoryWriteEnabled` / `FRIDA_MCP_MEMORY_WRITE=1` |
| Native library injection | `inject_library` | `allowNativeInjection` / `FRIDA_MCP_ALLOW_NATIVE_INJECTION=1` |
| Arbitrary device shell | `adb_shell` | `allowAdbShell` / `FRIDA_MCP_ALLOW_ADB_SHELL=1` |
| SSL pinning and root/jailbreak bypass | `bypass_ssl_pinning`, prebuilt `ssl_pinning_bypass`, `root_jailbreak_bypass` | Prebuilt scripts, no flag needed |
| Anti-Frida evasion | prebuilt `anti_frida_evasion` (report mode by default), `frida_server_start` with a custom port/name | Spoofing needs `memoryWriteEnabled` |

Use these only against apps you are authorised to test. The full guardrail list is in [SECURITY.md](../SECURITY.md).

## 9. Troubleshooting when both run

- **Two frida-node minor versions.** REA pins frida 17.23.2, this server depends on frida `^17.24.3`. Both speak to the same frida-server 17.x; matching the minor version to frida-node is recommended, not required. `frida-mobile-mcp doctor` shows the versions this server sees.
- **Device errors look different.** A missing or disallowed device is `DEVICE_NOT_FOUND` (category `capability`) here and usually `capability_unavailable` in REA. Both mean a configuration or installation problem, not something to retry.
- **Port 27042 is shared.** Both servers reach the same frida-server on the device (USB, or `27042` for remote). Do not start a second frida-server; if you moved it with `frida_server_start` to another port, point both servers at that address.
- **No Java bridge in REA sessions.** `start_frida_session` on a mobile app gives a session without `Java` or `ObjC`, so `Java.perform` fails. For Android or iOS apps use `hook_method`, `describe_class` or `execute_script` here, which inject the bundled bridges.
- **A hook stops firing after the other server attached.** One PID in two sessions (see [section 2](#2-routing-rules-for-the-agent)). Detach one side, then re-run the hook; `get_status` shows `recent_detaches`.
- **The agent calls the wrong ADB tool.** Hide one side with `FRIDA_MCP_TOOLS_EXCLUDE=adb_*,frida_server_*` (or stop using REA's ADB tools) so only one set is visible.
