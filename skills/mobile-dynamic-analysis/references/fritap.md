# capture_tls (friTap)

Detail for `SKILL.md`. Read this when capturing TLS keys or plaintext with
`capture_tls`, when instrumentation crashes an anti-tamper app, or when you
need to attribute traffic to an SDK.

Captures TLS session keys and decrypted plaintext from an app using the friTap
agent, independent of the TLS library (BoringSSL, OpenSSL, NSS, GnuTLS,
wolfSSL, mbedTLS, Conscrypt, Flutter/Dart, Cronet, ...). The pinned agent is
friTap v2.6.5; agent ABI 2 and 3 are accepted.

## Arguments

| Arg                | Default | Meaning |
|--------------------|---------|---------|
| `target`           | -       | Bundle ID, process name or PID string |
| `device`           | auto    | Device ID |
| `keylog_path`      | none    | Where to append the NSS key log; omitted: keys are only buffered as messages |
| `pcap_path`        | none    | Best-effort pcap of decrypted records (implies `full_capture`) |
| `spawn`            | `true`  | Spawn suspended -> load friTap agent -> configure -> resume, so the first TLS handshakes are caught. `false` attaches to the running process |
| `spawn_mode`       | `suspended` | With `spawn: true`: `suspended` loads friTap before resuming; if the suspended app dies during the start (Android start timeout: not resumed within ~10 s on a slow device; seen as a dead pid, a `process-terminated` detach, a closed connection or a timeout) it retries once as `early_resume`. A spawned app must still be alive ~1 s after the start, otherwise the result is a `PROCESS_TERMINATED` error (never a success). `early_resume` resumes right after the attach and loads friTap into the running app: TLS handshakes in the first seconds may be missed (reported in `limitations`) |
| `anti_root`        | `false` | Enable friTap anti-root/anti-detection helpers |
| `full_capture`     | `false` | Also capture decrypted plaintext (`fritap_datalog` messages), not only keys |
| `duration_seconds` | `0`     | `0` = keep running until `stop_instrumentation`; max 600 |
| `allow_download`   | `true`  | Fetch the pinned friTap agent bundle from GitHub into `~/.config/frida-mobile-mcp/fritap/<version>/` when `pip install friTap` is not present |
| `patterns`, `offsets` | none | friTap pattern/offset hooking JSON (object or string); pair with `generate_memory_pattern`. Must be a JSON object (or a JSON string of one), else `INVALID_ARGUMENT` before anything is spawned or attached |
| `protocols`        | `["tls"]` | Array of `tls`, `rc4`, `auto`, `all`. Combine concrete ones (`["tls","rc4"]`); `auto` (hook what is detected) and `all` (every hook) must be passed alone |
| `pairip_safe`      | `false` | PairIP/anti-tamper apps: minimal symbol-only keylog on system BoringSSL libs (no loader hook, pattern scan, Java or OHTTP hooks). Prefer `spawn: false` |
| `no_loader_hook`   | `false` | Skip the Android dynamic-loader hook (avoids anti-tamper crashes); TLS libraries loaded later are not hooked |
| `probe`            | `false` | Diagnostic dry run: installs no hooks and emits a `fritap_platform_report` message with the detected platform branch |
| `attribute_sdk`    | `false` | Emit one `fritap_caller_stack` backtrace per TLS connection: which SDK/app code produced the traffic |
| `default_fd`       | `false` | Keep plaintext records whose socket cannot be resolved, using placeholder addresses (127.0.0.1) instead of dropping them |
| `library_scan`     | `false` | Scan loaded modules for an SSL key-log callback and hook TLS libraries friTap does not know by name |
| `experimental`     | `false` | Enable friTap experimental hooks (may be unstable) |

Output: `session_id`, `script_id`, `agent_version`, `keylog_path`, `hooks`, `spawn_mode` (mode actually used), `start_retried`
(initial summary messages reporting which TLS libraries were hooked).

## Records and stats (read with get_messages)

- `fritap_datalog`: decrypted record, hex dump plus UTF-8 preview, capped per
  record and by the session buffer.
- `fritap_caller_stack`: backtrace per connection (needs `attribute_sdk`);
  group traffic by it into first-party vs third-party SDK.
- `fritap_platform_report`: platform branch detected by friTap (always emitted
  by `probe: true`).
- `stats.per_library`: per TLS library, what carried traffic and which hooked
  libraries stayed idle. Keyed by the agent's `library` when it sends one (QUIC),
  else by the library family of the hooked function (`SSL_read` ->
  `openssl/boringssl`, `PR_Read` -> `nss`, ...; also `library_family` on each
  `fritap_datalog`); friTap does not report which module (e.g. Conscrypt
  `libssl.so` vs Cronet) a record came from. Traffic without keys is a gap: retry with
  `library_scan` or `patterns`/`offsets`.

## Key log, plaintext, pcap

- Key log: NSS format (`CLIENT_RANDOM <client_random> <secret>`). Load it in
  Wireshark via Preferences -> Protocols -> TLS -> `(Pre)-Master-Secret log
  filename`, or `tls.keylog_file` in `tshark -o`.
- Plaintext: buffered as session messages; poll `get_messages({ session_id })`.
- pcap: full pcap writing (with TCP/IP framing) needs the friTap Python CLI:
  `fritap -m -p out.pcap -k keys.log -s com.example.app`. The MCP tool writes
  only a best-effort pcap of decrypted records, and only when `pcap_path` is
  given.

## When instrumentation crashes the app or nothing is captured

1. `capture_tls({ target, probe: true })`: reports the platform branch, installs no hooks.
2. Retry with `no_loader_hook: true`.
3. For PairIP/anti-tamper apps use `pairip_safe: true` with `spawn: false`.
4. Still blind to an unknown TLS stack: `library_scan: true`, `default_fd: true`.

## Agent discovery

Order: `FRITAP_AGENT_PATH` env -> installed `friTap` Python package
(`fritap_agent.js` next to `friTap/__init__.py`) -> cached download
`~/.config/frida-mobile-mcp/fritap/<version>/fritap_agent.js` fetched from
`https://raw.githubusercontent.com/fkie-cad/friTap/<tag>/friTap/fritap_agent.js`
(default tag `v2.6.5`; `FRITAP_VERSION` pins another tag).

Error `FRITAP_AGENT_UNAVAILABLE`: run `pip install friTap`, or set
`FRITAP_AGENT_PATH=/path/to/fritap_agent.js`, or allow the download.

## Typical sequence

`capture_tls({ target: "com.example.app" })` -> drive the app with
`mobile_action` -> `get_messages` for `fritap_datalog` -> open `keylog_path` in
Wireshark alongside a device-side capture (`tcpdump`, `androidtcpdump`) ->
`stop_instrumentation`.

The `capture_tls` result carries `stats_note` (counts are a snapshot and keep
growing), `warnings` and `java_bridge_patch`. Final stats including
`per_library` come back once as `fritap_captures[]` from `stop_instrumentation`,
`unload_script` or `detach_session`. A capture that ended on its own
(`duration_seconds` expired, or the app exited and took the session with it)
keeps its totals in memory (last 50 ended captures): `unload_script(session_id,
script_id)` or `stop_instrumentation(session_id)` still return them
(`already_ended: true`) instead of `SCRIPT_NOT_FOUND` / `SESSION_NOT_FOUND`.
A failed `capture_tls` on an existing session (`spawn=false`) only removes its
own friTap script; the session and your other hooks stay.
One friTap capture per process: a second `capture_tls` into a process that
already runs one (same session, or another session on the same pid) is refused
with `FRITAP_CAPTURE_ACTIVE` (category `request`, not retryable; `context`
names the running `session_id`/`script_id`), because two friTap agents in one
process crash the app. Keep reading the running capture with `get_messages`, or
`unload_script` it / `stop_instrumentation` first.

## Guided audit: the tls_traffic_audit prompt

The MCP prompt `tls_traffic_audit` (args: `target`, optional `device`,
`protocols` as a comma-separated list) walks capture (with `attribute_sdk`,
`probe` fallback), driving the app, reviewing `fritap_caller_stack` and
`stats.per_library`, and reporting plaintext/PII sent to third parties.

## Hand-off to friTap's own MCP server

If `fritap mcp` is installed and connected (`pip install 'fritap[mcp]'`;
captures there need `--allow-capture`), analyse the same session with
`get_digest`, `list_findings` and `find_values`. Do not run two captures on
the same app at once.
