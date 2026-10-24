# Security Policy

## Scope

frida-mobile-mcp is a dynamic-instrumentation server. By design it can attach to processes, hook functions, read process memory and, when explicitly enabled, execute arbitrary JavaScript inside a target and write memory. Anyone who can talk to the server has the same power as a Frida session on the connected device. Run it only against devices and apps you are authorised to analyse.

## Supported versions

Security fixes are released for the latest published version on npm. Please upgrade before reporting.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability reporting on <https://github.com/monkeywave/frida-mobile-mcp/security/advisories/new>. If that is not available to you, open an issue asking for a private contact without including details.

Include the version (`npx frida-mobile-mcp --version`), transport (stdio or HTTP), configuration flags, and reproduction steps. You should receive an acknowledgement within a few days; fixes are published through the normal release process and noted in `CHANGELOG.md`.

## Built-in guardrails

Defaults are conservative; relaxing them is a deliberate configuration change (`~/.config/frida-mobile-mcp/config.json`, CLI flags or `FRIDA_MCP_*` environment variables):

- `allowCustomScripts: false`: `execute_script` and custom `hook_function` handler bodies are refused (`CUSTOM_SCRIPTS_DISABLED`).
- `memoryWriteEnabled: false`: `write_memory` is refused (`MEMORY_WRITE_DISABLED`).
- `allowNativeInjection: false`: `inject_library` is refused (`FRIDA_MCP_ALLOW_NATIVE_INJECTION=1` enables it); it loads arbitrary native code into the target.
- `allowAdbShell: false`: `adb_shell` is refused (`FRIDA_MCP_ALLOW_ADB_SHELL=1` enables it); it runs arbitrary commands on the device.
- `allowedDevices`: optional allowlist of device IDs.
- Rate limits for script loads, memory reads/scans and attach/spawn; `maxSessions` and `sessionTimeoutMinutes` bound sessions.
- Append-only JSONL audit log (`auditLogPath`, default `~/.config/frida-mobile-mcp/audit.jsonl`) with an `evidence_id` per call.
- Every tool result (including memory dumps' metadata, read memory and found secrets) is persisted under the evidence path (`evidence.path`, default `~/.config/frida-mobile-mcp/evidence`) with mode 0600; opt out with `FRIDA_MCP_EVIDENCE=0`.
- `dump_module_memory` writes only under the current directory, the OS temp directory or `~/.config/frida-mobile-mcp/dumps`.
- HTTP transport binds to loopback by default, requires a Bearer token when bound to a non-loopback address, validates `Host`/`Origin`, and has no TLS of its own (use a reverse proxy or SSH tunnel).
- Template options are passed to agents as a JSON literal, never spliced into code.

## Third-party components

The server loads code it does not author into target processes: the bundled `frida-java-bridge`/`frida-objc-bridge` (built from npm at `npm run build:bridges`), the friTap agent for `capture_tls` (from `pip install friTap`, `FRITAP_AGENT_PATH`, or a pinned GitHub release download when `allow_download` is true) and, on demand, `@mobilenext/mobile-mcp` via `npx`. Review the pinned versions in `package.json` and `src/fritap/agent-loader.ts` if your threat model requires it. The downloaded friTap agent is verified against a pinned sha256; `FRITAP_AGENT_SHA256` supplies the expected digest for non-default `FRITAP_VERSION` tags. Dependencies are monitored by Dependabot and CodeQL.
