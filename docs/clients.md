# Client Setup

How to connect `frida-mobile-mcp` to MCP clients, run it over HTTP, reach a remote frida-server, and match Frida versions.

The server entry is the same for every client: run `npx -y frida-mobile-mcp` and pass options through environment variables. Replace `emulator-5554` with the device ID from `frida-mobile-mcp --list-devices` (or omit `FRIDA_DEVICE_ID` to pick the first USB device).

## Contents

- [Running the server](#running-the-server)
- [Automatic setup](#automatic-setup)
- [Claude Desktop](#claude-desktop)
- [Claude Code](#claude-code)
- [Cursor](#cursor)
- [VS Code](#vs-code)
- [Windsurf](#windsurf)
- [Codex](#codex)
- [HTTP mode](#http-mode)
- [Remote frida-server](#remote-frida-server)
- [Version matching](#version-matching)
- [Running next to other MCP servers](#running-next-to-other-mcp-servers)
- [Environment variables](#environment-variables)

## Running the server

```bash
npx -y frida-mobile-mcp            # stdio transport (default)
frida-mobile-mcp --list-devices    # print Frida devices and exit
frida-mobile-mcp doctor            # check the local setup
```

```
Usage: frida-mobile-mcp [options]
       frida-mobile-mcp doctor
       frida-mobile-mcp setup --client <name> [options]

Options:
  --device <id>            Frida device ID
  --remote <host[:port]>   Add a remote frida-server at startup (or FRIDA_MCP_REMOTE)
  --remote-token <token>   Auth token of that frida-server (or FRIDA_MCP_REMOTE_TOKEN)
  --remote-cert <path>     PEM certificate of a TLS frida-server (or FRIDA_MCP_REMOTE_CERT)
  --allow-custom-scripts   Allow custom Frida script execution
  --allow-memory-write     Allow memory write operations
  --allow-adb-shell        Allow raw adb shell commands (adb_shell)
  --no-mobile-mcp          Disable mobile-mcp integration
  --debug                  Enable debug logging
  --list-devices           Print Frida devices and exit
  --transport <type>       stdio (default) or http
  --host <addr>            HTTP bind address (default: 127.0.0.1)
  --port <n>               HTTP port; 0 picks a free port
  --http-token <token>     Bearer token for HTTP clients (or FRIDA_MCP_HTTP_TOKEN)
```

### doctor

`frida-mobile-mcp doctor` is the first thing to run when a client cannot talk to a device. It checks:

- Node.js >= 22.12
- the frida native binding loads
- `adb` is on `PATH` and lists devices
- Frida devices, and whether frida-server is reachable on each USB device, with hints when the frida-server version does not match the bundled frida-node
- bridge bundles are present
- `fritap` on `PATH` (optional)
- the config file at `~/.config/frida-mobile-mcp/config.json`

It exits with status 1 when a required check fails, so it can be used in scripts.

## Automatic setup

`frida-mobile-mcp setup` writes the server entry into a client's config for you:

```bash
frida-mobile-mcp setup --client claude-desktop
frida-mobile-mcp setup --client cursor --device emulator-5554
frida-mobile-mcp setup --client vscode --allow-custom-scripts
frida-mobile-mcp setup --client windsurf --print
frida-mobile-mcp setup --client codex
frida-mobile-mcp setup --client claude-code
```

- `--client` accepts `claude-code`, `claude-desktop`, `cursor`, `vscode`, `windsurf` or `codex`.
- `--device` is written into the entry's `env` block; `--allow-custom-scripts`, `--allow-memory-write`, `--allow-native-injection` and `--allow-adb-shell` are baked into the entry's `args` as the matching server flags.
- Existing config files are merged, not replaced; the previous file is saved next to it with a `.bak` suffix.
- `--print` prints the entry without writing anything.
- `codex` prints a TOML snippet to paste into `~/.codex/config.toml`.
- `claude-code` runs `claude mcp add --scope user frida -- npx -y frida-mobile-mcp`.

The sections below show the resulting configuration for each client if you prefer to edit by hand.

## One-click install (.mcpb)

Each GitHub release attaches an `frida-mobile-mcp.mcpb` bundle. MCPB-aware clients (e.g. Claude
Desktop) can install it in one click from the release page — no manual config needed. The server is
also published to the [MCP registry](https://github.com/modelcontextprotocol/registry) as
`io.github.monkeywave/frida-mobile-mcp` for clients that browse the registry.

## Claude Desktop

Config file:

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

```json
{
  "mcpServers": {
    "frida": {
      "command": "npx",
      "args": ["-y", "frida-mobile-mcp"],
      "env": {
        "FRIDA_DEVICE_ID": "emulator-5554"
      }
    }
  }
}
```

Restart Claude Desktop after editing. Claude Desktop only supports stdio servers launched from this file.

## Claude Code

Register the server once for your user:

```bash
claude mcp add --scope user frida -- npx -y frida-mobile-mcp
```

With a fixed device:

```bash
claude mcp add --scope user -e FRIDA_DEVICE_ID=emulator-5554 frida -- npx -y frida-mobile-mcp
```

Connect to a server already running in [HTTP mode](#http-mode):

```bash
claude mcp add --transport http frida http://127.0.0.1:PORT/mcp \
  --header "Authorization: Bearer <token>"
```

Check the connection with `claude mcp list` or `/mcp` inside Claude Code.

## Cursor

Global config: `~/.cursor/mcp.json`. Project config: `.cursor/mcp.json` in the repository root.

```json
{
  "mcpServers": {
    "frida": {
      "command": "npx",
      "args": ["-y", "frida-mobile-mcp"],
      "env": {
        "FRIDA_DEVICE_ID": "emulator-5554"
      }
    }
  }
}
```

Enable the server under Settings > MCP after saving.

## VS Code

Workspace config: `.vscode/mcp.json`. Note the top-level key is `servers` and each entry carries a `type`.

```json
{
  "servers": {
    "frida": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "frida-mobile-mcp"],
      "env": {
        "FRIDA_DEVICE_ID": "emulator-5554"
      }
    }
  }
}
```

To connect to a server running in [HTTP mode](#http-mode):

```json
{
  "servers": {
    "frida": {
      "type": "http",
      "url": "http://127.0.0.1:PORT/mcp",
      "headers": {
        "Authorization": "Bearer <token>"
      }
    }
  }
}
```

## Windsurf

Config file: `~/.codeium/windsurf/mcp_config.json`.

```json
{
  "mcpServers": {
    "frida": {
      "command": "npx",
      "args": ["-y", "frida-mobile-mcp"],
      "env": {
        "FRIDA_DEVICE_ID": "emulator-5554"
      }
    }
  }
}
```

## Codex

Config file: `~/.codex/config.toml`.

```toml
[mcp_servers.frida]
command = "npx"
args = ["-y", "frida-mobile-mcp"]

[mcp_servers.frida.env]
FRIDA_DEVICE_ID = "emulator-5554"
```

`frida-mobile-mcp setup --client codex` prints this snippet; paste it into the file.

## HTTP mode

The HTTP transport exposes a Streamable HTTP endpoint at `/mcp` and holds one MCP session per client. Use it when the client cannot spawn a local process, or to share one server between several clients.

### Start

```bash
# Loopback, fixed port
frida-mobile-mcp --transport http --host 127.0.0.1 --port 3000 --http-token <token>

# Loopback, ephemeral port
frida-mobile-mcp --transport http --port 0

# Reachable from the network (token is mandatory)
FRIDA_MCP_HTTP_TOKEN=<token> frida-mobile-mcp --transport http --host 0.0.0.0 --port 3000
```

On start the server prints a single JSON line to stderr with the bound URL. This is the line to parse when you used `--port 0`:

```json
{"event":"listening","url":"http://127.0.0.1:3000/mcp","transport":"http"}
```

### Talk to it with curl

Initialize a session:

```bash
curl -i http://127.0.0.1:3000/mcp \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "MCP-Protocol-Version: 2025-06-18" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-06-18",
      "capabilities": {},
      "clientInfo": { "name": "curl", "version": "1.0" }
    }
  }'
```

The response carries an `Mcp-Session-Id` header. Send it on every following request, for example to list tools:

```bash
curl http://127.0.0.1:3000/mcp \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -H "MCP-Protocol-Version: 2025-06-18" \
  -H "Mcp-Session-Id: <session-id>" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

End the session:

```bash
curl -X DELETE http://127.0.0.1:3000/mcp \
  -H "Authorization: Bearer <token>" \
  -H "Mcp-Session-Id: <session-id>"
```

### Security

- The server binds to `127.0.0.1` by default. Only local clients can reach it.
- A Bearer token (`--http-token` or `FRIDA_MCP_HTTP_TOKEN`) is required when `--host` is anything other than a loopback address; the server refuses to start without one. Set one on loopback too if other users share the machine.
- `Host` and `Origin` request headers are validated against the bound host to block DNS rebinding from a browser.
- There is no TLS. For access across a network, put the server behind a reverse proxy that terminates HTTPS, or tunnel over SSH.
- The server has the same powers as any Frida session on the connected device. Treat the token like a credential.

## Remote frida-server

By default the server talks to USB devices through the local Frida daemon. To reach a frida-server listening on the network, add it as a remote device.

At startup:

```bash
FRIDA_MCP_REMOTE=192.168.1.5:27042 npx -y frida-mobile-mcp
```

The port defaults to `27042` when omitted. The device is registered through Frida's `addRemoteDevice` at startup and then shows up alongside USB devices in `get_status`.

At runtime, through the `select_device` tool:

```json
{ "type": "remote", "host": "192.168.1.5:27042" }
```

On the device, frida-server must be told to listen on the network interface instead of the local socket:

```bash
adb shell "su -c '/data/local/tmp/frida-server -l 0.0.0.0:27042 &'"
```

A frida-server reachable over the network is open to anyone who can connect to it. Start it with an auth token (`frida-server -l 0.0.0.0:27042 --token <t>`, or `frida_server_start` with `token`) and pass the same token as `FRIDA_MCP_REMOTE_TOKEN` / `--remote-token`, or as `token` to `select_device`. For a TLS-enabled server (`--certificate`), point `FRIDA_MCP_REMOTE_CERT` / `--remote-cert` (or `select_device` `certificate`) at its PEM file. The token is never echoed in tool results.

```bash
FRIDA_MCP_REMOTE=192.168.1.5:27042 FRIDA_MCP_REMOTE_TOKEN=<t> npx -y frida-mobile-mcp
```

For a USB-tethered device you can forward the port instead of exposing it on Wi-Fi:

```bash
adb forward tcp:27042 tcp:27042
FRIDA_MCP_REMOTE=127.0.0.1:27042 npx -y frida-mobile-mcp
```

## Version matching

This package bundles frida-node 17.24.x, which speaks to frida-server 17.x. Keep the major version identical and ideally the minor version too.

Symptoms of a mismatch:

- `unable to connect to remote frida-server`
- protocol or serialization errors right after attaching
- tool calls that time out while `adb devices` still shows the device

Fix:

1. Run `frida-mobile-mcp doctor`. It prints the frida-node version and the frida-server version seen on each USB device, and flags mismatches.
2. Download the matching `frida-server` for your device architecture from <https://github.com/frida/frida/releases> (for example `frida-server-17.24.3-android-arm64.xz`).
3. Install and start it as root:

```bash
xz -d frida-server-17.24.3-android-arm64.xz
adb push frida-server-17.24.3-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server &'"
```

4. Run `frida-mobile-mcp doctor` again and confirm every check passes.

On jailbroken iOS, install the Frida package whose version matches from the Frida Cydia/Sileo repository.

## Running next to other MCP servers

frida-mobile-mcp is meant to share a client with static-analysis servers such as REA, ReVa (Ghidra) and IDA. Register each server under its own name; `frida-mobile-mcp setup --client <name>` only adds or replaces the `frida` entry and keeps the others. To keep the combined tool catalog small, trim this server:

```bash
FRIDA_MCP_TOOL_PROFILE=core                  # core tool set only
FRIDA_MCP_TOOLS_EXCLUDE=adb_*,frida_server_*  # hide tools another server covers
FRIDA_MCP_SCHEMA_PROFILE=compact             # short descriptions; core + compact is 17% of the full catalog
```

`get_status` reports how many tools were hidden (`hidden_tools`). Routing rules, the REA install lines and the evidence mapping are in [rea.md](rea.md); address notation and the three-server ReVa/IDA setup are in [interop.md](interop.md).

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FRIDA_DEVICE_ID` | first USB device | Device ID to use; same as `--device` |
| `FRIDA_MCP_ALLOW_CUSTOM_SCRIPTS` | unset | `1` enables `execute_script` with arbitrary JavaScript; same as `--allow-custom-scripts` |
| `FRIDA_MCP_MEMORY_WRITE` | unset | `1` enables `write_memory`; same as `--allow-memory-write` |
| `FRIDA_MCP_ALLOW_NATIVE_INJECTION` | unset | `1`/`true` enables `inject_library` (native .so/.dylib injection); same as `--allow-native-injection` |
| `FRIDA_MCP_ALLOW_ADB_SHELL` | unset | `1`/`true` enables `adb_shell` (arbitrary device shell commands); same as `--allow-adb-shell` |
| `FRIDA_MCP_DEBUG` | unset | `1` enables debug logging on stderr; same as `--debug` |
| `FRIDA_MCP_RUNTIME` | Script runtime override: `qjs` (default) or `v8` (Android debugging only) |
| `FRIDA_MCP_SNAPSHOTS` | unset | `1` pre-warms a per-session V8 snapshot of the Java/ObjC bridge; same as config `snapshots`. Only effective together with `FRIDA_MCP_RUNTIME=v8` |
| `FRIDA_MCP_EVIDENCE` | `1` | `0` stops persisting tool results to the evidence store; same as config `evidence.enabled` |
| `FRIDA_MCP_EVIDENCE_PATH` | `~/.config/frida-mobile-mcp/evidence` | Evidence store directory (`YYYY-MM-DD/<evidence_id>.json` plus `index.jsonl`, mode 0600); same as config `evidence.path` |
| `FRIDA_MCP_EVIDENCE_MAX_MB` | `200` | Size cap of the evidence store in MB, oldest records pruned first; same as config `evidence.maxMb` |
| `FRITAP_VERSION` | friTap release tag to download when no local agent is found (default v2.5.2) |
| `FRITAP_AGENT_SHA256` | Bare sha256 of the downloaded friTap agent for the selected `FRITAP_VERSION` tag. v2.5.2 is pinned built in; unpinned tags download with a warning. Not applied to `FRITAP_AGENT_PATH` or pip-installed agents |
| `FRITAP_AGENT_PATH` | Path to a friTap fritap_agent.js bundle for capture_tls (otherwise the installed friTap Python package or a pinned download is used) |
| `FRIDA_MCP_COMPILER_PROJECT_DIR` | Cache directory for the frida.Compiler project used to compile ES module scripts |
| `FRIDA_MCP_BRIDGES_DIR` | Directory with prebuilt Java/ObjC bridge bundles (defaults to dist/bridges inside the package) |
| `FRIDA_MCP_REMOTE` | unset | `host[:port]` of a frida-server to add as a remote device at startup; port defaults to `27042`; same as `--remote` |
| `FRIDA_MCP_REMOTE_TOKEN` | unset | Auth token the remote frida-server was started with (`--token`); same as `--remote-token` |
| `FRIDA_MCP_REMOTE_CERT` | unset | Path to the PEM certificate of a TLS remote frida-server (`--certificate`); same as `--remote-cert` |
| `FRIDA_MCP_HTTP_TOKEN` | unset | Bearer token for the HTTP transport; same as `--http-token`; required when `--host` is not loopback |
| `FRIDA_MCP_SCHEMA_PROFILE` | `full` | `compact` shortens tool schemas and descriptions for clients with small context windows |
| `FRIDA_MCP_TOOL_PROFILE` | `full` | `core` registers only the core tool set (smaller `tools/list`, e.g. next to REA); also `--tool-profile` |
| `FRIDA_MCP_TOOLS_EXCLUDE` | (none) | Comma-separated tool-name globs never registered, e.g. `adb_*,frida_server_*`; also `--exclude-tools` |
| `FRIDA_MCP_MAX_RESPONSE_CHARS` | `25000` | Maximum characters in a single tool response; longer output is truncated |

Persistent settings such as the device allowlist, rate limits and session timeouts live in `~/.config/frida-mobile-mcp/config.json`; see the README for the full file.

### Script snapshots (`snapshots` / `FRIDA_MCP_SNAPSHOTS`)

Every script the server creates carries the agent preamble plus the ~300 KB Java (or ~50 KB ObjC) bridge bundle. With `snapshots: true` in `config.json` (or `FRIDA_MCP_SNAPSHOTS=1`; `0` forces it off) the server instead takes one `session.snapshotScript` of the preamble and bridges per session and creates later scripts from that heap, so only the per-script context and body are sent. Snapshots are a V8 feature: QuickJS, Frida's default runtime, cannot produce them, so the setting is a no-op unless `FRIDA_MCP_RUNTIME=v8` is also set; a failed snapshot is remembered per session and the full source is sent as before. The feature is off by default because on a remote device the ~775 KB snapshot travels inline with each `createScript`, which measured no faster than sending the source (about 36 ms create+load either way on an Android 16 emulator with frida-server 17.24.3); it is kept for local or shared-memory setups and for experiments. The MCP library API exposes the same switch as `useSnapshot` on `createAgentScript`.
