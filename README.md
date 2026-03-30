# frida-mobile-mcp

Mobile Frida MCP Server — AI-powered mobile app exploration and testing via Frida dynamic instrumentation.

## Quick Start

```bash
npx frida-mobile-mcp
```

### Claude Desktop Configuration

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

## Features

- **31 MCP Tools** — 15 high-level (Tier 1) + 16 advanced (Tier 2)
- **8 Pre-built Scripts** — SSL bypass, root/jailbreak bypass, crypto monitor, network inspector, and more
- **mobile-mcp Integration** — UI automation (screenshots, taps, swipes) via gateway pattern
- **AI-Optimized UX** — Structured returns with `session_context` and `suggested_next` actions
- **Android + iOS** — Full support for both platforms
- **Security Guardrails** — Custom scripts disabled by default, memory write protection, audit logging, rate limiting

## Prerequisites

- **Node.js** 18+ (22+ recommended)
- **Frida server** running on target device
  - Android: `adb push frida-server /data/local/tmp/ && adb shell "/data/local/tmp/frida-server &"`
  - iOS: Install via Cydia/Sileo on jailbroken device
- **mobile-mcp** (optional): `npm install -g @mobilenext/mobile-mcp`

## Installation

```bash
# Run directly
npx frida-mobile-mcp

# Or install globally
npm install -g frida-mobile-mcp
frida-mobile-mcp
```

## CLI Options

```
Usage: frida-mobile-mcp [options]

Options:
  --transport <type>       stdio or http (default: "stdio")
  --port <number>          HTTP port (default: "3000")
  --device <id>            Frida device ID
  --allow-custom-scripts   Allow custom Frida script execution
  --allow-memory-write     Allow memory write operations
  --no-mobile-mcp          Disable mobile-mcp integration
  --debug                  Enable debug logging
```

## Tool Reference (Tier 1)

| Tool | Description |
|------|-------------|
| `get_status` | Overview of devices, sessions, hooks |
| `explore_app` | Launch app + enumerate classes/modules |
| `hook_method` | One-call method hooking (Java/ObjC/native) |
| `trace_method` | Trace function calls for a duration |
| `execute_script` | Run custom Frida JavaScript |
| `run_prebuilt_script` | Run from built-in script library |
| `bypass_ssl_pinning` | One-click SSL pinning bypass |
| `search_classes_and_methods` | Find classes/methods by pattern |
| `read_memory` | Read process memory |
| `write_memory` | Write process memory (disabled by default) |
| `scan_memory` | Search for byte patterns in memory |
| `get_messages` | Retrieve script/hook output |
| `stop_instrumentation` | Clean up all hooks/scripts |
| `mobile_action` | Gateway to mobile-mcp UI tools |
| `frida_help` | Topic-based help system |

Use `frida_help({ topic: "advanced" })` to discover Tier 2 tools.

## Pre-built Scripts

| Script | Platforms | Description |
|--------|-----------|-------------|
| `ssl_pinning_bypass` | Android, iOS | Bypass SSL certificate pinning |
| `root_jailbreak_bypass` | Android, iOS | Bypass root/jailbreak detection |
| `class_enumeration` | Android, iOS | List loaded classes with filter |
| `method_hook` | Android, iOS | Hook method with arg/retval logging |
| `crypto_monitor` | Android, iOS | Monitor crypto API calls |
| `network_inspector` | Android, iOS | Monitor network socket operations |
| `keychain_prefs` | Android, iOS | Monitor Keychain/SharedPreferences |
| `filesystem_monitor` | Android, iOS | Monitor file I/O operations |

## mobile-mcp Integration

When [mobile-mcp](https://github.com/mobile-next/mobile-mcp) is installed, use the `mobile_action` gateway:

```
mobile_action({ action: "mobile_take_screenshot" })
mobile_action({ action: "mobile_click_on_screen_at_coordinates", params: { x: 100, y: 200 } })
mobile_action({ action: "mobile_list_elements_on_screen" })
mobile_action({ action: "mobile_launch_app", params: { appId: "com.example.app" } })
```

mobile-mcp is lazily spawned on first use. All Frida tools work without it.

## Configuration

Config file: `~/.config/frida-mobile-mcp/config.json`

```json
{
  "allowCustomScripts": false,
  "memoryWriteEnabled": false,
  "allowedDevices": [],
  "maxSessions": 4,
  "sessionTimeoutMinutes": 30,
  "mobileMcp": {
    "enabled": true,
    "command": "npx",
    "args": ["-y", "@mobilenext/mobile-mcp@latest"]
  },
  "rateLimits": {
    "scriptsPerMinute": 10,
    "memoryReadsPerMinute": 60,
    "sessionsPerMinute": 5
  }
}
```

### Environment Variables

- `FRIDA_DEVICE_ID` — Default device ID
- `FRIDA_MCP_ALLOW_CUSTOM_SCRIPTS=1` — Enable custom scripts
- `FRIDA_MCP_MEMORY_WRITE=1` — Enable memory writes
- `FRIDA_MCP_DEBUG=1` — Debug logging

## Security

- Custom script execution **disabled by default**
- Memory writes **disabled by default**
- Device allowlist support
- Append-only audit log (`~/.config/frida-mobile-mcp/audit.jsonl`)
- Rate limiting per tool category
- Session timeout with auto-cleanup

## License

MIT
