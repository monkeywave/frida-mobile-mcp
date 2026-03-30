import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';

const HELP_TOPICS: Record<string, string> = {
  overview: `# frida-mobile-mcp: Mobile Frida MCP Server

## What is this?
A server that lets AI agents dynamically instrument and explore mobile apps on Android and iOS using Frida.

## Quick Start
1. \`get_status\` — See connected devices and current state
2. \`explore_app\` — Launch an app and get initial context (screenshot, classes, libraries)
3. \`hook_method\` — Hook a specific method to intercept calls
4. \`trace_method\` — Trace function calls for a duration
5. \`bypass_ssl_pinning\` — One-click SSL pinning bypass

## Tool Categories
- **Exploration**: explore_app, search_classes_and_methods
- **Instrumentation**: hook_method, trace_method, execute_script
- **Security**: bypass_ssl_pinning, run_prebuilt_script
- **Memory**: read_memory, write_memory, scan_memory
- **Mobile UI**: mobile_action (tap, swipe, screenshot, elements via mobile-mcp)
- **Management**: get_status, get_messages, stop_instrumentation

## Tip
Most tools auto-manage device selection and sessions. Just provide the app bundle ID or name.`,

  hooking: `# Method Hooking Guide

## hook_method
The simplest way to intercept method calls. Auto-manages device, session, and script lifecycle.

### Method Pattern Syntax
- **Java (Android)**: \`com.example.MyClass.myMethod\`
- **Objective-C (iOS)**: \`-[NSURLSession dataTaskWithRequest:]\` or \`+[MyClass staticMethod]\`
- **Native**: \`libssl.so!SSL_read\` or a hex address like \`0x12345\`

### Examples
- Hook a login method: \`hook_method({ target: "com.example.app", method: "com.example.auth.LoginManager.login" })\`
- Hook iOS networking: \`hook_method({ target: "MyApp", method: "-[NSURLSession dataTaskWithRequest:]" })\`
- Hook native SSL: \`hook_method({ target: "com.example.app", method: "libssl.so!SSL_write" })\`

### Options
- \`log_args: true\` — Log method arguments (default: true)
- \`log_retval: true\` — Log return value (default: true)
- \`log_backtrace: false\` — Log call stack (default: false)

### Retrieving Results
After hooking, use \`get_messages\` to retrieve intercepted calls with their arguments and return values.`,

  tracing: `# Function Tracing Guide

## trace_method
Simplified frida-trace equivalent. Traces function calls matching a pattern for a specified duration.

### Usage
\`trace_method({ target: "com.example.app", method: "com.example.network.*", duration_seconds: 10 })\`

### Patterns
- Glob patterns: \`com.example.network.*\` matches all methods in the class
- Multiple methods: provide an array of patterns
- Native functions: \`libssl.so!SSL_*\` traces all SSL functions

### Output
Returns all captured invocations with timestamps, arguments, return values, and optional backtraces.`,

  memory: `# Memory Operations Guide

## read_memory
Read raw bytes from a target process memory.
- Requires an active session (use explore_app or hook_method first)
- Address as hex string: \`"0x7fff12345678"\`
- Max read size: 4MB per call

## write_memory
Write bytes to process memory. **Disabled by default** for safety.
Enable via config: \`memoryWriteEnabled: true\`

## scan_memory
Search for byte patterns in memory.
Pattern format: \`"48 89 5c 24 ?? 57"\` (Frida Memory.scan format, ?? = wildcard)
Optional: specify a module to limit scan scope.`,

  scripts: `# Pre-built Script Library

## Available Scripts (use run_prebuilt_script)

### Security Bypass
- \`ssl_pinning_bypass\` — Bypass SSL certificate pinning (Android: TrustManager, OkHttp, Conscrypt; iOS: SecTrust, ATS, BoringSSL)
- \`root_jailbreak_bypass\` — Bypass root/jailbreak detection

### Enumeration
- \`class_enumeration\` — List all loaded Java/ObjC classes with regex filter

### Monitoring
- \`method_hook\` — Generic method hook with argument and return value logging
- \`crypto_monitor\` — Monitor crypto API calls (javax.crypto, CommonCrypto, OpenSSL)
- \`network_inspector\` — Monitor network socket operations
- \`keychain_prefs\` — Monitor iOS Keychain / Android SharedPreferences access
- \`filesystem_monitor\` — Monitor file system I/O operations

## Usage
\`run_prebuilt_script({ script_name: "ssl_pinning_bypass", target: "com.example.app" })\`
\`run_prebuilt_script()\` — Lists all available scripts when called without arguments.`,

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

### Prerequisites
Requires mobile-mcp to be installed: \`npm install -g @mobilenext/mobile-mcp\`
Mobile-mcp is spawned automatically on first use.

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
trace_method({ target: "com.example.app", method: "com.example.payment.*", duration_seconds: 15 })
# Trigger the payment flow in the app
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
- \`spawn_process\` — Spawn a process in suspended state for early instrumentation
- \`attach_process\` — Attach to an already running process
- \`resume_process\` — Resume a suspended process
- \`kill_process\` — Kill a process on the device
- \`detach_session\` — Detach from a specific Frida session
- \`list_sessions\` — List all active Frida sessions

## Module Inspection
- \`enumerate_modules\` — List loaded shared libraries/modules
- \`enumerate_exports\` — List exports (functions/variables) of a specific module

## Low-level Hooking
- \`hook_function\` — Install a hook with custom onEnter/onLeave JavaScript handlers
- \`unhook_function\` — Remove a specific hook by ID`,
};

export function registerHelpTool(server: McpServer): void {
  server.tool(
    'frida_help',
    'Get help on how to use frida-mobile-mcp tools. Use this to learn about available capabilities, method hooking patterns, script templates, and example workflows. Topics: overview, hooking, tracing, memory, scripts, mobile, examples, advanced.',
    {
      topic: z.string()
        .optional()
        .describe('Help topic: overview, hooking, tracing, memory, scripts, mobile, examples, advanced. Default: overview'),
    },
    async ({ topic }) => {
      const selectedTopic = topic || 'overview';
      const content = HELP_TOPICS[selectedTopic];

      if (!content) {
        const available = Object.keys(HELP_TOPICS).join(', ');
        return formatToolResponse(
          buildResult(
            { message: `Unknown topic "${selectedTopic}". Available topics: ${available}` },
            [{ tool: 'frida_help', args: { topic: 'overview' }, reason: 'Start with the overview' }]
          )
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
        )
      );
    }
  );
}
