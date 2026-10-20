import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/server';

export function registerPrompts(server: McpServer): void {
  server.registerPrompt(
    'explore_app',
    {
      description: 'Systematic mobile app exploration workflow — discover, map, interact, instrument, and document.',
      argsSchema: z.object({
        package_name: z.string().describe('App bundle ID (e.g., com.example.app)'),
        platform: z.string().optional().describe('android or ios'),
      }),
    },
    async ({ package_name, platform }) => ({
      messages: [{
        role: 'user' as const,
        content: {
          type: 'text' as const,
          text: `You are a mobile app exploration agent with access to Frida instrumentation and mobile UI automation tools.

Target: ${package_name}${platform ? ` on ${platform}` : ''}

Follow this systematic process:

## Phase 0: STATIC CONTEXT (if a static-analysis MCP server is connected)
If REA, ReVa/Ghidra or an IDA MCP server is available, ask it first for the package
structure, exported components and candidate functions (e.g. \`inspect_android_package\`,
\`decompile\`). Note interesting addresses in \`module+0xoffset\` form; frida-mobile-mcp
accepts that notation directly in \`hook_method\` / \`hook_function\`.

## Phase 1: DISCOVER
1. Call \`get_status()\` to check connected devices
2. Call \`explore_app({ target: "${package_name}" })\` to launch the app and gather initial context (classes, modules, libraries)
3. Call \`detect_app_technologies({ target: "${package_name}" })\` to learn the TLS/crypto/network stacks in use
4. Review the loaded classes and modules to understand the app structure

## Phase 2: MAP
4. Call \`mobile_action({ action: "mobile_take_screenshot" })\` to see the current screen
5. Call \`mobile_action({ action: "mobile_list_elements_on_screen" })\` to get the UI hierarchy
6. Identify navigation elements (tabs, menus, buttons) and document the screen

## Phase 3: INTERACT
7. Navigate through each major screen/tab using \`mobile_action({ action: "mobile_click_on_screen_at_coordinates", params: { x, y } })\`
8. For each screen: take screenshot, list elements, note interesting functionality
9. Document the screen map (which screens exist and how to reach them)

## Phase 4: INSTRUMENT
10. Call \`search_classes_and_methods({ target: "${package_name}", pattern: "${package_name.split('.').pop()}", include_methods: true })\`
11. Hook interesting methods: \`hook_method({ target: "${package_name}", method: "..." })\` (Java, ObjC, or native \`libfoo.so+0x1234\` / \`libfoo.so!symbol\`)
12. Trigger the hooked functionality via UI and check \`get_messages()\`
13. For TLS traffic use \`capture_tls({ target: "${package_name}", keylog_path: "./keys.log", full_capture: true })\` (friTap) to get session keys and plaintext
14. Backtraces and native addresses come back as \`module+0xoffset\`; hand them back to the static tool (Ghidra/IDA) to read the surrounding code
15. Finish with \`stop_instrumentation()\` when done

## Phase 5: DOCUMENT
Produce a structured summary:
- Screen map with navigation paths
- Key classes and their roles
- Network endpoints discovered
- Data storage patterns
- Security observations`,
        },
      }],
    })
  );

  server.registerPrompt(
    'security_audit',
    {
      description: 'Comprehensive mobile app security assessment — transport, storage, crypto, detection bypass, and reporting.',
      argsSchema: z.object({
        package_name: z.string().describe('App bundle ID'),
        platform: z.string().optional().describe('android or ios'),
        focus_areas: z.string().optional().describe('Comma-separated: transport,storage,crypto,root_detection'),
      }),
    },
    async ({ package_name, platform, focus_areas }) => ({
      messages: [{
        role: 'user' as const,
        content: {
          type: 'text' as const,
          text: `You are a mobile application security auditor with Frida instrumentation and UI automation tools.

Target: ${package_name}${platform ? ` on ${platform}` : ''}
Focus: ${focus_areas || 'all areas'}

Execute these assessment phases:

## Phase 0: STATIC BASELINE (optional)
If a static-analysis MCP server (REA \`inspect_android_package\`, ReVa/Ghidra \`decompile\`, IDA MCP) is connected, collect manifest permissions, exported components, pinning/root-detection code locations and native library candidates first. Keep addresses as \`module+0xoffset\` so they can be hooked directly.

## Phase 1: RECONNAISSANCE
1. \`explore_app({ target: "${package_name}" })\` — launch and enumerate
2. \`detect_app_technologies({ target: "${package_name}" })\` — TLS stack, crypto and network libraries
3. \`search_classes_and_methods({ target: "${package_name}", pattern: "crypto|security|ssl|trust|keychain|shared.*pref" })\`
4. Note detected TLS libraries and security-relevant classes

## Phase 2: TRANSPORT SECURITY
5. \`capture_tls({ target: "${package_name}", keylog_path: "./keys.log", full_capture: true })\` — friTap: TLS keys (Wireshark tls.keylog_file) and decrypted records as fritap_datalog messages
6. \`bypass_ssl_pinning({ target: "${package_name}" })\` — bypass certificate pinning if a proxy is needed
7. \`run_prebuilt_script({ script_name: "network_inspector", target: "${package_name}" })\` — monitor network
8. Navigate the app to trigger network requests
9. \`get_messages()\` — analyze: Are all connections HTTPS? Any plaintext? Tokens in headers?

## Phase 3: DATA STORAGE
10. \`run_prebuilt_script({ script_name: "keychain_prefs", target: "${package_name}" })\`
11. \`run_prebuilt_script({ script_name: "filesystem_monitor", target: "${package_name}" })\`
12. Interact with the app (login, view data) and check \`get_messages()\`
13. Look for: plaintext credentials, insecure storage, sensitive data in logs

## Phase 4: CRYPTOGRAPHY
14. \`run_prebuilt_script({ script_name: "crypto_monitor", target: "${package_name}" })\`
15. Trigger crypto operations and analyze: weak algorithms? hardcoded keys? predictable IVs?
16. For native crypto, hook the function from the static tool's address: \`hook_method({ target: "${package_name}", method: "libcrypto.so+0x1234" })\` and feed backtraces (\`module+0xoffset\`) back to Ghidra/IDA

## Phase 5: ROOT/JAILBREAK DETECTION
17. \`run_prebuilt_script({ script_name: "root_jailbreak_bypass", target: "${package_name}" })\`
18. Assess: Does the app detect root/jailbreak? How robust? Trivially bypassed?

## Phase 6: REPORT
19. \`stop_instrumentation()\` to release all hooks
Produce a security report with:
- Finding severity (Critical/High/Medium/Low/Info)
- Reproduction steps using exact tool calls; cite the \`evidence_id\` of each tool result
- Remediation recommendations
- Overall risk assessment`,
        },
      }],
    })
  );

  server.registerPrompt(
    'trace_functionality',
    {
      description: 'Reverse engineering workflow — trace how a specific feature is implemented in a mobile app.',
      argsSchema: z.object({
        package_name: z.string().describe('App bundle ID'),
        functionality: z.string().describe('Feature to trace (e.g., "login", "payment", "encryption")'),
      }),
    },
    async ({ package_name, functionality }) => ({
      messages: [{
        role: 'user' as const,
        content: {
          type: 'text' as const,
          text: `You are a reverse engineering agent. Trace how "${functionality}" is implemented in ${package_name}.

## Phase 1: STATIC DISCOVERY
1. If a static-analysis MCP server is connected (REA, ReVa/Ghidra \`decompile\`, IDA MCP), locate candidate functions for "${functionality}" there first and note them as \`module+0xoffset\` (native) or \`Class.method\` (Java/ObjC)
2. \`explore_app({ target: "${package_name}" })\` — launch and get context
3. \`detect_app_technologies({ target: "${package_name}" })\` — which libraries are involved
4. \`search_classes_and_methods({ target: "${package_name}", pattern: "${functionality}", include_methods: true })\`
5. Build a hypothesis about which classes/methods implement "${functionality}"

## Phase 2: DYNAMIC TRACING
6. Hook the most likely entry-point methods:
   \`hook_method({ target: "${package_name}", method: "ClassName.methodName" })\` or, for a native address from the static tool, \`hook_method({ target: "${package_name}", method: "libfoo.so+0x1234", log_backtrace: true })\`
7. Take a screenshot and identify the UI element that triggers "${functionality}":
   \`mobile_action({ action: "mobile_take_screenshot" })\`
8. Trigger it via UI: \`mobile_action({ action: "mobile_click_on_screen_at_coordinates", params: { x, y } })\`
9. Check what was captured: \`get_messages()\`

## Phase 3: DEEP DIVE
10. For each method that was invoked:
   a. Examine arguments (what data flows in?)
   b. Examine return values (what comes out?)
   c. Hook the methods it calls (go one level deeper)
   d. Backtrace frames are reported as \`module+0xoffset\`; decompile those offsets in Ghidra/IDA to close the static -> dynamic -> static loop
11. Use \`trace_method\` for broader tracing:
   \`trace_method({ target: "${package_name}", method: "com.example.${functionality}.*", duration_seconds: 15 })\`

## Phase 4: DATA FLOW
12. If "${functionality}" involves TLS: \`capture_tls({ target: "${package_name}", full_capture: true, keylog_path: "./keys.log" })\` (friTap) for decrypted records and session keys
13. If it involves network: \`run_prebuilt_script({ script_name: "network_inspector" })\`
14. If it involves crypto: \`run_prebuilt_script({ script_name: "crypto_monitor" })\`
15. If it involves storage: \`run_prebuilt_script({ script_name: "keychain_prefs" })\`
16. Correlate: UI action → method chain → network/storage/crypto
17. \`stop_instrumentation()\` when finished

## Phase 5: DOCUMENTATION
Produce:
- Call graph (entry point → intermediate → leaf operations)
- Data transformations at each step
- External dependencies (APIs, libraries)
- Key constants and configuration values discovered`,
        },
      }],
    })
  );
}
