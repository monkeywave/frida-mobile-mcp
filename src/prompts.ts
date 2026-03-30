import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

export function registerPrompts(server: McpServer): void {
  server.prompt(
    'explore_app',
    'Systematic mobile app exploration workflow — discover, map, interact, instrument, and document.',
    { package_name: z.string().describe('App bundle ID (e.g., com.example.app)'), platform: z.string().optional().describe('android or ios') },
    async ({ package_name, platform }) => ({
      messages: [{
        role: 'user' as const,
        content: {
          type: 'text' as const,
          text: `You are a mobile app exploration agent with access to Frida instrumentation and mobile UI automation tools.

Target: ${package_name}${platform ? ` on ${platform}` : ''}

Follow this systematic process:

## Phase 1: DISCOVER
1. Call \`get_status()\` to check connected devices
2. Call \`explore_app({ target: "${package_name}" })\` to launch the app and gather initial context (classes, modules, libraries)
3. Review the loaded classes and modules to understand the app structure

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
11. Hook interesting methods: \`hook_method({ target: "${package_name}", method: "..." })\`
12. Trigger the hooked functionality via UI and check \`get_messages()\`

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

  server.prompt(
    'security_audit',
    'Comprehensive mobile app security assessment — transport, storage, crypto, detection bypass, and reporting.',
    {
      package_name: z.string().describe('App bundle ID'),
      platform: z.string().optional().describe('android or ios'),
      focus_areas: z.string().optional().describe('Comma-separated: transport,storage,crypto,root_detection'),
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

## Phase 1: RECONNAISSANCE
1. \`explore_app({ target: "${package_name}" })\` — launch and enumerate
2. \`search_classes_and_methods({ target: "${package_name}", pattern: "crypto|security|ssl|trust|keychain|shared.*pref" })\`
3. Note detected TLS libraries and security-relevant classes

## Phase 2: TRANSPORT SECURITY
4. \`bypass_ssl_pinning({ target: "${package_name}" })\` — bypass certificate pinning
5. \`run_prebuilt_script({ script_name: "network_inspector", target: "${package_name}" })\` — monitor network
6. Navigate the app to trigger network requests
7. \`get_messages()\` — analyze: Are all connections HTTPS? Any plaintext? Tokens in headers?

## Phase 3: DATA STORAGE
8. \`run_prebuilt_script({ script_name: "keychain_prefs", target: "${package_name}" })\`
9. \`run_prebuilt_script({ script_name: "filesystem_monitor", target: "${package_name}" })\`
10. Interact with the app (login, view data) and check \`get_messages()\`
11. Look for: plaintext credentials, insecure storage, sensitive data in logs

## Phase 4: CRYPTOGRAPHY
12. \`run_prebuilt_script({ script_name: "crypto_monitor", target: "${package_name}" })\`
13. Trigger crypto operations and analyze: weak algorithms? hardcoded keys? predictable IVs?

## Phase 5: ROOT/JAILBREAK DETECTION
14. \`run_prebuilt_script({ script_name: "root_jailbreak_bypass", target: "${package_name}" })\`
15. Assess: Does the app detect root/jailbreak? How robust? Trivially bypassed?

## Phase 6: REPORT
Produce a security report with:
- Finding severity (Critical/High/Medium/Low/Info)
- Reproduction steps using exact tool calls
- Remediation recommendations
- Overall risk assessment`,
        },
      }],
    })
  );

  server.prompt(
    'trace_functionality',
    'Reverse engineering workflow — trace how a specific feature is implemented in a mobile app.',
    {
      package_name: z.string().describe('App bundle ID'),
      functionality: z.string().describe('Feature to trace (e.g., "login", "payment", "encryption")'),
    },
    async ({ package_name, functionality }) => ({
      messages: [{
        role: 'user' as const,
        content: {
          type: 'text' as const,
          text: `You are a reverse engineering agent. Trace how "${functionality}" is implemented in ${package_name}.

## Phase 1: STATIC DISCOVERY
1. \`explore_app({ target: "${package_name}" })\` — launch and get context
2. \`search_classes_and_methods({ target: "${package_name}", pattern: "${functionality}", include_methods: true })\`
3. Build a hypothesis about which classes/methods implement "${functionality}"

## Phase 2: DYNAMIC TRACING
4. Hook the most likely entry-point methods:
   \`hook_method({ target: "${package_name}", method: "ClassName.methodName" })\`
5. Take a screenshot and identify the UI element that triggers "${functionality}":
   \`mobile_action({ action: "mobile_take_screenshot" })\`
6. Trigger it via UI: \`mobile_action({ action: "mobile_click_on_screen_at_coordinates", params: { x, y } })\`
7. Check what was captured: \`get_messages()\`

## Phase 3: DEEP DIVE
8. For each method that was invoked:
   a. Examine arguments (what data flows in?)
   b. Examine return values (what comes out?)
   c. Hook the methods it calls (go one level deeper)
9. Use \`trace_method\` for broader tracing:
   \`trace_method({ target: "${package_name}", method: "com.example.${functionality}.*", duration_seconds: 15 })\`

## Phase 4: DATA FLOW
10. If "${functionality}" involves network: \`run_prebuilt_script({ script_name: "network_inspector" })\`
11. If it involves crypto: \`run_prebuilt_script({ script_name: "crypto_monitor" })\`
12. If it involves storage: \`run_prebuilt_script({ script_name: "keychain_prefs" })\`
13. Correlate: UI action → method chain → network/storage/crypto

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
