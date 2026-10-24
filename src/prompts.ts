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
With REA: pull the installed APK with \`get_app_info({ target: "${package_name}", pull_to: "<host dir>" })\`
(or REA \`pull_adb_package\`), run REA \`inspect_android_package\` on it and
\`inspect_android_method\` on candidate methods. Keep the APK sha256 from \`get_app_info\`
so static and runtime evidence refer to the same build.

## Phase 1: DISCOVER
0. Call \`get_app_info({ target: "${package_name}" })\` first to record the artifact identity (version, every APK with its sha256)
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
- Security observations
- Analysed artifact: version and APK sha256 from \`get_app_info\`
Export the bundle with \`export_evidence_bundle({ format: "markdown", out_path: "<host path>" })\` and cite both servers' evidence IDs (frida-mobile-mcp and the static server, e.g. REA).`,
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
With REA: get the exact installed APK with \`get_app_info({ target: "${package_name}", pull_to: "<host dir>" })\` (or REA \`pull_adb_package\`), then REA \`inspect_android_package\` (manifest, components) and \`inspect_android_method\` on pinning/root-detection candidates.

## Phase 1: RECONNAISSANCE
0. \`get_app_info({ target: "${package_name}" })\` — artifact identity: version, debuggable flag, every APK with its sha256
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
- Overall risk assessment
- Analysed artifact: version and APK sha256 from \`get_app_info\`
20. Export the bundle with \`export_evidence_bundle({ format: "markdown", out_path: "<host path>" })\` and cite both servers' evidence IDs (frida-mobile-mcp and the static server, e.g. REA) in the finding ledger`,
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
0. \`get_app_info({ target: "${package_name}" })\` — artifact identity (version, every APK with its sha256); add \`pull_to: "<host dir>"\` to hand the same APK to a static tool
1. If a static-analysis MCP server is connected (REA, ReVa/Ghidra \`decompile\`, IDA MCP), locate candidate functions for "${functionality}" there first and note them as \`module+0xoffset\` (native) or \`Class.method\` (Java/ObjC). With REA: \`inspect_android_package\` on the pulled APK (or REA \`pull_adb_package\`), then \`inspect_android_method\` on each candidate; its parameter types feed \`hook_method({ evidence: { class, signature } })\`
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
- Key constants and configuration values discovered
- Analysed artifact: version and APK sha256 from \`get_app_info\`
Export the bundle with \`export_evidence_bundle({ format: "markdown", out_path: "<host path>" })\` and cite both servers' evidence IDs (frida-mobile-mcp and the static server, e.g. REA).`,
        },
      }],
    })
  );

  server.registerPrompt(
    'write_frida_script',
    {
      description: 'Author, validate and save/export a working Frida script for a concrete goal (e.g. "log the RC4 key"), using the discovery → hook → drive → verify → deliver loop.',
      argsSchema: z.object({
        package_name: z.string().describe('App bundle ID (e.g., com.example.rc4demo)'),
        goal: z.string().describe('What the script must achieve in one line (e.g., "log the RC4 key in com.example.rc4demo")'),
        platform: z.string().optional().describe('android or ios'),
      }),
    },
    async ({ package_name, goal, platform }) => ({
      messages: [{
        role: 'user' as const,
        content: {
          type: 'text' as const,
          text: `You are writing a Frida script for ${package_name}${platform ? ` on ${platform}` : ''}.

Goal: ${goal}

Work this loop with the server's tools; do not hand-write a script before you know the exact target.

## Phase 0: LEARN THE AGENT API
1. \`frida_help({ topic: "script_api" })\` — the preamble helpers (findExport, hookNative, javaPerform), \`__FRIDA_MCP__.options\`, the send() convention, and Frida 17 instance-API equivalents.
2. \`frida_help({ topic: "recipes" })\` then \`search_recipes({ query: "<keywords from the goal>" })\` — start from the closest recipe instead of a blank file.

## Phase 1: RECON — find the real target (don't assume javax.crypto)
3. \`explore_app({ target: "${package_name}" })\`, then wait ~3 s (or \`watch_loads\`) for app classes/.so to load.
4. For a crypto goal: \`discover_crypto({ target: "${package_name}" })\` — it finds custom Java (e.g. \`Rc4Client\`) and native symbols, not just the JCE. Otherwise \`search_classes_and_methods\`.
5. \`describe_class({ session_id, class_name: "<candidate>" })\` — get exact method overloads and signatures.

## Phase 2: DRAFT from a recipe
6. Adapt the closest recipe's source to the class/method/signature you found. Read every parameter from \`__FRIDA_MCP__.options\`; never splice values into code. Keep it classic JS (no import/export) unless you deliberately need an ESM bundle.
7. \`validate_script({ source })\` — catch syntax and Frida-17 removed-API errors before touching the device.

## Phase 3: RUN & VERIFY the feedback loop
8. \`execute_script({ target: "${package_name}", source, persistent: true })\` (needs allowCustomScripts), or hook directly with \`hook_method({ evidence: { class, signature } })\` for a single overload.
9. \`trigger_and_wait\` — drive the app (launch/tap) and wait for the hook to fire.
10. \`get_status\` — check hook **liveness**: \`installed\`, \`fired\`, \`class_resolved\`, \`overloads_matched\`. If it installed but never fired, you hooked the wrong method/overload — go back to describe_class. If \`class_resolved\` is false, the class loads later — \`watch_loads\` then retry.
11. If the Java path yields nothing, fall back to the native implementation: \`discover_crypto\` native symbols → \`hook_method\` with \`evidence: { module, offset }\` from a static tool, or the native-export-hook / jni-register-natives recipes.

## Phase 4: DELIVER
12. When the script reliably produces the goal output, \`save_script({ name, source, description })\` to keep it.
13. \`export_script({ name, package: "${package_name}" })\` for a standalone file that runs under \`frida -U -f ${package_name} -l file.js\`. Note the exported file relies on the frida-tools CLI to inject the Java/ObjC bridge; a classic body that needs the bridge only works under a CLI that provides it.
14. \`stop_instrumentation\` when done.

Report the final script, how you verified it fired (liveness + a sample message), and the saved/exported path.`,
        },
      }],
    })
  );

  server.registerPrompt(
    'hunt_secrets',
    {
      description: 'Autonomous key-hunting workflow — arm wide-net crypto + coverage hooks, drive the UI to the crypto path hands-free, and recover the key (from a live event or from memory structure) as a reusable pattern.',
      argsSchema: z.object({
        package_name: z.string().describe('App bundle ID (e.g., com.example.rc4demo)'),
        secret_kind: z.string().optional().describe('What you are after (e.g., "RC4 key", "AES key", "API token"). Defaults to any symmetric key.'),
        platform: z.string().optional().describe('android or ios'),
      }),
    },
    async ({ package_name, secret_kind, platform }) => ({
      messages: [{
        role: 'user' as const,
        content: {
          type: 'text' as const,
          text: `You are hunting for a ${secret_kind || 'symmetric key / secret'} in ${package_name}${platform ? ` on ${platform}` : ''}. Work this loop end-to-end; prefer evidence (a key that flowed through a real crypto call, or structurally-verified bytes in memory) over guesses.

## Phase 1: DISCOVER THE CRYPTO SURFACE
1. \`explore_app({ target: "${package_name}" })\` — launch and get a live session (note the session_id). Wait ~3 s (or \`watch_loads\`) for app classes / .so to load.
2. \`discover_crypto({ session_id })\` — find the custom crypto (e.g. a \`Rc4Client\`) and native symbols, not just the JCE.

## Phase 2: ARM THE WIDE NET (arm BEFORE driving — drive_coverage arms nothing itself)
3. \`monitor_crypto({ session_id })\` — wide-net hooks that emit a \`crypto_event\` (with key_hex / plaintext) whenever a key is set up or used.
4. \`trace_coverage({ session_id, scope: "${package_name.split('.').slice(0, -1).join('.') || package_name}.*" })\` — a reachability map over the app package so you can watch the cold set shrink. Keep its \`coverage_id\`.

## Phase 3: DRIVE TO THE CRYPTO PATH (hands-free)
5. \`drive_coverage({ session_id, coverage_id, stop_on: "crypto_event" })\` — it taps through on-screen elements breadth-first, correlating each tap with hook output, and stops the instant a \`crypto_event\` (or any key-bearing message) fires or coverage stalls.
6. Read the result: \`captured\` is the message that stopped it; \`newly_covered\` is the code the drive exercised. If \`stopped_reason\` is \`coverage_stalled\` / \`no_more_elements\`, the key screen was not reached — navigate manually with \`trigger_and_wait\` and re-run, or widen the coverage scope.

## Phase 4: RECOVER THE KEY
7. If a crypto_event fired: \`get_messages({ session_id, since: <loop start seq> })\` — read the full captured key_hex / plaintext and the arguments around it.
8. If NOTHING fired (the key never flowed through a hooked call): \`find_secrets_in_memory({ session_id, scope: "heap" })\` — recover the key by STRUCTURE (an RC4 S-box = a 256-byte permutation of 0..255; an AES key schedule; a high-entropy 16/24/32-byte buffer; PEM/DER; JWT), independent of reaching the code.
9. CONFIRM the candidate: \`read_memory({ session_id, address, size })\` to pull the full bytes, and cross-check against a crypto_event if you have one.

## Phase 5: DELIVER A REUSABLE PATTERN
10. \`generate_memory_pattern({ session_id, address })\` — emit a reusable, friTap-ready byte pattern for the located key so the find survives app restarts and feeds offline tooling.
11. \`stop_instrumentation({ session_id })\` when done.

Caveats: hardware-backed keys (Android Keystore / iOS Secure Enclave) never leave secure hardware — you will see handles and ciphertext, not raw key bytes; report that rather than chasing a key that is not in process memory. Cite the \`evidence_id\` of each tool result in your findings.`,
        },
      }],
    })
  );
}
