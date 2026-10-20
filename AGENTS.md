# AGENTS.md

Notes for coding agents working in this repository (`frida-mobile-mcp`, a TypeScript MCP server for Frida 17 on Android/iOS). Read [README.md](README.md) for the user-facing picture; this file is about changing the code.

## Commands

```bash
npm ci --foreground-scripts       # deps + frida-node native prebuild (install scripts must run)
npm run build                     # build:bridges (rollup -> dist/bridges/{java,objc}.js) then tsc -> dist/
npm run lint                      # tsc --noEmit
npm test                          # vitest run (pretest rebuilds bridges); no device needed
npx vitest run test/tools/x.test.ts
FRIDA_MCP_E2E_DEVICE=emulator-5556 [FRIDA_MCP_E2E_TARGET=com.example.rc4demo] npx vitest run test/e2e
FRIDA_E2E=1 FRIDA_DEVICE_ID=emulator-5556 npx vitest run test/fritap/capture-tls.e2e.test.ts
node dist/index.js --help         # CLI smoke test (CI runs this)
```

Node >= 20. CI (`.github/workflows/ci.yml`) runs build, lint, test, the CLI smoke test and `npm pack` content checks on Linux/macOS/Windows with Node 20/22/24.

## Frida 17 rules

- The Java/ObjC bridges are not in the GumJS runtime. Classic scripts get them injected by `src/agent/script-factory.ts` (`defaultBridgesFor(platform)`: `java` on android, `objc` on ios/macos) from the bundles in `dist/bridges/`. Never assume `Java`/`ObjC` exist in agent code without that path; the preamble installs `{ available: false }` stubs for bridges that were not injected.
- Agent sources must use the Frida 17 Module *instance* API: `Process.getModuleByName(lib).findExportByName(name)`, `Module.findGlobalExportByName(name)`, `module.enumerateExports()`, `NativePointer#readX()/writeX()`, `Process.enumerateModules()`. The removed statics (`Module.findExportByName`, `Module.findBaseAddress`, `Module.enumerateExports`, `Memory.readX`, `*Sync`) are listed in `src/agent/lint.ts` (`REMOVED_API_PATTERNS`) and tested in `test/agent/removed-apis.test.ts`; generated template code must pass that lint.
- Use the preamble helpers in generated scripts: `findExport(lib, name)`, `hookNative(lib, name, callbacks)`, `javaPerform(fn)`, `objcClassNames()`, `reportSummary()`. Template options reach the agent only as the JSON literal `__FRIDA_MCP__.options`; never splice user input into code.
- User scripts (`kind: 'user'`) run through `Script.evaluate(name, source)` to keep their line numbers; ES modules are compiled host-side by `src/agent/compiler.ts` (frida `Compiler`); sources starting with `FRIDA_COMPILE_BUNDLE_MARKER` (`📦\n`) pass through untouched.
- Android kills a spawned process that stays suspended for more than ~10 s. Resume before anything that waits on `Java.perform` (see `src/tools/explore.ts`).
- Native addresses use the shared notation from `src/agent/address.ts` (`module!symbol`, `module+0xoff`, `0x...`, bare global export); return `module+0xoff` wherever possible. Keep `docs/interop.md` in sync when changing it.
- frida-node version is pinned to `^17.24.x`; the device needs frida-server 17.x. Do not bump the major without updating README, docs/clients.md and `src/cli/doctor.ts`.

## Where things live

| Path | Purpose |
|------|---------|
| `src/index.ts` | CLI (commander): default `serve`, `doctor`, `setup`; flags -> `RuntimeConfig` overrides / env |
| `src/server.ts`, `src/lib.ts` | `createServer()` and the library API (`registerFridaTools`, `createSessionServer`, re-exports) |
| `src/tools/register-all.ts` | The single list of tools (Tier 1 / Tier 2), resources and prompts. Add new tools here. |
| `src/tools/*.ts` | Tier 1 tools; `src/tools/advanced/*.ts` Tier 2 (device, process, session, modules, intercept, native) |
| `src/tools/help.ts` | `frida_help` topics; `test/tools/help.test.ts` greps this file, update both together |
| `src/fritap/` | `capture_tls`: agent discovery/download (`agent-loader.ts`), capture state, pcap writer |
| `src/agent/` | script composition (`script-factory.ts`), preamble, bridge loader, ESM compiler, removed-API lint, address parsing |
| `src/scripts/` | The 8 prebuilt templates + `registry.ts`; shared body helpers in `template-body.ts` |
| `src/config.ts`, `src/types.ts` | Config file schema, defaults, env overrides (`FRIDA_MCP_*`) |
| `src/helpers/` | result envelope (`result-builder.ts`), errors/codes (`errors.ts`), rate limiter, logger/audit log, RPC timeouts |
| `src/transport/` | stdio and Streamable HTTP (`/mcp`, token, Host/Origin checks) |
| `src/cli/` | `doctor.ts`, `setup.ts` (client config writers) |
| `src/resources.ts`, `src/prompts.ts` | `frida://` resources and workflow prompts |
| `build/bundle-bridges.mjs` | Rollup bundling of frida-java-bridge / frida-objc-bridge into classic IIFEs |
| `docs/clients.md`, `docs/interop.md` | Client setup / HTTP mode; address contract, envelope, static-tool interop |
| `skills/mobile-dynamic-analysis/SKILL.md` | Agent skill shipped in the npm package (`files`) |
| `server.json`, `manifest.json` | MCP registry entry and MCPB manifest; keep tool lists and versions in step with the code |

## Conventions

- Every tool: `registerTool` with `title`, `description`, zod `inputSchema`, `outputSchema: TOOL_RESULT_OUTPUT_SHAPE`/`toolOutputSchema()`, `annotations`, and `response_format` via `responseFormatSchema`. Return through `buildResult(...)` + `formatToolResponse(...)`; errors through `FridaMcpError`/`wrapFridaError(...).toErrorResponse()` with a code from `src/helpers/errors.ts`.
- Respect the guardrails: check `allowCustomScripts` / `memoryWriteEnabled`, `rateLimiter.check(...)`, and `allowedDevices` in the same way the existing tools do.
- Tests are vitest, under `test/` mirroring `src/`; unit tests must not need a device (device suites skip themselves without the env vars above).
- Commits use Conventional Commits; release-please owns `CHANGELOG.md` and version bumps, so do not edit them by hand.
- Do not add user-facing tool text outside `description`/help topics; keep `README.md` tool tables and `frida_help` topics in sync when adding or renaming a tool.
