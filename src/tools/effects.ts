/**
 * Declarative side-effect table for every MCP tool, so an orchestrating agent can gate
 * calls by effect. Data only: it is injected into the tool definitions as `_meta.effects`
 * elsewhere. Mirrors the shape of REA's `src/contracts/toolEffects.ts`.
 *
 * test/tools/effects.test.ts keeps this table in sync with the registered tools and
 * consistent with each tool's MCP annotations. `idempotent` is not tabled here: the tool gate
 * derives it from each tool's `idempotentHint` annotation when it stamps `_meta.effects`.
 */
export interface ToolEffects {
  /** Loads JS/native code into the target process. */
  executesForeignCode: boolean;
  /** Changes target process state (hooks, memory writes, spawn/kill/resume). */
  mutatesTarget: boolean;
  /** Spawns a process on the device or host (incl. mobile-mcp, frida-server, adb). */
  launchesProcess: boolean;
  /** Host-side network access (downloads, remote frida-server, HTTP). */
  accessesNetwork: boolean;
  /** Writes host or device files (dumps, keylogs, saved scripts, adb push). */
  writesFilesystem: boolean;
  /** Device-level changes (frida-server start/stop/install, adb push, forward, spawn gating). */
  mutatesDevice: boolean;
  /** Result content comes from the analysed app/device and must be treated as untrusted. */
  targetDerived: boolean;
}

const NO_EFFECTS: ToolEffects = {
  executesForeignCode: false,
  mutatesTarget: false,
  launchesProcess: false,
  accessesNetwork: false,
  writesFilesystem: false,
  mutatesDevice: false,
  targetDerived: false,
};

/** Builds an entry from only the flags that are true. */
function effects(overrides: Partial<ToolEffects>): ToolEffects {
  return { ...NO_EFFECTS, ...overrides };
}

export const TOOL_EFFECTS: Record<string, ToolEffects> = {
  adb_forward: effects({ launchesProcess: true, mutatesDevice: true }),
  // clear option flushes the device log buffer
  adb_logcat: effects({ launchesProcess: true, mutatesDevice: true, targetDerived: true }),
  adb_pull: effects({ launchesProcess: true, writesFilesystem: true, targetDerived: true }),
  adb_push: effects({ launchesProcess: true, writesFilesystem: true, mutatesDevice: true }),
  // arbitrary device shell command; gated by allowAdbShell
  adb_shell: effects({ mutatesTarget: true, launchesProcess: true, writesFilesystem: true, mutatesDevice: true, targetDerived: true }),
  analyze_native_function: effects({ executesForeignCode: true, targetDerived: true }),
  // returns pid/name only; loads nothing
  attach_process: effects({}),
  bypass_ssl_pinning: effects({ executesForeignCode: true, mutatesTarget: true }),
  // spawns the app and appends keylog/pcap files when paths are given
  capture_tls: effects({ executesForeignCode: true, mutatesTarget: true, launchesProcess: true, writesFilesystem: true, targetDerived: true }),
  child_gating: effects({ mutatesTarget: true }),
  describe_class: effects({ executesForeignCode: true, targetDerived: true }),
  detach_session: effects({ mutatesTarget: true }),
  detect_app_technologies: effects({ executesForeignCode: true, targetDerived: true }),
  discover_crypto: effects({ executesForeignCode: true, targetDerived: true }),
  // arms nothing itself; taps the UI through mobile-mcp
  drive_coverage: effects({ mutatesTarget: true, launchesProcess: true, accessesNetwork: true, targetDerived: true }),
  dump_module_memory: effects({ executesForeignCode: true, writesFilesystem: true, targetDerived: true }),
  enumerate_exports: effects({ executesForeignCode: true, targetDerived: true }),
  enumerate_imports: effects({ executesForeignCode: true, targetDerived: true }),
  enumerate_modules: effects({ executesForeignCode: true, targetDerived: true }),
  enumerate_symbols: effects({ executesForeignCode: true, targetDerived: true }),
  // pins an already loaded script in the target
  eternalize_script: effects({ mutatesTarget: true }),
  execute_script: effects({ executesForeignCode: true, mutatesTarget: true, targetDerived: true }),
  // spawns the app suspended, then instruments it
  explore_app: effects({ executesForeignCode: true, mutatesTarget: true, launchesProcess: true, targetDerived: true }),
  // writes the bundle to out_path when given; otherwise returns it inline
  export_evidence_bundle: effects({ writesFilesystem: true }),
  export_script: effects({ writesFilesystem: true }),
  find_secrets_in_memory: effects({ executesForeignCode: true, targetDerived: true }),
  frida_help: effects({}),
  // adb push + chmod of a local binary; no download
  frida_server_install: effects({ launchesProcess: true, writesFilesystem: true, mutatesDevice: true }),
  frida_server_start: effects({ launchesProcess: true, mutatesDevice: true }),
  // adb queries only; returns the asset URL without fetching it
  frida_server_status: effects({ launchesProcess: true, targetDerived: true }),
  frida_server_stop: effects({ launchesProcess: true, mutatesDevice: true }),
  generate_memory_pattern: effects({ executesForeignCode: true, targetDerived: true }),
  // fixed adb queries (pm path, dumpsys, sha256sum, stat); pull_to writes the APKs to the host
  get_app_info: effects({ launchesProcess: true, writesFilesystem: true, targetDerived: true }),
  get_device_info: effects({ targetDerived: true }),
  // reads a persisted record from the host-side evidence store; the record replays app output
  get_evidence: effects({ targetDerived: true }),
  get_frontmost_application: effects({ targetDerived: true }),
  // server-side buffer read; carries hook/script output from the app
  get_messages: effects({ targetDerived: true }),
  get_status: effects({}),
  hook_function: effects({ executesForeignCode: true, mutatesTarget: true }),
  hook_method: effects({ executesForeignCode: true, mutatesTarget: true, targetDerived: true }),
  // runs arbitrary native code in the target
  inject_library: effects({ executesForeignCode: true, mutatesTarget: true }),
  kill_process: effects({ mutatesTarget: true }),
  list_applications: effects({ targetDerived: true }),
  list_devices: effects({}),
  list_processes: effects({ targetDerived: true }),
  list_saved_scripts: effects({}),
  list_sessions: effects({}),
  list_threads: effects({ executesForeignCode: true, targetDerived: true }),
  // mobile-mcp is spawned via npx on first use (may download); UI actions change app state
  mobile_action: effects({ mutatesTarget: true, launchesProcess: true, accessesNetwork: true, targetDerived: true }),
  monitor_crypto: effects({ executesForeignCode: true, mutatesTarget: true, targetDerived: true }),
  read_memory: effects({ executesForeignCode: true, targetDerived: true }),
  resolve_address: effects({ executesForeignCode: true, targetDerived: true }),
  resume_process: effects({ mutatesTarget: true }),
  run_prebuilt_script: effects({ executesForeignCode: true, mutatesTarget: true, targetDerived: true }),
  run_saved_script: effects({ executesForeignCode: true, mutatesTarget: true, targetDerived: true }),
  save_script: effects({ writesFilesystem: true }),
  scan_memory: effects({ executesForeignCode: true, targetDerived: true }),
  search_classes_and_methods: effects({ executesForeignCode: true, targetDerived: true }),
  search_recipes: effects({}),
  select_device: effects({}),
  spawn_gating: effects({ mutatesDevice: true }),
  // spawns suspended; returns pid only
  spawn_process: effects({ mutatesTarget: true, launchesProcess: true }),
  stop_instrumentation: effects({ mutatesTarget: true }),
  trace_coverage: effects({ executesForeignCode: true, mutatesTarget: true, targetDerived: true }),
  trace_method: effects({ executesForeignCode: true, mutatesTarget: true, targetDerived: true }),
  // waits on an existing session; the optional action goes through mobile-mcp
  trigger_and_wait: effects({ mutatesTarget: true, launchesProcess: true, accessesNetwork: true, targetDerived: true }),
  unhook_function: effects({ mutatesTarget: true }),
  unload_script: effects({ mutatesTarget: true }),
  validate_script: effects({}),
  watch_loads: effects({ executesForeignCode: true, mutatesTarget: true, targetDerived: true }),
  // gated by memoryWriteEnabled
  write_memory: effects({ executesForeignCode: true, mutatesTarget: true }),
};

/** Effects for a registered tool name, or undefined when the tool is unknown. */
export function effectsFor(name: string): ToolEffects | undefined {
  return Object.prototype.hasOwnProperty.call(TOOL_EFFECTS, name) ? TOOL_EFFECTS[name] : undefined;
}
