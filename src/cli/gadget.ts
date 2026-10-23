/**
 * `frida-mobile-mcp gadget` - generate a frida-gadget `config.json` and print the
 * repackaging/injection guidance for embedding the gadget in an APK/IPA.
 *
 * Why a CLI command and not a session tool: frida-gadget is a library embedded by
 * REPACKAGING the app, not something the running server attaches at runtime. It is the
 * honest answer to native detection that runs in `.init_array` / `JNI_OnLoad` (before any
 * attach-time script can load) and it removes the frida-server `:27042` port as a fingerprint.
 *
 * This command only produces the config file and the step-by-step guidance; it never touches
 * a device. The pure builders (`buildGadgetConfig` / `renderGadgetConfig` / `gadgetGuidance`)
 * are unit-tested without a filesystem.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

export const GADGET_INTERACTIONS = ['listen', 'script'] as const;
export type GadgetInteraction = (typeof GADGET_INTERACTIONS)[number];

export const GADGET_PLATFORMS = ['android', 'ios'] as const;
export type GadgetPlatform = (typeof GADGET_PLATFORMS)[number];

export interface GadgetOptions {
  interaction: GadgetInteraction;
  platform: GadgetPlatform;
  /** listen: bind address (default 127.0.0.1). */
  address?: string;
  /** listen: TCP port (default 27042). */
  port?: number;
  /** listen: what to do if the port is taken (default 'fail'). */
  onPortConflict?: 'fail' | 'pick-next';
  /** listen: whether the gadget waits for a client before the app runs (default 'wait'). */
  onLoad?: 'resume' | 'wait';
  /** script: on-device path to the agent script the gadget runs (required for 'script'). */
  scriptPath?: string;
  /** script: reload the script when the file changes (default 'reload'). */
  onChange?: 'ignore' | 'reload';
  /** optional GumJS runtime override. */
  runtime?: 'qjs' | 'v8';
  /** output path for the generated config (default resolved per platform). */
  out?: string;
  /** print the config instead of writing it. */
  print?: boolean;
}

export interface GadgetIo {
  writeFile(p: string, text: string): void;
  mkdirp(p: string): void;
  log(line: string): void;
}

type JsonObject = Record<string, unknown>;

const DEFAULT_ADDRESS = '127.0.0.1';
const DEFAULT_PORT = 27042;

const ON_PORT_CONFLICT = ['fail', 'pick-next'] as const;
const ON_LOAD = ['resume', 'wait'] as const;
const ON_CHANGE = ['ignore', 'reload'] as const;
const RUNTIMES = ['qjs', 'v8'] as const;

/**
 * Default config basename per platform. The gadget loads the config file sitting next to its
 * own library with the library's name and a `.config` suffix; shipping it as `.config.so` on
 * Android keeps it inside `lib/<abi>/` where the packaging tools expect a `.so`.
 */
export function defaultConfigName(platform: GadgetPlatform): string {
  return platform === 'android' ? 'libgadget.config.so' : 'Frida.config';
}

// ---------------------------------------------------------------------------
// Pure config builder
// ---------------------------------------------------------------------------

export function buildGadgetConfig(opts: GadgetOptions): JsonObject {
  const config: JsonObject = { interaction: interactionBlock(opts) };
  if (opts.runtime) config.runtime = opts.runtime;
  return config;
}

function interactionBlock(opts: GadgetOptions): JsonObject {
  return opts.interaction === 'script' ? scriptInteraction(opts) : listenInteraction(opts);
}

function listenInteraction(opts: GadgetOptions): JsonObject {
  return {
    type: 'listen',
    address: opts.address ?? DEFAULT_ADDRESS,
    port: opts.port ?? DEFAULT_PORT,
    on_port_conflict: opts.onPortConflict ?? 'fail',
    on_load: opts.onLoad ?? 'wait',
  };
}

function scriptInteraction(opts: GadgetOptions): JsonObject {
  if (!opts.scriptPath || opts.scriptPath.trim() === '') {
    throw new Error("interaction 'script' requires a script path (--script <on-device path>)");
  }
  return { type: 'script', path: opts.scriptPath, on_change: opts.onChange ?? 'reload' };
}

export function renderGadgetConfig(opts: GadgetOptions): string {
  return JSON.stringify(buildGadgetConfig(opts), null, 2) + '\n';
}

// ---------------------------------------------------------------------------
// Repackaging / injection guidance
// ---------------------------------------------------------------------------

export function gadgetGuidance(opts: GadgetOptions, configName: string): string {
  return opts.platform === 'android'
    ? androidGuidance(opts, configName)
    : iosGuidance(opts, configName);
}

function androidGuidance(opts: GadgetOptions, configName: string): string {
  const libName = configName.replace(/\.config\.so$/, '.so');
  return [
    '# Android: embed frida-gadget by repackaging the APK',
    '',
    '1. Download the gadget for the target ABI from',
    '   https://github.com/frida/frida/releases (file: frida-gadget-<version>-android-<abi>.so.xz)',
    '   and decompress it.',
    '2. Decode the APK:   apktool d target.apk -o target_dec',
    `3. Copy the gadget into the native lib dir as "${libName}":`,
    `     cp frida-gadget-*-android-arm64.so target_dec/lib/arm64-v8a/${libName}`,
    `4. Copy this config next to it, named "${configName}":`,
    `     cp ${configName} target_dec/lib/arm64-v8a/${configName}`,
    '5. Make the app load the gadget early. Either add',
    `     System.loadLibrary("${libName.replace(/^lib/, '').replace(/\.so$/, '')}")`,
    '   to the first-run Application/Activity smali, or repackage so an existing native',
    '   library has a NEEDED dependency on it (e.g. with LIEF/patchelf).',
    '6. Rebuild and sign:',
    '     apktool b target_dec -o target_gadget.apk',
    '     apksigner sign --ks my.keystore target_gadget.apk',
    '7. Install:   adb install -r target_gadget.apk',
    '',
    interactionNote(opts),
  ].join('\n');
}

function iosGuidance(opts: GadgetOptions, configName: string): string {
  return [
    '# iOS: embed frida-gadget into the app bundle',
    '',
    '1. Download FridaGadget.dylib for iOS from',
    '   https://github.com/frida/frida/releases (file: frida-gadget-<version>-ios-universal.dylib.xz)',
    '   and decompress it.',
    '2. Copy it (and this config) into the .app bundle:',
    '     cp FridaGadget.dylib Payload/Target.app/Frameworks/',
    `     cp ${configName} Payload/Target.app/Frameworks/${configName}`,
    '3. Add a load command to the main binary so the dylib loads at launch:',
    '     install_name_tool / optool install -c load -p "@executable_path/Frameworks/FridaGadget.dylib" \\',
    '       Payload/Target.app/Target',
    '   (or add it as an embedded framework in the Xcode project for a re-signed build).',
    '4. Re-sign and repackage:',
    '     codesign -f -s "<signing identity>" Payload/Target.app/Frameworks/FridaGadget.dylib',
    '     codesign -f -s "<signing identity>" Payload/Target.app',
    '     zip -qr Target_gadget.ipa Payload',
    '5. Install with your usual sideloading flow (ios-deploy, AltStore, Sideloadly, ...).',
    '',
    interactionNote(opts),
  ].join('\n');
}

function interactionNote(opts: GadgetOptions): string {
  if (opts.interaction === 'script') {
    return [
      `Interaction 'script': the gadget runs ${opts.scriptPath} entirely on-device with NO`,
      'listening port — nothing to connect to, and no :27042 to fingerprint. Push the agent',
      'script to that path before launch.',
    ].join('\n');
  }
  const addr = opts.address ?? DEFAULT_ADDRESS;
  const port = opts.port ?? DEFAULT_PORT;
  return [
    `Interaction 'listen': after launch, reach the gadget over Frida's protocol at`,
    `${addr}:${port}. From this server set FRIDA_MCP_REMOTE=${addr}:${port}`,
    `(forward it first if bound to localhost on-device: adb forward tcp:${port} tcp:${port}).`,
    opts.onLoad === 'resume'
      ? "on_load=resume: the app runs immediately; attach fast to catch early startup."
      : "on_load=wait: the app blocks at startup until a client attaches — ideal for early hooks.",
  ].join('\n');
}

// ---------------------------------------------------------------------------
// Default IO (real filesystem)
// ---------------------------------------------------------------------------

export function defaultGadgetIo(): GadgetIo {
  return {
    writeFile: (p, text) => fs.writeFileSync(p, text, 'utf8'),
    mkdirp: (p) => fs.mkdirSync(p, { recursive: true }),
    log: (line) => console.log(line),
  };
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/**
 * Validate the enum-valued options (which arrive as free-form strings from the CLI) so a typo
 * fails loudly here instead of producing a config.json that frida-gadget silently rejects at
 * runtime. An undefined value means "use the builder default" and is left alone.
 */
function validateEnumOptions(opts: GadgetOptions): string | null {
  const checks: Array<[string, string | undefined, readonly string[]]> = [
    ['--on-port-conflict', opts.onPortConflict, ON_PORT_CONFLICT],
    ['--on-load', opts.onLoad, ON_LOAD],
    ['--on-change', opts.onChange, ON_CHANGE],
    ['--runtime', opts.runtime, RUNTIMES],
  ];
  for (const [flag, value, allowed] of checks) {
    if (value !== undefined && !allowed.includes(value)) {
      return `Invalid ${flag} "${value}". Valid: ${allowed.join(', ')}.`;
    }
  }
  return null;
}

export function runGadget(opts: GadgetOptions, io: GadgetIo = defaultGadgetIo()): number {
  if (!GADGET_INTERACTIONS.includes(opts.interaction)) {
    io.log(`Unknown interaction "${String(opts.interaction)}". Valid: ${GADGET_INTERACTIONS.join(', ')}`);
    return 2;
  }
  if (!GADGET_PLATFORMS.includes(opts.platform)) {
    io.log(`Unknown platform "${String(opts.platform)}". Valid: ${GADGET_PLATFORMS.join(', ')}`);
    return 2;
  }
  const badOption = validateEnumOptions(opts);
  if (badOption) {
    io.log(badOption);
    return 2;
  }

  let rendered: string;
  try {
    rendered = renderGadgetConfig(opts);
  } catch (err) {
    io.log((err as Error).message);
    return 1;
  }

  const configName = opts.out ? path.basename(opts.out) : defaultConfigName(opts.platform);
  if (opts.print) {
    io.log(rendered.trimEnd());
    io.log('');
    io.log(gadgetGuidance(opts, configName));
    return 0;
  }

  const target = opts.out ?? path.join(process.cwd(), configName);
  io.mkdirp(path.dirname(target));
  io.writeFile(target, rendered);
  io.log(`Wrote ${target}`);
  io.log('');
  io.log(gadgetGuidance(opts, configName));
  return 0;
}
