import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { toolOutputSchema } from '../helpers/output-schema.js';
import type { McpServer } from '@modelcontextprotocol/server';
import type { DeviceManager } from '../device/manager.js';
import type { SuggestedAction } from '../types.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError, FridaMcpError } from '../helpers/errors.js';
import { resolveInstrumentationTarget } from './hook.js';
import { responseFormatSchema } from '../constants.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { createAgentScript } from '../agent/script-factory.js';
import { callRpcWithTimeout } from '../helpers/rpc-timeout.js';
import { attachScriptSinks } from '../helpers/script-sink.js';
import { JAVA_CLASS_LOOKUP_SNIPPET } from '../agent/java-class-lookup.js';
import { formatJavaSignature } from '../agent/java-signature.js';

/**
 * describe_class: the full shape of one app class (methods with exact parameter/return
 * types, constructors, fields, superclass, interfaces), so an AI can pick one overload
 * and pass its `signature` straight to hook_method `evidence: { class, signature }`.
 */

// ---------------------------------------------------------------------------
// Agent sources (classic JS; options arrive only as __FRIDA_MCP__.options)
// ---------------------------------------------------------------------------

/** Java: reflection over the class found in any loader. Type names are `Class#getName()`. */
export const JAVA_DESCRIBE_SOURCE = JAVA_CLASS_LOOKUP_SNIPPET + `
rpc.exports.describe = function () {
  var o = __FRIDA_MCP__.options;
  return javaPerform(function () {
    var wrapper = useInAnyLoader(o.className);
    if (wrapper === null) return { found: false };
    var errors = [];
    function message(e) { return String(e && e.message ? e.message : e); }
    function collect(label, fn) {
      try { return fn(); } catch (e) { errors.push(label + ': ' + message(e)); return []; }
    }
    function typeNames(types) {
      var out = [];
      for (var i = 0; i < types.length; i++) out.push(types[i].getName());
      return out;
    }
    function methodsOf(klass, declaring) {
      return collect('methods of ' + declaring, function () {
        var methods = klass.getDeclaredMethods();
        var out = [];
        for (var i = 0; i < methods.length; i++) {
          var m = methods[i];
          var entry = { name: m.getName(), argTypes: typeNames(m.getParameterTypes()), returnType: m.getReturnType().getName(), modifiers: m.getModifiers() };
          if (declaring !== o.className) entry.declaringClass = declaring;
          out.push(entry);
        }
        return out;
      });
    }
    function fieldsOf(klass, declaring) {
      return collect('fields of ' + declaring, function () {
        var fields = klass.getDeclaredFields();
        var out = [];
        for (var i = 0; i < fields.length; i++) {
          var f = fields[i];
          var entry = { name: f.getName(), type: f.getType().getName(), modifiers: f.getModifiers() };
          if (declaring !== o.className) entry.declaringClass = declaring;
          out.push(entry);
        }
        return out;
      });
    }
    function constructorsOf(klass) {
      return collect('constructors', function () {
        var ctors = klass.getDeclaredConstructors();
        var out = [];
        for (var i = 0; i < ctors.length; i++) {
          out.push({ argTypes: typeNames(ctors[i].getParameterTypes()), modifiers: ctors[i].getModifiers() });
        }
        return out;
      });
    }

    var klass = wrapper.class;
    var result = {
      found: true,
      name: klass.getName(),
      modifiers: klass.getModifiers(),
      isInterface: !!klass.isInterface(),
      superclass: null,
      interfaces: collect('interfaces', function () { return typeNames(klass.getInterfaces()); }),
      methods: methodsOf(klass, o.className),
      constructors: constructorsOf(klass),
      fields: fieldsOf(klass, o.className),
      inheritedFrom: [],
      errors: errors
    };
    var parent = null;
    try { parent = klass.getSuperclass(); } catch (e) { errors.push('superclass: ' + message(e)); }
    if (parent) result.superclass = parent.getName();
    if (o.includeInherited) {
      // Walk up to (not including) java.lang.Object; its methods are noise for hooking.
      for (var depth = 0; parent && depth < 32; depth++) {
        var parentName = parent.getName();
        if (parentName === 'java.lang.Object') break;
        result.inheritedFrom.push(parentName);
        result.methods = result.methods.concat(methodsOf(parent, parentName));
        result.fields = result.fields.concat(fieldsOf(parent, parentName));
        try { parent = parent.getSuperclass(); } catch (e) { errors.push('superclass of ' + parentName + ': ' + message(e)); parent = null; }
      }
    }
    return result;
  });
};
`;

/** ObjC: selectors with their type encodings. */
export const OBJC_DESCRIBE_SOURCE = `
rpc.exports.describe = function () {
  var o = __FRIDA_MCP__.options;
  if (typeof ObjC === 'undefined' || !ObjC.available) throw new Error('Objective-C runtime not available in this process');
  if (!ObjC.classes.hasOwnProperty(o.className)) return { found: false };
  var cls = ObjC.classes[o.className];
  var errors = [];
  var selectors = (o.includeInherited ? cls.$methods : cls.$ownMethods) || [];
  var methods = [];
  for (var i = 0; i < selectors.length; i++) {
    var sel = selectors[i];
    try {
      var m = cls[sel];
      methods.push({ selector: sel, types: m.types, returnType: m.returnType, argumentTypes: m.argumentTypes });
    } catch (e) {
      errors.push(sel + ': ' + String(e && e.message ? e.message : e));
      methods.push({ selector: sel });
    }
  }
  var superclass = null;
  try { superclass = cls.$superClass ? cls.$superClass.$className : null; } catch (e) { /* root class */ }
  var protocols = [];
  try { protocols = Object.keys(cls.$protocols || {}); } catch (e) { /* none */ }
  return { found: true, name: cls.$className, superclass: superclass, protocols: protocols, methods: methods, errors: errors };
};
`;

// ---------------------------------------------------------------------------
// Host-side shaping
// ---------------------------------------------------------------------------

interface JavaMemberRaw {
  name: string;
  argTypes: string[];
  returnType: string;
  modifiers: number;
  declaringClass?: string;
}

interface JavaFieldRaw {
  name: string;
  type: string;
  modifiers: number;
  declaringClass?: string;
}

interface JavaDescribeRaw {
  found: true;
  name: string;
  modifiers: number;
  isInterface: boolean;
  superclass: string | null;
  interfaces: string[];
  methods: JavaMemberRaw[];
  constructors: Array<{ argTypes: string[]; modifiers: number }>;
  fields: JavaFieldRaw[];
  inheritedFrom: string[];
  errors: string[];
}

interface ObjcDescribeRaw {
  found: true;
  name: string;
  superclass: string | null;
  protocols: string[];
  methods: Array<{ selector: string; types?: string; returnType?: string; argumentTypes?: string[] }>;
  errors: string[];
}

type DescribeRaw = JavaDescribeRaw | ObjcDescribeRaw | { found: false };

export type JavaMemberKind = 'class' | 'method' | 'field';

/** java.lang.reflect.Modifier bits, in Modifier.toString order. */
const MODIFIER_BITS: ReadonlyArray<[number, string]> = [
  [0x0001, 'public'], [0x0004, 'protected'], [0x0002, 'private'],
  [0x0400, 'abstract'], [0x0008, 'static'], [0x0010, 'final'],
  [0x0080, 'transient'], [0x0040, 'volatile'], [0x0020, 'synchronized'],
  [0x0100, 'native'], [0x0800, 'strictfp'], [0x0200, 'interface'],
];

/** Bits whose meaning depends on the member kind (Method reuses volatile/transient bits). */
const METHOD_ONLY_BITS: ReadonlyArray<[number, string]> = [[0x0040, 'bridge'], [0x0080, 'varargs']];
const SYNTHETIC_BIT = 0x1000;

/**
 * Format reflection modifier bits like `Modifier.toString`, but kind-aware: on methods the
 * 0x40/0x80 bits mean bridge/varargs (not volatile/transient), and synthetic is reported.
 */
export function formatJavaModifiers(bits: number, kind: JavaMemberKind): string[] {
  const out: string[] = [];
  for (const [bit, name] of MODIFIER_BITS) {
    if (!(bits & bit)) continue;
    if (kind === 'method' && (bit === 0x0040 || bit === 0x0080)) continue;
    if (kind !== 'field' && (name === 'volatile' || name === 'transient')) continue;
    if (kind !== 'class' && name === 'interface') continue;
    out.push(name);
  }
  if (kind === 'method') {
    for (const [bit, name] of METHOD_ONLY_BITS) if (bits & bit) out.push(name);
  }
  if (bits & SYNTHETIC_BIT) out.push('synthetic');
  return out;
}

/** `formatJavaSignature`, but never throws on an odd runtime type name. */
function safeSignature(name: string, argTypes: string[]): string {
  try {
    return formatJavaSignature(name, argTypes);
  } catch {
    return `${name}(${argTypes.join(', ')})`;
  }
}

function shapeJavaMethod(m: JavaMemberRaw) {
  return {
    name: m.name,
    signature: safeSignature(m.name, m.argTypes),
    arg_types: m.argTypes,
    return_type: m.returnType,
    modifiers: formatJavaModifiers(m.modifiers, 'method'),
    ...(m.declaringClass ? { declaring_class: m.declaringClass } : {}),
  };
}

/** Code-point order on the signature: overloads sit together and output is locale-independent. */
function bySignature(a: { signature: string }, b: { signature: string }): number {
  if (a.signature === b.signature) return 0;
  return a.signature < b.signature ? -1 : 1;
}

export function shapeJavaDescription(raw: JavaDescribeRaw) {
  const methods = raw.methods.map(shapeJavaMethod).sort(bySignature);
  const constructors = raw.constructors
    .map((c) => shapeJavaMethod({ name: '$init', argTypes: c.argTypes, returnType: 'void', modifiers: c.modifiers }))
    .sort(bySignature);
  const fields = raw.fields.map((f) => ({
    name: f.name,
    type: f.type,
    modifiers: formatJavaModifiers(f.modifiers, 'field'),
    ...(f.declaringClass ? { declaring_class: f.declaringClass } : {}),
  }));
  return {
    class_name: raw.name,
    kind: raw.isInterface ? 'interface' : 'class',
    modifiers: formatJavaModifiers(raw.modifiers, 'class'),
    superclass: raw.superclass,
    interfaces: raw.interfaces,
    ...(raw.inheritedFrom.length > 0 ? { inherited_from: raw.inheritedFrom } : {}),
    method_count: methods.length,
    methods,
    constructors,
    fields,
  };
}

export function shapeObjcDescription(raw: ObjcDescribeRaw) {
  return {
    class_name: raw.name,
    superclass: raw.superclass,
    protocols: raw.protocols,
    method_count: raw.methods.length,
    methods: raw.methods.map((m) => ({
      selector: m.selector,
      ...(m.types !== undefined ? { types: m.types } : {}),
      ...(m.returnType !== undefined ? { return_type: m.returnType } : {}),
      ...(m.argumentTypes !== undefined ? { argument_types: m.argumentTypes } : {}),
    })),
  };
}

function selectDescribeSource(platform: string): string {
  if (platform === 'android') return JAVA_DESCRIBE_SOURCE;
  if (platform === 'ios' || platform === 'macos') return OBJC_DESCRIBE_SOURCE;
  throw new FridaMcpError(
    'PLATFORM_UNSUPPORTED',
    `describe_class needs a Java (Android) or Objective-C (iOS/macOS) runtime; this session's platform is "${platform}".`,
    [{ tool: 'search_classes_and_methods', reason: 'List native modules and exports instead' }],
    { platform }
  );
}

function classNotLoaded(className: string, target: string | undefined, sessionId: string): FridaMcpError {
  return new FridaMcpError(
    'CLASS_NOT_LOADED',
    `Class "${className}" is not loaded in any class loader (yet). Check the exact name, drive the app to the code path that loads it, or wait a few seconds after spawning.`,
    [
      { tool: 'watch_loads', args: { target, session_id: sessionId }, reason: 'Wait for the class to be loaded, then retry' },
      { tool: 'search_classes_and_methods', args: { session_id: sessionId, pattern: className.split('.').pop() ?? className }, reason: 'Find the exact class name' },
    ],
    { class_name: className, session_id: sessionId }
  );
}

/** First non-synthetic method (else first constructor) as a ready-to-use hook suggestion. */
function suggestHook(
  className: string,
  description: ReturnType<typeof shapeJavaDescription>,
  sessionId: string
): SuggestedAction[] {
  const pick = description.methods.find((m) => !m.declaring_class && !m.modifiers.includes('synthetic'))
    ?? description.constructors[0];
  if (!pick) return [];
  return [{
    tool: 'hook_method',
    args: { session_id: sessionId, evidence: { class: className, signature: pick.signature } },
    reason: `Hook exactly one overload (${pick.signature}); swap in any signature from this result`,
  }];
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

export function registerDescribeClassTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'describe_class',
    {
      title: 'Describe Class',
      description: 'Return the full shape of ONE loaded app class so you can pick an exact method overload before hooking. Android: every declared method with parameter types, return type, modifiers and a ready-to-use `signature` (e.g. "encrypt(byte[], java.lang.String)"), constructors (as "$init(...)"), fields, superclass and interfaces; searches all class loaders. iOS: selectors with Objective-C type encodings, superclass and protocols. Pass a returned signature verbatim to hook_method as evidence: {class, signature} to hook exactly that overload. The class must already be loaded; if it is not, use watch_loads or search_classes_and_methods.',
      inputSchema: z.object({
        target: z.string().optional().describe('App bundle ID, process name, or PID. Optional when session_id is given.'),
        session_id: z.string().optional().describe('Reuse an existing session (from explore_app/get_status) instead of re-attaching by target.'),
        device: z.string().optional().describe('Device ID'),
        class_name: z.string().min(1).describe('Fully-qualified class name, e.g. "com.example.Rc4Client" (Java) or "NSURLSession" (ObjC)'),
        include_inherited: z.boolean().optional().default(false).describe('Also list methods/fields declared by superclasses (Java: up to, not including, java.lang.Object; ObjC: $methods instead of $ownMethods). Default: false'),
        response_format: responseFormatSchema,
      }),
      outputSchema: toolOutputSchema(),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ target, session_id, device, class_name, include_inherited, response_format }) => {
      try {
        const resolved = resolveInstrumentationTarget(target, session_id);
        const { sessionEntry } = await getOrCreateSession(deviceManager, { target: resolved.target, device, sessionId: resolved.sessionId });
        const platform = sessionEntry.platform;
        const source = selectDescribeSource(platform);

        const script = await createAgentScript(sessionEntry.session, {
          sessionEntry,
          source,
          platform,
          name: 'describe_class:' + platform,
          kind: 'generated',
          options: { className: class_name, includeInherited: include_inherited ?? false },
        });
        const agentErrors: string[] = [];
        attachScriptSinks(script, sessionEntry.id, `describe_class-${randomUUID()}`, {
          onSend: () => { /* the agent answers over RPC only */ },
          onEntry: (entry) => {
            if (entry.type === 'error') agentErrors.push(String((entry.payload as { description?: string }).description));
          },
        });
        await script.load();
        let raw: DescribeRaw;
        try {
          raw = await callRpcWithTimeout(script.exports.describe() as Promise<DescribeRaw>, 'Class description');
        } finally {
          await script.unload();
        }

        if (!raw.found) throw classNotLoaded(class_name, resolved.target, sessionEntry.id);

        const errors = [...raw.errors, ...agentErrors];
        const evidenceMeta = errors.length > 0
          ? { limitations: [`Some members could not be reflected: ${errors.join('; ')}`], coverage: { status: 'unknown' as const, note: 'partial reflection' } }
          : { coverage: { status: 'complete' as const } };
        if (platform === 'android') {
          const description = shapeJavaDescription(raw as JavaDescribeRaw);
          return formatToolResponse(
            buildResult(
              { session_id: sessionEntry.id, platform, ...description },
              suggestHook(class_name, description, sessionEntry.id),
              evidenceMeta
            ),
            response_format
          );
        }
        const description = shapeObjcDescription(raw as ObjcDescribeRaw);
        const first = description.methods[0];
        const suggestions: SuggestedAction[] = first
          ? [{ tool: 'hook_method', args: { session_id: sessionEntry.id, method: `${first.selector.slice(0, 1)}[${class_name} ${first.selector.slice(2)}]` }, reason: `Hook ${first.selector}` }]
          : [];
        return formatToolResponse(
          buildResult(
            { session_id: sessionEntry.id, platform, ...description },
            suggestions,
            evidenceMeta
          ),
          response_format
        );
      } catch (err) {
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}
