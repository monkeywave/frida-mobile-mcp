import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { DeviceManager } from '../device/manager.js';
import { getState } from '../state.js';
import { buildResult, formatToolResponse } from '../helpers/result-builder.js';
import { wrapFridaError, FridaMcpError } from '../helpers/errors.js';
import { responseFormatSchema } from '../constants.js';
import { validateProcessTarget } from '../helpers/sanitize.js';
import { getOrCreateSession } from '../helpers/session-helper.js';
import { log } from '../helpers/logger.js';

interface TechFingerprint {
  name: string;
  category: string;
  patterns: string[];
}

const FINGERPRINTS: TechFingerprint[] = [
  // HTTP clients
  { name: 'okhttp3', category: 'http_client', patterns: ['okhttp3.OkHttpClient', 'okhttp3.Request'] },
  { name: 'okhttp4', category: 'http_client', patterns: ['okhttp3.internal.platform.Platform'] },
  { name: 'retrofit2', category: 'http_client', patterns: ['retrofit2.Retrofit', 'retrofit2.Call'] },
  { name: 'volley', category: 'http_client', patterns: ['com.android.volley.Request'] },

  // SSL/TLS
  { name: 'conscrypt', category: 'ssl_library', patterns: ['com.android.org.conscrypt.TrustManagerImpl'] },
  { name: 'okhttp_pinner', category: 'ssl_pinning', patterns: ['okhttp3.CertificatePinner'] },
  { name: 'trustkit', category: 'ssl_pinning', patterns: ['com.datatheorem.android.trustkit.TrustKit'] },

  // Root/jailbreak detection
  { name: 'rootbeer', category: 'root_detection', patterns: ['com.scottyab.rootbeer.RootBeer'] },
  { name: 'safetynet', category: 'root_detection', patterns: ['com.google.android.gms.safetynet.SafetyNetClient'] },
  { name: 'play_integrity', category: 'root_detection', patterns: ['com.google.android.play.core.integrity.IntegrityManager'] },

  // Crypto
  { name: 'javax_crypto', category: 'crypto', patterns: ['javax.crypto.Cipher'] },
  { name: 'bouncy_castle', category: 'crypto', patterns: ['org.bouncycastle.jce.provider.BouncyCastleProvider'] },

  // Storage
  { name: 'shared_preferences', category: 'storage', patterns: ['android.app.SharedPreferencesImpl'] },
  { name: 'encrypted_shared_preferences', category: 'storage', patterns: ['androidx.security.crypto.EncryptedSharedPreferences'] },
  { name: 'room', category: 'storage', patterns: ['androidx.room.RoomDatabase'] },
  { name: 'sqlite', category: 'storage', patterns: ['android.database.sqlite.SQLiteDatabase'] },
  { name: 'realm', category: 'storage', patterns: ['io.realm.Realm'] },

  // Frameworks
  { name: 'flutter', category: 'framework', patterns: ['io.flutter.embedding.engine.FlutterEngine'] },
  { name: 'react_native', category: 'framework', patterns: ['com.facebook.react.ReactActivity'] },
  { name: 'xamarin', category: 'framework', patterns: ['mono.android.Runtime'] },
  { name: 'cordova', category: 'framework', patterns: ['org.apache.cordova.CordovaActivity'] },
];

export function registerDetectTool(server: McpServer, deviceManager: DeviceManager): void {
  server.registerTool(
    'detect_app_technologies',
    {
      title: 'Detect App Technologies',
      description: 'Detect what libraries, frameworks, and security mechanisms an app uses. Returns structured results with recommended script targets. Run this before choosing which pre-built scripts to use.',
      inputSchema: {
        target: z.string().describe('App bundle ID or process name'),
        device: z.string().optional().describe('Device ID'),
        response_format: responseFormatSchema,
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ target, device, response_format }) => {
      try {
        validateProcessTarget(target);
        const { sessionEntry } = await getOrCreateSession(deviceManager, { target, device });

        const detected: Record<string, string[]> = {};
        const addDetection = (category: string, name: string): void => {
          (detected[category] ??= []).push(name);
        };
        const scriptRecommendations: Array<{ script: string; targets?: string; reason: string }> = [];

        if (sessionEntry.platform === 'android') {
          // Match fingerprints ON-DEVICE — only matched results cross the IPC bridge
          const script = await sessionEntry.session.createScript(`
            rpc.exports.detect = function(fingerprints) {
              var detected = {};
              function add(cat, name) {
                if (!detected[cat]) detected[cat] = [];
                if (detected[cat].indexOf(name) === -1) detected[cat].push(name);
              }

              var classLookup = {};
              for (var i = 0; i < fingerprints.length; i++) {
                var fp = fingerprints[i];
                for (var j = 0; j < fp.patterns.length; j++) {
                  classLookup[fp.patterns[j]] = fp;
                }
              }

              Java.perform(function() {
                Java.enumerateLoadedClasses({
                  onMatch: function(name) {
                    var match = classLookup[name];
                    if (match) add(match.category, match.name);
                  },
                  onComplete: function() {}
                });
              });

              if (Process.findModuleByName('libflutter.so')) add('framework', 'flutter');

              return detected;
            };
          `);
          await script.load();
          const onDeviceResult = await script.exports.detect(
            FINGERPRINTS.map(fp => ({ name: fp.name, category: fp.category, patterns: fp.patterns }))
          ) as Record<string, string[]>;
          await script.unload();

          for (const [category, names] of Object.entries(onDeviceResult)) {
            for (const name of names) addDetection(category, name);
          }

        } else if (sessionEntry.platform === 'ios') {
          // Match fingerprints ON-DEVICE for iOS
          const script = await sessionEntry.session.createScript(`
            rpc.exports.detect = function() {
              var detected = {};
              function add(cat, name) {
                if (!detected[cat]) detected[cat] = [];
                if (detected[cat].indexOf(name) === -1) detected[cat].push(name);
              }

              var modules = Process.enumerateModules().map(function(m) { return m.name; });
              if (modules.some(function(m) { return m.indexOf('Flutter') >= 0 || m.indexOf('flutter') >= 0; })) add('framework', 'flutter');
              if (modules.indexOf('libcommonCrypto.dylib') >= 0) add('crypto', 'commoncrypto');

              var classes = ObjC.enumerateLoadedClassesSync();
              for (var name in classes) {
                if (name.indexOf('AFSecurityPolicy') >= 0 || name.indexOf('AFHTTPSessionManager') >= 0) add('http_client', 'afnetworking');
                if (name.indexOf('Alamofire') >= 0) add('http_client', 'alamofire');
                if (name.indexOf('TrustKit') >= 0 || name.indexOf('TSKPinningValidator') >= 0) add('ssl_pinning', 'trustkit');
              }

              add('ssl_library', 'boringssl');
              return detected;
            };
          `);
          await script.load();
          const onDeviceResult = await script.exports.detect() as Record<string, string[]>;
          await script.unload();

          for (const [category, names] of Object.entries(onDeviceResult)) {
            for (const name of names) addDetection(category, name);
          }
        }

        // Generate recommendations
        if (detected['ssl_pinning'] || detected['ssl_library']) {
          const targets: string[] = [];
          if (detected['ssl_pinning']?.includes('okhttp_pinner')) targets.push('okhttp');
          if (detected['ssl_library']?.includes('conscrypt')) targets.push('conscrypt');
          if (detected['framework']?.includes('flutter')) targets.push('flutter');
          if (detected['ssl_library']?.includes('boringssl')) targets.push('boringssl');
          scriptRecommendations.push({
            script: 'ssl_pinning_bypass',
            targets: targets.length > 0 ? targets.join(',') : undefined,
            reason: 'Detected SSL libraries: ' + Object.values(detected).flat().filter(t => ['conscrypt', 'okhttp_pinner', 'boringssl', 'trustkit'].includes(t)).join(', '),
          });
        }

        if (detected['root_detection']) {
          scriptRecommendations.push({
            script: 'root_jailbreak_bypass',
            reason: 'Detected root/jailbreak detection: ' + detected['root_detection'].join(', '),
          });
        }

        if (detected['crypto']) {
          scriptRecommendations.push({
            script: 'crypto_monitor',
            reason: 'Detected crypto libraries: ' + detected['crypto'].join(', '),
          });
        }

        if (detected['storage']) {
          scriptRecommendations.push({
            script: 'keychain_prefs',
            reason: 'Detected storage: ' + detected['storage'].join(', '),
          });
        }

        log('info', `detect_app_technologies: found ${Object.keys(detected).length} categories for ${target}`);

        return formatToolResponse(
          buildResult(
            {
              target,
              platform: sessionEntry.platform,
              session_id: sessionEntry.id,
              detected,
              recommendations: scriptRecommendations,
            },
            scriptRecommendations.map(r => ({
              tool: 'run_prebuilt_script',
              args: { script_name: r.script, target, ...(r.targets ? { options: { targets: r.targets } } : {}) },
              reason: r.reason,
              priority: 'recommended' as const,
            }))
          ), response_format
        );
      } catch (err) {
        if (err instanceof FridaMcpError) return formatToolResponse(err.toErrorResponse(), response_format);
        return formatToolResponse(wrapFridaError(err).toErrorResponse(), response_format);
      }
    }
  );
}
