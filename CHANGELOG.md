# Changelog

## [0.2.3](https://github.com/monkeywave/frida-mobile-mcp/compare/v0.2.2...v0.2.3) (2026-04-03)


### Bug Fixes

* remove duplicate publish job from release.yml ([28a1504](https://github.com/monkeywave/frida-mobile-mcp/commit/28a150468ee4a32987bbab700c0467f8adc048a8))

## [0.2.2](https://github.com/monkeywave/frida-mobile-mcp/compare/v0.2.1...v0.2.2) (2026-04-03)


### Bug Fixes

* changed to Trusted Publishing ([4efc560](https://github.com/monkeywave/frida-mobile-mcp/commit/4efc5607e236b39bffe7b92fa95cbb25b7b42a2a))

## [0.2.1](https://github.com/monkeywave/frida-mobile-mcp/compare/v0.2.0...v0.2.1) (2026-04-03)


### Bug Fixes

* update CI pipeline and commit lock file ([7be4d80](https://github.com/monkeywave/frida-mobile-mcp/commit/7be4d8084ca795e7ceae2106200908abea357730))

## [0.2.0]

### Features

* new `detect_app_technologies` tool — fingerprints 20+ libraries and recommends targeted scripts
* shared Frida runtime helpers (`hookNative`, `hookJava`, `hookObjC`) for consistent error reporting
* `PlatformContext` type for API-level-aware script generation
* enhanced `SuggestedAction` with `condition` and `priority` fields
* task-oriented `script_catalog` help topic
* comprehensive test suite (118 tests, up from 36)
* CI workflow for GitHub Actions (Node 18+22, ubuntu+macos)
* release-please integration for automated CHANGELOG generation from conventional commits
* SSL pinning bypass: added OkHttp4 `check$okhttp`, WebViewClient, NetworkSecurityTrustManager, BoringSSL per-connection, AFNetworking (8→18 hooks)
* root/jailbreak bypass: added ProcessBuilder, SystemProperties, PackageManager, native fopen/access/stat, canOpenURL, sysctl (5→25 hooks)
* crypto monitor: added Cipher lifecycle, SecretKeySpec, Mac/HMAC, CCCryptorCreate, CC_SHA256, CC_MD5 (4→15 hooks)
* network inspector: added getaddrinfo (DNS), sendto/recvfrom (UDP), SSL_read/SSL_write (TLS plaintext) (3→12 hooks)
* keychain/prefs: added SecItemUpdate, SecItemDelete (12→18 hooks)
* filesystem monitor: added openat, stat/lstat, sqlite3_open/exec (8→15 hooks)
* class enumeration: added method listing, inheritance chain, interface/protocol info
* method hook: added ObjC method hooking support

### Bug Fixes

* SSL pinning bypass: `SSLContext.init` now injects permissive TrustManager (was passing original)
* SSL pinning bypass: BoringSSL `SSL_CTX_set_custom_verify` now installs permissive callback (was no-op causing default-deny)
* SSL pinning bypass: NULL pointer guard on `SecTrustEvaluate` result parameter
* script injection vulnerability: all user options now escaped via `escapeForScript()` before interpolation
* NULL pointer safety: try-catch wrappers on all native hook callbacks
* `--debug` CLI flag now correctly sets `FRIDA_MCP_DEBUG` environment variable
* version string now derived from package.json instead of hardcoded

## [0.1.0](https://github.com/user/frida-mobile-mcp/releases/tag/v0.1.0) (2026-03-31)

### Features

* initial release with 31 MCP tools (15 Tier 1 + 16 Tier 2)
* 8 pre-built Frida scripts
* mobile-mcp integration via gateway pattern
* security guardrails (rate limiting, audit logging, session timeout)
* stdio transport
