# Changelog

## [0.5.1](https://github.com/monkeywave/frida-mobile-mcp/compare/v0.5.0...v0.5.1) (2026-10-22)


### Bug Fixes

* add active_oracles to the session_context output schema ([75919d4](https://github.com/monkeywave/frida-mobile-mcp/commit/75919d4ecbf012e8f369cd969adec2464a685b8e))


### Miscellaneous

* release 0.5.1 ([b4e22a7](https://github.com/monkeywave/frida-mobile-mcp/commit/b4e22a72e0e50e770ab44333c98e3cbfbc881428))

## [0.5.0](https://github.com/monkeywave/frida-mobile-mcp/compare/v0.3.0...v0.5.0) (2026-10-22)


### Features

* improved the different scripts ([e08b67a](https://github.com/monkeywave/frida-mobile-mcp/commit/e08b67ac6c0938d2c352cde45ba1f3a9994a141f))


### Miscellaneous

* release 0.4.0 ([fcd3934](https://github.com/monkeywave/frida-mobile-mcp/commit/fcd393418208981247a745d6df1f818021a62c87))
* release 0.5.0 ([5586f90](https://github.com/monkeywave/frida-mobile-mcp/commit/5586f90ce91f8419357b44be24732f8dc89561db))

## [0.3.0](https://github.com/monkeywave/frida-mobile-mcp/compare/v0.2.3...v0.3.0) (2026-10-21)


### ⚠ BREAKING CHANGES

* Node.js 20 is no longer supported; Node.js >= 22.12 is required.

### Features

* Frida 17 support, native address interchange and static-tool analysis hand-off ([cf5bb38](https://github.com/monkeywave/frida-mobile-mcp/commit/cf5bb38df6d6deafb2d818c3c32ad729739cd274))
* require Node.js &gt;= 22.12 ([d1a74f2](https://github.com/monkeywave/frida-mobile-mcp/commit/d1a74f20579ea21ee6afae43d4a9080c65320e63))


### Bug Fixes

* **ci:** make the ESM compiler project and path tests work on Windows ([2e76ef1](https://github.com/monkeywave/frida-mobile-mcp/commit/2e76ef1225be8bcacf6c22542013aeb8d5d2e8d8))
* missing repo in package.json definition ([b2da55d](https://github.com/monkeywave/frida-mobile-mcp/commit/b2da55d6429438ed36e829e7478de42430cb4ef9))
* publish workflow fix ([3c273f0](https://github.com/monkeywave/frida-mobile-mcp/commit/3c273f0b1ca00cf605266d5b1b6b81262e6d9c89))
* publish workflow fix ([08cdee9](https://github.com/monkeywave/frida-mobile-mcp/commit/08cdee9f7ff663e5bdd946068b32044b83c93864))
* **security:** resolve CodeQL ReDoS and incomplete-escaping alerts ([e31817b](https://github.com/monkeywave/frida-mobile-mcp/commit/e31817ba3c2c8ef33e244e3069f316b01f33ca69))

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
