# Contributing

Thanks for helping improve frida-mobile-mcp. Issues and pull requests are welcome at <https://github.com/monkeywave/frida-mobile-mcp>.

## Setup

```bash
git clone https://github.com/monkeywave/frida-mobile-mcp
cd frida-mobile-mcp
npm ci --foreground-scripts   # also downloads the frida-node native prebuild
npm run build                 # bundles the Java/ObjC bridges and compiles TypeScript
npm test
```

Node.js >= 20 is required. `frida-mobile-mcp doctor` (or `node dist/index.js doctor`) checks your local toolchain and attached devices.

## Making changes

1. Create a branch from `main`.
2. Keep changes focused; follow the existing patterns described in [AGENTS.md](AGENTS.md) (tool registration, result envelope, error codes, guardrails, Frida 17 API rules).
3. Add or update tests under `test/` (vitest). Unit tests must run without a device. Device-dependent tests belong in `test/e2e/` or `test/fritap/*.e2e.test.ts` and must skip themselves unless `FRIDA_MCP_E2E_DEVICE` (or `FRIDA_E2E=1`) is set.
4. Run `npm run lint && npm test` before opening a PR. CI runs the same on Linux, macOS and Windows with Node 20, 22 and 24, plus a CLI smoke test and an `npm pack` content check.
5. If you add, rename or remove a tool, update `src/tools/register-all.ts`, the tables in `README.md`, the relevant `frida_help` topic in `src/tools/help.ts` (and `test/tools/help.test.ts`), `manifest.json` and, if the tool takes or returns addresses, `docs/interop.md`.
6. If you change configuration or environment variables, update `README.md`, `docs/clients.md` and `server.json`.

## Commit messages and releases

Commits follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `refactor:`, `perf:`, `chore:`, `security:`. A `!` or a `BREAKING CHANGE:` footer marks a breaking change.

[release-please](https://github.com/googleapis/release-please) reads these messages on `main`, opens a release PR, bumps the version and writes `CHANGELOG.md`. Do not edit `CHANGELOG.md` or the version fields by hand. When the release PR is merged, the `publish` job in `.github/workflows/release.yml` publishes to npm via OIDC trusted publishing.

## Reporting security issues

Please do not open public issues for vulnerabilities; see [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
