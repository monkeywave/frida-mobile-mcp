/**
 * Compatibility gates between frida-mobile-mcp and friTap releases (pure functions).
 *
 * - Agent ABI: friTap bundles report `agentAbiVersion()`; ABI 2 (friTap 2.5.x) and ABI 3
 *   (friTap >= 2.6.3: datalog `direction`/`library`, `caller_stack`, `platform_report`) are handled.
 * - pip-installed friTap: releases before 2.0.0 ship Frida 15/16-era agents that do not speak the
 *   config_batch handshake, so they are skipped in favour of the pinned download/cache.
 */

/** Agent ABI versions whose handshake and message shapes this server understands. */
export const SUPPORTED_FRITAP_AGENT_ABI_VERSIONS: readonly number[] = [2, 3];

/** Oldest pip-installed friTap release whose bundled agent is used. */
export const MIN_PIP_FRITAP_VERSION = '2.0.0';

/** True when the agent ABI is one this server handles. */
export function isSupportedFritapAbi(abi: number): boolean {
  return SUPPORTED_FRITAP_AGENT_ABI_VERSIONS.includes(abi);
}

/** Leading numeric [major, minor, patch] of a version like "2.6.5", "v2.6.5" or "2.6.5.post1"; null when unparseable. */
export function parseFritapVersion(version: string): [number, number, number] | null {
  const match = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(version.trim());
  if (!match) return null;
  return [Number(match[1]), Number(match[2] ?? 0), Number(match[3] ?? 0)];
}

/** Negative / zero / positive like a comparator; null when either side is unparseable. */
export function compareFritapVersions(a: string, b: string): number | null {
  const left = parseFritapVersion(a);
  const right = parseFritapVersion(b);
  if (!left || !right) return null;
  for (let i = 0; i < 3; i++) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return 0;
}

export interface PipFritapDecision {
  use: boolean;
  /** Why the package was skipped or accepted with caveats; null when it is accepted cleanly. */
  warning: string | null;
}

/**
 * Whether a pip-installed friTap of `version` should supply the agent. Too-old releases are
 * skipped; an unknown version keeps the historical behaviour (used) but warns.
 */
export function decidePipFritapUsage(version: string | null): PipFritapDecision {
  const comparison = version ? compareFritapVersions(version, MIN_PIP_FRITAP_VERSION) : null;
  if (comparison === null) {
    return { use: true, warning: `pip-installed friTap version is unknown (${version ?? 'none'}); using its agent as-is` };
  }
  if (comparison < 0) {
    return {
      use: false,
      warning: `pip-installed friTap ${version} is older than ${MIN_PIP_FRITAP_VERSION} (Frida 15/16-era agent); ignoring it and using the pinned agent instead`,
    };
  }
  return { use: true, warning: null };
}
