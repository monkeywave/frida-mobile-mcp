import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

/** Package version read from package.json so every surface reports the same number. */
export function getPackageVersion(): string {
  try {
    const pkg = require('../../package.json') as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}
