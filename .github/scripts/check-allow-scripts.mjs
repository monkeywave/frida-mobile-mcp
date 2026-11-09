// Verifies that package.json `allowScripts` approves the exact `frida` version the
// lockfile resolves. frida's install script downloads its native prebuild, and npm
// only runs it for approved name@version keys. Dependabot bumps the lockfile but
// never the allowScripts key, so a stale key would silently ship without bindings.
//   node .github/scripts/check-allow-scripts.mjs
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const GUARDED_PACKAGE = 'frida';

export function findAllowScriptsMismatch(packageJson, lockfile, packageName = GUARDED_PACKAGE) {
  const lockedVersion = lockfile.packages?.[`node_modules/${packageName}`]?.version;
  if (!lockedVersion) return `${packageName} is not in package-lock.json`;

  const approvedKeys = Object.keys(packageJson.allowScripts ?? {})
    .filter((key) => key.startsWith(`${packageName}@`));
  const expectedKey = `${packageName}@${lockedVersion}`;
  if (packageJson.allowScripts?.[expectedKey] === true) return null;

  const found = approvedKeys.length > 0 ? approvedKeys.join(', ') : 'none';
  return `allowScripts must approve "${expectedKey}" (lockfile version); found: ${found}`;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mismatch = findAllowScriptsMismatch(readJson('package.json'), readJson('package-lock.json'));
  if (mismatch) {
    console.error(mismatch);
    process.exit(1);
  }
  console.log(`allowScripts matches the locked ${GUARDED_PACKAGE} version.`);
}
