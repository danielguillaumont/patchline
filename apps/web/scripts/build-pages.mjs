// Use the same resolved subpath for the asset build, preview, and verifier.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { pagesBase } from './pages-base.mjs';
import { releaseFromRepo, verifyExplorerDirectory } from './explorer-public-release.mjs';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

const vite = fileURLToPath(new URL('../node_modules/vite/bin/vite.js', import.meta.url));
const base = pagesBase();
const release = releaseFromRepo();
const publicDir = process.env.PATCHLINE_E2E_PUBLIC_DIR;
if (!publicDir) throw Error('PATCHLINE_E2E_PUBLIC_DIR required for guarded Pages build');
const explorer = join(resolve(publicDir), 'explorer');
if (release.enabled) {
  verifyExplorerDirectory(explorer, release);
} else if (existsSync(explorer)) {
  throw Error('Unapproved Explorer files found in deployable staging folder');
}
const result = spawnSync(
  process.execPath,
  [vite, 'build', '--config', 'vite.e2e.config.mjs', '--base', base],
  { stdio: 'inherit', env: { ...process.env, VITE_EXPLORER_PUBLIC_RELEASE: release.enabled ? '1' : '0' } },
);
if (result.error) {
  console.error(`Exploit Atlas Pages build failed: ${result.error.message}`);
  process.exitCode = 1;
} else {
  process.exitCode = result.status === null ? 1 : result.status;
}
