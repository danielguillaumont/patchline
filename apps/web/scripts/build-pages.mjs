// Use the same resolved subpath for the asset build, preview, and verifier.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { pagesBase } from './pages-base.mjs';

const vite = fileURLToPath(new URL('../node_modules/vite/bin/vite.js', import.meta.url));
const base = pagesBase();
const result = spawnSync(
  process.execPath,
  [vite, 'build', '--config', 'vite.e2e.config.mjs', '--base', base],
  { stdio: 'inherit' },
);
if (result.error) {
  console.error(`Exploit Atlas Pages build failed: ${result.error.message}`);
  process.exitCode = 1;
} else {
  process.exitCode = result.status === null ? 1 : result.status;
}
