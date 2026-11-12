// Playwright starts an isolated Vite server with a newly generated, verified
// synthetic bundle. Never write to the developer's apps/web/public/demo folder.
import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repo = resolve(web, '..', '..');
const temp = mkdtempSync(join(tmpdir(), 'patchline-e2e-'));
const database = join(temp, 'fixture.duckdb');
const exportDir = join(temp, 'exports');
const publicDir = join(temp, 'public');
const demoDir = join(publicDir, 'demo');
const names = [
  'manifest.json',
  'm03_epss_coverage_of_kev.json',
  'm04_epss_population_summary.json',
  'm04_epss_score_bands.json',
];
let server;
let cleaned = false;

function cleanup() {
  if (cleaned) return;
  cleaned = true;
  if (server && !server.killed) server.kill();
  try { rmSync(temp, { recursive: true, force: true }); }
  catch (error) { console.warn(`Could not remove isolated browser fixture: ${error.message}`); }
}
function run(args, env = {}) {
  console.log(`e2e fixture: uv ${args.join(' ')}`);
  const result = spawnSync('uv', args, {
    cwd: repo,
    env: { ...process.env, ...env },
    stdio: 'inherit',
    windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw Error(`Fixture command exited ${result.status}: uv ${args[0]} ${args[1]}`);
}

try {
  run(['run', '--locked', 'python', '-m', 'patchline.fixtures.ci_warehouse', 'create', '--output', database]);
  const dbEnv = { PATCHLINE_DUCKDB_PATH: database };
  run(['run', '--locked', 'dbt', 'run', '--project-dir', 'dbt', '--profiles-dir', 'dbt'], dbEnv);
  run(['run', '--locked', 'dbt', 'test', '--project-dir', 'dbt', '--profiles-dir', 'dbt'], dbEnv);
  run(['run', '--locked', 'python', '-m', 'patchline.exports.analytics', 'create', '--database', database, '--output', exportDir]);
  run(['run', '--locked', 'python', '-m', 'patchline.exports.analytics', 'verify', '--output', exportDir]);
  const manifest = JSON.parse(readFileSync(join(exportDir, 'manifest.json'), 'utf8'));
  if (manifest.data_kind !== 'synthetic_fixture' || manifest.artifacts?.length !== 9) {
    throw Error('Browser fixture failed synthetic classification or nine-artifact boundary');
  }
  mkdirSync(demoDir, { recursive: true });
  for (const name of names) {
    const file = join(exportDir, name);
    if (!existsSync(file)) throw Error(`Verified fixture missing ${name}`);
    copyFileSync(file, join(demoDir, name));
  }
  console.log('Launching isolated browser-test Vite server on 127.0.0.1:5175');
  server = spawn(process.execPath, [
    join(web, 'node_modules', 'vite', 'bin', 'vite.js'),
    '--config', 'vite.e2e.config.mjs', '--host', '127.0.0.1', '--port', '5175', '--strictPort',
  ], {
    cwd: web,
    env: { ...process.env, PATCHLINE_E2E_PUBLIC_DIR: publicDir },
    stdio: 'inherit',
    windowsHide: true,
  });
  server.on('error', error => { console.error(error); cleanup(); process.exitCode = 1; });
  server.on('exit', code => { cleanup(); process.exitCode = code ?? 1; });
} catch (error) {
  console.error(`P4.1B3 browser setup failed: ${error.message}`);
  cleanup();
  process.exitCode = 1;
}

process.on('SIGINT', () => { cleanup(); process.exit(130); });
process.on('SIGTERM', () => { cleanup(); process.exit(143); });
