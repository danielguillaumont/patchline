// P5.2B1: verified, ephemeral local Spectral Index demonstration.
// Run through scripts/Start-PatchlineDemo.ps1 on Windows PowerShell 5.1.
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { assertSyntheticV2Manifest, demoJsonNames, parseDemoPort } from './demo-guard.mjs';

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repo = resolve(web, '..', '..');
const argumentsList = process.argv.slice(2);
let server;
let temp;
let stopping = false;
let failed = false;
let cleaned = false;

function cleanup() {
  if (cleaned) return;
  cleaned = true;
  if (temp) {
    try { rmSync(temp, { recursive: true, force: true, maxRetries: 3, retryDelay: 300 }); }
    catch (error) { console.error(`Temporary demo cleanup failed at ${temp}: ${error.message}`); }
  }
}

function stop(signal) {
  if (stopping) return;
  stopping = true;
  console.log(`\nStopping local demo (${signal}).`);
  if (server && server.exitCode === null && !server.killed) {
    server.kill();
  } else {
    cleanup();
    process.exitCode = 0;
  }
}
process.on('SIGINT', () => stop('Ctrl+C'));
process.on('SIGTERM', () => stop('SIGTERM'));

function run(label, executable, args, cwd = repo, env = {}) {
  console.log(`\n=== ${label} ===`);
  const options = { cwd, env: { ...process.env, ...env }, stdio: 'inherit', windowsHide: true };
  // Windows requires a shell to run npm.cmd. The command is fixed, not user input.
  const result = executable === 'npm' && process.platform === 'win32'
    ? spawnSync('cmd.exe', ['/d', '/s', '/c', 'npm ci'], options)
    : spawnSync(executable, args, options);
  if (result.error) throw Error(`${label}: ${result.error.message}`);
  if (result.status !== 0) throw Error(`${label}: command exited with code ${result.status}`);
}

async function ensurePortAvailable(port) {
  await new Promise((fulfill, reject) => {
    const probe = createServer();
    probe.once('error', error => reject(Error(`Port ${port} is unavailable: ${error.message}. Stop the other Vite server first.`)));
    probe.listen(port, '127.0.0.1', () => probe.close(fulfill));
  });
}

function hashFile(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

async function awaitVerifiedSite(port) {
  const url = `http://127.0.0.1:${port}/demo/manifest.json`;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (server?.exitCode !== null) throw Error('Vite exited before the demo was ready');
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1000), cache: 'no-store' });
      if (response.ok) {
        const manifest = await response.json();
        assertSyntheticV2Manifest(manifest);
        return;
      }
    } catch (error) {
      if (error.message.includes('Demo ' ) || error.message.includes('artifact')) throw error;
    }
    await delay(200);
  }
  throw Error('Vite did not serve the verified synthetic manifest within ten seconds');
}

async function main() {
  if (argumentsList.length !== 2 || argumentsList[0] !== '--port') {
    throw Error('Usage: node apps/web/scripts/serve-demo.mjs --port 5173');
  }
  const port = parseDemoPort(argumentsList[1]);
  if (Number(process.versions.node.split('.')[0]) < 22) {
    throw Error('Node.js 22 or newer is required');
  }
  if (!existsSync(join(repo, 'uv.lock')) || !existsSync(join(web, 'package-lock.json'))) {
    throw Error('Expected repository lockfiles not found. Run from a complete Patchline checkout.');
  }
  await ensurePortAvailable(port);
  if (!existsSync(join(web, 'node_modules', 'vite', 'bin', 'vite.js'))) {
    run('INSTALL FRONTEND LOCKFILE', 'npm', ['ci'], web);
  }
  // uv run --locked prepares the Python environment when necessary.
  temp = mkdtempSync(join(tmpdir(), 'patchline-local-demo-'));
  const database = join(temp, 'fixture.duckdb');
  const exports = join(temp, 'exports');
  const publicDir = join(temp, 'public');
  const demo = join(publicDir, 'demo');
  const dbEnv = { PATCHLINE_DUCKDB_PATH: database };
  console.log('\nLOCAL DEMO: SYNTHETIC FIXTURE ONLY. No live feeds or local archived data will be modified.');
  run('CREATE ISOLATED SYNTHETIC WAREHOUSE', 'uv', ['run', '--locked', 'python', '-m', 'patchline.fixtures.ci_warehouse', 'create', '--output', database]);
  run('BUILD DBT MODELS', 'uv', ['run', '--locked', 'dbt', 'run', '--project-dir', 'dbt', '--profiles-dir', 'dbt'], repo, dbEnv);
  run('TEST DBT MODELS', 'uv', ['run', '--locked', 'dbt', 'test', '--project-dir', 'dbt', '--profiles-dir', 'dbt'], repo, dbEnv);
  run('VERIFY M05 RECONCILIATION', 'uv', ['run', '--locked', 'python', '-m', 'patchline.fixtures.ci_warehouse', 'verify-m05', '--output', database]);
  run('CREATE V2 EXPORT', 'uv', ['run', '--locked', 'python', '-m', 'patchline.exports.analytics', 'create', '--contract', 'v2', '--database', database, '--output', exports]);
  run('VERIFY V2 EXPORT AND HASHES', 'uv', ['run', '--locked', 'python', '-m', 'patchline.exports.analytics', 'verify', '--output', exports]);
  const manifest = JSON.parse(readFileSync(join(exports, 'manifest.json'), 'utf8'));
  assertSyntheticV2Manifest(manifest);
  mkdirSync(demo, { recursive: true });
  for (const name of demoJsonNames) {
    const source = join(exports, name);
    const target = join(demo, name);
    if (!existsSync(source) || !statSync(source).isFile()) throw Error(`Verified demo file missing: ${name}`);
    copyFileSync(source, target);
    if (hashFile(source) !== hashFile(target)) throw Error(`Demo copy hash mismatch: ${name}`);
  }
  console.log('\n=== VERIFIED SYNTHETIC DEMO READY ===');
  console.log('Only temporary files are served. apps/web/public/demo is untouched.');
  server = spawn(process.execPath, [
    join(web, 'node_modules', 'vite', 'bin', 'vite.js'),
    '--config', 'vite.e2e.config.mjs', '--host', '127.0.0.1',
    '--port', String(port), '--strictPort',
  ], {
    cwd: web,
    env: { ...process.env, PATCHLINE_E2E_PUBLIC_DIR: publicDir },
    stdio: 'inherit', windowsHide: true,
  });
  server.once('error', error => {
    console.error(`Vite failed to start: ${error.message}`);
    cleanup();
    process.exitCode = 1;
  });
  server.once('exit', code => {
    cleanup();
    process.exitCode = failed ? 1 : (stopping ? 0 : (code ?? 1));
    if (!stopping) console.error(`Local demo server exited unexpectedly: ${code}`);
  });
  await awaitVerifiedSite(port);
  console.log(`\nOPEN http://127.0.0.1:${port}/`);
  console.log('The banner must say SYNTHETIC FIXTURE and patchline.analytics-export.v2.');
  console.log('Press Ctrl+C in this terminal to stop the demo and delete its temporary data.\n');
}

try { await main(); }
catch (error) {
  console.error(`\nP5.2B demo failed: ${error.message}`);
  failed = true;
  if (server && server.exitCode === null) {
    stopping = true;
    server.kill();
  } else cleanup();
  process.exitCode = 1;
}
