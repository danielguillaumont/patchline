// Static acceptance gate before any GitHub Pages deployment.
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { demoJsonNames, readAndVerifyPagesData } from './pages-data.mjs';
import { pagesBase } from './pages-base.mjs';

try {
  if (process.argv.length !== 4 || process.argv[2] !== '--dist') {
    throw Error('Usage: node scripts/verify-pages-dist.mjs --dist DIR');
  }
  const dist = resolve(process.argv[3]);
  const indexPath = join(dist,'index.html');
  if (!existsSync(indexPath) || !statSync(indexPath).isFile()) {
    throw Error('Built HTML entry point missing');
  }
  const index = readFileSync(indexPath,'utf8');
  const base = pagesBase();
  if (!index.includes(`${base}assets/`) || /(?:src|href)="\/assets\//.test(index)) {
    throw Error(`Static asset links do not use the ${base} base path`);
  }
  const demo = join(dist,'demo');
  const actualNames = readdirSync(demo).sort();
  const allowedNames = [...demoJsonNames].sort();
  if (JSON.stringify(actualNames) !== JSON.stringify(allowedNames)) {
    throw Error('Static demo must contain exactly the manifest and four approved JSON marts');
  }
  readAndVerifyPagesData(demo);
  console.log(`Exploit Atlas static site verified: ${pagesBase()} assets and synthetic v2 demo only.`);
} catch(error) {
  console.error(`Pages static verification failed: ${error.message}`);
  process.exitCode = 1;
}
