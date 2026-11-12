// Stages only five JSON files from a complete, verified synthetic v2 export.
// Refuses to overwrite an existing public demo directory.
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, renameSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { demoJsonNames, readAndVerifyPagesData } from './pages-data.mjs';

function option(flag) {
  const position = process.argv.indexOf(flag);
  if (position === -1 || position + 1 >= process.argv.length) {
    throw Error('Usage: node scripts/stage-pages-data.mjs --exports DIR --destination DIR');
  }
  return resolve(process.argv[position + 1]);
}

let staging;
try {
  if (process.argv.length !== 6 || process.argv[2] !== '--exports' || process.argv[4] !== '--destination') {
    throw Error('Usage: node scripts/stage-pages-data.mjs --exports DIR --destination DIR');
  }
  const source = option('--exports');
  const destination = option('--destination');
  if (source === destination || existsSync(destination)) {
    throw Error('Destination must not exist. Refusing to overwrite a demo.');
  }
  readAndVerifyPagesData(source, {fullBundle:true});
  mkdirSync(dirname(destination), {recursive:true});
  staging = mkdtempSync(join(dirname(destination), '.patchline-pages-stage-'));
  for (const name of demoJsonNames) copyFileSync(join(source,name), join(staging,name));
  readAndVerifyPagesData(staging);
  renameSync(staging,destination);
  staging = null;
  console.log('P5.2C1 synthetic Pages data staged: five JSON files, twelve source artifacts verified.');
} catch (error) {
  console.error(`Pages staging failed: ${error.message}`);
  process.exitCode = 1;
} finally {
  if (staging) rmSync(staging,{recursive:true,force:true});
}
