// Pages CI entry point; never creates an Explorer route while review is pending.
import { stagePublicExplorer } from './explorer-public-release.mjs';
try {
  if (process.argv.length !== 4 || process.argv[2] !== '--destination') {
    throw Error('Usage: node stage-public-explorer.mjs --destination ABSOLUTE-TEMP-PATH/explorer');
  }
  const result = stagePublicExplorer(process.argv[3]);
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
