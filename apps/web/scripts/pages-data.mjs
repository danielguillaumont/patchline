// Publish guard for the static Spectral Index showcase.
// The Python exporter must create and verify the full v2 bundle first.
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { validateBundle } from '../src/contract.mjs';

export const demoJsonNames = Object.freeze([
  'manifest.json',
  'm03_epss_coverage_of_kev.json',
  'm04_epss_population_summary.json',
  'm04_epss_score_bands.json',
  'm05_kev_epss_cohort_bands.json',
]);

const modelNames = [
  'm03_epss_coverage_of_kev',
  'm04_epss_population_summary',
  'm04_epss_score_bands',
  'm05_kev_epss_cohort_bands',
];
const allowedArtifacts = new Set(modelNames.flatMap(model =>
  ['csv', 'json', 'parquet'].map(ext => `${model}.${ext}`)));

export function assertPublishableManifest(manifest) {
  if (manifest?.data_kind !== 'synthetic_fixture' ||
      manifest?.schema_id !== 'patchline.analytics-export.v2') {
    throw Error('Public showcase accepts verified synthetic v2 exports only');
  }
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length !== 12 ||
      new Set(manifest.artifacts.map(a => a?.path)).size !== 12 ||
      manifest.artifacts.some(a => !allowedArtifacts.has(a?.path))) {
    throw Error('Public showcase requires the exact twelve-artifact manifest');
  }
  if (!Array.isArray(manifest.source_snapshots) ||
      manifest.source_snapshots.length !== 2 ||
      new Set(manifest.source_snapshots.map(s => s?.source)).size !== 2 ||
      manifest.source_snapshots.some(s => !['kev', 'epss'].includes(s?.source))) {
    throw Error('Public showcase requires KEV and EPSS fixture lineage');
  }
  return manifest;
}

function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

export function readAndVerifyPagesData(directory, { fullBundle = false } = {}) {
  const json = name => JSON.parse(readFileSync(join(directory, name), 'utf8'));
  const manifest = assertPublishableManifest(json('manifest.json'));
  const marts = demoJsonNames.slice(1).map(json);
  validateBundle(manifest, ...marts);
  const recordsByPath = new Map(manifest.artifacts.map(a => [a.path, a]));
  const paths = fullBundle ? [...allowedArtifacts] : demoJsonNames.slice(1);
  for (const path of paths) {
    const record = recordsByPath.get(path);
    const location = join(directory, path);
    if (!statSync(location).isFile()) throw Error(`Expected regular artifact: ${path}`);
    const bytes = readFileSync(location);
    if (record.bytes !== bytes.length || record.sha256 !== digest(bytes)) {
      throw Error(`Artifact content or SHA-256 mismatch: ${path}`);
    }
  }
  return { manifest, marts };
}
