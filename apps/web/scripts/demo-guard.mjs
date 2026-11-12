// A small boundary check around an already Python-verified synthetic export.
// This does not replace exporter schema, hash, or reconciliation verification.
const marts = [
  'm03_epss_coverage_of_kev',
  'm04_epss_population_summary',
  'm04_epss_score_bands',
  'm05_kev_epss_cohort_bands',
];

export const demoJsonNames = Object.freeze([
  'manifest.json',
  ...marts.map(name => `${name}.json`),
]);

export function assertSyntheticV2Manifest(manifest) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw Error('Demo manifest must be an object');
  }
  if (manifest.schema_id !== 'patchline.analytics-export.v2') {
    throw Error('Demo requires explicit analytics-export.v2');
  }
  if (manifest.data_kind !== 'synthetic_fixture') {
    throw Error('Demo refuses data that is not classified synthetic_fixture');
  }
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length !== 12) {
    throw Error('Demo requires all twelve v2 artifact records');
  }
  const expected = new Set(marts.flatMap(name =>
    ['csv', 'json', 'parquet'].map(extension => `${name}.${extension}`)));
  const actual = manifest.artifacts.map(item => item?.path);
  if (actual.some(path => typeof path !== 'string' || !expected.has(path)) ||
      new Set(actual).size !== expected.size) {
    throw Error('Unexpected, missing, or duplicate artifact paths');
  }
  return true;
}

export function parseDemoPort(text) {
  const port = Number(text);
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) {
    throw Error('Demo port must be an integer between 1024 and 65535');
  }
  return port;
}
