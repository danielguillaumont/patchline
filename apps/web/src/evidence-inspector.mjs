// Manifest metadata is displayed, not cryptographically verified, in the browser.
// The exporter and its Python verifier remain the authority for file digests.
const models = {
  m03_epss_coverage_of_kev: 'M03 / KEV coverage',
  m04_epss_population_summary: 'M04 / EPSS population',
  m04_epss_score_bands: 'M04 / EPSS bands',
  m05_kev_epss_cohort_bands: 'M05 / KEV cohort',
};
const formats = ['csv', 'json', 'parquet'];
const number = new Intl.NumberFormat('en-CA');
const validCount = n => Number.isSafeInteger(n) && n >= 0;

export function validateArtifactRegister(artifacts, rowCounts) {
  const names = Object.keys(rowCounts);
  if (names.length < 3 || names.some(name => !(name in models))) {
    throw Error('Unsupported export artifact model set');
  }
  const expected = new Set(names.flatMap(model => formats.map(ext => `${model}.${ext}`)));
  if (!Array.isArray(artifacts) || artifacts.length !== expected.size) {
    throw Error(`Export artifact register must contain exactly ${expected.size === 9 ? 'nine' : 'twelve'} records`);
  }
  const seen = new Set();
  for (const artifact of artifacts) {
    if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
      throw Error('Invalid export artifact record');
    }
    if (typeof artifact.path !== 'string' || !expected.has(artifact.path) || seen.has(artifact.path)) {
      throw Error('Missing, duplicate, or unexpected export artifact path');
    }
    seen.add(artifact.path);
    const extensionIndex = artifact.path.lastIndexOf('.');
    const model = artifact.path.slice(0, extensionIndex);
    if (artifact.model !== model || !validCount(artifact.bytes)
        || !validCount(artifact.rows) || artifact.rows !== rowCounts[model]) {
      throw Error('Export artifact model, size, or row count mismatch');
    }
    if (typeof artifact.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(artifact.sha256)) {
      throw Error('Malformed export artifact digest');
    }
    if (!Array.isArray(artifact.columns) || artifact.columns.length === 0
        || artifact.columns.some(c => typeof c !== 'string' || !c.trim())
        || new Set(artifact.columns).size !== artifact.columns.length) {
      throw Error('Invalid export artifact column list');
    }
  }
  return artifacts;
}

export function artifactReading(artifact) {
  const extension = artifact.path.slice(artifact.path.lastIndexOf('.') + 1);
  return {
    modelLabel: models[artifact.model] ?? 'Unknown export model',
    formatLabel: extension.toUpperCase(),
    rowsLabel: number.format(artifact.rows),
    bytesLabel: number.format(artifact.bytes),
    columnsLabel: artifact.columns.join(', '),
    digest: artifact.sha256,
  };
}
