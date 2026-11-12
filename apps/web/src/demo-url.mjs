// Build-time BASE_URL determines where a static Spectral Index installation lives.
// Root for local development, /patchline/ for the GitHub Pages project site.
const names = new Set([
  'manifest.json',
  'm03_epss_coverage_of_kev.json',
  'm04_epss_population_summary.json',
  'm04_epss_score_bands.json',
  'm05_kev_epss_cohort_bands.json',
]);

export function demoFileUrl(baseUrl, fileName) {
  if (typeof baseUrl !== 'string' || !/^\/(?:[a-zA-Z0-9_-]+\/)*$/.test(baseUrl)) {
    throw Error('Invalid Spectral Index base URL');
  }
  if (!names.has(fileName)) {
    throw Error('Unsupported demo JSON path');
  }
  return `${baseUrl}demo/${fileName}`;
}
