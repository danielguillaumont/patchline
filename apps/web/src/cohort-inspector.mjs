// Narrow v2 M05 consumer guard. The Python exporter is the authority for
// schema and cryptographic verification of immutable artifact bytes.
const integer = n => Number.isSafeInteger(n) && n >= 0;
const percent = n => typeof n === 'number' && Number.isFinite(n) && n >= 0 && n <= 100;
const close = (a, b) => typeof a === 'number' && typeof b === 'number' && Math.abs(a - b) <= 1e-6;
const optionalShare = (value, numerator, denominator) => denominator === 0
  ? value === null
  : percent(value) && close(value, 100 * numerator / denominator);
const exists = (row, key) => Object.prototype.hasOwnProperty.call(row, key);

export function validateCohort(manifest, coverage, population, bands, rows) {
  if (!Array.isArray(rows) || rows.length !== 6 || rows.some(r => !r || typeof r !== 'object' || Array.isArray(r))) {
    throw Error('M05 requires exactly six cohort records');
  }
  const kev = manifest.source_snapshots.find(source => source.source === 'kev');
  const epss = manifest.source_snapshots.find(source => source.source === 'epss');
  if (!kev || !epss || !integer(coverage.denominator_total_kev)
      || !integer(coverage.numerator_matched_kev) || !integer(coverage.unmatched_kev)) {
    throw Error('Missing M05 source lineage or denominators');
  }
  const total = coverage.denominator_total_kev;
  const scored = coverage.numerator_matched_kev;
  const missing = coverage.unmatched_kev;
  if (scored + missing !== total || population.scored_cve_count !== epss.row_count) {
    throw Error('M05 source population reconciliation failed');
  }
  const sorted = [...rows].sort((a, b) => a.band_order - b.band_order);
  const reference = [...bands].sort((a, b) => a.band_order - b.band_order);
  const required = [
    'metric_id', 'band_order', 'cohort_category', 'band_label', 'kev_cve_count',
    'kev_snapshot_id', 'epss_snapshot_id', 'kev_catalog_date_released', 'epss_source_date',
    'kev_retrieved_at_utc', 'epss_retrieved_at_utc', 'epss_model_version',
    'denominator_all_kev', 'denominator_scored_kev', 'unscored_kev',
    'lower_bound', 'upper_bound', 'upper_inclusive', 'share_all_kev_percent',
    'share_scored_kev_percent', 'full_epss_band_count', 'full_epss_denominator',
    'full_epss_population_percent',
  ];
  for (const [index, row] of sorted.entries()) {
    const order = index + 1;
    if (required.some(field => !exists(row, field)) || row.metric_id !== 'M05'
        || row.band_order !== order || !integer(row.kev_cve_count)) {
      throw Error('M05 band order, required fields, or counts are invalid');
    }
    const aligned = [
      ['kev_snapshot_id', kev.snapshot_id], ['epss_snapshot_id', epss.snapshot_id],
      ['kev_catalog_date_released', kev.source_date], ['epss_source_date', epss.source_date],
      ['kev_retrieved_at_utc', kev.retrieved_at_utc],
      ['epss_retrieved_at_utc', epss.retrieved_at_utc],
      ['epss_model_version', epss.model_version],
      ['denominator_all_kev', total], ['denominator_scored_kev', scored],
      ['unscored_kev', missing],
    ];
    if (aligned.some(([field, value]) => row[field] !== value)) {
      throw Error('M05 lineage or denominator mismatch');
    }
    if (!optionalShare(row.share_all_kev_percent, row.kev_cve_count, total)) {
      throw Error('M05 all-KEV share mismatch');
    }
    if (order <= 5) {
      const full = reference[index];
      if (row.cohort_category !== 'scored_band'
          || !optionalShare(row.share_scored_kev_percent, row.kev_cve_count, scored)
          || row.band_label !== full.band_label
          || row.lower_bound !== full.lower_bound
          || row.upper_bound !== full.upper_bound
          || row.upper_inclusive !== full.upper_inclusive
          || row.full_epss_band_count !== full.cve_count
          || row.full_epss_denominator !== population.scored_cve_count
          || row.full_epss_population_percent !== full.population_percent) {
        throw Error('M05 scored bands must reconcile to M04 and scored KEV');
      }
    } else if (row.cohort_category !== 'unscored_kev'
        || row.band_label !== 'No matching EPSS score' || row.kev_cve_count !== missing
        || ['lower_bound', 'upper_bound', 'upper_inclusive', 'share_scored_kev_percent',
          'full_epss_band_count', 'full_epss_denominator', 'full_epss_population_percent']
          .some(field => row[field] !== null)) {
      throw Error('M05 unscored KEV category must not impute an EPSS probability');
    }
  }
  if (sorted.slice(0, 5).reduce((sum, row) => sum + row.kev_cve_count, 0) !== scored
      || sorted.reduce((sum, row) => sum + row.kev_cve_count, 0) !== total) {
    throw Error('M05 KEV cohort total does not reconcile');
  }
  return sorted;
}

const number = new Intl.NumberFormat('en-CA');
export const cohortPercent = value => value === null ? 'Not defined' : `${value.toFixed(2)}%`;
export function cohortReading(row) {
  return {
    label: row.band_label,
    kevCount: number.format(row.kev_cve_count),
    epssCount: number.format(row.full_epss_band_count),
    scoredShare: cohortPercent(row.share_scored_kev_percent),
    epssShare: cohortPercent(row.full_epss_population_percent),
    allKevShare: cohortPercent(row.share_all_kev_percent),
  };
}
