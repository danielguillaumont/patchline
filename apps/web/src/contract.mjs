// Local, intentionally narrow read-only consumer guard. Backend JSON Schemas remain authoritative.
const records = (value, n) => Array.isArray(value) && value.length === n && value.every(x => x && typeof x === 'object' && !Array.isArray(x));
const integer = (n) => Number.isSafeInteger(n) && n >= 0;
const finite = (n) => typeof n === 'number' && Number.isFinite(n);
const probability = (n) => n === null || (finite(n) && n >= 0 && n <= 1);
export function validateBundle(manifest, m03, summary, bands) {
  if (!manifest || manifest.schema_id !== 'patchline.analytics-export.v1' || !['synthetic_fixture','archived_source_snapshots'].includes(manifest.data_kind)) throw Error('Unsupported export manifest or data classification');
  if (!records(manifest.source_snapshots, 2) || !records(manifest.artifacts, 9)) throw Error('Incomplete source manifest');
  const sources = Object.fromEntries(manifest.source_snapshots.map(s => [s.source, s]));
  if (!sources.kev || !sources.epss || ![sources.kev,sources.epss].every(s => typeof s.snapshot_id === 'string' && s.snapshot_id.length > 0 && typeof s.source_date === 'string' && integer(s.row_count))) throw Error('Invalid source lineage');
  if (!records(m03, 1) || !records(summary, 1) || !records(bands, 5)) throw Error('Incorrect analytical model row counts');
  const c = m03[0], s = summary[0];
  if (c.metric_id !== 'M03' || s.metric_id !== 'M04' || ![c.denominator_total_kev,c.numerator_matched_kev,c.unmatched_kev,s.scored_cve_count].every(integer)) throw Error('Invalid analytical counts');
  if (c.denominator_total_kev !== c.numerator_matched_kev + c.unmatched_kev || c.denominator_total_kev !== sources.kev.row_count || s.scored_cve_count !== sources.epss.row_count) throw Error('Population reconciliation failed');
  if (c.coverage_percent === null ? c.denominator_total_kev !== 0 : !finite(c.coverage_percent) || Math.abs(c.coverage_percent - 100*c.numerator_matched_kev/c.denominator_total_kev) > 1e-6) throw Error('Invalid M03 coverage');
  if (c.kev_snapshot_id !== sources.kev.snapshot_id || c.epss_snapshot_id !== sources.epss.snapshot_id || s.epss_snapshot_id !== sources.epss.snapshot_id || c.kev_catalog_date_released !== sources.kev.source_date || c.epss_source_date !== sources.epss.source_date || s.epss_source_date !== sources.epss.source_date) throw Error('Metric source mismatch');
  const sorted = [...bands].sort((a,b)=>a.band_order-b.band_order);
  if (sorted.some((b,i)=> b.band_order!==i+1 || b.metric_id!=='M04' || !integer(b.cve_count) || b.denominator_scored_cves!==s.scored_cve_count || b.epss_snapshot_id!==sources.epss.snapshot_id || b.epss_source_date!==sources.epss.source_date || (s.scored_cve_count ? !finite(b.population_percent) || Math.abs(b.population_percent-100*b.cve_count/s.scored_cve_count)>1e-6 : b.population_percent!==null))) throw Error('Band contract mismatch');
  if (sorted.reduce((n,b)=>n+b.cve_count,0)!==s.scored_cve_count) throw Error('EPSS band reconciliation failed');
  if (!['min_epss','max_epss','mean_epss','p25_epss','median_epss','p75_epss','p90_epss'].every(k=>probability(s[k]))) throw Error('Invalid EPSS probability');
  return {manifest, coverage:c, population:s, bands:sorted};
}
