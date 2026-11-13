// Strict local-only UI fixture semantics; not a publisher or cryptographic verifier.
const ID = /^CVE-2099-\d{4,}$/;
const ISO = /^\d{4}-\d{2}-\d{2}$/;
const STATES = new Set(['Analyzed', 'Awaiting Analysis']);
const SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', null]);
function requireFixture(ok, reason) { if (!ok) throw Error(`Local CVE fixture rejected: ${reason}`); }
const has = (item, fields) => Object.keys(item).sort().join('|') === [...fields].sort().join('|');
export function validateLocalExplorerFixture(input) {
  requireFixture(input !== null && typeof input === 'object' && !Array.isArray(input), 'invalid root');
  requireFixture(has(input, ['schema_id','data_kind','status','public_release_approved','provenance','scope','dates','epss_model','records']), 'unexpected root fields');
  requireFixture(input.schema_id === 'exploit-atlas.local-explorer-fixture.v1', 'schema version');
  requireFixture(input.data_kind === 'synthetic_fixture' && input.status === 'developer_preview_not_approved_for_publication' && input.public_release_approved === false, 'publication boundary');
  requireFixture(input.provenance === 'hand_curated_fictional_examples_not_source_archive_evidence' && input.scope === 'exactly_three_fictional_cves_not_the_nvd_corpus', 'provenance');
  requireFixture(input.dates && has(input.dates, ['nvd','kev','epss']) && Object.values(input.dates).every(d=>typeof d === 'string' && ISO.test(d) && !Number.isNaN(Date.parse(`${d}T00:00:00Z`))), 'source dates');
  requireFixture(input.epss_model === 'v-ci-synthetic', 'model type');
  requireFixture(Array.isArray(input.records) && input.records.length === 3, 'expected three fictional examples');
  const ids = new Set();
  for (const row of input.records) {
    requireFixture(row && typeof row === 'object' && !Array.isArray(row) && has(row, ['cve_id','title','summary','nvd_status','kev','kev_date_added','epss','epss_percentile','cvss']), 'record shape');
    requireFixture(typeof row.cve_id === 'string' && ID.test(row.cve_id) && !ids.has(row.cve_id), 'fictional CVE ID');
    ids.add(row.cve_id);
    requireFixture(typeof row.title === 'string' && row.title.length > 4 && typeof row.summary === 'string' && row.summary.length > 20, 'description');
    requireFixture(STATES.has(row.nvd_status), 'NVD status');
    requireFixture(typeof row.kev === 'boolean' && ((row.kev_date_added === null && !row.kev) || (row.kev && typeof row.kev_date_added === 'string' && ISO.test(row.kev_date_added))), 'KEV semantics');
    requireFixture((row.epss === null && row.epss_percentile === null) || (typeof row.epss === 'number' && Number.isFinite(row.epss) && row.epss >= 0 && row.epss <= 1 && typeof row.epss_percentile === 'number' && Number.isFinite(row.epss_percentile) && row.epss_percentile >= 0 && row.epss_percentile <= 1), 'EPSS null-vs-zero semantics');
    requireFixture(Array.isArray(row.cvss) && row.cvss.length <= 3, 'CVSS metric array');
    const versions = new Set();
    for (const item of row.cvss) {
      requireFixture(item && typeof item === 'object' && !Array.isArray(item) && has(item, ['version','score','severity','vector']), 'CVSS shape');
      requireFixture(['3.1','4.0','3.0'].includes(item.version) && !versions.has(item.version), 'CVSS distinct versions');
      versions.add(item.version);
      requireFixture((item.score === null && item.severity === null && item.vector === null) || (typeof item.score === 'number' && Number.isFinite(item.score) && item.score >= 0 && item.score <= 10 && SEVERITIES.has(item.severity) && typeof item.vector === 'string' && item.vector.length > 8), 'CVSS missing vs present');
    }
  }
  requireFixture([...ids].sort().join('|') === 'CVE-2099-0001|CVE-2099-0003|CVE-2099-9999', 'unexpected example membership');
  return input;
}
export function filterExplorerRecords(records, { query = '', kev = 'all', epss = 'all', analysis = 'all' } = {}) {
  if (!Array.isArray(records)) throw Error('Invalid explorer rows');
  if (!['all','yes','no'].includes(kev) || !['all','scored','missing'].includes(epss) || !['all','analyzed','pending'].includes(analysis)) throw Error('Invalid explorer filters');
  const term = String(query).trim().toLowerCase();
  return records.filter(row => {
    const matchesText = [row.cve_id,row.title,row.summary].some(value => value.toLowerCase().includes(term));
    return matchesText && (kev === 'all' || row.kev === (kev === 'yes'))
      && (epss === 'all' || (row.epss !== null) === (epss === 'scored'))
      && (analysis === 'all' || (row.nvd_status === 'Analyzed') === (analysis === 'analyzed'));
  }).slice().sort((a,b) => a.cve_id.localeCompare(b.cve_id));
}
export function epssText(score) { return score === null ? 'Not scored' : `${(score * 100).toFixed(2)}%`; }
export function cvssText(metrics) {
  const scored = metrics.find(metric => metric.score !== null);
  return scored ? `${scored.score.toFixed(1)} / CVSS ${scored.version}` : 'Not available';
}
