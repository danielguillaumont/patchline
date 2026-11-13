// EA-05B1: guarded candidate contract. This does NOT approve or publish a dataset.
import { createHash } from 'node:crypto';

const hasOnly = (obj, keys) => obj !== null && typeof obj === 'object' && !Array.isArray(obj)
  && Object.keys(obj).sort().join('|') === [...keys].sort().join('|');
const assert = (condition, detail) => { if (!condition) throw Error(`EA05B public candidate rejected: ${detail}`); };
const ids = ['CVE-2099-0001', 'CVE-2099-0003', 'CVE-2099-9999'];
const iso = /^\d{4}-\d{2}-\d{2}$/;
const dates = new Set(['2026-01-10', '2026-01-11', '2026-01-12', '2026-01-15']);
const states = new Set(['Analyzed', 'Awaiting Analysis']);
const severity = new Set(['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const cvssVersions = new Set(['3.0', '3.1', '4.0']);

export const CANDIDATE_SCHEMA = 'exploit-atlas.public-explorer-candidate.v1';
export const MANIFEST_SCHEMA = 'exploit-atlas.public-explorer-candidate-manifest.v1';

export function canonicalBytes(value) {
  function sort(input) {
    if (Array.isArray(input)) return input.map(sort);
    if (input !== null && typeof input === 'object') {
      return Object.fromEntries(Object.keys(input).sort().map(key => [key, sort(input[key])]));
    }
    return input;
  }
  return Buffer.from(`${JSON.stringify(sort(value))}\n`, 'utf8');
}
export function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

function validDate(s) {
  return typeof s === 'string' && iso.test(s) && dates.has(s) &&
    !Number.isNaN(Date.parse(`${s}T00:00:00Z`));
}

export function validatePublicCandidate(doc) {
  assert(hasOnly(doc, ['schema_id','data_kind','publication_state','public_release_approved','provenance','scope','dates','epss_model','records']), 'unexpected document fields');
  assert(doc.schema_id === CANDIDATE_SCHEMA, 'schema');
  assert(doc.data_kind === 'synthetic_fixture', 'data classification');
  assert(doc.publication_state === 'candidate_for_manual_review_not_deployed' && doc.public_release_approved === false, 'must remain unapproved');
  assert(doc.provenance === 'hand_curated_fictional_examples_not_source_archive_evidence', 'provenance');
  assert(doc.scope === 'exactly_three_fictional_cves_not_the_nvd_corpus', 'corpus scope');
  assert(hasOnly(doc.dates, ['nvd','kev','epss']) && doc.dates.nvd === '2026-01-12' && doc.dates.kev === '2026-01-15' && doc.dates.epss === '2026-01-15', 'illustrative dates');
  assert(doc.epss_model === 'v-ci-synthetic', 'illustrative EPSS model');
  assert(Array.isArray(doc.records) && doc.records.length === 3, 'record count');
  assert(doc.records.map(x => x?.cve_id).join('|') === ids.join('|'), 'fictional CVE membership/order');
  for (const row of doc.records) {
    assert(hasOnly(row, ['cve_id','title','summary','nvd_status','kev','kev_date_added','epss','epss_percentile','cvss']), 'unexpected record fields');
    assert(typeof row.title === 'string' && row.title.length > 4 && row.title.length <= 100, 'record title');
    assert(typeof row.summary === 'string' && row.summary.length > 20 && row.summary.length <= 350, 'record summary');
    assert(states.has(row.nvd_status), 'NVD state');
    assert(typeof row.kev === 'boolean' && (row.kev ? validDate(row.kev_date_added) : row.kev_date_added === null), 'KEV presence/date');
    assert((row.epss === null && row.epss_percentile === null) ||
      (typeof row.epss === 'number' && Number.isFinite(row.epss) && row.epss >= 0 && row.epss <= 1 &&
      typeof row.epss_percentile === 'number' && Number.isFinite(row.epss_percentile) && row.epss_percentile >= 0 && row.epss_percentile <= 1), 'EPSS missing versus zero');
    assert(Array.isArray(row.cvss) && row.cvss.length <= 3, 'CVSS metrics');
    const seen = new Set();
    for (const m of row.cvss) {
      assert(hasOnly(m, ['version','score','severity','vector']), 'CVSS metric fields');
      assert(cvssVersions.has(m.version) && !seen.has(m.version), 'CVSS version');
      seen.add(m.version);
      assert((m.score === null && m.severity === null && m.vector === null) ||
        (typeof m.score === 'number' && Number.isFinite(m.score) && m.score >= 0 && m.score <= 10 &&
        severity.has(m.severity) && typeof m.vector === 'string' && m.vector.startsWith(`CVSS:${m.version}/`) && m.vector.length <= 250), 'CVSS metric');
    }
  }
  // Cross-record constraints lock the intended demonstrations, not just their types.
  assert(doc.records[0].kev && doc.records[0].epss === 0 && doc.records[0].cvss.some(x => x.version === '3.1' && x.score === 9.8), 'zero/critical example');
  assert(doc.records[1].kev && doc.records[1].epss === null && doc.records[1].cvss.length === 0, 'missing EPSS example');
  assert(!doc.records[2].kev && doc.records[2].nvd_status === 'Awaiting Analysis' && doc.records[2].epss === null && doc.records[2].cvss.length === 0, 'pending analysis example');
  return doc;
}

export function makeCandidateManifest(dataBytes) {
  return {
    schema_id: MANIFEST_SCHEMA,
    data_kind: 'synthetic_fixture',
    publication_state: 'candidate_for_manual_review_not_deployed',
    public_release_approved: false,
    source_scope: 'hand_curated_cve_2099_examples_only',
    source_archives_reverified: false,
    filename: 'cve-records.json',
    sha256: sha256(dataBytes),
    bytes: dataBytes.length,
    record_count: 3,
  };
}
export function validateCandidateManifest(m, dataBytes) {
  assert(hasOnly(m, ['schema_id','data_kind','publication_state','public_release_approved','source_scope','source_archives_reverified','filename','sha256','bytes','record_count']), 'manifest fields');
  const want = makeCandidateManifest(dataBytes);
  assert(canonicalBytes(m).equals(canonicalBytes(want)), 'manifest integrity/identity');
  return m;
}
