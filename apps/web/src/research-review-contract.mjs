// EA-02C2: Browser-side structural review of a LOCAL-only insight pack.
// This is NOT a replacement for independent Python verification of source bytes.
export const reviewSchemaId = 'exploit-atlas.archived-insights.v1';
const idOrder = ['highest-epss-band', 'epss-coverage', 'epss-at-least-point-one'];
const rootKeys = ['data_kind', 'global_limitation', 'insights', 'method', 'population_relation',
  'public_release_approved', 'publication_scope', 'schema_id', 'source_snapshots'];
const sourceKeys = ['row_count', 'snapshot_id', 'source', 'source_date'];
const metricKeys = ['count', 'label', 'population', 'share_percent'];
const contentKeys = ['caveat', 'headline', 'id', 'measures', 'next_question', 'plain_language', 'why_it_matters'];

function refuse(message) { throw new Error(`Research review rejected: ${message}`); }
function record(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) refuse(`${label} must be an object`);
  return value;
}
function exactlyKeys(value, keys, label) {
  if (Object.keys(record(value, label)).sort().join('|') !== [...keys].sort().join('|')) {
    refuse(`${label} has missing or unexpected fields`);
  }
}
function nonempty(value, label, max = 1000) {
  if (typeof value !== 'string' || value.trim().length === 0 || value.length > max) {
    refuse(`${label} is missing or invalid`);
  }
}
function integer(value, label, allowZero = false) {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1)) refuse(`${label} must be a valid integer`);
}
function validateMetric(value, label) {
  exactlyKeys(value, metricKeys, label);
  nonempty(value.label, `${label} label`, 80);
  integer(value.count, `${label} count`, true);
  integer(value.population, `${label} denominator`);
  if (value.count > value.population ||
      value.share_percent !== (100 * value.count / value.population).toFixed(2)) {
    refuse(`${label} percentage does not reconcile with its count and denominator`);
  }
}
export function validateResearchReviewPack(input) {
  const pack = record(input, 'insight pack');
  exactlyKeys(pack, rootKeys, 'insight pack');
  if (pack.schema_id !== reviewSchemaId || pack.data_kind !== 'archived_source_snapshots' ||
    pack.public_release_approved !== false || pack.publication_scope !== 'local_review_only' ||
    pack.method !== 'verified_v2_m03_m04_m05_descriptive_comparison' ||
    pack.population_relation !== 'scored_kev_is_subset_of_full_scored_epss') {
    refuse('unexpected contract, provenance, or publication status');
  }
  nonempty(pack.global_limitation, 'global limitation');
  if (!Array.isArray(pack.source_snapshots) || pack.source_snapshots.length !== 2) {
    refuse('expected exactly two source snapshots');
  }
  pack.source_snapshots.forEach((source, index) => {
    exactlyKeys(source, sourceKeys, `source ${index}`);
    if (source.source !== ['kev', 'epss'][index]) refuse('expected ordered KEV and EPSS snapshots');
    if (typeof source.snapshot_id !== 'string' || !/^[a-f0-9]{64}$/.test(source.snapshot_id)) {
      refuse('invalid source snapshot digest');
    }
    nonempty(source.source_date, 'source timestamp', 60);
    if (!/^20\d\d-\d\d-\d\dT/.test(source.source_date) ||
        !Number.isFinite(Date.parse(source.source_date))) refuse('invalid source timestamp');
    integer(source.row_count, 'source population');
  });
  if (!Array.isArray(pack.insights) || pack.insights.length !== 3) {
    refuse('expected exactly three reviewed findings');
  }
  pack.insights.forEach((insight, index) => {
    const optional = index === 1 ? ['unmatched_kev_count'] : ['threshold'];
    exactlyKeys(insight, [...contentKeys, ...optional], `finding ${index}`);
    if (insight.id !== idOrder[index]) refuse('unknown or reordered finding');
    for (const key of ['headline', 'plain_language', 'why_it_matters', 'next_question', 'caveat']) {
      nonempty(insight[key], `finding ${index} ${key}`, 1000);
    }
    if (!Array.isArray(insight.measures) || insight.measures.length !== (index === 1 ? 1 : 2)) {
      refuse('incorrect number of comparison populations');
    }
    insight.measures.forEach((metric, j) => validateMetric(metric, `finding ${index} measure ${j}`));
    if (index !== 1 && insight.threshold !== (index === 0 ? 'EPSS 0.500 to 1.000 inclusive' : 'EPSS >= 0.100')) {
      refuse('changed interval definition');
    }
  });
  const [high, coverage, above] = pack.insights;
  const kevTotal = pack.source_snapshots[0].row_count;
  const epssTotal = pack.source_snapshots[1].row_count;
  const scoredKev = coverage.measures[0].count;
  if (coverage.measures[0].label !== 'KEV records with EPSS' ||
    coverage.measures[0].population !== kevTotal ||
    !Number.isSafeInteger(coverage.unmatched_kev_count) ||
    coverage.unmatched_kev_count < 0 ||
    coverage.unmatched_kev_count + scoredKev !== kevTotal ||
    scoredKev > epssTotal) refuse('KEV source coverage does not reconcile');
  for (const group of [high, above]) {
    if (group.measures[0].label !== 'Scored KEV' || group.measures[0].population !== scoredKev ||
      group.measures[1].label !== 'Full scored EPSS' || group.measures[1].population !== epssTotal) {
      refuse('population label or denominator mismatch');
    }
  }
  if (high.measures.some((metric, i) => metric.count > above.measures[i].count)) {
    refuse('highest band cannot exceed at-or-above-0.100 band');
  }
  return pack;
}

export function formatReviewSourceDate(sourceDate) {
  const day = sourceDate.slice(0, 10);
  return new Date(`${day}T12:00:00Z`).toLocaleDateString('en-CA', {
    timeZone: 'UTC', year: 'numeric', month: 'short', day: 'numeric',
  });
}
