// EA-02A: Derive non-prescriptive language only from a validated export bundle.
// Never use the source-pair join rate as organizational risk or exploitation probability.
const count = n => new Intl.NumberFormat('en-CA').format(n);

export function intelligenceBrief(manifest, coverage, population) {
  if (!manifest || !coverage || !population || !['synthetic_fixture', 'archived_source_snapshots'].includes(manifest.data_kind)) {
    throw Error('Intelligence brief requires a classified, validated export');
  }
  const total = coverage.denominator_total_kev;
  const matched = coverage.numerator_matched_kev;
  const unmatched = coverage.unmatched_kev;
  if (![total, matched, unmatched, population.scored_cve_count].every(n => Number.isSafeInteger(n) && n >= 0) || matched + unmatched !== total) {
    throw Error('Intelligence brief requires reconciled population counts');
  }
  const sources = manifest.source_snapshots || [];
  const kevDate = sources.find(s => s.source === 'kev')?.source_date;
  const epssDate = sources.find(s => s.source === 'epss')?.source_date;
  if (typeof kevDate !== 'string' || typeof epssDate !== 'string') {
    throw Error('Intelligence brief requires source dates');
  }
  const sample = manifest.data_kind === 'synthetic_fixture';
  const headline = total === 0
    ? 'No KEV records are available to compare in this selection.'
    : `${count(matched)} of ${count(total)} KEV ${total === 1 ? 'record has' : 'records have'} a matching EPSS score.`;
  const unmatchedNote = total === 0
    ? 'Without KEV records, coverage cannot be calculated.'
    : unmatched === 0
      ? 'Every KEV record has a corresponding EPSS score in this selection.'
      : `${count(unmatched)} ${unmatched === 1 ? 'record has' : 'records have'} no EPSS match. Missing data must not be treated as zero probability.`;
  return {
    classification: sample ? 'SYNTHETIC EXAMPLE' : 'HISTORICAL SNAPSHOT',
    headline,
    unmatchedNote,
    scopeNote: sample
      ? 'These figures come from fabricated test records. They demonstrate the interface, not real-world exploitation trends.'
      : 'These figures describe one archived source pair, not a current feed or your organization.',
    why: 'CISA KEV lists vulnerabilities with evidence of exploitation. FIRST EPSS estimates exploitation probability over the next 30 days. A matching CVE identifier is a data link, not proof of a new attack.',
    next: 'For a real operational decision, first confirm affected assets, exposure and vendor remediation guidance. Public intelligence alone cannot identify vulnerabilities in your environment.',
    sourceLine: `KEV ${kevDate} / EPSS ${epssDate} / ${count(population.scored_cve_count)} scored EPSS CVEs`,
  };
}
