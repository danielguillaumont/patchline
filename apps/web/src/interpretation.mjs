// EA-02B: Source-scoped editorial readings of already validated analytical aggregates.
// Never interpret a source distribution as asset exposure or organizational risk.
const format = new Intl.NumberFormat('en-CA');
const isCount = value => Number.isSafeInteger(value) && value >= 0;
const classified = value => ['synthetic_fixture', 'archived_source_snapshots'].includes(value);
const scope = dataKind => dataKind === 'synthetic_fixture'
  ? 'Synthetic illustration only. These are fabricated test counts, not observed vulnerability trends.'
  : 'Archived source-pair observation only. Not a live measure or a forecast for an organization.';

export const glossaryTerms = Object.freeze([
  { term: 'CVE', meaning: 'A shared identifier for a publicly disclosed vulnerability. An identifier does not by itself establish exposure or exploitation.' },
  { term: 'KEV', meaning: 'CISA Known Exploited Vulnerabilities: catalog entries supported by evidence of known exploitation. This is not a list of vulnerabilities in your environment.' },
  { term: 'EPSS', meaning: 'FIRST Exploit Prediction Scoring System: an estimate of a vulnerability\'s exploitation probability over the next 30 days, not a record of attacks.' },
  { term: 'CVSS', meaning: 'Common Vulnerability Scoring System: a measure of vulnerability severity characteristics, not the same as EPSS exploitation probability.' },
  { term: 'Coverage', meaning: 'The fraction of one source population with a matching record in another. Here, it measures a CVE join, not security readiness.' },
  { term: 'Population', meaning: 'The complete group counted for one percentage. In Figure 01, that is all scored CVEs in the selected EPSS snapshot.' },
  { term: 'Cohort', meaning: 'A specific subset for comparison. Here, scored KEV CVEs are also part of the full EPSS population, so the two groups overlap.' },
  { term: 'Percentile', meaning: 'A relative position among other scores. It is not itself an exploitation probability.' },
]);

export function distributionOverview(dataKind, bands, scoredPopulation) {
  if (!classified(dataKind) || !isCount(scoredPopulation) || !Array.isArray(bands)
      || bands.length !== 5 || bands.some(b => !b || !isCount(b.cve_count) || !isCount(b.band_order))
      || bands.reduce((sum, b) => sum + b.cve_count, 0) !== scoredPopulation) {
    throw Error('Distribution reading requires classified, reconciled M04 bands');
  }
  if (scoredPopulation === 0) {
    return {
      headline: 'There are no scored CVEs to compare.',
      detail: 'All five intervals are empty in this selection. Population percentages are not defined.',
      scope: scope(dataKind),
    };
  }
  const largest = bands.reduce((best, band) => band.cve_count > best.cve_count ? band : best, bands[0]);
  if (typeof largest.population_percent !== 'number' || !Number.isFinite(largest.population_percent)
      || largest.population_percent < 0 || largest.population_percent > 100) {
    throw Error('Largest EPSS band has no valid population share');
  }
  const intervalLabel = typeof largest.band_label === 'string' && largest.band_label.trim()
    ? largest.band_label.trim() : `Band ${largest.band_order} (interval label unavailable)`;
  return {
    headline: `${format.format(largest.cve_count)} of ${format.format(scoredPopulation)} scored CVEs fall in the largest interval.`,
    detail: `That interval is ${intervalLabel} (${largest.population_percent.toFixed(2)}% of this EPSS population). The chart shows how scores are distributed, not how many attacks occurred.`,
    scope: scope(dataKind),
  };
}

export function cohortIntervalNarrative(dataKind, row, scoredKev, fullEpss) {
  if (!classified(dataKind) || !row || row.cohort_category !== 'scored_band'
      || !isCount(scoredKev) || !isCount(fullEpss) || !isCount(row.kev_cve_count)
      || !isCount(row.full_epss_band_count) || row.kev_cve_count > scoredKev
      || row.full_epss_band_count > fullEpss || typeof row.band_label !== 'string') {
    throw Error('Cohort reading requires a classified, reconciled M05 scored interval');
  }
  const share = (value, denominator, supplied) => {
    if (denominator === 0) {
      if (supplied !== null || value !== 0) throw Error('Empty cohort must have an undefined share');
      return 'not defined';
    }
    if (typeof supplied !== 'number' || !Number.isFinite(supplied) || supplied < 0 || supplied > 100
        || Math.abs(100 * value / denominator - supplied) > 0.011) {
      throw Error('Cohort share does not reconcile to its denominator');
    }
    return `${supplied.toFixed(2)}%`;
  };
  const kevShare = share(row.kev_cve_count, scoredKev, row.share_scored_kev_percent);
  const epssShare = share(row.full_epss_band_count, fullEpss, row.full_epss_population_percent);
  return {
    headline: `How to read ${row.band_label}`,
    detail: `${format.format(row.kev_cve_count)} of ${format.format(scoredKev)} scored KEV CVEs (${kevShare}) and ${format.format(row.full_epss_band_count)} of ${format.format(fullEpss)} full EPSS CVEs (${epssShare}) fall in this same interval.`,
    caveat: 'Scored KEV is a subset of the full EPSS population. These are overlapping distributions, not independent samples or observed attack rates.',
    scope: scope(dataKind),
  };
}
