// Formatting only. The validated M04 export owns band counts, shares, and labels.
const countFormat = new Intl.NumberFormat('en-CA');

export function bandReading(band, scoredPopulation) {
  const rangeLabel = typeof band.band_label === 'string' && band.band_label.trim()
    ? band.band_label.trim()
    : `Band ${band.band_order} (interval not provided)`;
  const shareLabel = band.population_percent === null
    ? 'Not defined'
    : `${band.population_percent.toFixed(2)}%`;
  const countLabel = countFormat.format(band.cve_count);
  const populationLabel = countFormat.format(scoredPopulation);
  return {
    rangeLabel,
    shareLabel,
    countLabel,
    populationLabel,
    accessibleLabel: `Band ${band.band_order}, ${rangeLabel}: ${countLabel} of ${populationLabel} scored CVEs, ${shareLabel} of the EPSS population. Select to inspect.`,
    emptyNote: scoredPopulation === 0
      ? 'The selected EPSS snapshot has no scored CVEs, so population shares are not defined.'
      : band.cve_count === 0
        ? 'Zero scored CVEs fall in this interval for the selected snapshot.'
        : 'This count covers the full scored EPSS population, not only KEV entries.',
  };
}
