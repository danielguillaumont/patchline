"""EA-02B guarded local patch application; source zip is unpacked outside Git.

Usage: uv run --locked python <extracted>/exploit-atlas/scripts/EA02B-Apply.py --repo <repository>
Only modifies the clean, expected EA-02B development branch.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path

BRANCH = "feat/ea02b-chart-interpretation"
BASELINE = "d4f45ed"
NEW_FILES = (
    "apps/web/src/interpretation.mjs",
    "apps/web/src/interpretation.css",
    "apps/web/tests/interpretation.test.mjs",
    "apps/web/tests/e2e/interpretation.spec.mjs",
    "docs/ea02b-chart-interpretation.md",
    "scripts/EA02B-Apply.py",
)

GLOSSARY_COMPONENT = '''function EvidenceGlossary() {
  return <section className="interpretation-lexicon" aria-label="Glossary of intelligence terms">
    <div className="interpretation-lexicon-heading"><div><span className="eyebrow">FIELD NOTES / DEFINITIONS</span><h2>Know the language.</h2></div><p>Open any definition. Understanding the terms matters before comparing the numbers.</p></div>
    <div className="interpretation-terms">
      {glossaryTerms.map(item => <details key={item.term}><summary>{item.term}</summary><p>{item.meaning}</p></details>)}
    </div>
  </section>;
}

'''

DISTRIBUTION_READING = '''    <section className="chart-reading" aria-label="EPSS distribution interpretation">
      <span className="eyebrow">READING FIGURE 01</span>
      <h4>{overview.headline}</h4><p>{overview.detail}</p><small>{overview.scope}</small>
    </section>
'''

COHORT_READING = '''      <section className="chart-reading chart-reading-selected" aria-label="Selected cohort interval interpretation" aria-live="polite" aria-atomic="true">
        <span className="eyebrow">READING THE SELECTED INTERVAL</span>
        <h4>{intervalNarrative.headline}</h4><p>{intervalNarrative.detail}</p>
        <p>{intervalNarrative.caveat}</p><small>{intervalNarrative.scope}</small>
      </section>
'''

V2_TEST = '''test('provides a classified interpretation for the selected M05 interval', async ({ page }) => {
  await page.goto('/');
  const panel = page.getByRole('region', { name: 'Selected cohort interval interpretation' });
  await expect(panel).toContainText('1 of 2 scored KEV CVEs (50.00%)');
  await expect(panel).toContainText('1 of 4 full EPSS CVEs (25.00%)');
  await expect(panel).toContainText('overlapping distributions');
  await expect(panel).toContainText('Synthetic illustration');
  const buttons = page.getByRole('group', {name:'Compare KEV and full EPSS probability bands'}).getByRole('button');
  await buttons.nth(1).click();
  await expect(panel).toContainText('0 of 2 scored KEV CVEs');
});

'''


def replace_exact(content: str, old: str, new: str, label: str) -> str:
    hits = content.count(old)
    if hits != 1:
        raise RuntimeError(f"{label}: expected one exact anchor; found {hits}. Nothing applied.")
    return content.replace(old, new, 1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    source = Path(__file__).resolve().parent.parent

    def git(*argv: str) -> str:
        result = subprocess.run(['git', *argv], cwd=repo, text=True, capture_output=True, check=True)
        return result.stdout.strip()

    if git('branch', '--show-current') != BRANCH:
        raise RuntimeError('Incorrect branch. Stop.')
    if not git('rev-parse', 'HEAD').startswith(BASELINE):
        raise RuntimeError('Unexpected EA-02A baseline. Stop.')
    if git('status', '--porcelain=v1', '-uall'):
        raise RuntimeError('Working tree is not clean. Stop.')
    if 'exploit-atlas' not in git('remote', 'get-url', 'origin'):
        raise RuntimeError('Git origin does not identify Exploit Atlas. Stop.')

    for rel in NEW_FILES:
        if not (source / rel).is_file() or (repo / rel).exists():
            raise RuntimeError(f'Missing staged source or unexpected existing destination: {rel}')

    main_rel = 'apps/web/src/main.tsx'
    v2_rel = 'apps/web/tests/e2e/v2-cohorts.spec.mjs'
    main_original = (repo / main_rel).read_text(encoding='utf-8')
    v2_original = (repo / v2_rel).read_text(encoding='utf-8')
    revised = main_original
    changes = (
        ("import { intelligenceBrief } from './brief-reading.mjs';", "import { intelligenceBrief } from './brief-reading.mjs';\nimport { distributionOverview, cohortIntervalNarrative, glossaryTerms } from './interpretation.mjs';", 'interpretation import'),
        ("import './brief.css';", "import './brief.css';\nimport './interpretation.css';", 'interpretation stylesheet'),
        ("function Bars({bands, population, sourceDate}:{bands:Band[];population:number;sourceDate:string}) {", "function Bars({bands, population, sourceDate, dataKind}:{bands:Band[];population:number;sourceDate:string;dataKind:Manifest['data_kind']}) {", 'M04 props'),
        ("  const reading = bandReading(current, population);", "  const reading = bandReading(current, population);\n  const overview = distributionOverview(dataKind, bands, population);", 'M04 derive reading'),
        ('  return <>\n    <p className="bars-instruction">', '  return <>\n' + DISTRIBUTION_READING + '    <p className="bars-instruction">', 'M04 reading card'),
        ("function CohortComparison({rows, coverage, population, sourceDate}:{rows:CohortRow[];coverage:Metric;population:Population;sourceDate:string}) {", "function CohortComparison({rows, coverage, population, sourceDate, dataKind}:{rows:CohortRow[];coverage:Metric;population:Population;sourceDate:string;dataKind:Manifest['data_kind']}) {", 'M05 props'),
        ("  const reading = cohortReading(selected);", "  const reading = cohortReading(selected);\n  const intervalNarrative = cohortIntervalNarrative(dataKind, selected, coverage.numerator_matched_kev, population.scored_cve_count);", 'M05 derive reading'),
        ('      </section>\n    </div>\n    <div className="cohort-unscored">', '      </section>\n' + COHORT_READING + '    </div>\n    <div className="cohort-unscored">', 'M05 reading card'),
        ('<section className="section-intro">', '<EvidenceGlossary/><section className="section-intro">', 'glossary placement'),
        ('<Bars bands={bundle.bands} population={bundle.population.scored_cve_count} sourceDate={bundle.population.epss_source_date}/>', '<Bars bands={bundle.bands} population={bundle.population.scored_cve_count} sourceDate={bundle.population.epss_source_date} dataKind={bundle.manifest.data_kind}/>', 'M04 data classification'),
        ('<CohortComparison rows={bundle.cohort} coverage={bundle.coverage} population={bundle.population} sourceDate={bundle.population.epss_source_date}/>', '<CohortComparison rows={bundle.cohort} coverage={bundle.coverage} population={bundle.population} sourceDate={bundle.population.epss_source_date} dataKind={bundle.manifest.data_kind}/>', 'M05 data classification'),
    )
    for old, new, label in changes:
        revised = replace_exact(revised, old, new, label)
    revised = replace_exact(revised, 'function Bars(', GLOSSARY_COMPONENT + 'function Bars(', 'glossary component')
    v2_revised = replace_exact(v2_original,
        "test('keeps the document contained and existing atlas view functional', async ({ page }) => {",
        V2_TEST + "test('keeps the document contained and existing atlas view functional', async ({ page }) => {",
        'v2 browser regression insertion')

    outputs = {main_rel: revised.encode('utf-8'), v2_rel: v2_revised.encode('utf-8')}
    outputs.update({rel:(source / rel).read_bytes() for rel in NEW_FILES})
    previous = {rel:(repo / rel).read_bytes() for rel in (main_rel, v2_rel)}
    written = []
    try:
        for rel, data in outputs.items():
            destination = repo / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temp = tempfile.mkstemp(prefix='.ea02b-', dir=str(destination.parent))
            try:
                with os.fdopen(descriptor, 'wb') as handle:
                    handle.write(data)
                os.replace(temp, destination)
            finally:
                if os.path.exists(temp):
                    os.unlink(temp)
            written.append(rel)
    except Exception:
        for rel in reversed(written):
            dest = repo / rel
            if rel in previous:
                dest.write_bytes(previous[rel])
            else:
                dest.unlink(missing_ok=True)
        raise
    print('EA02B SOURCE APPLIED')
    print(git('status', '--short'))
    print('Next: run frontend unit tests, production build and both v1/v2 Playwright suites before committing.')


if __name__ == '__main__':
    main()
