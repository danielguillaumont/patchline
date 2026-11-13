"""EA-02A: fail-closed, reviewable migration for the existing Exploit Atlas frontend.

Use --check first. All expected source anchors are checked before --apply writes.
This never accesses warehouses, archive snapshots or persisted batch records.
"""
from __future__ import annotations

import argparse
from pathlib import Path

BRIEF_COMPONENT = '''function IntelligenceBrief({brief,onMethods}:{brief:ReturnType<typeof intelligenceBrief>;onMethods:()=>void}) {
  return <section className="intel-brief" aria-label="Intelligence brief">
    <div className="intel-brief-heading">
      <div><span className="eyebrow">01 / INTERPRETATION BEFORE INVESTIGATION</span><h2 id="brief-heading">The intelligence brief.</h2></div>
      <p>A simple reading of what the sources show, what they cannot prove, and where to look next.</p>
    </div>
    <div className="intel-brief-grid">
      <article className="intel-brief-main">
        <span className="eyebrow">WHAT THIS COMPARISON SHOWS</span>
        <h3>{brief.headline}</h3>
        <span className="brief-classification">{brief.classification}</span>
        <p>{brief.scopeNote}</p>
        <p className="brief-unmatched">{brief.unmatchedNote}</p>
      </article>
      <div className="intel-brief-side">
        <article><span className="eyebrow">WHY THIS MATTERS</span><h3>Two signals. Different meanings.</h3><p>{brief.why}</p></article>
        <article><span className="eyebrow">WHAT TO CHECK NEXT</span><h3>Context comes before decisions.</h3><p>{brief.next}</p></article>
      </div>
    </div>
    <div className="intel-brief-footer"><span>{brief.sourceLine}</span><button type="button" onClick={onMethods}>Inspect sources and methods ↗</button></div>
  </section>;
}
'''

REPLACEMENTS: dict[str, list[tuple[str, str]]] = {
    'apps/web/src/main.tsx': [
        ("import { demoFileUrl } from './demo-url.mjs';", "import { demoFileUrl } from './demo-url.mjs';\nimport { intelligenceBrief } from './brief-reading.mjs';"),
        ("import './identity.css';", "import './identity.css';\nimport './brief.css';"),
        ('function Bars({bands, population, sourceDate}', BRIEF_COMPONENT + '\nfunction Bars({bands, population, sourceDate}'),
        ("['atlas','01 / Intelligence atlas']", "['atlas','01 / Intelligence brief']"),
        ('INTELLIGENCE ATLAS <span className="hairline"/> VOLUME 001', 'INTELLIGENCE BRIEF <span className="hairline"/> VOLUME 001'),
        ('<h1>Signals in<br/><em>the noise.</em></h1>', '<h1>What the<br/><em>data says.</em></h1>'),
        ('<p className="lede">An evidence-led reading of exploitation signals. Two public datasets, one carefully documented perspective.</p>', '<p className="lede">Known exploitation and modeled likelihood are different signals. Explore where the sources overlap, what is missing, and what we can responsibly conclude.</p>'),
        ('<div className="aside-top">THE MEASURE <span>↗</span></div>', '<div className="aside-top">SOURCE COVERAGE / NOT RISK <span>↗</span></div>'),
        ('<p>of KEV entries in this selected catalog have a corresponding EPSS score.</p>', '<p>of KEV records have a matching EPSS score in this source pair. This measures data coverage, not organizational risk.</p>'),
        ('</section><section className="section-intro">', '</section><IntelligenceBrief brief={intelligenceBrief(bundle.manifest,bundle.coverage,bundle.population)} onMethods={() => setView(\'methods\')}/><section className="section-intro">'),
    ],
    'apps/web/tests/e2e/spectral-index.spec.mjs': [
        ('/Intelligence atlas/i', '/Intelligence brief/i'),
        ("await expect(page.locator('.classification')).toContainText('SYNTHETIC FIXTURE');", "await expect(page.locator('.classification')).toContainText('SYNTHETIC FIXTURE');\n  await expect(page.getByRole('region',{name:'Intelligence brief'})).toContainText('2 of 3 KEV records have a matching EPSS score.');\n  await expect(page.getByRole('region',{name:'Intelligence brief'})).toContainText('fabricated test records');"),
    ],
    'apps/web/tests/e2e/v2-cohorts.spec.mjs': [
        ('/Intelligence atlas/i', '/Intelligence brief/i'),
    ],
    'apps/web/tests/e2e/pages-preview.spec.mjs': [
        ("await expect(page.locator('.wordmark').first()).toContainText('Exploit Atlas');", "await expect(page.locator('.wordmark').first()).toContainText('Exploit Atlas');\n  await expect(page.getByRole('region',{name:'Intelligence brief'})).toContainText('SYNTHETIC EXAMPLE');\n  await expect(page.getByRole('region',{name:'Intelligence brief'})).toContainText('not real-world exploitation trends');"),
    ],
}


def prepare(root: Path) -> dict[Path, str]:
    changes: dict[Path, str] = {}
    for name, operations in REPLACEMENTS.items():
        path = root / name
        if not path.is_file():
            raise ValueError(f'Missing baseline file: {name}')
        content = path.read_text(encoding='utf-8')
        for old, new in operations:
            if content.count(old) != 1:
                raise ValueError(f'Expected exactly one original anchor in {name}: {old[:80]!r}')
            content = content.replace(old, new, 1)
        changes[path] = content
    return changes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, default=Path('.'))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    root = args.repo.resolve()
    changes = prepare(root)
    if args.check:
        for p in changes:
            print('EA02A preflight:', p.relative_to(root).as_posix())
        print('EA02A PREFLIGHT PASSED')
        return
    for p, content in changes.items():
        p.write_text(content, encoding='utf-8', newline='')
        print('EA02A updated:', p.relative_to(root).as_posix())
    print('EA02A MIGRATION APPLIED')


if __name__ == '__main__':
    main()
