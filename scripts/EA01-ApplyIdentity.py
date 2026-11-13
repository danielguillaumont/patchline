"""Apply the EA-01 public-identity migration to the exact reviewed source tree.

This is a one-time, fail-closed source migration, not a runtime dependency.
Run --check before --apply. Existing data contracts and Python package names stay put.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    expected = 2 if label.endswith('page navigation') else 1
    if count != expected:
        raise ValueError(f"{label}: expected exactly {expected} source anchor(s), found {count}")
    return text.replace(old, new, expected)


def transform(repo: Path) -> dict[Path, tuple[bytes, bytes]]:
    changes: dict[Path, tuple[bytes, bytes]] = {}

    def patch(relative: str, replacements: list[tuple[str, str, str]]) -> None:
        path = repo / relative
        raw = path.read_bytes()
        # Preserve the file's current newline convention and final newline.
        newline = '\r\n' if b'\r\n' in raw else '\n'
        text = raw.decode('utf-8').replace('\r\n', '\n')
        for old, new, label in replacements:
            text = replace_once(text, old, new, f"{relative}: {label}")
        updated = text.replace('\n', newline).encode('utf-8')
        if updated == raw:
            raise ValueError(f"{relative}: migration made no changes")
        changes[path] = (raw, updated)

    patch('README.md', [
        ('# Patchline\n', '# Exploit Atlas\n', 'product heading'),
        ('**Evidence-led vulnerability intelligence, built to be reproduced.**',
         '**Vulnerability Intelligence, Made Clear.**', 'new tagline'),
        ('Patchline is a local-first security analytics project',
         'Exploit Atlas is a local-first security analytics project', 'intro identity'),
        ('It combines a tested data pipeline with **Spectral Index**, a research interface',
         'It combines a tested data pipeline with an interactive research interface',
         'research interface description'),
        ('       Spectral Index UI', '       Exploit Atlas UI', 'pipeline diagram'),
        ('**Live demo:** [Open Spectral Index]',
         '**Live demo:** [Open Exploit Atlas]', 'live demo label'),
        ('**Real-data research:** [Archived KEV and EPSS cohort study](docs/research/archived-kev-epss-2026-11.md)',
         '**Real-data research:** [Archived KEV and EPSS cohort study](docs/research/archived-kev-epss-2026-11.md)\n\n**Product roadmap:** [Exploit Atlas development plan](docs/roadmap-exploit-atlas.md)',
         'roadmap link'),
        ('Patchline is not a live feed or an organizational risk-scoring system.',
         'Exploit Atlas is not a live feed or an organizational risk-scoring system.', 'demo caveat'),
        ('## Inside Spectral Index', '## Inside Exploit Atlas', 'inside section'),
        ('and starts Spectral Index locally.', 'and starts Exploit Atlas locally.', 'demo description'),
        ('The hosted demo uses verified synthetic data. It is not a live vulnerability feed.',
         'The hosted demo uses verified synthetic data. It is not a live vulnerability feed.\n\n**Compatibility note:** Existing Python imports, CLI commands, environment variables, data contract IDs, and local batch paths still use `patchline`. They are retained intentionally while the public product identity changes.',
         'compatibility explanation'),
    ])

    patch('apps/web/src/main.tsx', [
        ("import './styles.css';", "import './styles.css';\nimport './identity.css';", 'brand styles import'),
        ('<span>patchline<span className="brand-star">',
         '<span>Exploit Atlas<span className="brand-star">', 'wordmark'),
        ('<span className="header-pill">SPECTRAL INDEX</span>',
         '<span className="header-pill">VULNERABILITY INTELLIGENCE</span>',
         'edition label'),
        ('<p>Patchline · Spectral Index / A research interface, not operational security advice.</p>',
         '<p>Exploit Atlas / Source-backed vulnerability intelligence, not operational security advice.</p>',
         'footer identity'),
    ])

    patch('apps/web/index.html', [
        ('Patchline Spectral Index: provenance-first vulnerability intelligence.',
         'Exploit Atlas: vulnerability intelligence made clear through traceable KEV and EPSS analysis.',
         'SEO description'),
        ('<title>Patchline | Spectral Index</title>',
         '<title>Exploit Atlas | Vulnerability Intelligence</title>',
         'browser title'),
    ])

    patch('apps/web/package.json', [
        ('"build:pages": "tsc --noEmit && vite build --config vite.e2e.config.mjs --base /patchline/"',
         '"build:pages": "tsc --noEmit && node scripts/build-pages.mjs"',
         'dynamic Pages build'),
    ])

    patch('apps/web/playwright.pages.config.mjs', [
        ("import base from './playwright.config.mjs';",
         "import base from './playwright.config.mjs';\nimport { pagesBase } from './scripts/pages-base.mjs';\n\nconst siteBase = pagesBase();",
         'Pages base resolver'),
        ("command: 'npx vite preview --base /patchline/ --host 127.0.0.1 --port 4175 --strictPort',",
         "command: `npx vite preview --base ${siteBase} --host 127.0.0.1 --port 4175 --strictPort`,",
         'preview command'),
        ("url: 'http://127.0.0.1:4175/patchline/',",
         "url: `http://127.0.0.1:4175${siteBase}`,",
         'preview URL'),
    ])

    patch('apps/web/tests/e2e/pages-preview.spec.mjs', [
        ("import { test, expect } from '@playwright/test';",
         "import { test, expect } from '@playwright/test';\nimport { pagesBase } from '../../scripts/pages-base.mjs';\n\nconst siteBase = pagesBase();",
         'test base resolver'),
        ("await page.goto('/patchline/');", "await page.goto(siteBase);", 'page navigation'),
        # Update both existing browser visits using the same safe site base.
        ("expect(urls).toContain('/patchline/demo/manifest.json');",
         "expect(urls).toContain(`${siteBase}demo/manifest.json`);",
         'manifest path assertion'),
        ("expect(urls.every(url => url.startsWith('/patchline/demo/'))).toBe(true);",
         "expect(urls.every(url => url.startsWith(`${siteBase}demo/`))).toBe(true);",
         'demo path assertions'),
        ("await expect(page.locator('.classification')).toContainText('SYNTHETIC FIXTURE');",
         "await expect(page.locator('.classification')).toContainText('SYNTHETIC FIXTURE');\n  await expect(page.locator('.wordmark').first()).toContainText('Exploit Atlas');",
         'new brand smoke assertion'),
    ])

    patch('apps/web/scripts/verify-pages-dist.mjs', [
        ("import { demoJsonNames, readAndVerifyPagesData } from './pages-data.mjs';",
         "import { demoJsonNames, readAndVerifyPagesData } from './pages-data.mjs';\nimport { pagesBase } from './pages-base.mjs';",
         'static verifier base resolver'),
        ("  if (!/\\/patchline\\/assets\\//.test(index) || /(?:src|href)=\"\\/assets\\//.test(index)) {\n    throw Error('Static asset links do not use the /patchline/ base path');\n  }",
         "  const base = pagesBase();\n  if (!index.includes(`${base}assets/`) || /(?:src|href)=\"\\/assets\\//.test(index)) {\n    throw Error(`Static asset links do not use the ${base} base path`);\n  }",
         'base-aware static verifier'),
        ("  console.log('P5.2C1 static site verified: /patchline/ assets and synthetic v2 demo only.');",
         "  console.log(`Exploit Atlas static site verified: ${pagesBase()} assets and synthetic v2 demo only.`);",
         'verifier output'),
    ])

    patch('.github/workflows/pages-preview.yml', [
        ('name: Spectral Index Pages Preview', 'name: Exploit Atlas Pages Preview',
         'workflow name'),
        ('      - name: Test production build at /patchline/\n        working-directory: apps/web\n        run: npx playwright test --config playwright.pages.config.mjs',
         '      - name: Test production build at current repository path\n        working-directory: apps/web\n        run: npx playwright test --config playwright.pages.config.mjs\n'
         '      - name: Rehearse future /exploit-atlas/ deployment path\n        working-directory: apps/web\n'
         '        env:\n          EXPLOIT_ATLAS_PAGES_SITE: exploit-atlas\n'
         '          PATCHLINE_E2E_PUBLIC_DIR: ${{ runner.temp }}/patchline-pages-public\n        run: |\n'
         '          npm run build:pages\n          node scripts/verify-pages-dist.mjs --dist dist\n'
         '          npx playwright test --config playwright.pages.config.mjs\n'
         '      - name: Restore deployable site at current repository path\n        working-directory: apps/web\n'
         '        env:\n          PATCHLINE_E2E_PUBLIC_DIR: ${{ runner.temp }}/patchline-pages-public\n'
         '        run: |\n          npm run build:pages\n          node scripts/verify-pages-dist.mjs --dist dist',
         'pre-rename new-path rehearsal and restoration'),
        ('name: spectral-index-pages-preview', 'name: exploit-atlas-pages-preview',
         'preview artifact name'),
        ('name: Deploy verified Spectral Index', 'name: Deploy verified Exploit Atlas',
         'deployment display name'),
    ])

    patch('.github/workflows/ci.yml', [
        ('name: Spectral Index frontend', 'name: Exploit Atlas frontend',
         'frontend job display name'),
    ])

    return changes


def main() -> int:
    parser = argparse.ArgumentParser(description='Prepare Exploit Atlas display and dual-path Pages migration')
    parser.add_argument('--repo', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    repo = args.repo.resolve()
    changes = transform(repo)
    print(f'EA-01 identity migration validated against {len(changes)} existing files')
    for path in changes:
        print(path.relative_to(repo).as_posix())
    if args.apply:
        for path, (_, updated) in changes.items():
            path.write_bytes(updated)
        print('EA01 IDENTITY SOURCE UPDATED')
    else:
        print('EA01 IDENTITY PRECHECK PASSED (no files modified)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
