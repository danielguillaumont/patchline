# P5.1C: Versioned cohort comparison in Spectral Index

The Spectral Index accepts either an explicit v1 or v2 export manifest. It never
selects a version from the number of files or invents an M05 dataset when the
loaded manifest is v1.

| Demo contract | JSON files served | Artifact register | Atlas |
| --- | --- | --- | --- |
| `patchline.analytics-export.v1` | Manifest plus M03 and two M04 marts (4) | 9 records | Original Atlas and EPSS distribution |
| `patchline.analytics-export.v2` | Manifest plus M03, two M04 marts and M05 (5) | 12 records | Original Atlas plus M05 cohort comparison |

The v2 frontend validates source lineage, M03 KEV counts, M04 full-EPSS totals,
all five common probability intervals, all six M05 rows, denominator policies,
manifest artifact metadata and the separate unscored KEV category. A malformed
v2 payload produces a data-unavailable state; it is not silently rendered as v1.

## Correct interpretation

- Full EPSS band shares use every scored CVE in the selected EPSS snapshot.
- Scored KEV band shares use only KEV CVEs with a matching EPSS score.
- All-KEV shares use every CVE in the selected KEV catalog.
- The scored KEV group is part of the full EPSS group, not an independent sample.
- M05 row six is **unscored KEV**. A missing score is never treated as a zero
  probability, and row six does not belong on the five-band probability axis.
- A percentage here is descriptive; it is not organizational risk, an observed
  exploitation rate, or evidence that an EPSS score caused KEV membership.

The website checks shape and arithmetic, not the bytes or cryptographic digests
of published files. The Python exporter remains responsible for local verification.
The demo uses an explicitly labeled synthetic fixture.

## Browser tests

Run from `apps/web` after installing locked dependencies and Playwright Chromium:

```powershell
npm test
npm run build
npm run test:e2e
npm run test:e2e:v2
```

Both browser suites generate an **isolated synthetic fixture** and launch an
isolated Vite server on port 5175. Run them sequentially, not concurrently.
Neither modifies `apps/web/public/demo`, local archived feeds, or existing
DuckDB files. v1 and v2 screenshots and reports use separate ignored directories.
GitHub Actions runs both suites in sequence.

## Manually display v2 locally

From the repository root in **PATCHLINE MAIN**, first use a newly created
synthetic database and verified v2 export directory. These examples use a random
identifier to avoid overwriting previous local outputs:

```powershell
$id = [guid]::NewGuid().ToString('N')
$db = Join-Path $env:TEMP ("patchline-p51c-" + $id + ".duckdb")
$out = Join-Path $env:TEMP ("patchline-p51c-v2-" + $id)
$env:PATCHLINE_DUCKDB_PATH = $db
uv run --locked python -m patchline.fixtures.ci_warehouse create --output $db
uv run --locked dbt run --project-dir dbt --profiles-dir dbt
uv run --locked dbt test --project-dir dbt --profiles-dir dbt
uv run --locked python -m patchline.exports.analytics create --contract v2 --database $db --output $out
uv run --locked python -m patchline.exports.analytics verify --output $out
```

Only after every command succeeds, copy `manifest.json` and the **four** v2 mart
JSON files from that directory into the Git-ignored `apps/web/public/demo/`.
Replace any prior **synthetic demo** files; do not overwrite a different or
unverified dataset. Start Vite only once using **PATCHLINE FRONTEND** and
`npm run dev -- --strictPort`, then review Intelligence Atlas and Methods & Quality.

To verify v1 compatibility in a browser, use a separately verified default-v1
export and copy its manifest plus the three v1 mart JSON files. The old chart
and nine-file register should remain, while M05 comparison is omitted.
