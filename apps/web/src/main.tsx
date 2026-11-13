import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { validateBundle } from './contract.mjs';
import { bandReading } from './band-inspector.mjs';
import { artifactReading } from './evidence-inspector.mjs';
import { cohortReading, cohortPercent } from './cohort-inspector.mjs';
import { demoFileUrl } from './demo-url.mjs';
import { intelligenceBrief } from './brief-reading.mjs';
import { distributionOverview, cohortIntervalNarrative, glossaryTerms } from './interpretation.mjs';
import './styles.css';
import './identity.css';
import './brief.css';
import './interpretation.css';

type Source = {source:string; snapshot_id:string; source_date:string; retrieved_at_utc?:string; row_count:number; model_version?:string|null};
type Artifact = {path:string;sha256:string;bytes:number;rows:number;columns:string[];model:string};
type Manifest = {schema_id:string; data_kind:'synthetic_fixture'|'archived_source_snapshots'; source_snapshots:Source[]; artifacts: Artifact[]; validation?:{kev_total:number;kev_matched:number;kev_unmatched:number;epss_scored_total:number}};
type Metric = {metric_id:string; numerator_matched_kev:number; denominator_total_kev:number; unmatched_kev:number; coverage_percent:number|null; epss_source_date:string;kev_catalog_date_released:string};
type Population = {scored_cve_count:number;median_epss:number|null;p90_epss:number|null;mean_epss:number|null;epss_source_date:string};
type Band = {band_order:number;band_label?:string;cve_count:number;population_percent:number|null;lower_bound?:number;upper_bound?:number};
type CohortRow = {band_order:number;band_label:string;cohort_category:string;kev_cve_count:number;share_scored_kev_percent:number|null;share_all_kev_percent:number|null;full_epss_band_count:number|null;full_epss_population_percent:number|null};
type Bundle = {manifest:Manifest;coverage:Metric;population:Population;bands:Band[];cohort:CohortRow[]|null};
type View = 'atlas'|'explorer'|'methods';
const coreFiles = ['m03_epss_coverage_of_kev.json','m04_epss_population_summary.json','m04_epss_score_bands.json'];
async function readDemoFile(name:string, signal:AbortSignal):Promise<unknown> {
  const response = await fetch(demoFileUrl(import.meta.env.BASE_URL, name), {signal, cache:'no-store'});
  if (!response.ok) throw Error(`Missing verified demo export: ${name} (${response.status})`);
  return response.json() as Promise<unknown>;
}
async function fetchBundle(signal:AbortSignal):Promise<Bundle> {
  const manifest = await readDemoFile('manifest.json',signal);
  const schema = (manifest as {schema_id?:string}|null)?.schema_id;
  if (schema !== 'patchline.analytics-export.v1' && schema !== 'patchline.analytics-export.v2') {
    throw Error('Unsupported demo manifest version. Expected explicit v1 or v2.');
  }
  const names = schema === 'patchline.analytics-export.v2'
    ? [...coreFiles,'m05_kev_epss_cohort_bands.json']
    : coreFiles;
  const values = await Promise.all(names.map(name=>readDemoFile(name,signal)));
  return validateBundle(manifest,values[0],values[1],values[2],values[3]) as Bundle;
}
const fmt=(n:number)=>new Intl.NumberFormat('en-CA').format(n);
const pct=(n:number|null)=>n===null?'Not defined':`${n.toFixed(2)}%`;
const chance=(n:number|null)=>n===null?'Not defined':`${(n*100).toFixed(2)}%`;
function Logo(){return <div className="wordmark"><svg viewBox="0 0 43 43" fill="none" aria-hidden="true"><path d="M5 5v33M38 5v33" stroke="currentColor" strokeWidth="3"/><path d="M5 12h10l13 19h10M5 31h10L28 12h10" stroke="currentColor" strokeWidth="3"/><circle cx="21.5" cy="21.5" r="5" fill="#DDEC7E" stroke="#302040" strokeWidth="2"/></svg><span>Exploit Atlas<span className="brand-star">✳</span></span></div>}
function IntelligenceBrief({brief,onMethods}:{brief:ReturnType<typeof intelligenceBrief>;onMethods:()=>void}) {
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

function EvidenceGlossary() {
  return <section className="interpretation-lexicon" aria-label="Glossary of intelligence terms">
    <div className="interpretation-lexicon-heading"><div><span className="eyebrow">FIELD NOTES / DEFINITIONS</span><h2>Know the language.</h2></div><p>Open any definition. Understanding the terms matters before comparing the numbers.</p></div>
    <div className="interpretation-terms">
      {glossaryTerms.map(item => <details key={item.term}><summary>{item.term}</summary><p>{item.meaning}</p></details>)}
    </div>
  </section>;
}

function Bars({bands, population, sourceDate, dataKind}:{bands:Band[];population:number;sourceDate:string;dataKind:Manifest['data_kind']}) {
  const [selectedOrder, setSelectedOrder] = useState(1);
  const max = Math.max(1, ...bands.map(b => b.cve_count));
  const current = bands.find(b => b.band_order === selectedOrder) ?? bands[0];
  const reading = bandReading(current, population);
  const overview = distributionOverview(dataKind, bands, population);

  return <>
    <section className="chart-reading" aria-label="EPSS distribution interpretation">
      <span className="eyebrow">READING FIGURE 01</span>
      <h4>{overview.headline}</h4><p>{overview.detail}</p><small>{overview.scope}</small>
    </section>
    <p className="bars-instruction">Select a probability band to inspect its source interval and exact population share.</p>
    <div className="bars" role="group" aria-label="Inspect EPSS probability bands">
      {bands.map((band, index) => {
        const selected = band.band_order === current.band_order;
        const label = bandReading(band, population);
        return <button
          type="button"
          className="band"
          key={band.band_order}
          aria-pressed={selected}
          aria-controls="epss-band-inspector"
          aria-label={label.accessibleLabel}
          onClick={() => setSelectedOrder(band.band_order)}
        >
          <div className="bar-track" aria-hidden="true">
            <div className={`bar-fill band-${index}`} style={{height:`${Math.max(band.cve_count ? 7 : 0, (band.cve_count / max) * 100)}%`}} />
          </div>
          <strong aria-hidden="true">{fmt(band.cve_count)}</strong>
          <small aria-hidden="true">{band.band_label || `Band ${band.band_order}`}</small>
        </button>;
      })}
    </div>
    <section className="band-inspector" id="epss-band-inspector" aria-live="polite" aria-atomic="true" aria-label="Selected EPSS band details">
      <div className="band-inspector-description">
        <span className="eyebrow">SELECTED BAND / {String(current.band_order).padStart(2, '0')}</span>
        <h4>{reading.rangeLabel}</h4>
        <p>{reading.emptyNote}</p>
        <small>FIRST EPSS source date: {sourceDate}</small>
      </div>
      <div className="band-inspector-metrics">
        <div><span>CVES IN BAND</span><strong>{reading.countLabel}</strong><small>of {reading.populationLabel} scored CVEs</small></div>
        <div><span>SHARE OF POPULATION</span><strong>{reading.shareLabel}</strong><small>Full EPSS snapshot</small></div>
      </div>
    </section>
  </>;
}
function CohortComparison({rows, coverage, population, sourceDate, dataKind}:{rows:CohortRow[];coverage:Metric;population:Population;sourceDate:string;dataKind:Manifest['data_kind']}) {
  const [selectedOrder,setSelectedOrder] = useState(3);
  const selected = rows.find(row=>row.band_order===selectedOrder) ?? rows[0];
  const unscored = rows[5];
  const reading = cohortReading(selected);
  const intervalNarrative = cohortIntervalNarrative(dataKind, selected, coverage.numerator_matched_kev, population.scored_cve_count);
  const label = (value:number|null) => value === null ? 'Not defined' : `${value.toFixed(2)}%`;
  const barWidth = (value:number|null) => `${value===null ? 0 : value}%`;
  return <section className="cohort-section" aria-labelledby="cohort-heading">
    <div className="cohort-intro"><div><span className="eyebrow">FIGURE 02 / COHORT LENS / M05</span>
      <h2 id="cohort-heading">The cohort<br/><em>in context.</em></h2></div>
      <p>Compare the same five EPSS intervals using <strong>two different denominators</strong>. Scored KEV CVEs are included in the full EPSS population, not an independent population.</p>
    </div>
    <div className="cohort-panel">
      <div className="cohort-panel-head"><div><span className="eyebrow">PROBABILITY INTERVAL / READING</span>
        <h3>Same bands. Different populations.</h3></div>
        <div className="cohort-legend"><span><i className="cohort-swatch cohort-swatch-all"/>Full EPSS <strong>({fmt(population.scored_cve_count)})</strong></span>
          <span><i className="cohort-swatch cohort-swatch-kev"/>Scored KEV <strong>({fmt(coverage.numerator_matched_kev)})</strong></span></div>
      </div>
      <p className="cohort-instruction">Select an interval to inspect the counts behind each percentage. Empty denominators display as not defined.</p>
      <div className="cohort-rows" role="group" aria-label="Compare KEV and full EPSS probability bands">
        {rows.slice(0,5).map(row => {
          const active = row.band_order===selected.band_order;
          return <button type="button" key={row.band_order} className="cohort-option" aria-pressed={active} aria-controls="cohort-inspector"
            aria-label={`${row.band_label}. Full EPSS ${label(row.full_epss_population_percent)}, scored KEV ${label(row.share_scored_kev_percent)}`}
            onClick={()=>setSelectedOrder(row.band_order)}>
            <span className="cohort-row-label"><small>{String(row.band_order).padStart(2,'0')}</small><strong>{row.band_label}</strong></span>
            <span className="cohort-tracks"><span className="cohort-track"><span className="cohort-fill cohort-fill-all" style={{width:barWidth(row.full_epss_population_percent)}}/></span>
              <span className="cohort-track"><span className="cohort-fill cohort-fill-kev" style={{width:barWidth(row.share_scored_kev_percent)}}/></span></span>
            <span className="cohort-values"><strong>{label(row.full_epss_population_percent)}</strong><strong>{label(row.share_scored_kev_percent)}</strong></span>
          </button>;
        })}
      </div>
      <section className="cohort-inspector" id="cohort-inspector" aria-live="polite" aria-atomic="true" aria-label="Selected cohort interval details">
        <div><span className="eyebrow">SELECTED INTERVAL / {String(selected.band_order).padStart(2,'0')}</span>
          <h4>{selected.band_label}</h4><p>Both distributions use the same EPSS thresholds. Percentage shares are descriptive and must not be interpreted as observed exploitation.</p></div>
        <dl><div><dt>FULL EPSS</dt><dd>{reading.epssCount} <small>of {fmt(population.scored_cve_count)}</small></dd><span>{reading.epssShare} of scored EPSS CVEs</span></div>
          <div><dt>SCORED KEV</dt><dd>{reading.kevCount} <small>of {fmt(coverage.numerator_matched_kev)}</small></dd><span>{reading.scoredShare} of scored KEV CVEs</span></div>
          <div><dt>ALL KEV SHARE</dt><dd>{reading.allKevShare}</dd><span>Denominator: {fmt(coverage.denominator_total_kev)} KEV CVEs</span></div></dl>
      </section>
      <section className="chart-reading chart-reading-selected" aria-label="Selected cohort interval interpretation" aria-live="polite" aria-atomic="true">
        <span className="eyebrow">READING THE SELECTED INTERVAL</span>
        <h4>{intervalNarrative.headline}</h4><p>{intervalNarrative.detail}</p>
        <p>{intervalNarrative.caveat}</p><small>{intervalNarrative.scope}</small>
      </section>
    </div>
    <div className="cohort-unscored"><div><span className="eyebrow">06 / UNSCORED KEV</span>
      <h3>No EPSS match is not zero probability.</h3><p>{fmt(unscored.kev_cve_count)} KEV {unscored.kev_cve_count === 1 ? 'entry has' : 'entries have'} no matched EPSS score in this snapshot pair. They are excluded from the scored comparison, not placed into its first interval.</p></div>
      <div><strong>{fmt(unscored.kev_cve_count)}</strong><span>of {fmt(coverage.denominator_total_kev)} KEV records</span><strong className="cohort-unscored-share">{cohortPercent(unscored.share_all_kev_percent)}</strong></div></div>
    <p className="cohort-footnote">M05 and M04 source dates: {sourceDate}. Source pairing, different denominators, and dataset classification remain visible throughout the page.</p>
  </section>;
}
function ArtifactRegister({artifacts}:{artifacts:Artifact[]}) {
  const [selectedPath, setSelectedPath] = useState('m03_epss_coverage_of_kev.json');
  const selected = artifacts.find(a => a.path === selectedPath) ?? artifacts[0];
  const detail = artifactReading(selected);
  return <section className="artifact-section" aria-labelledby="artifact-heading">
    <div className="artifact-intro">
      <div><span className="eyebrow">EXPORT REGISTER / {String(artifacts.length).padStart(2,'0')} ARTIFACTS</span><h2 id="artifact-heading">Evidence, file by file.</h2></div>
      <p>Inspect metadata recorded by the immutable export manifest. {artifacts.length / 3} analytical marts are published in CSV, JSON and Parquet.</p>
    </div>
    <div className="artifact-options" role="group" aria-label="Select a manifest artifact">
      {artifacts.map(a => {
        const item = artifactReading(a);
        return <button type="button" key={a.path} className="artifact-option" aria-pressed={a.path === selected.path}
          aria-controls="selected-artifact-details" onClick={() => setSelectedPath(a.path)}>
          <span>{item.formatLabel} <span aria-hidden="true">/</span> {item.rowsLabel} ROWS</span>
          <strong>{item.modelLabel}</strong>
          <small>{a.path}</small>
        </button>;
      })}
    </div>
    <section className="artifact-detail" id="selected-artifact-details" aria-live="polite" aria-atomic="true" aria-label="Selected artifact metadata">
      <div className="artifact-detail-heading"><span className="eyebrow">SELECTED ARTIFACT / MANIFEST RECORD</span>
        <h3>{selected.path}</h3><p>This is a recorded manifest entry. The browser does not fetch or verify the artifact bytes.</p></div>
      <dl className="artifact-fields">
        <div><dt>MODEL</dt><dd>{detail.modelLabel}</dd></div>
        <div><dt>FORMAT</dt><dd>{detail.formatLabel}</dd></div>
        <div><dt>ROWS</dt><dd>{detail.rowsLabel}</dd></div>
        <div><dt>FILE SIZE</dt><dd>{detail.bytesLabel} bytes</dd></div>
        <div className="artifact-full"><dt>COLUMNS / EXPORTED ORDER</dt><dd className="artifact-columns">{detail.columnsLabel}</dd></div>
        <div className="artifact-full"><dt>SHA-256 / RECORDED, NOT BROWSER-VERIFIED</dt><dd><code className="artifact-digest">{detail.digest}</code></dd></div>
      </dl>
    </section>
    <p className="artifact-verification-note">For cryptographic verification, run <code>uv run --locked python -m patchline.exports.analytics verify --output &lt;export-directory&gt;</code> against the complete local bundle. The site serves only the manifest and {artifacts.length / 3} JSON marts, not all {artifacts.length} artifact files.</p>
  </section>;
}
const localExplorerEnabled = import.meta.env.DEV && import.meta.env.VITE_CVE_EXPLORER_LOCAL === '1';
const LocalExplorer = localExplorerEnabled
  ? React.lazy(() => import('./explorer-local').then(module => ({default:module.ExplorerLocal})))
  : null;
// Pages builds set this flag only after verifying a separate, checksum-pinned approval.
const publicExplorerEnabled = import.meta.env.PROD && import.meta.env.VITE_EXPLORER_PUBLIC_RELEASE === '1';
const PublicExplorer = publicExplorerEnabled
  ? React.lazy(() => import('./explorer-public').then(module => ({default:module.ExplorerPublic})))
  : null;
function App(){const [view,setView]=useState<View>('atlas');const [bundle,setBundle]=useState<Bundle|null>(null);const [error,setError]=useState('');const [loading,setLoading]=useState(true);
useEffect(()=>{const controller=new AbortController();fetchBundle(controller.signal).then(setBundle).catch(e=>{if(!controller.signal.aborted)setError(String(e?.message||e))}).finally(()=>{if(!controller.signal.aborted)setLoading(false)});return ()=>controller.abort()},[]);
const kind=bundle?.manifest.data_kind==='synthetic_fixture'?'SYNTHETIC FIXTURE':'ARCHIVED SNAPSHOT';const kev=bundle?.manifest.source_snapshots.find(x=>x.source==='kev');const epss=bundle?.manifest.source_snapshots.find(x=>x.source==='epss');
return <div className="site"><a className="skip" href="#main">Skip to content</a><header className="topbar"><Logo/><div className="header-right"><span className="edition">RESEARCH EDITION <b> / 01</b></span><span className="header-pill">VULNERABILITY INTELLIGENCE</span></div></header><nav aria-label="Primary navigation" className="navigation">{([['atlas','01 / Intelligence brief'],['explorer','02 / Vulnerability explorer'],['methods','03 / Methods & quality']] as const).map(([key,label])=><button key={key} className={view===key?'selected':''} aria-current={view===key?'page':undefined} onClick={()=>setView(key)}>{label}</button>)}<span className="nav-end">DATA FIRST. CLAIMS SECOND.</span></nav><main id="main">{loading?<section className="status" role="status">Checking available data exports…</section>:error||!bundle?<section className="status" role="alert"><span className="eyebrow">DATA CONNECTION / UNAVAILABLE</span><h1>No verified export loaded.</h1><p>The interface never substitutes invented statistics. Generate and verify a synthetic export bundle, then copy the manifest and JSON marts into <code>apps/web/public/demo/</code>.</p><details><summary>Technical detail</summary><code>{error}</code></details></section>:<><div className="classification"><span><span className="live-dot"/> {kind} · {bundle.manifest.schema_id}</span><span>KEV {kev?.source_date} <i>/</i> EPSS {epss?.source_date}</span></div>{view==='atlas'?<><section className="hero"><div><div className="eyebrow">INTELLIGENCE BRIEF <span className="hairline"/> VOLUME 001</div><h1>What the<br/><em>data says.</em></h1><p className="lede">Known exploitation and modeled likelihood are different signals. Explore where the sources overlap, what is missing, and what we can responsibly conclude.</p><div className="hero-footer"><span className="pill-ink">{kind}</span><span>Source pairing, not a risk prediction.</span></div></div><aside className="hero-aside"><div className="aside-top">SOURCE COVERAGE / NOT RISK <span>↗</span></div><div className="huge-stat">{pct(bundle.coverage.coverage_percent)}</div><p>of KEV records have a matching EPSS score in this source pair. This measures data coverage, not organizational risk.</p><div className="aside-rule"/><div className="aside-numbers"><div><span>MATCHED</span><strong>{fmt(bundle.coverage.numerator_matched_kev)}</strong></div><div><span>CATALOG</span><strong>{fmt(bundle.coverage.denominator_total_kev)}</strong></div><div><span>UNMATCHED</span><strong>{fmt(bundle.coverage.unmatched_kev)}</strong></div></div></aside></section><IntelligenceBrief brief={intelligenceBrief(bundle.manifest,bundle.coverage,bundle.population)} onMethods={() => setView('methods')}/><EvidenceGlossary/><section className="section-intro"><div><span className="eyebrow">FIGURE 01 / DISTRIBUTION</span><h2>The full EPSS<br/>population, in view.</h2></div><p>Probability bands are calculated across <strong>all scored CVEs</strong> in the selected EPSS snapshot, not only records also listed in KEV.</p></section><section className="chart-card"><div className="chart-header"><div><span className="eyebrow">EPSS PROBABILITY · BANDS</span><h3>{fmt(bundle.population.scored_cve_count)} <small>scored CVEs</small></h3></div><div className="legend"><span/> Distribution of scored CVEs</div></div><Bars bands={bundle.bands} population={bundle.population.scored_cve_count} sourceDate={bundle.population.epss_source_date} dataKind={bundle.manifest.data_kind}/><div className="chart-foot"><span>Bands are mutually exclusive · labels reflect source SQL thresholds</span><span>EPSS {epss?.source_date}</span></div></section><section className="stat-row"><div><span>POPULATION MEAN</span><strong>{chance(bundle.population.mean_epss)}</strong><small>Average EPSS probability</small></div><div><span>MEDIAN / P50</span><strong>{chance(bundle.population.median_epss)}</strong><small>50th-percentile score</small></div><div><span>P90</span><strong>{chance(bundle.population.p90_epss)}</strong><small>90th-percentile score</small></div></section>{bundle.cohort?<CohortComparison rows={bundle.cohort} coverage={bundle.coverage} population={bundle.population} sourceDate={bundle.population.epss_source_date} dataKind={bundle.manifest.data_kind}/>:null}<section className="note"><div className="note-marker">!</div><div><span className="eyebrow">READING THE DATA</span><h3>Probability is not observation.</h3><p>EPSS estimates the probability of exploitation in the next 30 days. KEV membership identifies vulnerabilities with evidence of known exploitation. Neither metric alone measures the risk to a particular organization.</p></div><button onClick={()=>setView('methods')}>Methods & provenance <span aria-hidden="true">↗</span></button></section></>:view==='explorer'?LocalExplorer?<React.Suspense fallback={<section className="status" role="status">Loading local Explorer...</section>}><LocalExplorer/></React.Suspense>:PublicExplorer?<React.Suspense fallback={<section className="status" role="status">Loading verified fictional Explorer...</section>}><PublicExplorer/></React.Suspense>:<section className="status"><span className="eyebrow">02 / VULNERABILITY EXPLORER</span><h1>A closer look,<br/><em>not a guess.</em></h1><p>The current contracts publish validated aggregate metrics, not an approved CVE-level browser dataset. The searchable explorer will activate after a curated, validated export is added. No placeholder CVE rows are presented as findings.</p><button className="primary" onClick={()=>setView('atlas')}>Return to intelligence atlas ↗</button></section>:<><section className="methods-head"><span className="eyebrow">03 / METHODS & DATA QUALITY</span><h1>Every figure<br/><em>has a source.</em></h1><p>The present view is backed by a validated local export bundle. Validation and provenance belong alongside the story.</p></section><section className="quality-grid"><div><span>DATA CLASSIFICATION</span><strong>{kind}</strong><p>{bundle.manifest.data_kind==='synthetic_fixture'?'Fixture outputs are not empirical measurements.':'Archived observations are historical snapshots, not a live feed.'}</p></div><div><span>SCHEMA CONTRACT</span><strong>{bundle.manifest.schema_id}</strong><p>Versioned consumer format.</p></div><div><span>ARTIFACT RECORDS</span><strong>{bundle.manifest.artifacts.length}</strong><p>Manifest-listed dataset artifacts; verify SHA-256 with the Python exporter before publishing.</p></div></section><section className="sources"><h2>Snapshot register</h2>{bundle.manifest.source_snapshots.map(s=><div key={s.source} className="source-row"><span>{s.source.toUpperCase()}</span><div><strong>{s.source_date}</strong><small>Snapshot ID: {s.snapshot_id}</small></div><div><strong>{fmt(s.row_count)} records</strong><small>Retrieved {s.retrieved_at_utc||'Not stated'}</small></div></div>)}</section><ArtifactRegister artifacts={bundle.manifest.artifacts}/><div className="note"><div className="note-marker">i</div><div><h3>Source integrity caveat</h3><p>The browser checks data shape and accounting. It does not cryptographically verify file hashes. Use <code>python -m patchline.exports.analytics verify</code> to validate the export bundle before copying it into the site.</p></div></div></>}</>}<footer><Logo/><div><span>DESIGNED TO EXPLAIN. BUILT TO REPRODUCE.</span><p>Exploit Atlas / Source-backed vulnerability intelligence, not operational security advice.</p></div><a href="https://github.com/danielguillaumont/exploit-atlas" rel="noreferrer" target="_blank">SOURCE REPOSITORY ↗</a></footer></main></div>}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>);
