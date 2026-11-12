import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { validateBundle } from './contract.mjs';
import { bandReading } from './band-inspector.mjs';
import { artifactReading } from './evidence-inspector.mjs';
import './styles.css';

type Source = {source:string; snapshot_id:string; source_date:string; retrieved_at_utc?:string; row_count:number; model_version?:string|null};
type Artifact = {path:string;sha256:string;bytes:number;rows:number;columns:string[];model:string};
type Manifest = {schema_id:string; data_kind:'synthetic_fixture'|'archived_source_snapshots'; source_snapshots:Source[]; artifacts: Artifact[]; validation?:{kev_total:number;kev_matched:number;kev_unmatched:number;epss_scored_total:number}};
type Metric = {metric_id:string; numerator_matched_kev:number; denominator_total_kev:number; unmatched_kev:number; coverage_percent:number|null; epss_source_date:string;kev_catalog_date_released:string};
type Population = {scored_cve_count:number;median_epss:number|null;p90_epss:number|null;mean_epss:number|null;epss_source_date:string};
type Band = {band_order:number;band_label?:string;cve_count:number;population_percent:number|null;lower_bound?:number;upper_bound?:number};
type Bundle = {manifest:Manifest;coverage:Metric;population:Population;bands:Band[]};
type View = 'atlas'|'explorer'|'methods';
const files = ['manifest.json','m03_epss_coverage_of_kev.json','m04_epss_population_summary.json','m04_epss_score_bands.json'];
async function fetchBundle(signal:AbortSignal):Promise<Bundle>{
 const values = await Promise.all(files.map(async name=>{
   const response = await fetch(`/demo/${name}`,{signal,cache:'no-store'});
   if(!response.ok) throw Error(`Missing verified demo export: ${name} (${response.status})`);
   return response.json() as Promise<unknown>;
 }));
 return validateBundle(values[0], values[1], values[2], values[3]) as Bundle;
}
const fmt=(n:number)=>new Intl.NumberFormat('en-CA').format(n);
const pct=(n:number|null)=>n===null?'Not defined':`${n.toFixed(2)}%`;
const chance=(n:number|null)=>n===null?'Not defined':`${(n*100).toFixed(2)}%`;
function Logo(){return <div className="wordmark"><svg viewBox="0 0 43 43" fill="none" aria-hidden="true"><path d="M5 5v33M38 5v33" stroke="currentColor" strokeWidth="3"/><path d="M5 12h10l13 19h10M5 31h10L28 12h10" stroke="currentColor" strokeWidth="3"/><circle cx="21.5" cy="21.5" r="5" fill="#DDEC7E" stroke="#302040" strokeWidth="2"/></svg><span>patchline<span className="brand-star">✳</span></span></div>}
function Bars({bands, population, sourceDate}:{bands:Band[];population:number;sourceDate:string}) {
  const [selectedOrder, setSelectedOrder] = useState(1);
  const max = Math.max(1, ...bands.map(b => b.cve_count));
  const current = bands.find(b => b.band_order === selectedOrder) ?? bands[0];
  const reading = bandReading(current, population);

  return <>
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
function ArtifactRegister({artifacts}:{artifacts:Artifact[]}) {
  const [selectedPath, setSelectedPath] = useState('m03_epss_coverage_of_kev.json');
  const selected = artifacts.find(a => a.path === selectedPath) ?? artifacts[0];
  const detail = artifactReading(selected);
  return <section className="artifact-section" aria-labelledby="artifact-heading">
    <div className="artifact-intro">
      <div><span className="eyebrow">EXPORT REGISTER / 09 ARTIFACTS</span><h2 id="artifact-heading">Evidence, file by file.</h2></div>
      <p>Inspect metadata recorded by the immutable export manifest. Three analytical marts are published in CSV, JSON and Parquet.</p>
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
    <p className="artifact-verification-note">For cryptographic verification, run <code>uv run --locked python -m patchline.exports.analytics verify --output &lt;export-directory&gt;</code> against the complete local bundle. The site serves only the manifest and three JSON marts, not all nine artifact files.</p>
  </section>;
}
function App(){const [view,setView]=useState<View>('atlas');const [bundle,setBundle]=useState<Bundle|null>(null);const [error,setError]=useState('');const [loading,setLoading]=useState(true);
useEffect(()=>{const controller=new AbortController();fetchBundle(controller.signal).then(setBundle).catch(e=>{if(!controller.signal.aborted)setError(String(e?.message||e))}).finally(()=>{if(!controller.signal.aborted)setLoading(false)});return ()=>controller.abort()},[]);
const kind=bundle?.manifest.data_kind==='synthetic_fixture'?'SYNTHETIC FIXTURE':'ARCHIVED SNAPSHOT';const kev=bundle?.manifest.source_snapshots.find(x=>x.source==='kev');const epss=bundle?.manifest.source_snapshots.find(x=>x.source==='epss');
return <div className="site"><a className="skip" href="#main">Skip to content</a><header className="topbar"><Logo/><div className="header-right"><span className="edition">RESEARCH EDITION <b> / 01</b></span><span className="header-pill">SPECTRAL INDEX</span></div></header><nav aria-label="Primary navigation" className="navigation">{([['atlas','01 / Intelligence atlas'],['explorer','02 / Vulnerability explorer'],['methods','03 / Methods & quality']] as const).map(([key,label])=><button key={key} className={view===key?'selected':''} aria-current={view===key?'page':undefined} onClick={()=>setView(key)}>{label}</button>)}<span className="nav-end">DATA FIRST. CLAIMS SECOND.</span></nav><main id="main">{loading?<section className="status" role="status">Checking available data exports…</section>:error||!bundle?<section className="status" role="alert"><span className="eyebrow">DATA CONNECTION / UNAVAILABLE</span><h1>No verified export loaded.</h1><p>The interface never substitutes invented statistics. Generate and verify a synthetic export bundle, then copy the four JSON files into <code>apps/web/public/demo/</code>.</p><details><summary>Technical detail</summary><code>{error}</code></details></section>:<><div className="classification"><span><span className="live-dot"/> {kind} · {bundle.manifest.schema_id}</span><span>KEV {kev?.source_date} <i>/</i> EPSS {epss?.source_date}</span></div>{view==='atlas'?<><section className="hero"><div><div className="eyebrow">INTELLIGENCE ATLAS <span className="hairline"/> VOLUME 001</div><h1>Signals in<br/><em>the noise.</em></h1><p className="lede">An evidence-led reading of exploitation signals. Two public datasets, one carefully documented perspective.</p><div className="hero-footer"><span className="pill-ink">{kind}</span><span>Source pairing, not a risk prediction.</span></div></div><aside className="hero-aside"><div className="aside-top">THE MEASURE <span>↗</span></div><div className="huge-stat">{pct(bundle.coverage.coverage_percent)}</div><p>of KEV entries in this selected catalog have a corresponding EPSS score.</p><div className="aside-rule"/><div className="aside-numbers"><div><span>MATCHED</span><strong>{fmt(bundle.coverage.numerator_matched_kev)}</strong></div><div><span>CATALOG</span><strong>{fmt(bundle.coverage.denominator_total_kev)}</strong></div><div><span>UNMATCHED</span><strong>{fmt(bundle.coverage.unmatched_kev)}</strong></div></div></aside></section><section className="section-intro"><div><span className="eyebrow">FIGURE 01 / DISTRIBUTION</span><h2>The full EPSS<br/>population, in view.</h2></div><p>Probability bands are calculated across <strong>all scored CVEs</strong> in the selected EPSS snapshot, not only records also listed in KEV.</p></section><section className="chart-card"><div className="chart-header"><div><span className="eyebrow">EPSS PROBABILITY · BANDS</span><h3>{fmt(bundle.population.scored_cve_count)} <small>scored CVEs</small></h3></div><div className="legend"><span/> Distribution of scored CVEs</div></div><Bars bands={bundle.bands} population={bundle.population.scored_cve_count} sourceDate={bundle.population.epss_source_date}/><div className="chart-foot"><span>Bands are mutually exclusive · labels reflect source SQL thresholds</span><span>EPSS {epss?.source_date}</span></div></section><section className="stat-row"><div><span>POPULATION MEAN</span><strong>{chance(bundle.population.mean_epss)}</strong><small>Average EPSS probability</small></div><div><span>MEDIAN / P50</span><strong>{chance(bundle.population.median_epss)}</strong><small>50th-percentile score</small></div><div><span>P90</span><strong>{chance(bundle.population.p90_epss)}</strong><small>90th-percentile score</small></div></section><section className="note"><div className="note-marker">!</div><div><span className="eyebrow">READING THE DATA</span><h3>Probability is not observation.</h3><p>EPSS estimates the probability of exploitation in the next 30 days. KEV membership identifies vulnerabilities with evidence of known exploitation. Neither metric alone measures the risk to a particular organization.</p></div><button onClick={()=>setView('methods')}>Methods & provenance <span aria-hidden="true">↗</span></button></section></>:view==='explorer'?<section className="status"><span className="eyebrow">02 / VULNERABILITY EXPLORER</span><h1>A closer look,<br/><em>not a guess.</em></h1><p>The current contracts publish validated aggregate metrics, not an approved CVE-level browser dataset. The searchable explorer will activate after a curated, validated export is added. No placeholder CVE rows are presented as findings.</p><button className="primary" onClick={()=>setView('atlas')}>Return to intelligence atlas ↗</button></section>:<><section className="methods-head"><span className="eyebrow">03 / METHODS & DATA QUALITY</span><h1>Every figure<br/><em>has a source.</em></h1><p>The present view is backed by a validated local export bundle. Validation and provenance belong alongside the story.</p></section><section className="quality-grid"><div><span>DATA CLASSIFICATION</span><strong>{kind}</strong><p>Fixture outputs are not empirical measurements.</p></div><div><span>SCHEMA CONTRACT</span><strong>{bundle.manifest.schema_id}</strong><p>Versioned consumer format.</p></div><div><span>ARTIFACT RECORDS</span><strong>{bundle.manifest.artifacts.length}</strong><p>Manifest-listed dataset artifacts; verify SHA-256 with the Python exporter before publishing.</p></div></section><section className="sources"><h2>Snapshot register</h2>{bundle.manifest.source_snapshots.map(s=><div key={s.source} className="source-row"><span>{s.source.toUpperCase()}</span><div><strong>{s.source_date}</strong><small>Snapshot ID: {s.snapshot_id}</small></div><div><strong>{fmt(s.row_count)} records</strong><small>Retrieved {s.retrieved_at_utc||'Not stated'}</small></div></div>)}</section><ArtifactRegister artifacts={bundle.manifest.artifacts}/><div className="note"><div className="note-marker">i</div><div><h3>Source integrity caveat</h3><p>The browser checks data shape and accounting. It does not cryptographically verify file hashes. Use <code>python -m patchline.exports.analytics verify</code> to validate the export bundle before copying it into the site.</p></div></div></>}</>}<footer><Logo/><div><span>DESIGNED TO EXPLAIN. BUILT TO REPRODUCE.</span><p>Patchline · Spectral Index / A research interface, not operational security advice.</p></div><a href="https://github.com/danielguillaumont/patchline" rel="noreferrer" target="_blank">SOURCE REPOSITORY ↗</a></footer></main></div>}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>);
