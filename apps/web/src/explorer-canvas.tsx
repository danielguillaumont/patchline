import { useState, type ChangeEvent } from 'react';
import './explorer-local.css';
import { filterExplorerRecords, epssText, cvssText } from './explorer-model.mjs';

// Shared presentation only: never import the local fixture into a public bundle.
export type LocalMetric = { version: string; score: number | null; severity: string | null; vector: string | null };
export type Row = {
  cve_id: string; title: string; summary: string; nvd_status: string;
  kev: boolean; kev_date_added: string | null; epss: number | null;
  epss_percentile: number | null; cvss: LocalMetric[];
};
export type ExplorerFixture = { records: Row[]; dates: {nvd:string;kev:string;epss:string}; epss_model:string };
function Flag({ positive, label }: {positive:boolean;label:string}) {
  return <span className={positive ? 'local-flag local-flag-yes' : 'local-flag'}>{label}</span>;
}
function RecordDetail({ row }: {row:Row}) {
  return <section id="local-selected-cve-details" className="local-explorer-detail" aria-label="Selected fictional CVE details">
    <div className="local-detail-top"><span className="eyebrow">INSPECT / FICTIONAL RECORD</span><Flag positive={row.kev} label={row.kev ? 'KEV EXAMPLE / LISTED' : 'NO KEV LISTING'}/></div>
    <h3>{row.cve_id}</h3><h4>{row.title}</h4><p>{row.summary}</p>
    <dl className="local-detail-facts">
      <div><dt>NVD STATUS</dt><dd>{row.nvd_status}</dd></div>
      <div><dt>CVSS SCORE</dt><dd>{cvssText(row.cvss)}</dd></div>
      <div><dt>EPSS / 30-DAY MODEL</dt><dd>{epssText(row.epss)}</dd></div>
      <div><dt>KEV DATE ADDED</dt><dd>{row.kev_date_added ?? 'Not listed'}</dd></div>
    </dl>
    <div className="local-metric-heading"><span className="eyebrow">CVSS METRICS / SEPARATE VERSIONS</span><span>{row.cvss.length} metric records</span></div>
    {row.cvss.length === 0 ? <p className="local-empty-metrics">No CVSS metrics are present in this fictional record. A missing metric is not a zero severity score.</p> :
      <div className="local-cvss-list">{row.cvss.map(metric=><div key={metric.version}>
        <div><strong>CVSS {metric.version}</strong><span>{metric.score === null ? 'Not scored' : `${metric.score.toFixed(1)} · ${metric.severity}`}</span></div>
        <code>{metric.vector ?? 'No vector provided'}</code>
      </div>)}</div>}
    <div className="local-detail-footnote"><strong>How to read this record</strong><p>KEV is evidence of known exploitation; EPSS estimates future 30-day exploitation probability; CVSS measures severity. These are different signals and cannot determine exposure in your organization. {row.epss === null ? 'The absent EPSS value is not a score of zero.' : row.epss === 0 ? 'This sample has an explicit zero EPSS value; it is not a missing observation.' : ''}</p></div>
  </section>;
}
export function ExplorerCanvas({ fixture, mode }: { fixture: ExplorerFixture; mode: "local" | "public" }) {
  const sample = fixture;
  const isPublic = mode === "public";
  const [query, setQuery] = useState('');
  const [kev, setKev] = useState('all');
  const [epss, setEpss] = useState('all');
  const [analysis, setAnalysis] = useState('all');
  const [selectedId, setSelectedId] = useState('CVE-2099-0001');
  const rows = filterExplorerRecords(sample.records, {query,kev,epss,analysis});
  const selected:Row|undefined = rows.find((row:Row)=>row.cve_id===selectedId) ?? rows[0];
  const reset = () => {setQuery('');setKev('all');setEpss('all');setAnalysis('all');setSelectedId('CVE-2099-0001');};
  return <div className="local-explorer" role="region" aria-label={isPublic ? "Public fictional vulnerability explorer" : "Local synthetic vulnerability explorer"}>
    <section className="local-explorer-hero"><div><span className="eyebrow">{isPublic ? "02 / PUBLIC FICTIONAL DEMO / CVE EXPLORER" : "02 / LOCAL LAB / CVE-LEVEL INTELLIGENCE"}</span><h1>Inspect the<br/><em>evidence.</em></h1><p>Search fictional records, compare KEV and EPSS signals, and inspect individual CVSS versions. This demonstration is intentionally small and not a live vulnerability database.</p></div>
      <div className="local-explorer-stamp"><span>DATA CLASSIFICATION</span><strong>FICTIONAL</strong><span>3 CURATED EXAMPLES</span><small>{isPublic ? "REVIEWED FICTIONAL DEMO" : "LOCAL DEVELOPMENT ONLY"}</small></div></section>
    <div className="local-explorer-scope" role="note"><strong>{isPublic ? "PUBLIC DEMO / FICTIONAL EXAMPLES ONLY" : "DEV ONLY / NOT PUBLICATION APPROVED"}</strong><span>The three CVE-2099 identifiers and their details are invented for interface testing. No real exploitation, asset exposure or complete NVD coverage is claimed. This fixture is not the independently verified EA-03A4E2 local export. {isPublic ? "The examples are reviewed for demonstration, not real NVD, KEV or EPSS findings." : ""}</span></div>
    <section className="local-explorer-toolbar" aria-label="CVE search and filters"><div className="local-filter-search"><label htmlFor="local-cve-search">SEARCH FICTIONAL RECORDS</label><input id="local-cve-search" type="search" value={query} onChange={(event:ChangeEvent<HTMLInputElement>)=>setQuery(event.target.value)} placeholder="CVE ID, name or description" /></div>
      <div><label htmlFor="local-kev-filter">KEV STATUS</label><select id="local-kev-filter" value={kev} onChange={(event:ChangeEvent<HTMLSelectElement>)=>setKev(event.target.value)}><option value="all">All</option><option value="yes">Listed</option><option value="no">Not listed</option></select></div>
      <div><label htmlFor="local-epss-filter">EPSS STATUS</label><select id="local-epss-filter" value={epss} onChange={(event:ChangeEvent<HTMLSelectElement>)=>setEpss(event.target.value)}><option value="all">All</option><option value="scored">Scored, including zero</option><option value="missing">Missing score</option></select></div>
      <div><label htmlFor="local-analysis-filter">NVD ANALYSIS</label><select id="local-analysis-filter" value={analysis} onChange={(event:ChangeEvent<HTMLSelectElement>)=>setAnalysis(event.target.value)}><option value="all">All</option><option value="analyzed">Analyzed</option><option value="pending">Awaiting analysis</option></select></div>
      <button className="local-reset" type="button" onClick={reset}>Clear filters</button></section>
    <div className="local-selection-status" role="status" aria-live="polite" aria-atomic="true">{selected ? `Selected ${selected.cve_id}: ${selected.title}.` : "No fictional record selected."}</div>
    <div className="local-explorer-body"><section className="local-results" aria-label="Filtered fictional CVE records"><div className="local-results-heading"><div><span className="eyebrow">RESULTS / SELECTED QUERY</span><h2>{rows.length} <small>of {sample.records.length} fictional CVEs</small></h2></div><span aria-live="polite">{rows.length} matching records</span></div>
      {rows.length === 0 ? <div className="local-no-results" role="status"><h3>No matches in this tiny fixture.</h3><p>Try fewer filters. Nothing is inferred about real-world vulnerabilities.</p><button type="button" onClick={reset}>Reset search and filters</button></div> :
      <div className="local-results-list" role="group" aria-label="Select a fictional CVE">{rows.map((row:Row)=><button type="button" key={row.cve_id} className={selected?.cve_id === row.cve_id?'local-result local-result-active':'local-result'} aria-pressed={selected?.cve_id===row.cve_id} aria-controls="local-selected-cve-details" onClick={()=>setSelectedId(row.cve_id)}>
        <span className="local-result-top"><strong>{row.cve_id}</strong><span>{row.nvd_status}</span></span>
        <span className="local-result-title">{row.title}</span><span className="local-result-bottom"><span>{row.kev?'KEV example':'Not KEV-listed'}</span><span>EPSS {epssText(row.epss)}</span></span>
      </button>)}</div>}</section>
      {selected ? <RecordDetail key={selected.cve_id} row={selected}/> : <section className="local-explorer-detail local-empty-selection" role="status"><h3>No selected record</h3><p>Change the filters to inspect another fictional example.</p></section>}</div>
    <div className="local-explorer-footer"><span>REFERENCE DATES / FICTIONAL</span><span>NVD {sample.dates.nvd} · KEV {sample.dates.kev} · EPSS {sample.dates.epss} · {sample.epss_model}</span><span>NO SOURCE-ARCHIVE ATTESTATION</span></div>
  </div>;
}
