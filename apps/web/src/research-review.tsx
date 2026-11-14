/** EA-02C2 local-only review. Never import from main.tsx or Pages build. */
import React, {useRef, useState} from 'react';
import {createRoot} from 'react-dom/client';
import {formatReviewSourceDate, validateResearchReviewPack} from './research-review-contract.mjs';
import './research-review.css';

type Source = {source: string; source_date: string; snapshot_id: string; row_count: number};
type Measure = {label: string; count: number; population: number; share_percent: string};
type Insight = {id: string; headline: string; plain_language: string; why_it_matters: string;
  next_question: string; caveat: string; measures: Measure[]; threshold?: string};
type InsightPack = {schema_id: string; data_kind: string; publication_scope: string;
  global_limitation: string; source_snapshots: Source[]; insights: Insight[]};
const serial = ['01', '02', '03'];
const titles = ['A closer look at probability', 'The completeness check', 'The distribution shifts'];
function number(n: number) { return n.toLocaleString('en-CA'); }

function App() {
  const [pack, setPack] = useState<InsightPack | null>(null);
  const [active, setActive] = useState(0);
  const [error, setError] = useState('');
  const [filename, setFilename] = useState('');
  const fileInput = useRef<HTMLInputElement>(null);
  async function load(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    // Never retain or publish an invalid input or transmit its bytes.
    setPack(null); setError(''); setFilename(''); setActive(0);
    try {
      if (file.size > 64 * 1024 || file.size === 0) throw Error('Expected a JSON insight pack smaller than 64 KB.');
      const parsed: unknown = JSON.parse(await file.text());
      const validated = validateResearchReviewPack(parsed) as InsightPack;
      setPack(validated);
      setFilename(file.name);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to open the selected research file.');
    } finally {
      if (fileInput.current) fileInput.current.value = '';
    }
  }
  const finding = pack?.insights[active];
  return <div className="review-shell">
    <a href="#review-main" className="review-skip">Skip to research</a>
    <header className="review-header">
      <div className="review-brand"><span className="review-logo" aria-hidden="true">✳</span> Exploit Atlas<span className="review-brand-star">✳</span></div>
      <div className="review-header-meta">RESEARCH DESK <span>/</span> LOCAL EDITION</div>
    </header>
    <div className="review-banner" role="note"><span className="review-dot"/> ARCHIVED RESEARCH <span className="review-banner-divider">/</span> PRIVATE BROWSER PREVIEW <span className="review-banner-right">NOT PUBLISHED · NOT LIVE</span></div>
    <main id="review-main">
      <section className="review-intro">
        <div className="review-intro-content">
          <p className="review-eyebrow">EA-02C2 / EDITORIAL REVIEW</p>
          <h1>From data<br/>to <em>meaning.</em></h1>
          <p className="review-lede">An evidence-led explanation of vulnerability intelligence. Load a verified, archived insight pack to see what the numbers say, why they matter, and what to check next.</p>
        </div>
        <div className="review-load">
          <p className="review-eyebrow">01 / SOURCE PACK</p>
          <h2>{pack ? 'Research loaded.' : 'Begin with evidence.'}</h2>
          <p>Choose your locally generated <code>exploit-atlas.archived-insights.v1</code> JSON. The file is read in this browser only; it is not uploaded or saved.</p>
          <label className="review-upload" htmlFor="review-file"><input ref={fileInput} id="review-file" type="file" accept=".json,application/json" onChange={load}/>{pack ? 'Replace research file' : 'Choose insight JSON'} <span aria-hidden="true">↗</span></label>
          <div className="review-upload-foot" aria-live="polite">{pack ? filename : 'LOCAL FILE · MAXIMUM 64 KB'}</div>
          {error && <p className="review-error" role="alert">{error}</p>}
        </div>
      </section>
      {pack && finding ? <>
        <div className="review-context"><div><span className="review-eyebrow">KEV SNAPSHOT</span><strong>{formatReviewSourceDate(pack.source_snapshots[0].source_date)}</strong></div><div><span className="review-eyebrow">EPSS SNAPSHOT</span><strong>{formatReviewSourceDate(pack.source_snapshots[1].source_date)}</strong></div><div><span className="review-eyebrow">SOURCE POPULATIONS</span><strong>{number(pack.source_snapshots[0].row_count)} KEV / {number(pack.source_snapshots[1].row_count)} EPSS</strong></div><div className="review-local-pill">LOCAL REVIEW ONLY</div></div>
        <section className="review-stories" aria-labelledby="review-stories-heading">
          <div className="review-section-heading"><p className="review-eyebrow">02 / THE THREE READINGS</p><h2 id="review-stories-heading">One dataset pair. <em>Three important observations.</em></h2><p>Select a reading to explore its population, plain-language meaning, and limitations.</p></div>
          <div className="review-story-tabs" role="group" aria-label="Select an insight">
            {pack.insights.map((item, index) => <button key={item.id} type="button" aria-pressed={active===index} onClick={()=>setActive(index)}><span>{serial[index]} / INSIGHT</span><strong>{titles[index]}</strong><span className="review-arrow" aria-hidden="true">↗</span></button>)}
          </div>
          <div className="review-main-grid" aria-live="polite">
            <article className="review-main-story"><p className="review-eyebrow">INSIGHT / {serial[active]} <span className="review-hairline"/> OBSERVATION</p><h3>{finding.headline}</h3><p className="review-plain">{finding.plain_language}</p><div className="review-why"><p className="review-eyebrow">WHY IT MATTERS</p><p>{finding.why_it_matters}</p></div></article>
            <aside className="review-measures"><p className="review-eyebrow">THE MEASURES / NOT A RISK RANKING</p>{finding.threshold && <p className="review-threshold">{finding.threshold}</p>}
              {finding.measures.map((m,index) => <div className="review-meter" key={m.label}><div className="review-meter-header"><span>{m.label}</span><strong>{m.share_percent}%</strong></div><div className="review-track" role="img" aria-label={`${m.label}: ${m.share_percent}%`}><div className={index===0 ? 'review-fill review-fill-primary':'review-fill review-fill-secondary'} style={{width:`${m.share_percent}%`}}/></div><small>{number(m.count)} / {number(m.population)} records</small></div>)}
              <p className="review-measure-note">The two groups overlap. Different denominators require careful interpretation.</p>
            </aside>
          </div>
          <div className="review-followup"><section><p className="review-eyebrow">03 / A USEFUL NEXT QUESTION</p><h3>{finding.next_question}</h3></section><section><p className="review-eyebrow">04 / WHAT THIS DOES NOT PROVE</p><p>{finding.caveat}</p></section></div>
        </section>
        <section className="review-provenance"><div><p className="review-eyebrow">05 / PROVENANCE</p><h2>Evidence has an address.</h2><p>Source IDs and dates stay attached to the interpretation. Browser-side validation checks structure and arithmetic only—it does not verify the original data archive. Independent verification happens with the Python CLI before review.</p></div><div className="review-source-list">{pack.source_snapshots.map(source=><details key={source.source}><summary>{source.source.toUpperCase()} / {formatReviewSourceDate(source.source_date)} <span>VIEW SOURCE ID</span></summary><code>{source.snapshot_id}</code></details>)}</div></section>
        <footer className="review-footer"><strong>Exploit Atlas / Research Desk</strong><p>{pack.global_limitation}</p><span>NO PUBLICATION APPROVAL</span></footer>
      </> : <section className="review-empty"><span>01—03</span><h2>The research brief starts after you select a verified insight pack.</h2><p>No source data is bundled with this preview, and nothing in this page approves publication.</p></section>}
    </main>
  </div>;
}
const container = document.getElementById('research-review-root');
if (!container) throw Error('Missing local research review root');
createRoot(container).render(<App/>);
