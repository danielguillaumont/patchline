"""EA-05D1: render an offline, local-only CVE investigation HTML report.

Verifies an existing bounded-join consumer bundle against its original join JSON.
No network access, repo writes, source authentication, or publication is performed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from patchline.exports.cve_bundle import REPO_ROOT, CVEBundleError, verify_bundle

REPORT_ID = "exploit-atlas.local-cve-investigation.v1"
MAX_REPORT_RECORDS = 5000


class LocalCVEExplorerError(ValueError):
    """Report creation was unsafe or inconsistent with the verified bundle."""


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise LocalCVEExplorerError(reason)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _embedded_json(value: dict[str, Any]) -> str:
    """Produce JSON that cannot terminate its containing script element."""
    text = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(",", ":"))
    return (text.replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026").replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'none'; connect-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Local CVE Investigation | Exploit Atlas</title>
<style>
:root{color-scheme:light;font-family:system-ui,-apple-system,Segoe UI,Arial,sans-serif;background:#f5f2fa;color:#2e2441}*{box-sizing:border-box}body{margin:0}button,input,select{font:inherit}button{cursor:pointer}button:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid #7d58ce;outline-offset:3px}.mast{background:#2e2441;color:#f8f5ff;padding:20px clamp(18px,5vw,70px);display:flex;justify-content:space-between;gap:20px;align-items:center;font-size:13px}.mast strong{font-size:20px;letter-spacing:-.04em}.tag{font:700 10px ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.11em;padding:9px 12px;background:#d9f17c;color:#2e2441}.hero{background:#2e2441;color:#fff;padding:55px clamp(18px,5vw,70px) 65px;display:grid;grid-template-columns:minmax(0,1.4fr) minmax(235px,.6fr);gap:38px;align-items:end}.eyebrow{font:700 11px ui-monospace,Consolas,monospace;letter-spacing:.11em;color:#9078bd}.hero .eyebrow{color:#d9f17c}.hero h1{font-size:clamp(48px,7vw,94px);line-height:.99;letter-spacing:-.075em;margin:20px 0 22px}.hero h1 em{font-weight:450;color:#d9f17c}.hero p{color:#d6cce7;line-height:1.75;max-width:620px;font-size:15px}.stamp{border:1px solid #8b7b9b;padding:24px;background:#3b2d52}.stamp strong{display:block;color:#d9f17c;font-size:25px;margin:13px 0}.stamp p{margin:0;font-size:12px}.content{max-width:1570px;margin:auto;padding:0 clamp(18px,5vw,70px) 55px}.notice{padding:20px 24px;border-left:5px solid #7455bb;background:#e7dff3;font-size:13px;line-height:1.7;margin:25px 0}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));border:1px solid #ded7e9;background:#fff;margin-bottom:27px}.stat{padding:22px;border-right:1px solid #ded7e9}.stat:last-child{border-right:0}.stat small{display:block;font:700 10px ui-monospace,Consolas,monospace;letter-spacing:.06em;color:#665973}.stat strong{display:block;font-size:36px;letter-spacing:-.06em;margin-top:7px}.toolbar{display:grid;grid-template-columns:minmax(190px,2fr) repeat(3,minmax(120px,1fr)) auto;gap:12px;align-items:end;margin:32px 0 19px}.toolbar label{display:block;font:700 11px ui-monospace,Consolas,monospace;margin-bottom:9px}.toolbar input,.toolbar select{width:100%;min-width:0;padding:12px;border:1px solid #cfc5db;border-radius:0;background:#fff;color:#2e2441;height:47px}.toolbar button{height:47px;padding:0 17px;border:1px solid #2e2441;background:transparent;color:#2e2441;font-size:12px;font-weight:700}.split{display:grid;grid-template-columns:minmax(275px,.85fr) minmax(0,1.15fr);gap:18px}.pane{min-width:0;background:#fff;border:1px solid #ded7e9}.pane-title{padding:20px 23px;border-bottom:1px solid #ded7e9;display:flex;justify-content:space-between;gap:12px;align-items:center}.pane-title h2{font-size:24px;margin:0;letter-spacing:-.04em}.pane-title span{font-size:12px;color:#6e627b}.results{max-height:670px;overflow:auto}.result{width:100%;text-align:left;padding:19px 23px;display:block;background:#fff;color:inherit;border:0;border-left:4px solid transparent;border-bottom:1px solid #e9e4f0}.result:hover{background:#f8f5fc}.result[aria-pressed="true"]{border-left-color:#7855cc;background:#f0eafa}.result strong{font:700 14px ui-monospace,Consolas,monospace}.result span{display:block;font-size:12px;color:#665973;margin-top:8px}.result .result-sub{margin-top:11px;font-size:11px}.detail{padding:26px 30px;min-height:350px}.detail h2{font-size:clamp(27px,4vw,46px);letter-spacing:-.065em;margin:13px 0 5px;overflow-wrap:anywhere}.detail h3{font-size:18px;margin:15px 0}.detail p{line-height:1.7;color:#655777}.facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;background:#dcd5e7;border:1px solid #dcd5e7;margin:23px 0}.fact{background:#f3eff9;padding:17px;min-width:0}.fact small{font:700 10px ui-monospace,Consolas,monospace;color:#655777}.fact strong{display:block;margin-top:9px;font-size:16px;overflow-wrap:anywhere}.metrics{margin-top:26px}.metric{padding:13px 0;border-top:1px solid #ded7e9}.metric strong{display:block}.metric code{display:block;overflow-wrap:anywhere;color:#655777;font-size:11px;margin-top:7px}.fine{background:#eee9f7;padding:20px;font-size:12px;line-height:1.7}.source{margin-top:30px;padding:24px;background:#fff;border:1px solid #ded7e9;font-size:12px}.source h2{margin:0 0 16px;font-size:22px}.source dl{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px}.source dt{font-size:11px;color:#665973}.source dd{margin:5px 0 0;overflow-wrap:anywhere;font-family:ui-monospace,Consolas,monospace}summary{cursor:pointer;font-weight:700}.empty{padding:20px;color:#655777}.footer{padding:30px 0;color:#655777;font-size:11px} @media(max-width:1000px){.toolbar{grid-template-columns:repeat(2,minmax(0,1fr))}.toolbar .search{grid-column:1/-1}.toolbar button{width:100%}.split{grid-template-columns:1fr}.results{max-height:420px}}@media(max-width:640px){.hero{grid-template-columns:1fr;padding-top:37px}.hero h1{font-size:56px}.stamp{max-width:380px}.toolbar{grid-template-columns:1fr}.toolbar .search{grid-column:auto}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.stat:nth-child(2){border-right:0}.stat:nth-child(-n+2){border-bottom:1px solid #ded7e9}.facts{grid-template-columns:1fr}.source dl{grid-template-columns:1fr}.detail{padding:20px}.mast{flex-wrap:wrap}}
</style>
</head>
<body>
<header class="mast"><strong>Exploit Atlas <span aria-hidden="true">/</span> Research Lab</strong><span class="tag">OFFLINE · LOCAL-ONLY REPORT</span></header>
<section class="hero"><div><span class="eyebrow">CVE INVESTIGATION / SOURCE-SCOPED</span><h1>Trace the<br><em>signal.</em></h1><p>Inspect individually returned vulnerability records across NVD, KEV and EPSS without collapsing severity, known exploitation and predicted exploitation into one misleading score.</p></div><aside class="stamp"><span class="eyebrow">VERIFICATION STATE</span><strong>CONSISTENCY CHECKED</strong><p>The candidate bundle was reconciled against the supplied original bounded join before this report was written. This is not independent proof of upstream source authenticity.</p></aside></section>
<main class="content">
<div class="notice"><strong>Local research only — not a public vulnerability catalog.</strong> Records represent one bounded NVD query, not the full NVD corpus. Source dates may differ; historical as-of reconstruction, organizational exposure and original archive authentication are not established. Never commit or publish this generated report as a verified live feed.</div>
<section class="stats" aria-label="Bounded query statistics"><div class="stat"><small>QUERY CVEs</small><strong id="stat-all"></strong></div><div class="stat"><small>KEV MATCHES</small><strong id="stat-kev"></strong></div><div class="stat"><small>EPSS OBSERVED</small><strong id="stat-epss"></strong></div><div class="stat"><small>CVSS METRIC ROWS</small><strong id="stat-cvss"></strong></div></section>
<section class="toolbar" aria-label="Investigation filters"><div class="search"><label for="query">SEARCH CVE / STATUS</label><input type="search" id="query" placeholder="CVE-2026-... or status" autocomplete="off"></div><div><label for="kev">KEV MEMBERSHIP</label><select id="kev"><option value="all">All</option><option value="yes">Listed</option><option value="no">Not listed</option></select></div><div><label for="epss">EPSS OBSERVATION</label><select id="epss"><option value="all">All</option><option value="yes">Scored (including zero)</option><option value="no">Missing</option></select></div><div><label for="status">NVD STATUS</label><select id="status"><option value="all">All statuses</option><option value="Analyzed">Analyzed</option><option value="Awaiting Analysis">Awaiting Analysis</option><option value="other">Other statuses</option></select></div><button id="reset" type="button">CLEAR FILTERS</button></section>
<div class="split"><section class="pane" aria-label="CVE results"><div class="pane-title"><h2>Results</h2><span id="count" aria-live="polite"></span></div><div class="results" id="results"></div></section><section class="pane" aria-label="Selected CVE evidence"><div id="detail" class="detail" aria-live="polite"></div></section></div>
<section class="source"><h2>Evidence register</h2><p>Recorded identifiers and dates describe the selected source pair and query, not live status. SHA-256 digests indicate exact file identity relative to the files supplied to the verifier.</p><details><summary>Inspect source identifiers and verification scope</summary><dl id="source-dl"></dl></details></section>
<footer class="footer">EXPLOIT ATLAS / OFFLINE RESEARCH • NO LIVE API • NO REMEDIATION PRIORITY SCORE • NO PUBLICATION AUTHORIZATION</footer>
</main>
<script id="report-data" type="application/json">__PAYLOAD__</script>
<script>
(()=>{'use strict';
const report=JSON.parse(document.getElementById('report-data').textContent);
const rows=report.records.slice().sort((a,b)=>a.cve_id.localeCompare(b.cve_id));
const id=x=>document.getElementById(x);
const node=(tag,text,cls)=>{const el=document.createElement(tag);if(text!==undefined)el.textContent=String(text);if(cls)el.className=cls;return el};
const add=(parent,tag,text,cls)=>{const el=node(tag,text,cls);parent.appendChild(el);return el};
const f=(n)=>Number(n).toLocaleString('en-US');
const score=v=>v===null||v===undefined?'Missing observation':(Number(v)*100).toFixed(2)+'%';
const selected={id:rows[0]?.cve_id||null};
const cov=report.coverage;
id('stat-all').textContent=f(cov.nvd_query_cves);id('stat-kev').textContent=f(cov.in_selected_kev_snapshot);
id('stat-epss').textContent=f(cov.with_selected_epss_score);id('stat-cvss').textContent=f(cov.nvd_cvss_metric_rows);
const labels=[['NVD query ID',report.source_ids.nvd_query_id],['NVD query mode',report.source_ids.nvd_query_mode],['KEV snapshot ID',report.source_ids.kev_snapshot_id],['KEV source date',report.source_ids.kev_source_date],['EPSS snapshot ID',report.source_ids.epss_snapshot_id],['EPSS score date',report.source_ids.epss_score_date],['EPSS model version',report.source_ids.epss_model_version],['Analysis cutoff',report.analysis_cutoff_date],['Time-precision caveat',report.time_precision],['Bounded-join SHA-256',report.source_join_sha256],['Consumer candidate SHA-256',report.candidate_sha256],['Bundle classification',report.data_kind],['Release approval',String(report.public_release_approved)]];
labels.forEach(([k,v])=>{const dl=id('source-dl');add(dl,'dt',k);add(dl,'dd',v===null?'Not supplied':v)});
function fact(parent,label,value){const w=add(parent,'div',undefined,'fact');add(w,'small',label);add(w,'strong',value)}
function detail(r){const el=id('detail');el.replaceChildren();if(!r){add(el,'h2','No matching CVEs');add(el,'p','Clear or adjust your filters. No records are inferred.');return}
add(el,'span','SELECTED RECORD / BOUNDED SOURCE','eyebrow');add(el,'h2',r.cve_id);
const n=r.nvd,k=r.kev,e=r.epss;
add(el,'p','Source-scoped record. Values reflect the selected inputs and may not match current vendor or NVD data.');
const facts=add(el,'div',undefined,'facts');fact(facts,'NVD STATUS',n.vuln_status||'Not supplied');fact(facts,'KEV MEMBERSHIP',k.listed_in_selected_snapshot?'Listed in selected snapshot':'Not listed in selected snapshot');fact(facts,'EPSS · 30-DAY PROBABILITY',score(e.score));fact(facts,'KEV DATE ADDED',k.date_added||'Not listed');fact(facts,'NVD PUBLISHED',n.published_source_timestamp||'Not supplied');fact(facts,'NVD MODIFIED',n.modified_source_timestamp||'Not supplied');
add(el,'h3','Separate CVSS metric versions');const ms=Array.isArray(n.cvss_metrics)?n.cvss_metrics:[];
if(!ms.length){add(el,'p','No CVSS metrics were present for this record. Missing is not zero.')}else ms.forEach(m=>{const d=add(el,'div',undefined,'metric');add(d,'strong','CVSS '+(m.cvss_version||'unknown')+' · '+(m.base_score===null?'Not scored':Number(m.base_score).toFixed(1)+' / '+(m.base_severity||'severity unspecified')));add(d,'code',m.vector_string||'Vector not supplied');add(d,'small','Metric source: '+(m.metric_source||'Not supplied')+' · type: '+(m.metric_type||'Not supplied'))});
const foot=add(el,'div',undefined,'fine');add(foot,'strong','How to interpret');add(foot,'p','KEV records known exploitation, EPSS estimates future 30-day exploitation probability, and CVSS describes severity. None determines whether your organization has an affected asset.');if(e.score===null)add(foot,'p','No EPSS observation was matched; this is not a zero score.');else if(e.score===0)add(foot,'p','The EPSS observation is explicitly 0.00% in this snapshot, rather than missing.');
}
function render(){const query=id('query').value.trim().toLowerCase(),kev=id('kev').value,epss=id('epss').value,status=id('status').value;
const filtered=rows.filter(r=>(!query||[r.cve_id,r.nvd.vuln_status].some(x=>String(x||'').toLowerCase().includes(query)))&&(kev==='all'||r.kev.listed_in_selected_snapshot===(kev==='yes'))&&(epss==='all'||r.epss.has_score_in_selected_snapshot===(epss==='yes'))&&(status==='all'||(status==='other'?!['Analyzed','Awaiting Analysis'].includes(r.nvd.vuln_status):r.nvd.vuln_status===status)));
if(!filtered.some(r=>r.cve_id===selected.id))selected.id=filtered[0]?.cve_id||null;
id('count').textContent=f(filtered.length)+' matching / '+f(rows.length)+' bounded CVEs';const list=id('results');list.replaceChildren();if(filtered.length===0)add(list,'p','No CVEs match these filters.','empty');
const limit=200;filtered.slice(0,limit).forEach(r=>{const b=add(list,'button',undefined,'result');b.type='button';b.setAttribute('aria-pressed',String(r.cve_id===selected.id));add(b,'strong',r.cve_id);add(b,'span','NVD: '+(r.nvd.vuln_status||'Unknown'));add(b,'span',(r.kev.listed_in_selected_snapshot?'KEV listed':'No KEV listing')+' · EPSS '+score(r.epss.score),'result-sub');b.addEventListener('click',()=>{selected.id=r.cve_id;render()})});if(filtered.length>limit)add(list,'p','Showing the first '+limit+' records. Narrow filters to inspect more.','empty');detail(filtered.find(r=>r.cve_id===selected.id))}
['query','kev','epss','status'].forEach(k=>id(k).addEventListener(k==='query'?'input':'change',render));
id('reset').addEventListener('click',()=>{id('query').value='';id('kev').value='all';id('epss').value='all';id('status').value='all';selected.id=rows[0]?.cve_id||null;render()});render();
})();
</script>
</body>
</html>
'''


def create_local_report(*, source_report: Path, bundle_dir: Path,
                        output_file: Path) -> dict[str, Any]:
    """Verify source/candidate consistency, then write a new standalone local HTML."""
    source_report = Path(source_report)
    bundle_dir = Path(bundle_dir)
    output_file = Path(output_file)
    _require(output_file.is_absolute(), "Output must be an absolute path")
    _require(output_file.suffix.lower() == ".html", "Output must be an .html file")
    _require(not output_file.exists() and not output_file.is_symlink(),
             "Output exists or is a symlink; refusing overwrite")
    _require(output_file.parent.is_dir() and not output_file.parent.is_symlink(),
             "Output parent must be an existing real directory")
    _require(not output_file.resolve().is_relative_to(REPO_ROOT),
             "Report output cannot be placed inside the source repository")
    _require(not any((p / ".git").exists() for p in (output_file.parent.resolve(),
                                                      *output_file.parent.resolve().parents)),
             "Report output cannot be inside any Git working tree")
    verified = verify_bundle(source_report=source_report, bundle_dir=bundle_dir)
    _require(verified["public_release_approved"] is False,
             "Unexpected public approval in verified bundle")
    source_bytes = source_report.read_bytes()
    candidate_bytes = (bundle_dir / "candidate.json").read_bytes()
    manifest_bytes = (bundle_dir / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    candidate = json.loads(candidate_bytes)
    _require(_sha(source_bytes) == verified["source_join_sha256"],
             "Source changed after verification")
    _require(_sha(candidate_bytes) == manifest["files"][0]["sha256"]
             and len(candidate_bytes) == manifest["files"][0]["bytes"],
             "Candidate changed after verification")
    _require(len(candidate["records"]) == verified["records_checked"],
             "Record count changed after verification")
    _require(len(candidate["records"]) <= MAX_REPORT_RECORDS,
             "Bounded report exceeds 5,000 records")
    _require(candidate["published_to_public_demo"] is False,
             "Unsupported published candidate")
    payload = {
        "schema_id": REPORT_ID,
        "source_join_sha256": verified["source_join_sha256"],
        "candidate_sha256": _sha(candidate_bytes),
        "data_kind": candidate["data_kind"],
        "public_release_approved": False,
        "analysis_cutoff_date": candidate["analysis_cutoff_date"],
        "time_precision": candidate["time_precision"],
        "source_ids": candidate["source_ids"],
        "coverage": candidate["coverage"],
        "records": candidate["records"],
    }
    rendered = _HTML.replace("__PAYLOAD__", _embedded_json(payload)).encode("utf-8")
    # Exclusive-create avoids overwriting an existing local research artifact.
    with output_file.open("xb") as handle:
        handle.write(rendered)
    return {
        "schema_id": REPORT_ID,
        "status": "verified_consistency_local_html_created",
        "records": len(candidate["records"]),
        "report_sha256": _sha(rendered),
        "public_release_approved": False,
        "output": str(output_file),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-report", required=True, type=Path)
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = create_local_report(source_report=args.source_report,
                                     bundle_dir=args.bundle_dir,
                                     output_file=args.output)
    except (LocalCVEExplorerError, CVEBundleError, OSError, ValueError, KeyError,
            TypeError, OverflowError) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}, sort_keys=True),
              file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
