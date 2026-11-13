// EA-05B3 read-only human review evidence. No approval mutation or public output.
import { readFileSync } from 'node:fs';
import { candidatePath, approvalPath, PINNED_CANDIDATE_SHA256, releaseFromRepo } from './explorer-public-release.mjs';
import { canonicalBytes, sha256, validatePublicCandidate } from './explorer-public-contract.mjs';

if (process.argv.length !== 2) throw Error('Read-only review tool takes no arguments');
const doc = JSON.parse(readFileSync(candidatePath, 'utf8'));
const approval = JSON.parse(readFileSync(approvalPath, 'utf8'));
validatePublicCandidate(doc);
const digest = sha256(canonicalBytes(doc));
if (digest !== PINNED_CANDIDATE_SHA256) throw Error('Candidate differs from pinned SHA-256');
if (approval.candidate_sha256 !== digest) throw Error('Approval points to a different candidate');
const release = releaseFromRepo();
if (release.enabled !== approval.approved) throw Error('Unexpected release approval state');
console.log(JSON.stringify({
  review_only: true, approved: approval.approved, candidate_sha256: digest,
  classification: doc.data_kind, provenance: doc.provenance, scope: doc.scope,
  source_archives_reverified: false, records: doc.records.map(r=>({
    cve_id:r.cve_id, title:r.title, summary:r.summary, nvd_status:r.nvd_status,
    kev:r.kev, kev_date_added:r.kev_date_added, epss:r.epss,
    epss_percentile:r.epss_percentile, cvss:r.cvss,
  })),
},null,2));
