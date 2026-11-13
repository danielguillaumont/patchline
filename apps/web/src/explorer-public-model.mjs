// Browser shape validation only. Pages build gates provide pinned source attestation.
import { validateLocalExplorerFixture } from './explorer-model.mjs';
export const PUBLIC_DATA_SCHEMA = 'exploit-atlas.public-explorer-data.v1';
export const PUBLIC_MANIFEST_SCHEMA = 'exploit-atlas.public-explorer-release-manifest.v1';
const fields = (value, allowed) => value !== null && typeof value === 'object' &&
  !Array.isArray(value) && Object.keys(value).sort().join('|') === allowed.slice().sort().join('|');
const insist = (ok, issue) => { if (!ok) throw Error(`Public fictional Explorer rejected: ${issue}`); };
export function validatePublicExplorerPayload(payload, manifest, byteLength) {
  insist(fields(payload, ['schema_id','data_kind','publication_state','public_release_approved','provenance','scope','dates','epss_model','records']), 'record fields');
  insist(payload.schema_id === PUBLIC_DATA_SCHEMA && payload.data_kind === 'synthetic_fixture' &&
    payload.publication_state === 'approved_fictional_examples_only' && payload.public_release_approved === true, 'data publication classification');
  insist(fields(manifest, ['schema_id','data_kind','publication_state','public_release_approved','filename','sha256','bytes','record_count','source_candidate_sha256','source_archives_reverified']), 'manifest fields');
  insist(manifest.schema_id === PUBLIC_MANIFEST_SCHEMA && manifest.data_kind === 'synthetic_fixture' &&
    manifest.publication_state === payload.publication_state && manifest.public_release_approved === true, 'manifest classification');
  insist(manifest.filename === 'cve-records.json' && manifest.record_count === 3 &&
    Number.isSafeInteger(manifest.bytes) && manifest.bytes > 0 && manifest.bytes === byteLength &&
    typeof manifest.sha256 === 'string' && /^[a-f0-9]{64}$/.test(manifest.sha256) &&
    manifest.source_candidate_sha256 === '79901457953bcfb1d29999aca7b79e03f0f1005f1ed771a5eba72a976d3f07af' &&
    manifest.source_archives_reverified === false, 'manifest identity');
  const { publication_state: _discard, ...rest } = payload;
  return validateLocalExplorerFixture({ ...rest,
    schema_id: 'exploit-atlas.local-explorer-fixture.v1',
    status: 'developer_preview_not_approved_for_publication',
    public_release_approved: false,
  });
}
export function explorerPublicUrls(base) {
  insist(typeof base === 'string' && /^\/(?:[A-Za-z0-9_-]+\/)*$/.test(base), 'unsafe base URL');
  return { records: `${base}explorer/cve-records.json`, manifest: `${base}explorer/manifest.json` };
}
