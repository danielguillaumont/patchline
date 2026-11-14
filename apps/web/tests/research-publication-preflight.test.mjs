import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {
  canonicalBytes, makeAggregateCandidate,
} from '../scripts/research-publication-candidate.mjs';
import {
  PREFLIGHT_SCHEMA, validateHistoricalPreflight, writeLocalHistoricalPreflight,
} from '../scripts/research-publication-preflight.mjs';

const example = () => readFileSync(new URL('./fixtures/research-review-invented.json', import.meta.url));
const sha = raw => createHash('sha256').update(raw).digest('hex');
const create = () => {
  const insights = example();
  const candidate = makeAggregateCandidate(insights);
  const candidateBytes = canonicalBytes(candidate);
  const receipt = {
    schema_id: 'exploit-atlas.archived-evidence-verification-receipt.v1',
    status: 'verified_local_evidence_only',
    data_kind: 'archived_source_snapshots',
    publication_scope: 'offline_review_only',
    public_release_approved: false,
    export_artifacts_verified: true,
    insight_bytes_independently_rederived: true,
    upstream_feed_authenticity_independently_proven: false,
    candidate_sha256: sha(candidateBytes),
    insight_sha256: sha(insights),
    export_manifest_sha256: 'c'.repeat(64),
    source_snapshots: candidate.source_snapshots,
    insight_ids: candidate.insight_ids,
  };
  return {insights, candidate, candidateBytes, receipt};
};
const checked = x => validateHistoricalPreflight(x.insights, x.candidateBytes, canonicalBytes(x.receipt));
const temp = fn => {
  const folder = mkdtempSync(path.join(tmpdir(), 'ea02c3-preflight-test-'));
  try {return fn(folder);} finally {rmSync(folder, {recursive: true, force: true});}
};

test('accepted invented receipt links metadata without approving release', () => {
  const state = checked(create());
  assert.equal(state.schema_id, PREFLIGHT_SCHEMA);
  assert.equal(state.status, 'receipt_metadata_matched_local_review_only');
  assert.equal(state.public_release_approved, false);
  assert.equal(state.publishable_artifacts_created, false);
  assert.equal(state.upstream_feed_authenticity_independently_proven, false);
  assert.equal(state.human_editorial_approval_required, true);
  assert.equal(state.evidence_scope, 'matching_local_receipt_metadata_not_archive_reverification');
  assert.equal(state.insight_ids.length, 3);
});

test('changed insight bytes invalidate both candidate and receipt', () => {
  const state = create();
  state.insights = Buffer.from(JSON.stringify(JSON.parse(state.insights.toString('utf8')), null, 2));
  assert.throws(() => checked(state), /exact input bytes/);
});

test('changed candidate bytes reject stale receipt', () => {
  const state = create();
  state.candidateBytes = Buffer.from(`${state.candidateBytes.toString('utf8')} `);
  assert.throws(() => checked(state), /canonical JSON/);
});

test('incorrect candidate digest in receipt fails', () => {
  const state = create(); state.receipt.candidate_sha256 = 'd'.repeat(64);
  assert.throws(() => checked(state), /receipt digest/);
});

test('incorrect insight digest in receipt fails', () => {
  const state = create(); state.receipt.insight_sha256 = 'd'.repeat(64);
  assert.throws(() => checked(state), /receipt digest/);
});

test('changed snapshot identity and reordered insight IDs fail', () => {
  const state = create(); state.receipt.source_snapshots = structuredClone(state.receipt.source_snapshots);
  state.receipt.source_snapshots[0].snapshot_id = 'f'.repeat(64);
  assert.throws(() => checked(state), /source or insight identity/);
  const other = create(); other.receipt.insight_ids = [...other.receipt.insight_ids].reverse();
  assert.throws(() => checked(other), /source or insight identity/);
});

test('synthetic or public receipt claim is rejected', () => {
  for (const [field, value] of [
    ['data_kind', 'synthetic_fixture'], ['public_release_approved', true],
    ['publication_scope', 'public'], ['status', 'approved'],
    ['upstream_feed_authenticity_independently_proven', true],
    ['export_artifacts_verified', false], ['insight_bytes_independently_rederived', false],
  ]) {
    const state = create(); state.receipt[field] = value;
    assert.throws(() => checked(state), /verification status or publication safety/, field);
  }
});

test('unknown receipt keys are rejected; cannot add a risk score or fake approval', () => {
  const state = create(); state.receipt.risk_score = 99;
  assert.throws(() => checked(state), /missing or unexpected fields/);
});

test('duplicate JSON keys and noncanonical receipt bytes are rejected', () => {
  const state = create();
  const raw = canonicalBytes(state.receipt).toString('utf8').trimEnd();
  const duplicate = Buffer.from(raw.replace(/^\{/, '{"schema_id":"made-up",') + '\n');
  assert.throws(() => validateHistoricalPreflight(state.insights, state.candidateBytes, duplicate), /canonical JSON/);
  assert.throws(() => validateHistoricalPreflight(state.insights, state.candidateBytes,
    Buffer.from(JSON.stringify(state.receipt, null, 2))), /canonical JSON/);
});

test('receipt checksum must use lowercase SHA-256 format', () => {
  const state = create(); state.receipt.export_manifest_sha256 = 'A'.repeat(64);
  assert.throws(() => checked(state), /receipt digest/);
});

test('writes only a metadata preflight file to a new external TEMP directory', () => temp(dir => {
  const state = create();
  const insights = path.join(dir, 'insights.json');
  const candidate = path.join(dir, 'candidate.json');
  const receipt = path.join(dir, 'evidence-receipt.json');
  writeFileSync(insights, state.insights);
  writeFileSync(candidate, state.candidateBytes);
  writeFileSync(receipt, canonicalBytes(state.receipt));
  const {output, report} = writeLocalHistoricalPreflight(insights, candidate, receipt, dir);
  assert.deepEqual(readdirSync(path.dirname(output)), ['review-preflight.json']);
  assert.equal(readFileSync(output, 'utf8'), canonicalBytes(report).toString('utf8'));
  assert.equal(JSON.stringify(report).includes('Invented example'), false);
}));

test('does not accept relative or repository-local research files', () => temp(dir => {
  const file = path.join(dir, 'i.json'); writeFileSync(file, example());
  assert.throws(() => writeLocalHistoricalPreflight('./insights.json', file, file, dir), /absolute/);
  const repoFixture = path.resolve('tests/fixtures/research-review-invented.json');
  assert.throws(() => writeLocalHistoricalPreflight(repoFixture, file, file, dir), /inside the repository/);
}));

test('no metadata is written if any safety validation fails', () => temp(dir => {
  const state = create(); state.receipt.public_release_approved = true;
  const i = path.join(dir, 'i.json'), c = path.join(dir, 'c.json'), r = path.join(dir, 'r.json');
  writeFileSync(i, state.insights);
  writeFileSync(c, state.candidateBytes);
  writeFileSync(r, canonicalBytes(state.receipt));
  assert.throws(() => writeLocalHistoricalPreflight(i, c, r, dir), /publication safety/);
  assert.deepEqual(readdirSync(dir).sort(), ['c.json','i.json','r.json']);
}));
