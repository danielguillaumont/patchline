import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFileSync, existsSync, mkdirSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  validatedRelease, releaseFromRepo, stagePublicExplorer,
  verifyExplorerDirectory, candidatePath, approvalPath, PINNED_CANDIDATE_SHA256,
} from '../scripts/explorer-public-release.mjs';
import {canonicalBytes, sha256} from '../scripts/explorer-public-contract.mjs';
const fresh = () => JSON.parse(readFileSync(candidatePath,'utf8'));
const approval = () => JSON.parse(readFileSync(approvalPath,'utf8'));
function approved() {return {...approval(),approved:true,approved_by:'repository_owner',approved_at_utc:'2026-11-13T20:00:00Z',review_note:'I reviewed all three deliberately fictional CVE records and their checksum.'};}
function testDir(fn) {
  const parent = join(tmpdir(),`ea05b2-test-${randomUUID()}`);
  mkdirSync(parent);
  try { return fn(join(parent,'explorer')); } finally { rmSync(parent,{recursive:true,force:true}); }
}

test('exact candidate SHA remains pinned to EA-05B1 canonical source',()=>{
  assert.equal(sha256(canonicalBytes(fresh())),PINNED_CANDIDATE_SHA256);
});
test('repository release state matches explicit reviewed approval',()=>{
  const record = approval();
  const state = releaseFromRepo();
  assert.equal(state.enabled, record.approved);
  if (record.approved) {
    assert.equal(record.approved_by, 'repository_owner');
    assert.match(record.approved_at_utc, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    assert.ok(record.review_note.length >= 24);
    assert.equal(JSON.parse(state.dataBytes).records.length, 3);
    assert.equal(state.manifest.source_archives_reverified, false);
  } else {
    assert.equal('dataBytes' in state,false);
  }
});
test('pending approval always withholds data, even with a valid seed',()=>{
  const pending = {...approval(),approved:false,approved_by:null,approved_at_utc:null,review_note:null};
  const result = validatedRelease(fresh(),pending);
  assert.equal(result.enabled,false);
  assert.equal('dataBytes' in result,false);
});
test('cannot stage public directory while approval is pending',()=>testDir(dest=>{
  const pending = {...approval(),approved:false,approved_by:null,approved_at_utc:null,review_note:null};
  const result=stagePublicExplorer(dest,validatedRelease(fresh(),pending));
  assert.equal(result.status,'withheld_pending_review');
  assert.equal(existsSync(dest),false);
}));
test('approved object must explicitly bind exact candidate digest',()=>{
  const a=approved();a.candidate_sha256='0'.repeat(64);
  assert.throws(()=>validatedRelease(fresh(),a),/identity/);
});
test('candidate mutation cannot be approved by just recomputing manifest',()=>{
  const f=fresh();f.records[0].title='Different invented network service';
  assert.throws(()=>validatedRelease(f,approved()),/pinned/);
});
test('approval rejects claimed reviewer when the state is pending',()=>{
  const a={...approval(),approved:false,approved_by:'repository_owner',approved_at_utc:null,review_note:null};
  assert.throws(()=>validatedRelease(fresh(),a),/pending approval/);
});
test('approval rejects missing reviewer identity',()=>{
  const a=approved();a.approved_by=null;
  assert.throws(()=>validatedRelease(fresh(),a),/repository owner/);
});
test('approval rejects invalid timestamp',()=>{
  const a=approved();a.approved_at_utc='today';
  assert.throws(()=>validatedRelease(fresh(),a),/UTC timestamp/);
});
test('approval rejects empty review note',()=>{
  const a=approved();a.review_note='okay';
  assert.throws(()=>validatedRelease(fresh(),a),/review note/);
});
test('approval rejects extra policy field',()=>{
  const a=approved();a.allow_live_data=true;
  assert.throws(()=>validatedRelease(fresh(),a),/approval fields/);
});
test('approved public payload is separate from the always-unapproved candidate',()=>{
  const records=validatedRelease(fresh(),approved());
  assert.equal(records.enabled,true);
  const doc=JSON.parse(records.dataBytes);
  assert.equal(doc.public_release_approved,true);
  assert.equal(doc.publication_state,'approved_fictional_examples_only');
  assert.equal(doc.records.length,3);
  assert.equal(fresh().public_release_approved,false);
  assert.equal(JSON.parse(records.manifestBytes).source_archives_reverified,false);
});
test('approved staging produces exact two files and verifies bytes',()=>testDir(dest=>{
  const state=validatedRelease(fresh(),approved());
  const result=stagePublicExplorer(dest,state);
  assert.equal(result.status,'staged_approved_fictional_demo');
  assert.deepEqual(verifyExplorerDirectory(dest,state),state.manifest);
}));
test('approved staging refuses overwriting existing output',()=>testDir(dest=>{
  const state=validatedRelease(fresh(),approved());
  stagePublicExplorer(dest,state);
  assert.throws(()=>stagePublicExplorer(dest,state),/overwrite/);
}));
test('verification rejects extra file in approved public artifact',()=>testDir(dest=>{
  const state=validatedRelease(fresh(),approved());stagePublicExplorer(dest,state);
  writeFileSync(join(dest,'archive.json'),'{}');
  assert.throws(()=>verifyExplorerDirectory(dest,state),/unexpected/);
}));
test('verification rejects altered records even with unchanged manifest',()=>testDir(dest=>{
  const state=validatedRelease(fresh(),approved());stagePublicExplorer(dest,state);
  writeFileSync(join(dest,'cve-records.json'),'{}');
  assert.throws(()=>verifyExplorerDirectory(dest,state),/record bytes/);
}));
test('verification rejects altered manifest',()=>testDir(dest=>{
  const state=validatedRelease(fresh(),approved());stagePublicExplorer(dest,state);
  writeFileSync(join(dest,'manifest.json'),'{}');
  assert.throws(()=>verifyExplorerDirectory(dest,state),/manifest bytes/);
}));
test('staging refuses any repository-local destination',()=>{
  const state=validatedRelease(fresh(),approved());
  assert.throws(()=>stagePublicExplorer(fileURLToPath(new URL('../public/explorer',import.meta.url)),state),/repository output prohibited/);
});
test('staging refuses relative output',()=>{
  const state=validatedRelease(fresh(),approved());
  assert.throws(()=>stagePublicExplorer('explorer',state),/absolute/);
});
test('staging refuses location not ending in explorer',()=>testDir(dest=>{
  const state=validatedRelease(fresh(),approved());
  assert.throws(()=>stagePublicExplorer(dest+'-wrong',state),/end with explorer/);
}));
