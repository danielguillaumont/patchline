import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validatedRelease, approvalPath, candidatePath} from '../scripts/explorer-public-release.mjs';
import {validatePublicExplorerPayload, explorerPublicUrls} from '../src/explorer-public-model.mjs';
const files=()=>{
  const c=JSON.parse(readFileSync(candidatePath));
  const a=JSON.parse(readFileSync(approvalPath));
  Object.assign(a,{approved:true,approved_by:'repository_owner',approved_at_utc:'2026-11-13T20:00:00Z',review_note:'All three fictional examples reviewed carefully for public preview.'});
  const state=validatedRelease(c,a);
  return {doc:JSON.parse(state.dataBytes),manifest:state.manifest,length:state.dataBytes.length};
};
test('browser validates approved fictional public payload',()=>{
  const {doc,manifest,length}=files();
  const out=validatePublicExplorerPayload(doc,manifest,length);
  assert.equal(out.records.length,3);
  assert.equal(out.records[0].epss,0);
  assert.equal(out.records[1].epss,null);
});
test('browser rejects fake release data status',()=>{
  const {doc,manifest,length}=files();doc.public_release_approved=false;
  assert.throws(()=>validatePublicExplorerPayload(doc,manifest,length),/classification/);
});
test('browser rejects extra risk score',()=>{
  const {doc,manifest,length}=files();doc.records[0].risk_score=99;
  assert.throws(()=>validatePublicExplorerPayload(doc,manifest,length),/record shape/);
});
test('browser rejects forged source archive verification',()=>{
  const {doc,manifest,length}=files();manifest.source_archives_reverified=true;
  assert.throws(()=>validatePublicExplorerPayload(doc,manifest,length),/identity/);
});
test('browser rejects incorrect data byte count',()=>{
  const {doc,manifest,length}=files();
  assert.throws(()=>validatePublicExplorerPayload(doc,manifest,length+1),/identity/);
});
test('browser keeps strict Pages base URLs',()=>{
  assert.deepEqual(explorerPublicUrls('/exploit-atlas/'),{records:'/exploit-atlas/explorer/cve-records.json',manifest:'/exploit-atlas/explorer/manifest.json'});
  for(const bad of ['//attacker/','/exploit-atlas','/../','https://example.com/']) assert.throws(()=>explorerPublicUrls(bad),/unsafe/);
});
