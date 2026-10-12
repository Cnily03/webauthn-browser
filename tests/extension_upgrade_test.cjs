'use strict';
// Actual packaged recovery script in a VM; not a real Chromium upgrade test.
// Chromium refreshes unpacked scripts through extension reload, not a web SW
// unregister call: see service_worker_registration_apitest.cc ReloadExtension.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const extensionBuild = fs.readFileSync(path.join(__dirname,'../extension/build.sha256'),'utf8');
const source = fs.readFileSync(path.join(__dirname,'../extension/upgrade.js'),'utf8');
const now = 1800000000000;
const attempt = 'a'.repeat(32) + '-1';
const query = (id=attempt,expires=now+15000) => '?attempt=' + id + '&expires=' + expires;
function fixture(response, {error=false,storageFails=false,marker=false,hold=false,
  search=query(),clock=now,storage=new Map(),reloadThrows=false}={}) {
  let callback,timeout,reloads=0,queries=0;
  const writes=[],status={};
  const markerKey='broker-upgrade-' + extensionBuild + '-' + new URLSearchParams(search).get('attempt');
  if(marker)storage.set(markerKey,'attempted');
  const chrome={runtime:{sendMessage(message,fn){queries++;assert.deepEqual(JSON.parse(JSON.stringify(message)),{type:'broker_version'});callback=fn;if(!hold){this.lastError=error?{message:'No receiving end'}:undefined;fn(response);this.lastError=undefined;}},reload(){assert.equal(storage.get(markerKey),'attempted');reloads++;if(reloadThrows)throw Error('transient reload error');}}};
  vm.runInNewContext(source,{chrome,URLSearchParams,location:{search},Date:{now:()=>clock},
    document:{getElementById(id){assert.equal(id,'status');return status;}},
    sessionStorage:{getItem(key){if(storageFails)throw Error('denied');return storage.get(key);},setItem(key,value){storage.set(key,value);writes.push([key,value]);}},
    setTimeout(fn,ms){assert.equal(ms,2000);timeout=fn;return 1;},clearTimeout(){}});
  return {status,writes,storage,get reloads(){return reloads;},get queries(){return queries;},
    timeout:()=>timeout?.(),reply:result=>callback?.(result),advance:ms=>{clock+=ms;}};
}
const current={extensionVersion:'1.0.29',extensionBuild,protocolVersion:1,capabilities:['heartbeat','mode_ack_generation','mode_progress','mode_lease']};
const fresh=fixture(current);assert.equal(fresh.reloads,0);assert.match(fresh.status.textContent,/confirm readiness/);
fresh.timeout();assert.equal(fresh.reloads,0);
for(const response of [undefined,{}, {extensionVersion:'1.0.27'}, {...current,extensionVersion:'1.0.28'},
  {...current,extensionBuild:undefined},{...current,extensionBuild:'0'.repeat(64)},{...current,protocolVersion:2},{...current,capabilities:['heartbeat']},
  {...current,capabilities:current.capabilities.filter(value=>value!=='mode_lease')}]){
  const stale=fixture(response);assert.equal(stale.reloads,1);stale.timeout();stale.reply(current);assert.equal(stale.reloads,1);
}
const legacy=fixture(undefined,{error:true});assert.equal(legacy.reloads,1);
const timeout=fixture(undefined,{hold:true});assert.equal(timeout.reloads,0);timeout.timeout();assert.equal(timeout.reloads,1);timeout.reply(current);assert.equal(timeout.reloads,1);
const repeated=fixture(undefined,{marker:true});assert.equal(repeated.reloads,0);assert.match(repeated.status.textContent,/Do not delete/);
const denied=fixture(undefined,{storageFails:true});assert.equal(denied.reloads,0);assert.match(denied.status.textContent,/Cannot safely track/);
// A failed first call does not consume the supervisor's distinct second attempt.
const first=fixture(undefined,{reloadThrows:true});assert.equal(first.reloads,1);assert.match(first.status.textContent,/could not reload/);
const second=fixture(undefined,{search:query('a'.repeat(32)+'-2'),storage:first.storage});assert.equal(second.reloads,1);
const restored=fixture(undefined,{search:query('a'.repeat(32)+'-2'),storage:second.storage});assert.equal(restored.reloads,0);
const manualEpisode=fixture(undefined,{search:query('b'.repeat(32)+'-1'),storage:second.storage});assert.equal(manualEpisode.reloads,1);
// The old permanent per-build marker cannot poison newly authorized attempts.
const oldStorage=new Map([['broker-upgrade-'+extensionBuild,'attempted']]);
assert.equal(fixture(undefined,{storage:oldStorage}).reloads,1);
// Delayed replies and timeout callbacks from an expired attempt never reload.
for(const reply of [undefined,current]){
  const delayed=fixture(undefined,{hold:true});delayed.advance(15000);delayed.reply(reply);delayed.timeout();
  assert.equal(delayed.reloads,0);assert.match(delayed.status.textContent,/expired/);
}
const old=fixture(undefined,{hold:true});old.advance(16000);
const newer=fixture(current,{clock:now+16000,search:query('a'.repeat(32)+'-2',now+31000)});
old.timeout();old.reply(undefined);assert.equal(old.reloads,0);assert.equal(newer.reloads,0);assert.match(newer.status.textContent,/confirm readiness/);
for(const search of ['',query('bad'),query('a'.repeat(32)+'-3'),query(attempt,now),query(attempt,now+15001),
  query(attempt,now+15000)+'&attempt='+attempt,query(attempt,now+15000)+'&expires='+(now+15000),
  query()+'&origin=https://example.test', '?attempt='+attempt+'&expires=Infinity',
  '?attempt='+attempt+'&expires=1e12']){
  const invalid=fixture(undefined,{search});invalid.timeout();invalid.reply(undefined);
  assert.equal(invalid.reloads,0);assert.equal(invalid.queries,0);assert.equal(invalid.writes.length,0);
  assert.match(invalid.status.textContent,/no longer active/);
}
console.log('Packaged recovery VM: exact image build, two distinct bounded attempts, explicit new episodes, expired/stale callbacks, malformed markers, session restore, transient reload errors and no false readiness passed.');
