'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const extensionBuild = fs.readFileSync(path.join(root,'extension/build.sha256'),'utf8');
function event() {
  const listeners = [];
  return {addListener(fn) {listeners.push(fn);}, emit(...args) {for (const fn of listeners) fn(...args);}};
}
async function flush() { for (let i=0;i<20;i++) await Promise.resolve(); }
async function fixture() {
  const sent = [], completions = [], connections = [], timers = [];
  const api = Object.fromEntries(['onCreateRequest','onGetRequest','onIsUvpaaRequest','onRequestCanceled','onRemoteSessionStateChange'].map(key => [key,event()]));
  api.attach = async () => undefined;
  api.detach = async () => undefined;
  for (const [method,type] of [['completeCreateRequest','create'],['completeGetRequest','get'],['completeIsUvpaaRequest','uvpaa']])
    api[method] = async message => {completions.push({type,...message});};
  const chrome = {webAuthenticationProxy:api, runtime:{id:'test-extension',onMessage:event(),onStartup:event(),onInstalled:event(), connectNative(name) {
    assert.equal(name,'com.auth_browser.proxy');
    const port={onMessage:event(),onDisconnect:event(),postMessage(message) {sent.push(message);},disconnect() {this.onDisconnect.emit();}};
    connections.push(port); return port;
  }}, alarms:{create() {},clear() {},onAlarm:event()}};
  vm.runInNewContext(fs.readFileSync(path.join(root,'extension/background.js'),'utf8'),{chrome,clearTimeout() {},setTimeout(fn) {timers.push(fn); return timers.length;}});
  await flush();
  return {api,chrome,sent,completions,connections,timers};
}
(async () => {
  const manifest=JSON.parse(fs.readFileSync(path.join(root,'extension/manifest.json')));
  const native=JSON.parse(fs.readFileSync(path.join(root,'runtime/com.auth_browser.proxy.json')));
  const id=[...crypto.createHash('sha256').update(Buffer.from(manifest.key,'base64')).digest('hex').slice(0,32)].map(c => String.fromCharCode(97+parseInt(c,16))).join('');
  assert.deepEqual(native.allowed_origins,[`chrome-extension://${id}/`]);
  assert.equal(manifest.manifest_version,3);
  assert.equal(manifest.content_scripts,undefined);
  assert.equal(manifest.externally_connectable,undefined);
  const f=await fixture();
  assert.equal(f.sent[0].type,'ready');
  assert.equal(f.sent[0].extensionVersion,'1.0.29');
  assert.equal(f.sent[0].extensionBuild,extensionBuild);
  assert.equal(f.sent[0].protocolVersion,1);
  assert.equal(f.sent[0].capabilities.join(','),'heartbeat,mode_ack_generation,mode_progress,mode_lease,local_navigation');
  const replies=[];
  const query=sender=>f.chrome.runtime.onMessage.emit({type:'broker_version'},sender,v=>replies.push(v));
  for(const sender of [{id:'external',url:'chrome-extension://test-extension/upgrade.html'},
    {id:'test-extension',url:'https://example.test/upgrade.html'},
    {id:'test-extension',url:'chrome-extension://test-extension/background.js'},
    {id:'test-extension',url:'chrome-extension://test-extension/upgrade.html.evil'}]) query(sender);
  assert.equal(replies.length,0);
  query({id:'test-extension',url:'chrome-extension://test-extension/upgrade.html?expected=1.0.29'});
  assert.equal(replies.length,1);
  assert.equal(replies[0].extensionVersion,'1.0.29');
  assert.equal(replies[0].extensionBuild,extensionBuild);
  assert.equal(Object.keys(replies[0]).sort().join(','),'capabilities,extensionBuild,extensionVersion,protocolVersion');
  const details='{"challenge":"exact","extensions":{"remoteDesktopClientOverride":{"origin":"https://example.test"}}}';
  f.api.onCreateRequest.emit({requestId:1,requestDetailsJson:details});
  assert.equal(f.sent[1].requestDetailsJson,details);
  f.connections[0].onMessage.emit({type:'get',requestId:1,responseJson:'{}'});
  assert.equal(f.completions.length,0);
  f.connections[0].onMessage.emit({type:'create',requestId:1,responseJson:'{}'});
  f.connections[0].onMessage.emit({type:'create',requestId:1,responseJson:'{}'});
  assert.equal(f.completions.length,1);
  f.api.onGetRequest.emit({requestId:2,requestDetailsJson:'{}'});
  f.api.onRequestCanceled.emit(2);
  assert.equal(f.sent.at(-1).type,'cancel');
  f.connections[0].onMessage.emit({type:'get',requestId:2,responseJson:'{}'});
  assert.equal(f.completions.length,1);
  f.api.onGetRequest.emit({requestId:3,requestDetailsJson:'{}'});
  f.api.onIsUvpaaRequest.emit({requestId:4});
  f.connections[0].onDisconnect.emit();
  assert.equal(f.completions.length,3);
  assert.equal(f.completions[1].error.name,'NotAllowedError');
  assert.equal(f.completions[2].isUvpaa,false);
  f.api.onGetRequest.emit({requestId:5,requestDetailsJson:'{}'});
  assert.equal(f.completions.at(-1).error.name,'NotAllowedError');
  f.timers.at(-1)(); await flush();
  assert.equal(f.connections.length,2);
  f.api.onIsUvpaaRequest.emit({requestId:6});
  f.connections[0].onMessage.emit({type:'uvpaa',requestId:6,isUvpaa:true});
  assert.equal(f.completions.length,4);
  f.connections[1].onMessage.emit({type:'uvpaa',requestId:6,isUvpaa:true});
  assert.equal(f.completions.at(-1).isUvpaa,true);
  const n=await fixture();
  let detachDone;
  n.api.detach=()=>new Promise(resolve=>{detachDone=resolve;});
  n.connections[0].onMessage.emit({type:'mode',mode:'native',generation:1,leaseRemainingMs:120000});
  await flush();
  assert.equal(n.sent.filter(x=>x.type==='mode_ready').length,0);
  detachDone(); await flush();
  assert.deepEqual(JSON.parse(JSON.stringify(n.sent.at(-1))),{type:'mode_ready',mode:'native',generation:1,
    attached:false,extensionVersion:'1.0.29',protocolVersion:1});
  n.connections[0].onMessage.emit({type:'mode',mode:'proxy',generation:2}); await flush();
  assert.equal(n.sent.at(-1).mode,'proxy');
  n.connections[0].onMessage.emit({type:'mode',mode:'native',generation:1,leaseRemainingMs:120000}); await flush();
  assert.equal(n.sent.at(-1).mode,'proxy');
  n.api.detach=async()=>undefined;
  n.connections[0].onMessage.emit({type:'mode',mode:'native',generation:3,leaseRemainingMs:120000}); await flush();
  let reattached=0;
  n.api.attach=async()=>{reattached++;};
  n.connections[0].onDisconnect.emit(); await flush();
  assert.equal(reattached,0);
  const race=await fixture();
  let detachRace;
  race.api.detach=()=>new Promise(resolve=>{detachRace=resolve;});
  race.connections[0].onMessage.emit({type:'mode',mode:'native',generation:1,leaseRemainingMs:120000}); await flush();
  race.connections[0].onDisconnect.emit(); detachRace(); await flush();
  assert.equal(race.sent.filter(x=>x.type==='mode_ready').length,0);
  console.log('Extension proxy: forwarding, cancellation, stale/duplicate responses, disconnect and reconnect passed.');
})().catch(error => {console.error(error); process.exitCode=1;});
