'use strict';
// Executes the actual MV3 worker with both Chrome callback and Promise APIs.
// This is a binding/event-order regression, not a real Chromium/phone test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname,'../extension/background.js'),'utf8');
function event(){const listeners=[];return {addListener(fn){listeners.push(fn);},emit(...args){for(const fn of listeners)fn(...args);}};}
async function flush(){for(let i=0;i<40;i++)await Promise.resolve();}
async function fixture(binding){
  let id=0,now=0;
  const timers=new Map(),sent=[],completions=[],calls=[],waiting=[];
  const api=Object.fromEntries(['onCreateRequest','onGetRequest','onIsUvpaaRequest','onRequestCanceled','onRemoteSessionStateChange'].map(k=>[k,event()]));
  const port={onMessage:event(),onDisconnect:event(),postMessage(v){sent.push(v);},disconnect(){this.onDisconnect.emit();}};
  const chrome={webAuthenticationProxy:api,runtime:{id:'test-extension',onMessage:event(),onStartup:event(),onInstalled:event(),connectNative(){return port;}},alarms:{create(){},clear(){},onAlarm:event()}};
  for(const method of ['attach','detach'])api[method]=callback=>{
    calls.push(method);
    if(method==='attach'&&calls.length===1){if(binding==='callback'){callback();return;}return Promise.resolve();}
    if(binding==='callback'){waiting.push({method,done(error){chrome.runtime.lastError=error?{message:error}:undefined;callback();chrome.runtime.lastError=undefined;}});return;}
    return new Promise((resolve,reject)=>waiting.push({method,done(error){if(error)reject(new Error(error));else resolve();}}));
  };
  for(const method of ['completeGetRequest','completeCreateRequest','completeIsUvpaaRequest'])api[method]=value=>{
    completions.push(value);
    // Chrome's request cancellation can arrive before or after the completion.
    api.onRequestCanceled.emit(value.requestId);
    return Promise.resolve();
  };
  vm.runInNewContext(source,{chrome,Date:{now:()=>now},setTimeout(fn,ms){timers.set(++id,{fn,at:now+ms});return id;},clearTimeout(id){timers.delete(id);}});
  await flush();
  async function advance(ms){const end=now+ms;for(;;){const next=[...timers].filter(([,t])=>t.at<=end).sort((a,b)=>a[1].at-b[1].at)[0];if(!next)break;now=next[1].at;timers.delete(next[0]);next[1].fn();await flush();}now=end;}
  return {api,port,sent,calls,waiting,completions,advance};
}
(async()=>{
  for(const binding of ['callback','promise']){
    const f=await fixture(binding);
    assert.equal(f.sent.find(v=>v.type==='ready').attached,true);
    assert.equal(f.sent.find(v=>v.type==='ready').extensionVersion,'1.0.29');
    assert.equal(f.sent.find(v=>v.type==='ready').protocolVersion,1);
    assert.equal(f.sent.find(v=>v.type==='ready').capabilities.join(','),'heartbeat,mode_ack_generation,mode_progress,mode_lease,local_navigation');
    f.api.onGetRequest.emit({requestId:41,requestDetailsJson:'{"challenge":"do-not-replay"}'});
    f.port.onMessage.emit({type:'get',requestId:41,error:{name:'NotAllowedError',message:'Phone mode selected. Retry sign-in on the website after native mode is ready.'}});
    f.port.onMessage.emit({type:'mode',mode:'native',generation:1,leaseRemainingMs:120000});await flush();
    assert.equal(f.completions.length,1);
    assert.equal(f.sent.some(v=>v.type==='mode_ready'),false,'undefined callback return is not completion');
    await f.advance(4000);
    assert.equal(f.sent.filter(v=>v.type==='mode_error').length,1);
    assert.equal(f.sent.find(v=>v.type==='mode_error').operation,'detach');
    f.port.onMessage.emit({type:'mode',mode:'proxy',generation:2});await flush();
    f.api.onGetRequest.emit({requestId:42,requestDetailsJson:'{}'});
    assert.equal(f.sent.some(v=>v.type==='get'&&v.requestId===42),false,'unresolved physical transition blocks proxy forwarding');
    await f.advance(1000);
    const ping=f.sent.find(v=>v.type==='ping');assert.ok(ping,'timeout cannot stop heartbeat');
    f.port.onMessage.emit({type:'pong',nonce:ping.nonce});
    assert.equal(f.calls.join(','),'attach,detach','rollback may not overlap late detach');
    f.waiting.shift().done();await flush();
    assert.equal(f.calls.join(','),'attach,detach,attach');
    assert.equal(f.sent.some(v=>v.type==='mode_ready'),false);
    f.waiting.shift().done();await flush();
    const acknowledgements=f.sent.filter(v=>v.type==='mode_ready');
    assert.equal(acknowledgements.length,1);assert.equal(acknowledgements[0].mode,'proxy');assert.equal(acknowledgements[0].generation,2);
    assert.equal(f.sent.some(v=>v.type==='mode_ready'&&v.mode==='native'),false);
    assert.equal(f.completions.filter(v=>v.requestId===41).length,1);
    const e=await fixture(binding);
    e.port.onMessage.emit({type:'mode',mode:'native',generation:1,leaseRemainingMs:120000});await flush();
    e.waiting.shift().done('Browser rejected detach');await flush();
    const errors=e.sent.filter(v=>v.type==='mode_error');assert.equal(errors.length,1);assert.equal(errors[0].reason,'api_error');
    assert.equal(e.sent.some(v=>v.type==='mode_ready'),false);
    await e.advance(4000);assert.equal(e.sent.filter(v=>v.type==='mode_error').length,1,'API error clears watchdog');
  }
  console.log('Extension mode: callback/Promise completion, cancellation ordering, bounded failure, no false ack/replay, serial late rollback and heartbeat passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
