'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname,'../extension/background.js'),'utf8');
function event() { const listeners=[]; return {addListener(fn){listeners.push(fn);},emit(...args){for(const fn of listeners)fn(...args);}}; }
async function flush(){for(let i=0;i<30;i++)await Promise.resolve();}
function deferred(){let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};}
async function fixture(operations={}){
  let now=0,id=0,attaches=0,detaches=0;
  const timers=new Map(),ports=[],completed=[];
  const api=Object.fromEntries(['onCreateRequest','onGetRequest','onIsUvpaaRequest','onRequestCanceled','onRemoteSessionStateChange'].map(k=>[k,event()]));
  api.attach=async()=>{attaches++;await operations.attach?.();}; api.detach=async()=>{detaches++;await operations.detach?.();};
  for(const k of ['completeCreateRequest','completeGetRequest','completeIsUvpaaRequest'])api[k]=async v=>completed.push(v);
  const chrome={webAuthenticationProxy:api,runtime:{id:'test-extension',onMessage:event(),onStartup:event(),onInstalled:event(),connectNative(){
    const port={sent:[],onMessage:event(),onDisconnect:event(),postMessage(v){this.sent.push(v);},disconnect(){this.onDisconnect.emit();}};ports.push(port);return port;
  }},alarms:{create(){},clear(){},onAlarm:event()}};
  vm.runInNewContext(source,{chrome,Date:{now:()=>now},setTimeout(fn,ms){timers.set(++id,{fn,at:now+ms,ms});return id;},clearTimeout(id){timers.delete(id);}});
  await flush();
  async function advance(ms){const end=now+ms;while(true){const next=[...timers].filter(([,v])=>v.at<=end).sort((a,b)=>a[1].at-b[1].at)[0];if(!next)break;now=next[1].at;timers.delete(next[0]);next[1].fn();await flush();}now=end;await flush();}
  return {api,chrome,ports,completed,advance,timerCount(ms){return [...timers.values()].filter(t=>t.ms===ms).length;},get attaches(){return attaches;},get detaches(){return detaches;}};
}
async function acknowledgeHeartbeat(f,connection){
  const before=connection.sent.filter(m=>m.type==='ping').length;
  await f.advance(5000);
  const pings=connection.sent.filter(m=>m.type==='ping');
  assert.equal(pings.length,before+1,'each interval must send exactly one heartbeat');
  assert.equal(f.timerCount(10000),1,'exactly one pong deadline must be active');
  const ping=pings.at(-1);
  connection.onMessage.emit({type:'pong',nonce:ping.nonce});
  connection.onMessage.emit({type:'pong',nonce:ping.nonce});
  await flush();
  assert.equal(f.timerCount(10000),0);
  assert.equal(f.timerCount(5000),1,'duplicate pongs must not add heartbeat timers');
  return ping;
}
async function pendingInitializationHeartbeats(){
  const attach=deferred();
  const f=await fixture({attach:()=>attach.promise}),connection=f.ports[0];
  assert.equal(f.attaches,1);
  assert.equal(connection.sent.length,0,'pending attach must not announce proxy readiness');
  for(let i=0;i<5;i++)await acknowledgeHeartbeat(f,connection);
  assert.equal(f.ports.length,1,'pending initialization must stay connected beyond the backend idle timeout');
  assert.equal(connection.sent.some(m=>m.type==='ready'),false);
  attach.resolve();await flush();
  const ready=connection.sent.filter(m=>m.type==='ready');
  assert.equal(ready.length,1);assert.equal(ready[0].mode,'proxy');assert.equal(ready[0].attached,true);
  assert.equal(f.timerCount(5000),1,'completing initialization must not start a second heartbeat loop');
  await acknowledgeHeartbeat(f,connection);
  connection.onDisconnect.emit();
  assert.equal(f.timerCount(5000),0);assert.equal(f.timerCount(10000),0);

  const stalledAttach=deferred();
  const stalled=await fixture({attach:()=>stalledAttach.promise});
  await stalled.advance(15000);
  assert.equal(stalled.timerCount(5000),0);assert.equal(stalled.timerCount(10000),0);
  stalledAttach.resolve();await flush();
  assert.equal(stalled.ports[0].sent.some(m=>m.type==='ready'),false,'a timed-out initializer must never announce readiness');
  await stalled.advance(1000);assert.equal(stalled.ports.length,2);
}
async function pendingDetachReconnectHeartbeats(){
  const detach=deferred();
  const f=await fixture({detach:()=>detach.promise}),original=f.ports[0];
  f.api.onGetRequest.emit({requestId:41,requestDetailsJson:'{"challenge":"never-replay"}'});
  assert.equal(original.sent.at(-1).type,'get');
  original.onMessage.emit({type:'mode',mode:'native',generation:1,leaseRemainingMs:120000});await flush();
  assert.equal(f.completed.length,1);assert.equal(f.completed[0].requestId,41);
  assert.equal(f.completed[0].error.name,'NotAllowedError');
  assert.equal(f.detaches,1);assert.equal(original.sent.some(m=>m.type==='mode_ready'),false);
  await f.advance(5000);const originalPing=original.sent.at(-1);assert.equal(originalPing.type,'ping');
  await f.advance(3000);original.onDisconnect.emit();await f.advance(1000);
  const replacement=f.ports[1];
  assert.equal(replacement.sent.length,0,'reconnect must wait for the interrupted detach before ready');
  assert.equal(f.attaches,1);assert.equal(f.detaches,1,'reconnect must not overlap detach operations');
  await f.advance(5000);
  const ping=replacement.sent.at(-1);assert.ok(ping,'replacement must heartbeat before pending detach finishes');assert.equal(ping.type,'ping');
  assert.notEqual(ping.nonce,originalPing.nonce,'reconnect must not reuse heartbeat nonces');
  original.onMessage.emit({type:'pong',nonce:ping.nonce});
  replacement.onMessage.emit({type:'pong',nonce:originalPing.nonce});
  assert.equal(f.timerCount(10000),1,'old-port and stale pongs must not clear the current deadline');
  assert.equal(f.timerCount(5000),0);
  replacement.onMessage.emit({type:'pong',nonce:ping.nonce});await flush();
  for(let i=0;i<4;i++)await acknowledgeHeartbeat(f,replacement);
  assert.equal(f.ports.length,2,'reconnect must stay alive while detach remains unresolved for over 20 seconds');
  assert.equal(replacement.sent.every(m=>m.type==='ping'),true,'heartbeat must not falsely announce mode readiness');
  original.onMessage.emit({type:'get',requestId:41,responseJson:'{}'});
  replacement.onMessage.emit({type:'get',requestId:41,responseJson:'{}'});
  assert.equal(f.completed.length,1,'canceled authentication must complete only once');
  detach.resolve();await flush();
  const ready=replacement.sent.filter(m=>m.type==='ready');
  assert.equal(ready.length,1);assert.equal(ready[0].mode,'native');assert.equal(ready[0].attached,false);
  assert.equal(ready[0].leaseRemainingMs,86000,'reconnect must retain the original native lease');
  assert.equal(f.attaches,1);assert.equal(f.detaches,1);
  assert.equal(f.ports.flatMap(p=>p.sent).filter(m=>m.type==='mode_ready').length,0,'old transition acknowledgements must not reach a replacement connection');
  assert.equal(replacement.sent.some(m=>m.type==='get'),false,'canceled authentication must never replay');
  assert.equal(f.timerCount(5000),1,'late readiness must not duplicate the heartbeat loop');
  for(let i=0;i<17;i++)await acknowledgeHeartbeat(f,replacement);
  await f.advance(999);assert.equal(f.attaches,1);
  await f.advance(1);assert.equal(f.attaches,2,'proxy must be restored at the original lease deadline');
  assert.equal(replacement.sent.at(-1).type,'ready');assert.equal(replacement.sent.at(-1).mode,'proxy');
  assert.equal(replacement.sent.at(-1).attached,true);assert.equal(f.detaches,1);
  assert.equal(f.ports.length,2);assert.equal(f.completed.length,1);
}
async function pendingDetachRevocation(){
  for(const revokeAfterReconnect of [false,true]){
    const detach=deferred(),reattach=deferred();
    let attachCalls=0,detaching=false;
    const f=await fixture({
      attach:()=>{assert.equal(detaching,false,'proxy restoration must not overlap pending detach');if(++attachCalls>1)return reattach.promise;},
      detach:()=>{detaching=true;return detach.promise.then(()=>{detaching=false;});}
    }),original=f.ports[0];
    original.onMessage.emit({type:'mode',mode:'native',generation:1,leaseRemainingMs:120000});await flush();
    if(!revokeAfterReconnect)original.onMessage.emit({type:'mode',mode:'proxy',generation:2});
    original.onDisconnect.emit();await f.advance(1000);
    const replacement=f.ports[1];
    if(revokeAfterReconnect)replacement.onMessage.emit({type:'mode',mode:'proxy',generation:2});
    await flush();
    for(let i=0;i<5;i++)await acknowledgeHeartbeat(f,replacement);
    assert.equal(f.detaches,1);assert.equal(f.attaches,1);
    assert.equal(f.timerCount(120000),0,'explicit proxy revocation must clear the native lease');
    detach.resolve();await flush();
    assert.equal(f.attaches,2);assert.equal(f.detaches,1);
    assert.equal(replacement.sent.every(m=>['ping','mode_progress','mode_error'].includes(m.type)),true,'proxy readiness must wait for the serialized reattach');
    await acknowledgeHeartbeat(f,replacement);
    reattach.resolve();await flush();
    const ready=replacement.sent.filter(m=>m.type==='ready');
    assert.equal(ready.length,1);assert.equal(ready[0].mode,'proxy');assert.equal(ready[0].attached,true);
    assert.equal(ready[0].leaseRemainingMs,0);
    const acknowledgements=replacement.sent.filter(m=>m.type==='mode_ready');
    assert.equal(acknowledgements.length,revokeAfterReconnect?1:0);
    if(revokeAfterReconnect){assert.equal(acknowledgements[0].mode,'proxy');assert.equal(acknowledgements[0].generation,2);}
    assert.equal(f.ports.flatMap(p=>p.sent).some(m=>['ready','mode_ready'].includes(m.type)&&m.mode==='native'),false,'revocation must not publish transient native readiness');
    assert.equal(f.attaches,2);assert.equal(f.detaches,1);assert.equal(f.timerCount(5000),1);
    await acknowledgeHeartbeat(f,replacement);
  }
}
(async()=>{
  await pendingInitializationHeartbeats();
  await pendingDetachReconnectHeartbeats();
  await pendingDetachRevocation();
  const f=await fixture();
  f.api.onGetRequest.emit({requestId:1,requestDetailsJson:'{}'});
  await f.advance(5000);
  const ping=f.ports[0].sent.at(-1);assert.equal(ping.type,'ping');
  f.ports[0].onMessage.emit({type:'pong',nonce:ping.nonce+1});
  await f.advance(10000);
  assert.equal(f.completed.length,1);assert.equal(f.completed[0].error.name,'NotAllowedError');
  await f.advance(999);assert.equal(f.ports.length,1);
  await f.advance(1);assert.equal(f.ports.length,2);
  f.ports[0].onMessage.emit({type:'get',requestId:1,responseJson:'{}'});assert.equal(f.completed.length,1);
  assert.equal(f.ports[1].sent.filter(x=>x.type==='get').length,0,'old authentication must never replay');
  f.ports[1].onDisconnect.emit();f.chrome.runtime.onStartup.emit();f.chrome.alarms.onAlarm.emit({name:'proxy-reconnect'});
  await f.advance(1999);assert.equal(f.ports.length,2);
  await f.advance(1);assert.equal(f.ports.length,3);
  for(const delay of [4000,8000,16000,30000,30000]){
    f.ports.at(-1).onDisconnect.emit();await f.advance(delay-1);const before=f.ports.length;await f.advance(1);assert.equal(f.ports.length,before+1);
  }
  // A minute of valid heartbeat responses resets a crash-loop's backoff.
  for(let i=0;i<12;i++){await f.advance(5000);const port=f.ports.at(-1);const p=port.sent.at(-1);port.onMessage.emit({type:'pong',nonce:p.nonce});await flush();}
  const count=f.ports.length;f.ports.at(-1).onDisconnect.emit();await f.advance(1000);assert.equal(f.ports.length,count+1);
  const n=await fixture();
  n.ports[0].onMessage.emit({type:'mode',mode:'native',generation:1,leaseRemainingMs:120000});await flush();
  assert.equal(n.detaches,1);assert.equal(n.attaches,1);
  await n.advance(3000);n.ports[0].onDisconnect.emit();await n.advance(1000);
  assert.equal(n.attaches,1,'helper crash must not reattach global proxy');
  const hello=n.ports[1].sent[0];assert.equal(hello.mode,'native');assert.equal(hello.attached,false);assert.equal(hello.leaseRemainingMs,116000);
  // Do not keep connection alive: repeated reconnects still cannot renew lease.
  await n.advance(116000);assert.equal(n.attaches,2,'only original lease expiry restores proxy');
  const r=await fixture();let finishDetach;r.api.detach=()=>new Promise(resolve=>{finishDetach=resolve;});
  r.ports[0].onMessage.emit({type:'mode',mode:'native',generation:1,leaseRemainingMs:120000});await flush();r.ports[0].onDisconnect.emit();finishDetach();await flush();await r.advance(1000);
  assert.equal(r.attaches,1);assert.equal(r.ports[1].sent[0].mode,'native');assert.equal(r.ports[1].sent[0].attached,false);
  await r.advance(119000);assert.equal(r.attaches,2);
  console.log('Extension recovery: pre-ready heartbeat, pending detach reconnect/revocation, single heartbeat loop, heartbeat timeout, stale pong, cancellation once, no replay, bounded backoff, stable reset, native lease and detach race passed.');
})().catch(e=>{console.error(e);process.exitCode=1;});
