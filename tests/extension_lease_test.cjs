'use strict';
// Executes the shipped worker. Fake Chrome/clock coverage is not a real
// Chromium, native-host transport, or phone-authentication end-to-end test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname,'../extension/background.js'),'utf8');
function event(){const listeners=[];return {addListener(fn){listeners.push(fn);},emit(...args){for(const fn of listeners)fn(...args);}};}
async function flush(){for(let i=0;i<50;i++)await Promise.resolve();}
async function fixture(binding='callback'){
  let now=0,id=0,inFlight=0;
  const timers=new Map(),ports=[],calls=[],waiting=[],hold=new Set(),completed=[];
  const api=Object.fromEntries(['onCreateRequest','onGetRequest','onIsUvpaaRequest','onRequestCanceled','onRemoteSessionStateChange'].map(key=>[key,event()]));
  const chrome={webAuthenticationProxy:api,runtime:{id:'test-extension',onMessage:event(),onStartup:event(),onInstalled:event(),connectNative(){
    const port={sent:[],onMessage:event(),onDisconnect:event(),postMessage(message){this.sent.push(message);if(message.type==='ping')this.onMessage.emit({type:'pong',nonce:message.nonce});},disconnect(){this.onDisconnect.emit();}};
    ports.push(port);return port;
  }},alarms:{create(){},clear(){},onAlarm:event()}};
  for(const method of ['attach','detach'])api[method]=callback=>{
    calls.push(method);assert.equal(++inFlight,1,'physical browser operations must never overlap');
    let resolve,reject,completed=false;
    const promise=binding==='callback'?undefined:new Promise((yes,no)=>{resolve=yes;reject=no;});
    const operation={method,done(error){
      if(!completed){completed=true;inFlight--;}
      if(binding!=='promise'){
        chrome.runtime.lastError=error?{message:error}:undefined;
        callback();chrome.runtime.lastError=undefined;
      }
      if(binding!=='callback'){if(error)reject(new Error(error));else resolve();}
    }};
    if(hold.has(method))waiting.push(operation);else operation.done();
    return promise;
  };
  for(const [method,type] of [['completeCreateRequest','create'],['completeGetRequest','get'],['completeIsUvpaaRequest','uvpaa']])api[method]=async value=>{completed.push({type,...value});};
  vm.runInNewContext(source,{chrome,Date:{now:()=>now},setTimeout(fn,ms){timers.set(++id,{fn,at:now+ms,ms});return id;},clearTimeout(timer){timers.delete(timer);}});
  await flush();
  async function advance(ms){const end=now+ms;for(;;){const next=[...timers].filter(([,timer])=>timer.at<=end).sort((a,b)=>a[1].at-b[1].at)[0];if(!next)break;now=Math.max(now,next[1].at);timers.delete(next[0]);next[1].fn();await flush();}now=end;await flush();}
  return {api,ports,calls,waiting,hold,completed,advance,elapse(ms){now+=ms;},get now(){return now;},timer(ms){return [...timers.values()].filter(timer=>timer.ms===ms).at(-1);},get port(){return ports.at(-1);}};
}
function native(port,generation=1,leaseRemainingMs=10000){port.onMessage.emit({type:'mode',mode:'native',generation,leaseRemainingMs});}
function proxy(port,generation=2){port.onMessage.emit({type:'mode',mode:'proxy',generation});}
function renew(port,leaseGeneration=1,leaseRemainingMs=10000,generation=1){port.onMessage.emit({type:'mode_lease',generation,leaseGeneration,leaseRemainingMs});}
function acknowledgements(port,type='mode_lease_ready'){return port.sent.filter(message=>message.type===type);}
function checkAck(message,type,mode,generation,leaseGeneration){
  assert.deepEqual(JSON.parse(JSON.stringify(message)),{type,mode,generation,...(leaseGeneration===undefined?{}:{leaseGeneration}),
    attached:mode==='proxy',extensionVersion:'1.0.29',protocolVersion:1});
}
async function idleRenewal(binding){
  const f=await fixture(binding);
  assert.equal(f.port.sent[0].capabilities.includes('mode_lease'),true);
  native(f.port,1,5000);await flush();
  checkAck(acknowledgements(f.port,'mode_ready')[0],'mode_ready','native',1);
  const obsoleteTimer=f.timer(5000);
  // Keep native mode alive without a WebAuthn request for longer than the
  // maximum individual lease. Heartbeats do not renew mode authorization.
  for(let generation=1;generation<=40;generation++){
    await f.advance(4000);renew(f.port,generation,5000);await flush();
    checkAck(acknowledgements(f.port).at(-1),'mode_lease_ready','native',1,generation);
  }
  assert.equal(f.now,160000);
  assert.equal(f.calls.join(','),'attach,detach','lease renewal must not churn attach/detach');
  assert.equal(f.port.sent.some(message=>['create','get','uvpaa'].includes(message.type)),false);
  // A callback already queued before clearTimeout cannot expire a new lease.
  obsoleteTimer.fn();await flush();assert.equal(f.calls.join(','),'attach,detach');
  const liveTimer=f.timer(5000);
  proxy(f.port);await flush();checkAck(acknowledgements(f.port,'mode_ready').at(-1),'mode_ready','proxy',2);
  renew(f.port,41,120000);liveTimer.fn();await flush();
  assert.equal(acknowledgements(f.port).length,40,'stop must reject an old lease grant');
  assert.equal(f.calls.join(','),'attach,detach,attach');
  await f.advance(120000);assert.equal(f.calls.join(','),'attach,detach,attach');
}
async function invalidGrantsAndExpiry(binding){
  const f=await fixture(binding);
  renew(f.port);await flush();assert.equal(acknowledgements(f.port).length,0);
  for(const duration of [undefined,0,-1,120001,1.5,NaN,Infinity,'5000']){
    f.port.onMessage.emit({type:'mode',mode:'native',generation:1,leaseRemainingMs:duration});await flush();
  }
  assert.equal(f.calls.join(','),'attach','invalid initial lease must not detach or consume a generation');
  native(f.port,1,5000);await flush();await f.advance(1000);
  renew(f.port,1,5000);await flush();assert.equal(acknowledgements(f.port).length,1);
  const originalTimer=f.timer(5000);
  for(const generation of [-1,0,2,1.5,NaN,Infinity,'1'])renew(f.port,2,120000,generation);
  for(const generation of [undefined,-1,0,1,1.5,NaN,Infinity,'2']){
    f.port.onMessage.emit({type:'mode_lease',generation:1,leaseGeneration:generation,leaseRemainingMs:120000});
  }
  for(const duration of [undefined,0,-1,120001,1.5,NaN,Infinity,'5000']){
    f.port.onMessage.emit({type:'mode_lease',generation:1,leaseGeneration:2,leaseRemainingMs:duration});
  }
  await flush();assert.equal(acknowledgements(f.port).length,1);assert.equal(f.timer(5000),originalTimer);
  await f.advance(4999);assert.equal(f.calls.join(','),'attach,detach');
  await f.advance(1);assert.equal(f.calls.join(','),'attach,detach,attach');
  assert.equal(f.port.sent.at(-1).type,'ready');assert.equal(f.port.sent.at(-1).mode,'proxy');assert.equal(f.port.sent.at(-1).attached,true);
  renew(f.port,2,120000);native(f.port,1,120000);await flush();
  assert.equal(f.calls.join(','),'attach,detach,attach','expiry cannot be revived by stale mode or lease grants');
  assert.equal(acknowledgements(f.port).length,1);
  native(f.port,3,5000);await flush();renew(f.port,1,5000,3);await flush();
  assert.equal(acknowledgements(f.port).length,2,'new mode generation starts a new lease sequence');
  checkAck(acknowledgements(f.port).at(-1),'mode_lease_ready','native',3,1);

  const delayed=await fixture(binding);
  native(delayed.port,1,1);await flush();delayed.elapse(1);
  renew(delayed.port,1,120000);await flush();
  assert.equal(acknowledgements(delayed.port).length,0,'deadline wins even when its timer callback has not run yet');
  await delayed.advance(0);assert.equal(delayed.calls.join(','),'attach,detach,attach');
}
async function delayedDetach(binding){
  const f=await fixture(binding);f.hold.add('detach');
  native(f.port,1,100);await flush();
  assert.equal(f.calls.join(','),'attach,detach');
  renew(f.port,1,120000);await flush();assert.equal(acknowledgements(f.port).length,0,'unfinished detach cannot grant renewal');
  assert.equal(acknowledgements(f.port,'mode_ready').length,0);
  await f.advance(100);
  renew(f.port,2,120000);await flush();assert.equal(acknowledgements(f.port).length,0);
  const oldOperation=f.waiting.shift();oldOperation.done();await flush();
  assert.equal(f.calls.join(','),'attach,detach,attach');
  assert.equal(acknowledgements(f.port,'mode_ready').length,0,'expired delayed detach cannot acknowledge native mode');
  assert.equal(f.port.sent.at(-1).type,'ready');assert.equal(f.port.sent.at(-1).attached,true);
  f.hold.delete('detach');native(f.port,3,1000);await flush();
  oldOperation.done();await flush();
  renew(f.port,1,1000,3);await flush();
  checkAck(acknowledgements(f.port).at(-1),'mode_lease_ready','native',3,1);
  assert.equal(f.calls.join(','),'attach,detach,attach,detach','duplicate old callbacks cannot mutate the new physical state');
}
async function reconnectDoesNotRenew(binding){
  const f=await fixture(binding),original=f.port;
  native(original,1,10000);await flush();await f.advance(1000);
  original.onDisconnect.emit();await f.advance(1000);
  const replacement=f.port;assert.notEqual(replacement,original);
  assert.equal(replacement.sent[0].mode,'native');assert.equal(replacement.sent[0].attached,false);
  assert.equal(replacement.sent[0].leaseRemainingMs,8000);
  renew(original,1,120000);renew(replacement,1,120000);await flush();
  assert.equal(acknowledgements(original).length,0);assert.equal(acknowledgements(replacement).length,0);
  await f.advance(7999);assert.equal(f.calls.join(','),'attach,detach');
  await f.advance(1);assert.equal(f.calls.join(','),'attach,detach,attach');
  assert.equal(replacement.sent.at(-1).mode,'proxy');assert.equal(replacement.sent.at(-1).attached,true);
  // An explicit new command, followed by completion, is required on this port.
  native(replacement,3,1000);await flush();renew(replacement,1,1000,3);await flush();
  checkAck(acknowledgements(replacement).at(-1),'mode_lease_ready','native',3,1);
  proxy(replacement,4);await flush();renew(original,9,120000,3);renew(replacement,9,120000,3);await flush();
  assert.equal(acknowledgements(replacement).length,1);
  checkAck(acknowledgements(replacement,'mode_ready').at(-1),'mode_ready','proxy',4);
}
async function requestParity(binding){
  const f=await fixture(binding);
  for(const [type,id] of [['create',1],['get',2]])f.api[type==='create'?'onCreateRequest':'onGetRequest'].emit({requestId:id,requestDetailsJson:'{}'});
  native(f.port,1,10000);await flush();
  for(const [type,id] of [['create',1],['get',2]]){
    assert.equal(f.completed.filter(value=>value.type===type&&value.requestId===id).length,1);
    assert.equal(f.completed.find(value=>value.requestId===id).error.name,'NotAllowedError');
    f.port.onMessage.emit({type,requestId:id,responseJson:'{}'});
  }
  renew(f.port);await flush();
  for(const [type,id] of [['create',3],['get',4]]){
    f.api[type==='create'?'onCreateRequest':'onGetRequest'].emit({requestId:id,requestDetailsJson:'{}'});
    assert.equal(f.port.sent.some(value=>value.type===type&&value.requestId===id),false);
    assert.equal(f.completed.find(value=>value.requestId===id).error.name,'NotAllowedError');
  }
  proxy(f.port);await flush();
  for(const [type,id] of [['create',5],['get',6]]){
    f.api[type==='create'?'onCreateRequest':'onGetRequest'].emit({requestId:id,requestDetailsJson:'{}'});
    assert.equal(f.port.sent.filter(value=>value.type===type&&value.requestId===id).length,1);
    f.port.onMessage.emit({type,requestId:id,responseJson:'{}'});
    assert.equal(f.completed.find(value=>value.requestId===id).responseJson,'{}');
  }
  assert.equal(f.completed.length,6,'canceled create/get ceremonies are never revived or replayed');
}
async function reconnectDuringExpiredRollback(binding){
  const idle=await fixture(binding);
  native(idle.port,1,100);await flush();
  idle.hold.add('attach');idle.port.onDisconnect.emit();await idle.advance(1000);
  idle.waiting.shift().done();await flush();
  assert.equal(idle.port.sent.filter(message=>message.type==='ready').length,1,'old rollback must not publish readiness to a new connection');
  assert.equal(idle.port.sent.at(-1).mode,'proxy');assert.equal(idle.port.sent.at(-1).attached,true);

  const f=await fixture(binding);
  native(f.port,1,100);await flush();
  f.hold.add('attach');f.port.onDisconnect.emit();
  await f.advance(1000);
  assert.equal(f.calls.join(','),'attach,detach,attach');
  const replacement=f.port;
  f.hold.add('detach');native(replacement,3,5000);await flush();
  f.waiting.shift().done();await flush();
  assert.equal(f.calls.join(','),'attach,detach,attach,detach','reconnect and a fresh mode command must share the operation queue');
  assert.equal(replacement.sent.some(message=>['ready','mode_ready'].includes(message.type)),false,'pending detach must not report readiness');
  const detach=f.waiting.shift();detach.done();await flush();
  checkAck(acknowledgements(replacement,'mode_ready').at(-1),'mode_ready','native',3);
  renew(replacement,1,5000,3);await flush();
  checkAck(acknowledgements(replacement).at(-1),'mode_lease_ready','native',3,1);
}
(async()=>{
  for(const binding of ['callback','promise','dual']){
    await idleRenewal(binding);
    await invalidGrantsAndExpiry(binding);
    await delayedDetach(binding);
    await reconnectDoesNotRenew(binding);
    await requestParity(binding);
    await reconnectDuringExpiredRollback(binding);
  }
  console.log('Extension lease: request-independent renewal beyond two minutes, exact expiry, stale/invalid grants, stop/reconnect, no attach churn, truthful metadata, callback/Promise races and create/get parity passed (VM).');
})().catch(error=>{console.error(error);process.exitCode=1;});
