'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'extension/local_navigation.js'), 'utf8');
let count = 0;
function event() { const handlers=[]; return {handlers, addListener(fn,filter,extra){handlers.push({fn,filter,extra});}, emit(v){for(const h of handlers)h.fn(v);}}; }
function fixture(withScope=true) {
  let now=1000, next=0; const timers=new Map(), sent=[];
  const webNavigation=Object.fromEntries(['onBeforeNavigate','onCreatedNavigationTarget','onCommitted','onErrorOccurred','onHistoryStateUpdated','onReferenceFragmentUpdated'].map(name=>[name,event()]));
  const webRequest={onBeforeRequest:event()}; const tabs={onRemoved:event()};
  const context={URL,TextEncoder,Date:{now:()=>now},setTimeout(fn,ms){timers.set(++next,{fn,at:now+ms});return next;},clearTimeout(id){timers.delete(id);}};
  vm.createContext(context);vm.runInContext(source,context);
  const observer=context.createLocalNavigationObserver({webNavigation,webRequest,tabs},v=>{sent.push(JSON.parse(JSON.stringify(v)));return true;});
  const scope=(value='scope-1234567890abcdef',generation=7)=>observer.setScope({scope:value,mode_generation:generation});
  if(withScope)scope();
  const nav=(name,extra={})=>webNavigation[name].emit({tabId:1,frameId:0,frameType:'outermost_frame',url:'http://localhost:8321/callback?a=%2B#token',timeStamp:now,transitionType:'link',transitionQualifiers:[],...extra});
  const request=(extra={})=>webRequest.onBeforeRequest.emit({tabId:1,frameId:0,type:'main_frame',url:'http://localhost:8321/callback?a=%2B',initiator:'https://example.com',timeStamp:now,...extra});
  function advance(ms){now+=ms;for(const [id,t] of [...timers])if(t.at<=now){timers.delete(id);t.fn();}}
  return {observer,scope,nav,request,advance,sent,webRequest,tabs,offers:()=>sent.filter(v=>v.type==='local_navigation')};
}
function test(name,fn){fn();count++;console.log('PASS:',name);}

test('committed link retains query and fragment exactly, without opening or fetching',()=>{
  const f=fixture();f.nav('onCommitted');assert.equal(f.offers()[0].url,'http://localhost:8321/callback?a=%2B#token');
  assert.equal(f.offers()[0].mode_generation,7);assert.equal(f.offers()[0].observed_at_ms,1000);
  assert.deepEqual(Object.keys(f.offers()[0]).sort(),['mode_generation','observed_at_ms','scope','sequence','type','url']);
});
for(const url of ['http://127.0.0.1:99/x?q=a%20b#z','HTTPS://LOCALHOST/a#b','http://localhost','https://127.0.0.1/?x=1&x=2'])test('accepts literal local target '+url,()=>{
  const f=fixture();f.nav('onCommitted',{url});assert.equal(f.offers()[0].url,url);
});
for(const url of ['file://localhost/a','javascript:alert(1)','http://127.1/','http://2130706433/','http://0x7f000001/','http://localhost./','http://localhost.example/','http://localhost@evil.test/','http://u:p@localhost/','http://[::1]/','http://localhost:99999/','http://localhost\\@evil.test/',' http://localhost/','http://localhost/\nsecret','http://localhost/%20'+'a'.repeat(8200)])test('rejects nonliteral/unsafe/oversized target',()=>{
  const f=fixture();f.nav('onCommitted',{url});assert.equal(f.offers().length,0);
});
for(const details of [{transitionType:'typed'},{transitionType:'link',transitionQualifiers:['from_address_bar']},{transitionType:'reload'},{transitionType:'generated'},{transitionType:'keyword'},{transitionType:'keyword_generated'},{transitionQualifiers:['forward_back']},{transitionType:'auto_toplevel'},{transitionQualifiers:undefined},{frameId:2},{frameType:'sub_frame'},{tabId:-1}])test('excludes manual/unproven/subframe navigation',()=>{
  const f=fixture();f.nav('onCommitted',details);assert.equal(f.offers().length,0);
});
for(const qualifier of ['client_redirect','server_redirect'])test('accepts explicit nonmanual redirect evidence',()=>{
  const f=fixture();f.nav('onCommitted',{transitionType:'auto_toplevel',transitionQualifiers:[qualifier]});assert.equal(f.offers().length,1);
});
for(const transitionType of ['form_submit','auto_bookmark'])test('accepts non-typed form/bookmark target as an ordinary GET offer',()=>{
  const f=fixture();f.nav('onCommitted',{transitionType});assert.equal(f.offers().length,1);
});
for(const order of ['before-first','request-first'])test('late old script evidence cannot authorize a newer typed same-URL attempt '+order,()=>{
  const f=fixture();f.nav('onBeforeNavigate',{timeStamp:1000});f.advance(20);
  if(order==='request-first')f.request({timeStamp:1010});
  f.nav('onBeforeNavigate',{timeStamp:1020});
  f.request({initiator:undefined,timeStamp:1021});
  if(order==='before-first')f.request({timeStamp:1010});
  f.nav('onCommitted',{timeStamp:1015,transitionType:'link'});
  f.nav('onCommitted',{timeStamp:1025,transitionType:'typed',transitionQualifiers:['from_address_bar']});
  assert.equal(f.offers().length,order==='request-first'?1:0);
  assert.equal(f.sent.at(-1)?.type,order==='request-first'?'local_navigation_clear':undefined);
});
test('late old before-navigation cannot overwrite a newer typed attempt',()=>{
  const f=fixture();f.advance(20);f.nav('onBeforeNavigate',{timeStamp:1020});f.nav('onBeforeNavigate',{timeStamp:1000});f.request({timeStamp:1010});
  assert.equal(f.offers().length,0);
});
test('overlapping unfinished identical navigations fail closed even with a late link commit',()=>{
  const f=fixture();f.nav('onBeforeNavigate');f.advance(10);f.nav('onBeforeNavigate');f.request();
  f.nav('onCommitted',{transitionType:'link'});assert.equal(f.offers().length,0);
});
test('typed and reload completions cannot resurrect an earlier offered URL',()=>{
  const f=fixture();f.nav('onBeforeNavigate');f.request();f.advance(10);f.nav('onBeforeNavigate');
  f.nav('onCommitted',{transitionType:'reload'});assert.equal(f.offers().length,1);assert.equal(f.sent.at(-1).type,'local_navigation_clear');
});
test('event observed before a new scope is discarded despite delayed callback delivery',()=>{
  const f=fixture();f.advance(100);f.scope('replacement-1234567890',8);f.nav('onCommitted',{timeStamp:1000});assert.equal(f.offers().length,0);
});
test('typed public origin with proven redirect offers the local target',()=>{
  const f=fixture();f.nav('onBeforeNavigate',{url:'https://example.test/start?private=not-retained'});f.advance(10);
  f.nav('onCommitted',{transitionType:'typed',transitionQualifiers:['from_address_bar','server_redirect']});assert.equal(f.offers().length,1);
  assert.equal(JSON.stringify(f.sent).includes('private=not-retained'),false);
});
test('typing local target, even with a local redirect, does not offer',()=>{
  const f=fixture();f.nav('onBeforeNavigate');f.nav('onCommitted',{transitionType:'typed',transitionQualifiers:['from_address_bar','server_redirect']});assert.equal(f.offers().length,0);
});
test('completed public navigation cannot authorize a later typed local target',()=>{
  const f=fixture();f.nav('onBeforeNavigate',{url:'https://example.test/'});f.nav('onCommitted',{url:'https://example.test/'});f.nav('onBeforeNavigate');
  f.nav('onCommitted',{transitionType:'typed',transitionQualifiers:['from_address_bar','server_redirect']});assert.equal(f.offers().length,0);
});
test('created popup offers before refused connection and deduplicates matching before/commit',()=>{
  const f=fixture();f.nav('onCreatedNavigationTarget',{sourceTabId:2,sourceFrameId:0});f.nav('onBeforeNavigate');f.nav('onCommitted',{transitionType:'auto_toplevel'});
  assert.equal(f.offers().length,1);assert.equal(f.sent.length,1);
});
test('created target deduplicates when before-navigation callback came first',()=>{
  const f=fixture();f.nav('onBeforeNavigate');f.nav('onCreatedNavigationTarget',{sourceTabId:2});f.nav('onCommitted');assert.equal(f.offers().length,1);
});
test('new nonlocal top-level navigation clears the prompt without serializing its URL',()=>{
  const f=fixture();f.nav('onCommitted');f.nav('onBeforeNavigate',{url:'https://example.test/private'});assert.equal(f.sent.at(-1).type,'local_navigation_clear');assert.equal('url' in f.sent.at(-1),false);
});
test('same-tab link/script main-frame evidence offers exact fragment before TCP failure',()=>{
  const f=fixture();f.nav('onBeforeNavigate');f.advance(1);f.request();assert.equal(f.offers().length,1);assert.equal(f.offers()[0].url,'http://localhost:8321/callback?a=%2B#token');
  // No committed event is emitted after this realistic failed-navigation callback.
  f.nav('onErrorOccurred',{error:'net::ERR_CONNECTION_REFUSED'});
  f.advance(100);assert.equal(f.offers().length,1);
});
test('reverse callback delivery still correlates browser event timestamps',()=>{
  const f=fixture();f.request({timeStamp:1001});f.nav('onBeforeNavigate',{timeStamp:1000});assert.equal(f.offers().length,1);
});
for(const initiator of [undefined,null,'null','data:text/plain,test','file:///tmp/test','chrome-extension://id'])test('missing/opaque/non-web source never authorizes an early local offer',()=>{
  const f=fixture();f.nav('onBeforeNavigate');f.request({initiator});assert.equal(f.offers().length,0);
});
test('subframe or wrong network target cannot authorize top-level local navigation',()=>{
  const f=fixture();f.nav('onBeforeNavigate');f.request({type:'sub_frame'});f.request({url:'http://localhost:8321/other'});assert.equal(f.offers().length,0);
});
test('old request cannot authorize later typed navigation to the same URL',()=>{
  const f=fixture();f.request({timeStamp:1000});f.advance(20);f.nav('onBeforeNavigate');f.request({initiator:undefined,timeStamp:1021});assert.equal(f.offers().length,0);
});
test('one-use correlation and committed duplicate do not replay the same offer',()=>{
  const f=fixture();f.nav('onBeforeNavigate');f.request();f.nav('onCommitted');f.nav('onBeforeNavigate');f.request({initiator:undefined});assert.equal(f.offers().length,1);
});
test('scope loss and replacement discard pending URLs and never replay on reconnect',()=>{
  const f=fixture();f.nav('onBeforeNavigate');f.observer.reset();f.request();assert.equal(f.offers().length,0);f.scope('replacement-1234567890',8);f.request();assert.equal(f.offers().length,0);
  f.nav('onCommitted');assert.equal(f.offers()[0].mode_generation,8);assert.equal(f.offers()[0].sequence,1);
});
test('no scope means no recording/offer; identical scope delivery does not reset sequence',()=>{
  const f=fixture(false);f.nav('onCommitted');assert.equal(f.offers().length,0);f.scope();f.nav('onCommitted');f.scope();f.nav('onBeforeNavigate',{url:'https://example.test/'});assert.equal(f.sent.at(-1).sequence,2);
});
test('URL cache expiry does not dismiss a received prompt, while later navigation does',()=>{
  const f=fixture();f.nav('onCommitted');f.advance(60000);
  assert.equal(f.sent.length,1);
  f.nav('onBeforeNavigate',{url:'https://example.test/next'});
  assert.equal(f.sent.at(-1).type,'local_navigation_clear');
  assert.equal(f.offers().length,1);
});
test('target close clears a long-hover prompt after URL cache expiry',()=>{
  const f=fixture();f.nav('onCommitted');f.advance(60000);
  assert.equal(f.sent.length,1);f.tabs.onRemoved.emit(1);
  assert.equal(f.sent.at(-1).type,'local_navigation_clear');
});
test('a fresh offer replaces a long-hover prompt without retaining or replaying its URL',()=>{
  const f=fixture();f.nav('onCommitted');f.advance(60000);
  f.nav('onCommitted',{tabId:2,url:'http://127.0.0.1/new'});
  assert.deepEqual(f.sent.map(v=>v.type),['local_navigation','local_navigation_clear','local_navigation']);
  assert.equal(f.sent[1].url,undefined);
});
test('pending URL expires after five seconds and old request never revives it',()=>{
  const f=fixture();f.nav('onBeforeNavigate');f.advance(5000);f.request();assert.equal(f.offers().length,0);
});
test('bounded tab metadata fails closed instead of evicting replay protection',()=>{
  const f=fixture();for(let tabId=0;tabId<65;tabId++)f.nav('onBeforeNavigate',{tabId});f.request({tabId:64});assert.equal(f.offers().length,0);
  f.tabs.onRemoved.emit(0);f.nav('onBeforeNavigate',{tabId:64});f.request({tabId:64});assert.equal(f.offers().length,1);
});
for(const initial of ['onCommitted','onCreatedNavigationTarget'])test('slow commit does not re-offer after the original prompt expires '+initial,()=>{
  const f=fixture();f.nav(initial,{sourceTabId:2});f.advance(6000);f.nav('onCommitted');assert.equal(f.offers().length,1);
  f.nav('onBeforeNavigate');f.request();assert.equal(f.offers().length,2);
});
test('closed target clears the active prompt',()=>{
  const f=fixture();f.nav('onCommitted');f.tabs.onRemoved.emit(1);assert.equal(f.sent.at(-1).type,'local_navigation_clear');
});
const documentId='12345678-1234-1234-1234-123456789abc';
for(const kind of ['onHistoryStateUpdated','onReferenceFragmentUpdated']) {
  test('fresh same-document script event replaces full-navigation announcement '+kind,()=>{
    const f=fixture();f.nav('onCommitted',{documentId});f.advance(10);
    const url='http://localhost:8321/callback?new=%2B#next';
    f.nav(kind,{documentId,url});assert.equal(f.offers().length,2);assert.equal(f.offers().at(-1).url,url);
    assert.equal(f.sent.filter(v=>v.type==='local_navigation_clear').length,1);
  });
  test('same-document event works without a prior recorded full commit '+kind,()=>{
    const f=fixture();f.nav(kind,{documentId});assert.equal(f.offers().length,1);
  });
  for(const extra of [{transitionType:'typed',transitionQualifiers:['from_address_bar']},{transitionType:'link',transitionQualifiers:['from_address_bar']},{transitionQualifiers:['forward_back']},{frameId:2},{documentId:undefined}])test('same-document manual/history/subframe/missing identity is excluded '+kind,()=>{
    const f=fixture();f.nav(kind,{documentId,...extra});assert.equal(f.offers().length,0);
  });
  test('same-document duplicate timestamp is ignored but newer same URL is a new event '+kind,()=>{
    const f=fixture();f.nav(kind,{documentId});f.nav(kind,{documentId});assert.equal(f.offers().length,1);
    f.advance(1);f.nav(kind,{documentId});assert.equal(f.offers().length,2);
  });
  test('old same-document callback cannot replace a newer document '+kind,()=>{
    const f=fixture();f.nav('onCommitted',{documentId});f.advance(10);
    const replacement='abcdefab-1234-1234-1234-123456789abc';
    f.nav('onBeforeNavigate');f.nav('onCommitted',{documentId:replacement});const before=f.offers().length;
    f.advance(10);f.nav(kind,{documentId});assert.equal(f.offers().length,before);
  });
  test('stale same-document callback or overlapping full navigation fails closed '+kind,()=>{
    const f=fixture();f.nav('onCommitted',{documentId});f.advance(20);f.nav(kind,{documentId,timeStamp:990});assert.equal(f.offers().length,1);
    f.nav('onBeforeNavigate');f.advance(1);f.nav(kind,{documentId});assert.equal(f.offers().length,1);
  });
}
test('history/fragment duplicate delivery shares one same-document generation',()=>{
  const f=fixture();f.nav('onHistoryStateUpdated',{documentId});f.nav('onReferenceFragmentUpdated',{documentId});assert.equal(f.offers().length,1);
});
test('webRequest registration stays destination-only/main_frame and never blocking/body/header',()=>{
  const f=fixture();const h=f.webRequest.onBeforeRequest.handlers[0];assert.equal(h.extra,undefined);
  assert.deepEqual(JSON.parse(JSON.stringify(h.filter)),{urls:['http://localhost/*','https://localhost/*','http://127.0.0.1/*','https://127.0.0.1/*'],types:['main_frame']});
});
test('manifest declares only necessary source-host grants; no content injection or external messages',()=>{
  const manifest=JSON.parse(fs.readFileSync(path.join(root,'extension/manifest.json')));
  assert.deepEqual(manifest.host_permissions,['http://*/*','https://*/*']);assert.equal(manifest.permissions.includes('webRequestBlocking'),false);
  assert.equal(manifest.content_scripts,undefined);assert.equal(manifest.externally_connectable,undefined);
});
console.log(`${count} local-navigation observer cases passed.`);

(async()=>{
  const sent=[];const connections=[];const timers=[];
  const api=Object.fromEntries(['onCreateRequest','onGetRequest','onIsUvpaaRequest','onRequestCanceled','onRemoteSessionStateChange'].map(name=>[name,event()]));
  api.attach=async()=>{};api.detach=async()=>{};
  for(const method of ['completeCreateRequest','completeGetRequest','completeIsUvpaaRequest'])api[method]=async()=>{};
  const chrome={webAuthenticationProxy:api,webNavigation:Object.fromEntries(['onBeforeNavigate','onCreatedNavigationTarget','onCommitted','onErrorOccurred','onHistoryStateUpdated','onReferenceFragmentUpdated'].map(name=>[name,event()])),
    webRequest:{onBeforeRequest:event()},tabs:{onRemoved:event()},
    alarms:{onAlarm:event(),create(){},clear(){}},runtime:{id:'test',onMessage:event(),onStartup:event(),onInstalled:event(),connectNative(){
      const port={onMessage:event(),onDisconnect:event(),postMessage(value){sent.push(value);},disconnect(){this.onDisconnect.emit();}};connections.push(port);return port;
    }}};
  const context={chrome,URL,TextEncoder,Date:{now:()=>1000},setTimeout(fn){timers.push(fn);return timers.length;},clearTimeout(){}};
  vm.createContext(context);context.importScripts=name=>{
    assert.equal(name,'local_navigation.js');vm.runInContext(source,context);
  };
  vm.runInContext(fs.readFileSync(path.join(root,'extension/background.js'),'utf8'),context);
  for(let i=0;i<20;i++)await Promise.resolve();
  assert.equal(sent.find(v=>v.type==='ready').capabilities.includes('local_navigation'),true);
  const nav={tabId:1,frameId:0,timeStamp:1000,url:'http://localhost:9911/callback?state=exact#part'};
  chrome.webNavigation.onCommitted.emit({...nav,transitionType:'link',transitionQualifiers:[]});assert.equal(sent.some(v=>v.type==='local_navigation'),false);
  connections[0].onMessage.emit({type:'navigation_scope',scope:'scope-1234567890abcdef',mode_generation:4});
  chrome.webNavigation.onBeforeNavigate.emit(nav);
  chrome.webRequest.onBeforeRequest.emit({...nav,url:nav.url.split('#')[0],type:'main_frame',initiator:'https://example.test'});
  assert.equal(sent.find(v=>v.type==='local_navigation').url,nav.url);
  connections[0].onDisconnect.emit();
  const count=sent.length;chrome.webNavigation.onCommitted.emit({...nav,transitionType:'link',transitionQualifiers:[]});assert.equal(sent.length,count);
  console.log('PASS: packaged background imports observer, negotiates scope, forwards exact URL and resets on port loss');
})().catch(error=>{console.error(error);process.exitCode=1;});
