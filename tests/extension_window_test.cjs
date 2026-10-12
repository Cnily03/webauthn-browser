'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../extension/browser_window.js'),'utf8');
const crypto=require('node:crypto').webcrypto;
const clone=v=>JSON.parse(JSON.stringify(v));
const tab=(id,url,extra={})=>({id,url,pinned:false,groupId:-1,active:false,...extra});
const window=(id,tabs,extra={})=>({id,type:'normal',incognito:false,focused:false,state:'normal',tabs,...extra});
function fixture(initial,groups={}) {
  let windows=clone(initial),now=1000,current=true,next=1000;const calls=[],sent=[];
  const normalize=()=>{windows=windows.filter(w=>w.tabs.length);for(const w of windows)w.tabs.forEach((t,i)=>{t.index=i;t.windowId=w.id;});};normalize();
  let beforeMove=null;
  function move(ids,target,index){
    const moved=[];for(const id of ids)for(const w of windows){const found=w.tabs.find(t=>t.id===id);if(found){moved.push(found);w.tabs=w.tabs.filter(t=>t.id!==id);}}
    const dest=windows.find(w=>w.id===target);if(!dest)throw Error('missing target');dest.tabs.splice(index<0?dest.tabs.length:index,0,...moved);normalize();
  }
  const browser={windows:{
    async getAll(){calls.push(['getAll']);return clone(windows);},
    async create(options){calls.push(['create',options]);windows.push(window(next++,[tab(next++,'about:blank')],{focused:true,state:'maximized'}));normalize();return clone(windows.at(-1));},
    async update(id,options){calls.push(['windowUpdate',id,options]);Object.assign(windows.find(w=>w.id===id),options);},
  },tabs:{
    async move(id,options){calls.push(['tabMove',id,options]);if(beforeMove)await beforeMove();move([id],options.windowId,options.index);},
    async update(id,options){calls.push(['tabUpdate',id,options]);for(const w of windows)for(const t of w.tabs)if(t.id===id)Object.assign(t,options);},
  },tabGroups:{
    async get(id){return clone(groups[id]);},
    async move(id,options){calls.push(['groupMove',id,options]);const ids=windows.flatMap(w=>w.tabs).filter(t=>t.groupId===id).map(t=>t.id);move(ids,options.windowId,options.index);},
  }};
  const context={crypto,TextEncoder,Uint8Array,Date:{now:()=>now}};vm.createContext(context);vm.runInContext(source,context);
  const controller=context.createBrowserWindowController(browser);let request=0;
  const handle=(action='consolidate',extra={})=>controller.handle({nonce:'request_nonce_0000'+(++request),action,remaining_ms:10000,expected_window_count:windows.length,...extra},{postMessage:v=>sent.push(clone(v))},()=>current);
  return {controller,handle,calls,sent,browser,windows:()=>windows,mutations:()=>calls.filter(c=>c[0]!=='getAll'),setCurrent(v){current=v;},advance(ms){now+=ms;},beforeMove(fn){beforeMove=fn;},replace(v){windows=clone(v);normalize();}};
}
let count=0;async function test(name,fn){await fn();count++;console.log('PASS:',name);}
(async()=>{
await test('ensure creates exactly one maximized blank window only when none exists',async()=>{const f=fixture([]);await f.handle('ensure');assert.equal(f.sent[0].ok,true);assert.equal(f.windows().length,1);assert.equal(f.calls.filter(c=>c[0]==='create').length,1);await f.handle('ensure');assert.equal(f.calls.filter(c=>c[0]==='create').length,1);});
await test('one existing window is maximized without creating or moving tabs',async()=>{const f=fixture([window(1,[tab(1,'https://one.test/',{active:true})])]);await f.handle('ensure');assert.equal(f.sent[0].ok,true);assert.equal(f.calls.some(c=>c[0]==='create'||c[0]==='tabMove'),false);assert.equal(f.windows()[0].state,'maximized');});
await test('multiple normal windows preserve ordered contents pinned tabs and whole groups',async()=>{
 const f=fixture([window(1,[tab(1,'https://one.test/'),tab(2,'https://two.test/',{groupId:7})],{focused:true}),window(2,[tab(3,'https://pin.test/',{pinned:true}),tab(4,'https://group.test/',{groupId:8}),tab(5,'https://group2.test/',{groupId:8}),tab(6,'https://last.test/')])],{7:{title:'A',color:'blue',collapsed:false},8:{title:'B',color:'red',collapsed:true}});
 await f.handle();assert.equal(f.sent[0].ok,true);assert.deepEqual(f.windows()[0].tabs.map(t=>t.id),[3,1,2,4,5,6]);assert.equal(f.calls.filter(c=>c[0]==='groupMove').length,1);assert.equal(f.windows()[0].tabs[0].pinned,true);assert.equal(JSON.stringify(f.sent).includes('https://'),false);
});
for(const extra of [{incognito:true},{type:'popup'},{type:'devtools'}])await test('unsupported privacy/window type fails before any mutation',async()=>{const f=fixture([window(1,[tab(1,'https://one.test/')]),window(2,[tab(2,'https://two.test/')],extra)]);await f.handle();assert.equal(f.sent[0].reason,'unsupported_windows');assert.equal(f.mutations().length,0);});
await test('X/extension count mismatch fails before changing any tabs',async()=>{const f=fixture([window(1,[tab(1,'https://one.test/')])]);await f.handle('ensure',{expected_window_count:2});assert.equal(f.sent[0].reason,'window_count_changed');assert.equal(f.mutations().length,0);});
await test('shared group fails before moving any ungrouped tab',async()=>{const f=fixture([window(1,[tab(1,'https://one.test/')]),window(2,[tab(2,'https://two.test/',{groupId:1})])],{1:{title:'shared',color:'blue',collapsed:false,shared:true}});await f.handle();assert.equal(f.sent[0].reason,'unsupported_groups');assert.equal(f.mutations().length,0);});
await test('pending navigation fails before mutation',async()=>{const f=fixture([window(1,[tab(1,'https://one.test/',{pendingUrl:'https://next.test/'})])]);await f.handle();assert.equal(f.sent[0].reason,'unstable_tabs');assert.equal(f.mutations().length,0);});
await test('new numeric tab/window/group IDs preserve stable restored fingerprint',async()=>{const f=fixture([window(1,[tab(1,'https://one.test/'),tab(2,'https://two.test/',{groupId:7})])],{7:{title:'A',color:'blue',collapsed:false},99:{title:'A',color:'blue',collapsed:false}});await f.handle();const fingerprint=f.sent[0].fingerprint;f.replace([window(40,[tab(101,'https://one.test/'),tab(102,'https://two.test/',{groupId:99})])]);await f.handle('verify',{expected_fingerprint:fingerprint});assert.equal(f.sent[1].ok,true);});
for(const change of ['url','order','pinned','group'])await test('restoration mismatch rejects changed '+change,async()=>{const groups={7:{title:'A',color:'blue',collapsed:false},8:{title:'B',color:'red',collapsed:true}};const f=fixture([window(1,[tab(1,'https://one.test/'),tab(2,'https://two.test/',{groupId:7})])],groups);await f.handle();const fingerprint=f.sent[0].fingerprint;const tabs=clone(f.windows()[0].tabs);if(change==='url')tabs[0].url='https://other.test/';if(change==='order')tabs.reverse();if(change==='pinned')tabs[0].pinned=true;if(change==='group')tabs[1].groupId=8;f.replace([window(2,tabs)]);await f.handle('verify',{expected_fingerprint:fingerprint});assert.equal(f.sent[1].reason,'restore_mismatch');});
await test('logout during a move stops all later moves with no tab close or stale reply',async()=>{const f=fixture([window(1,[tab(1,'https://one.test/')]),window(2,[tab(2,'https://two.test/'),tab(3,'https://three.test/')])]);f.beforeMove(()=>f.setCurrent(false));await f.handle();assert.equal(f.calls.filter(c=>c[0]==='tabMove').length,1);assert.equal(f.windows().flatMap(w=>w.tabs).length,3);assert.equal(f.sent.length,0);});
await test('deadline during move stops later mutations and reports only a static reason',async()=>{const f=fixture([window(1,[tab(1,'https://one.test/')]),window(2,[tab(2,'https://two.test/'),tab(3,'https://three.test/')])]);f.beforeMove(()=>f.advance(10001));await f.handle();assert.equal(f.calls.filter(c=>c[0]==='tabMove').length,1);assert.equal(f.sent[0].reason,'canceled');assert.equal(f.windows().flatMap(w=>w.tabs).length,3);});
await test('canceled pending Chrome mutation blocks a newer operation until the old call settles',async()=>{
 const f=fixture([window(1,[tab(1,'https://one.test/')]),window(2,[tab(2,'https://two.test/'),tab(3,'https://three.test/')])]);
 let release;const pending=new Promise(resolve=>{release=resolve;});f.beforeMove(()=>pending);
 const first=f.handle();for(let i=0;i<50&&!f.calls.some(c=>c[0]==='tabMove');i++)await new Promise(resolve=>setImmediate(resolve));
 f.controller.cancel('request_nonce_00001');await f.handle();assert.equal(f.sent[0].reason,'busy');
 release();await first;assert.equal(f.calls.filter(c=>c[0]==='tabMove').length,1);assert.equal(f.sent.at(-1).reason,'canceled');
 f.beforeMove(null);await f.handle();assert.equal(f.sent.at(-1).ok,true);assert.equal(f.windows().flatMap(w=>w.tabs).length,3);
});
await test('concurrent navigation makes final verification fail without losing any tabs',async()=>{const f=fixture([window(1,[tab(1,'https://one.test/')]),window(2,[tab(2,'https://two.test/')])]);f.beforeMove(()=>{f.windows()[0].tabs[0].url='https://changed.test/';});await f.handle();assert.equal(f.sent[0].reason,'restore_mismatch');assert.equal(f.windows().flatMap(w=>w.tabs).length,2);});
await test('arbitrary API error payload never enters native reply',async()=>{const f=fixture([window(1,[tab(1,'https://one.test/')])]);f.browser.windows.update=async()=>{throw Error('secret URL payload');};await f.handle();assert.equal(f.sent[0].reason,'operation_failed');assert.equal(JSON.stringify(f.sent).includes('secret'),false);});
await test('unsupported action or raw URL command is ignored',async()=>{const f=fixture([]);await f.handle('close');assert.equal(f.sent.length,0);assert.equal(f.calls.length,0);});
await test('packaged background advertises capability and forwards fixed authenticated native RPC',async()=>{
 const f=fixture([window(1,[tab(1,'https://one.test/')])]);
 const event=()=>({handlers:[],addListener(fn){this.handlers.push(fn);},emit(value){for(const fn of this.handlers)fn(value);}});
 const sent=[];const port={onMessage:event(),onDisconnect:event(),postMessage(v){sent.push(clone(v));},disconnect(){this.onDisconnect.emit();}};
 const api=Object.fromEntries(['onCreateRequest','onGetRequest','onIsUvpaaRequest','onRequestCanceled','onRemoteSessionStateChange'].map(name=>[name,event()]));api.attach=async()=>{};api.detach=async()=>{};
 const chrome={...f.browser,webAuthenticationProxy:api,alarms:{onAlarm:event(),create(){},clear(){}},runtime:{id:'test',onMessage:event(),onStartup:event(),onInstalled:event(),connectNative:()=>port}};
 const context={chrome,crypto,TextEncoder,Uint8Array,Date,setTimeout(){return 1;},clearTimeout(){}};vm.createContext(context);context.importScripts=name=>{assert.equal(name,'browser_window.js');vm.runInContext(source,context);};
 vm.runInContext(fs.readFileSync(path.join(__dirname,'../extension/background.js'),'utf8'),context);
 for(let i=0;i<20;i++)await Promise.resolve();assert.equal(sent.find(v=>v.type==='ready').capabilities.includes('window_control'),true);
 port.onMessage.emit({type:'window_control',nonce:'native_request_12345',action:'ensure',remaining_ms:10000,expected_window_count:1});
 for(let i=0;i<50&&!sent.some(v=>v.type==='window_control_result');i++)await new Promise(resolve=>setImmediate(resolve));
 assert.equal(sent.find(v=>v.type==='window_control_result').ok,true);
 assert.equal(JSON.stringify(sent).includes('https://one.test/'),false);
});
console.log(count+' managed-window VM cases passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
