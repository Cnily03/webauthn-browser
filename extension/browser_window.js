/* Fixed managed-window operations. No caller-supplied URL, CDP, tab ID or script. */
'use strict';
function createBrowserWindowController(browser) {
  const MAX_TABS = 512, MAX_WINDOWS = 16;
  let active = null;
  function fault(reason) { const error = new Error(reason); error.reason = reason; throw error; }
  function check(job) {
    if (active !== job || job.canceled || !job.current() || Date.now() >= job.deadline) fault('canceled');
  }
  async function invoke(job, operation) {
    check(job); const result = await operation(); check(job); return result;
  }
  async function inventory(job) {
    const windows = await invoke(job, () => browser.windows.getAll({populate:true, windowTypes:['normal','popup','panel','app','devtools']}));
    if (!Array.isArray(windows) || windows.length > MAX_WINDOWS) fault('unsupported_windows');
    const ids = new Set(); let count = 0;
    for (const window of windows) {
      if (!Number.isInteger(window.id) || window.id < 0 || window.incognito || window.type !== 'normal'
        || !Array.isArray(window.tabs) || window.tabs.length === 0) fault('unsupported_windows');
      window.tabs.sort((a,b) => a.index - b.index);
      for (const [index,tab] of window.tabs.entries()) {
        if (tab.index !== index || tab.windowId !== window.id || ++count > MAX_TABS || !Number.isInteger(tab.id) || tab.id < 0 || ids.has(tab.id)
          || tab.incognito || typeof tab.pinned !== 'boolean' || tab.pendingUrl
          || typeof tab.url !== 'string' || tab.url.length > 131072
          || !Number.isInteger(tab.groupId) || tab.groupId < -1 || (tab.pinned && tab.groupId !== -1)) fault('unstable_tabs');
        ids.add(tab.id);
      }
    }
    return windows;
  }
  async function groupsFor(job, windows) {
    const groups = new Map();
    for (const window of windows) for (const tab of window.tabs) if (tab.groupId !== -1 && !groups.has(tab.groupId)) {
      const group = await invoke(job, () => browser.tabGroups.get(tab.groupId));
      if (!group || group.shared || (group.title !== undefined && typeof group.title !== 'string') || (group.title || '').length > 1024
        || typeof group.color !== 'string' || typeof group.collapsed !== 'boolean') fault('unsupported_groups');
      groups.set(tab.groupId, [group.title || '',group.color,group.collapsed]);
    }
    return groups;
  }
  function plan(windows) {
    const ordered = windows.slice().sort((a,b) => Number(b.focused)-Number(a.focused) || a.id-b.id);
    const tabs = ordered.flatMap(window => window.tabs);
    return {target:ordered[0], tabs:[...tabs.filter(tab=>tab.pinned),...tabs.filter(tab=>!tab.pinned)]};
  }
  function stableTabs(tabs, groups) {
    const groupOrder = new Map();
    return tabs.map(tab => {
      if (tab.groupId !== -1 && !groupOrder.has(tab.groupId)) groupOrder.set(tab.groupId,groupOrder.size);
      return [tab.url,tab.pinned,tab.groupId===-1?null:[groupOrder.get(tab.groupId),groups.get(tab.groupId)]];
    });
  }
  async function digest(job, values) {
    const bytes = new TextEncoder().encode(JSON.stringify(values));
    if (bytes.length > 4*1024*1024) fault('unstable_tabs');
    const hash = await invoke(job, () => crypto.subtle.digest('SHA-256',bytes));
    return Array.from(new Uint8Array(hash),byte=>byte.toString(16).padStart(2,'0')).join('');
  }
  async function perform(job, message) {
    let windows = await inventory(job);
    if (windows.length !== message.expected_window_count) fault('window_count_changed');
    if (windows.length === 0) {
      if (message.action !== 'ensure') fault('no_window');
      await invoke(job, () => browser.windows.create({type:'normal',url:'about:blank',state:'maximized',focused:true}));
      windows = await inventory(job);
      if (windows.length !== 1) fault('window_count_changed');
    }
    const beforeGroups = await groupsFor(job, windows);
    const planned = plan(windows);
    const expected = await digest(job, stableTabs(planned.tabs,beforeGroups));
    if (message.action === 'verify') {
      if (windows.length !== 1 || expected !== message.expected_fingerprint) fault('restore_mismatch');
    } else {
      const target = planned.target.id;
      const oldActive = planned.target.tabs.find(tab => tab.active)?.id;
      // Moving existing tab contents retains navigation state. Empty source
      // windows close themselves; we never remove a window or close a tab.
      let pinnedCount = planned.target.tabs.filter(tab=>tab.pinned).length;
      for (const tab of planned.tabs) if (tab.pinned && tab.windowId !== target) {
        await invoke(job, () => browser.tabs.move(tab.id,{windowId:target,index:pinnedCount++}));
      }
      const movedGroups = new Set();
      for (const tab of planned.tabs) if (!tab.pinned && tab.windowId !== target) {
        if (tab.groupId === -1) await invoke(job, () => browser.tabs.move(tab.id,{windowId:target,index:-1}));
        else if (!movedGroups.has(tab.groupId)) {
          movedGroups.add(tab.groupId);
          await invoke(job, () => browser.tabGroups.move(tab.groupId,{windowId:target,index:-1}));
        }
      }
      if (oldActive !== undefined) await invoke(job, () => browser.tabs.update(oldActive,{active:true}));
      await invoke(job, () => browser.windows.update(target,{state:'maximized',focused:true}));
    }
    const finalWindows = await inventory(job);
    if (finalWindows.length !== 1) fault('window_count_changed');
    const finalGroups = await groupsFor(job, finalWindows);
    const actual = await digest(job, stableTabs(finalWindows[0].tabs,finalGroups));
    if (actual !== expected || (message.action === 'verify' && actual !== message.expected_fingerprint)) fault('restore_mismatch');
    return {window_count:1,tab_count:finalWindows[0].tabs.length,fingerprint:actual};
  }
  return {
    // A Chrome API call already in progress cannot be undone. Retain its
    // single-flight lock until it settles, even after owner/port cancellation,
    // so a late move cannot overlap a newer operation in the same browser.
    reset() { if (active) active.canceled = true; },
    cancel(nonce) { if (active?.nonce === nonce) active.canceled = true; },
    async handle(message, connection, current) {
      if (!message || typeof message.nonce !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(message.nonce)
        || Object.keys(message).some(key=>!['type','nonce','action','remaining_ms','expected_window_count','expected_fingerprint'].includes(key))
        || !['ensure','consolidate','verify'].includes(message.action)
        || !Number.isSafeInteger(message.remaining_ms) || message.remaining_ms < 1 || message.remaining_ms > 10000
        || !Number.isSafeInteger(message.expected_window_count) || message.expected_window_count < 0 || message.expected_window_count > MAX_WINDOWS
        || (message.action === 'verify' && !/^[0-9a-f]{64}$/.test(message.expected_fingerprint || ''))) return;
      const reply = {type:'window_control_result',nonce:message.nonce,action:message.action};
      if (active) { if (current()) { try { connection.postMessage({...reply,ok:false,reason:'busy'}); } catch (_) {} } return; }
      const job = {nonce:message.nonce,current,deadline:Date.now()+message.remaining_ms}; active = job;
      try {
        const result = await perform(job,message); check(job);
        connection.postMessage({...reply,ok:true,...result});
      } catch (error) {
        if (active === job && current()) {
          const known = ['canceled','unsupported_windows','unstable_tabs','unsupported_groups','window_count_changed','no_window','restore_mismatch'];
          try { connection.postMessage({...reply,ok:false,reason:known.includes(error.reason)?error.reason:'operation_failed'}); } catch (_) {}
        }
      } finally { if (active === job) active = null; }
    },
  };
}
