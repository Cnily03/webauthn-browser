/* Browser-owned WebAuthn interception. No content scripts, injected JavaScript,
 * externally_connectable messages, page-accessible secrets, or localhost fetch. */
'use strict';
const api = chrome.webAuthenticationProxy;
const extensionVersion = '1.0.29';
// Literal belongs to this running script, never read from a newer image at runtime.
const extensionBuild = '3070fc4f66da456b2ff5f03d0a2e6b8289f1fb369ddc5e39395074e5b3a4230c';
const protocolVersion = 1;
const capabilities = Object.freeze(['heartbeat','mode_ack_generation','mode_progress','mode_lease','local_navigation',...(chrome.windows && chrome.tabs && chrome.tabGroups ? ['window_control'] : [])]);
const pending = new Map();
let port = null;
// Packaged observer only; no page-accessible messaging or persistent URL state.
let localNavigation = null;
if (chrome.webNavigation) {
  importScripts('local_navigation.js');
  localNavigation = createLocalNavigationObserver(chrome, message => {
    if (!port) return false;
    try { port.postMessage(message); return true; } catch (_) { return false; }
  });
}

let browserWindow = null;
if (chrome.windows && chrome.tabs && chrome.tabGroups) {
  importScripts('browser_window.js');
  browserWindow = createBrowserWindowController(chrome);
}

let attached = false;
let browserModePending = 0;
let retry = null;
let desiredMode = 'proxy';
let modeGeneration = -1;
let modeQueue = Promise.resolve();
let retryDelay = 1000;
let heartbeat = null;
let heartbeatDeadline = null;
let pingNonce = 0;
let awaitingPong = null;
let healthyPongs = 0;
function clearHeartbeat() {
  if (heartbeat !== null) clearTimeout(heartbeat);
  if (heartbeatDeadline !== null) clearTimeout(heartbeatDeadline);
  heartbeat = heartbeatDeadline = null;
  awaitingPong = null;
  healthyPongs = 0;
}
function startHeartbeat(connection) {
  if (port !== connection || heartbeat !== null || awaitingPong !== null) return;
  heartbeat = setTimeout(() => {
    heartbeat = null;
    if (port !== connection) return;
    awaitingPong = ++pingNonce;
    heartbeatDeadline = setTimeout(() => loseConnection(connection), 10000);
    try { connection.postMessage({type:'ping',nonce:awaitingPong,extensionVersion}); }
    catch (_) { loseConnection(connection); }
  }, 5000);
}
function loseConnection(connection) {
  if (!connection || port !== connection) return;
  // Invalidate before disconnect(): Chrome may notify synchronously or later.
  port = null;
  localNavigation?.reset();
  browserWindow?.reset();
  modeGeneration = -1;
  nativeReadyGeneration = -1;
  leaseGeneration = 0;
  clearHeartbeat();
  for (const [requestId,type] of pending) unavailable(requestId,type);
  try { connection.disconnect(); } catch (_) {}
  // Retain the original, time-bounded native choice. A transport failure must
  // neither attach the global interceptor nor extend/replay phone approval.
  scheduleReconnect();
}
// A local lease also restores fail-closed interception if the backend stops.
let nativeLease = null;
let nativeLeaseDeadline = 0;
let nativeLeaseToken = 0;
let nativeReadyGeneration = -1;
let leaseGeneration = 0;
function validLeaseDuration(value) {
  return Number.isSafeInteger(value) && value > 0 && value <= 120000;
}
function clearNativeLease() {
  if (nativeLease !== null) clearTimeout(nativeLease);
  nativeLease = null;
  nativeLeaseDeadline = 0;
  nativeLeaseToken++;
  nativeReadyGeneration = -1;
  leaseGeneration = 0;
}
function armNativeLease(remainingMs) {
  if (nativeLease !== null) clearTimeout(nativeLease);
  const token = ++nativeLeaseToken;
  nativeLeaseDeadline = Date.now() + remainingMs;
  nativeLease = setTimeout(() => {
    if (token !== nativeLeaseToken || desiredMode !== 'native') return;
    const generation = modeGeneration;
    const connection = port;
    restoreProxy().then(() => {
      if (connection && port === connection && generation === modeGeneration && desiredMode === 'proxy' && attached && !browserModePending) {
        try { connection.postMessage({type:'ready',extensionVersion,extensionBuild,protocolVersion,capabilities,mode:'proxy',attached}); } catch (_) {}
      }
    });
  },remainingMs);
}
// Use Chrome's completion callback explicitly. Some supported API bindings
// return no Promise when a callback is supplied; never treat that as success.
// A watchdog reports a failure but does not release the serialization lock:
// a late detach must finish before a recovery attach can run.
function modeProgress(connection,generation,stage) {
  if (!connection || port !== connection || generation < 0) return;
  try { connection.postMessage({type:'mode_progress',generation,stage,extensionVersion}); } catch (_) {}
}
function browserModeOperation(operation) {
  const connection = port;
  const generation = modeGeneration;
  modeProgress(connection,generation,operation + '_started');
  let reported = false;
  function report(reason) {
    if (reported) return;
    reported = true;
    if (port === connection && connection) {
      try { connection.postMessage({type:'mode_error',operation,reason,generation}); } catch (_) {}
    }
  }
  return new Promise((resolve,reject) => {
    let settled = false;
    browserModePending++;
    const deadline = setTimeout(() => report('timeout'),4000);
    function complete(error) {
      if (settled) return;
      settled = true;
      browserModePending--;
      clearTimeout(deadline);
      if (error) { report('api_error'); reject(new Error(String(error))); }
      else { modeProgress(connection,generation,operation + '_completed'); resolve(); }
    }
    try {
      const result = api[operation](error => {
        const runtimeError = chrome.runtime.lastError;
        complete(runtimeError ? runtimeError.message : error);
      });
      if (result && typeof result.then === 'function') result.then(complete,error => complete(error || 'Browser mode operation failed'));
    } catch (error) { complete(error); }
  });
}
function restoreProxy() {
  desiredMode = 'proxy';
  clearNativeLease();
  modeQueue = modeQueue.then(async () => {
    if (!attached) { await browserModeOperation('attach'); attached = true; }
  }).catch(() => { if (port) loseConnection(port); else scheduleReconnect(); });
  return modeQueue;
}
function changeMode(connection, message) {
  if (!['native','proxy'].includes(message.mode) || !Number.isSafeInteger(message.generation) || message.generation <= modeGeneration) return;
  if (message.mode === 'native' && !validLeaseDuration(message.leaseRemainingMs)) return;
  modeGeneration = message.generation;
  clearNativeLease();
  desiredMode = message.mode;
  const generation = modeGeneration;
  modeProgress(connection,generation,'received');
  // Start the bounded lease before awaiting detach; a disconnect during that
  // await must not leave an unbounded native state.
  if (message.mode === 'native') armNativeLease(message.leaseRemainingMs);
  modeQueue = modeQueue.then(async () => {
    if (port !== connection || generation !== modeGeneration || desiredMode !== message.mode) return;
    for (const [requestId,type] of pending) unavailable(requestId,type);
    if (message.mode === 'native' && attached) {
      await browserModeOperation('detach'); attached = false;
    } else if (message.mode === 'proxy' && !attached) {
      await browserModeOperation('attach'); attached = true;
    }
    if (port !== connection || generation !== modeGeneration || desiredMode !== message.mode || browserModePending) return;
    if (message.mode === 'native' && (attached || nativeLease === null || nativeLeaseDeadline <= Date.now())) return;
    if (message.mode === 'proxy' && !attached) return;
    connection.postMessage({type:'mode_ready',mode:message.mode,generation,attached,extensionVersion,protocolVersion});
    if (message.mode === 'native') nativeReadyGeneration = generation;
  }).catch(() => {
    restoreProxy();
  });
}

function renewModeLease(connection, message) {
  if (port !== connection || desiredMode !== 'native' || attached || browserModePending ||
      !Number.isSafeInteger(message.generation) || message.generation < 0 ||
      message.generation !== modeGeneration || nativeReadyGeneration !== modeGeneration ||
      !Number.isSafeInteger(message.leaseGeneration) || message.leaseGeneration <= leaseGeneration ||
      !validLeaseDuration(message.leaseRemainingMs) || nativeLease === null || nativeLeaseDeadline <= Date.now()) return;
  leaseGeneration = message.leaseGeneration;
  armNativeLease(message.leaseRemainingMs);
  try {
    connection.postMessage({type:'mode_lease_ready',generation:modeGeneration,leaseGeneration,
      mode:'native',attached,extensionVersion,protocolVersion});
  } catch (_) { loseConnection(connection); }
}

function finish(message) {
  if (pending.get(message.requestId) !== message.type) return;
  // Consume before calling Chrome; cancellation/disconnection races cannot
  // cause a duplicate response or retry a completed browser ceremony.
  pending.delete(message.requestId);
  let operation;
  try {
  if (message.type === 'uvpaa') {
    operation = api.completeIsUvpaaRequest({requestId: message.requestId, isUvpaa: message.isUvpaa === true});
  } else {
    const details = {requestId: message.requestId};
    if (message.error) details.error = {name: String(message.error.name), message: String(message.error.message)};
    else if (typeof message.responseJson === 'string') details.responseJson = message.responseJson;
    else details.error = {name: 'NotAllowedError', message: 'Invalid response from authentication broker.'};
    operation = message.type === 'create' ? api.completeCreateRequest(details) : api.completeGetRequest(details);
  }
  } catch (_) { return; } // A synchronous browser cancellation can also win.
  Promise.resolve(operation).catch(() => {}); // A browser cancellation can win.
}

function unavailable(requestId, type) {
  finish({requestId, type, isUvpaa: false,
    error: {name: 'NotAllowedError', message: 'Authentication broker is unavailable. Try again after reconnecting.'}});
}

function forward(type, event) {
  pending.set(event.requestId, type);
  if (!port || !attached || browserModePending || desiredMode !== 'proxy') { unavailable(event.requestId, type); return; }
  try {
    const message = {type, requestId: event.requestId};
    if (type !== 'uvpaa') message.requestDetailsJson = event.requestDetailsJson;
    port.postMessage(message);
  } catch (_) { loseConnection(port); unavailable(event.requestId, type); }
}

api.onCreateRequest.addListener(event => forward('create', event));
api.onGetRequest.addListener(event => forward('get', event));
api.onIsUvpaaRequest.addListener(event => forward('uvpaa', event));
api.onRequestCanceled.addListener(requestId => {
  pending.delete(requestId);
  if (port) { try { port.postMessage({type: 'cancel', requestId}); } catch (_) {} }
});

function scheduleReconnect() {
  if (retry !== null) return;
  const delay = retryDelay;
  retryDelay = Math.min(30000, retryDelay * 2);
  retry = setTimeout(() => { retry = null; connect(); }, delay);
  // Alarms wake a suspended worker; they do not bypass an active backoff timer.
  chrome.alarms.create('proxy-reconnect', {delayInMinutes: 0.5});
}

function connect() {
  if (port || retry !== null) return;
  let connection;
  try { connection = chrome.runtime.connectNative('com.auth_browser.proxy'); }
  catch (_) { scheduleReconnect(); return; }
  port = connection;
  connection.onMessage.addListener(message => {
    if (port !== connection || !message || typeof message !== 'object') return;
    if (message.type === 'pong') {
      if (awaitingPong === null || message.nonce !== awaitingPong) return;
      clearTimeout(heartbeatDeadline);
      heartbeatDeadline = null;
      awaitingPong = null;
      if (++healthyPongs >= 12) retryDelay = 1000;
      startHeartbeat(connection);
    } else if (message.type === 'navigation_scope') localNavigation?.setScope(message);
    else if (message.type === 'window_control') void browserWindow?.handle(message,connection,()=>port===connection);
    else if (message.type === 'window_control_cancel') browserWindow?.cancel(message.nonce);
    else if (message.type === 'mode') changeMode(connection,message);
    else if (message.type === 'mode_lease') renewModeLease(connection,message);
    else finish(message);
  });
  connection.onDisconnect.addListener(() => {
    void chrome.runtime.lastError;
    loseConnection(connection);
  });
  // Transport liveness is independent of Chrome's asynchronous attach/detach.
  // Keep the native host alive while readiness waits for an interrupted mode
  // transition, without acknowledging that transition or replaying requests.
  startHeartbeat(connection);
  modeQueue = modeQueue.then(async () => {
    try {
      // Initialization uses the same queue as commands and lease rollback.
      // Merely awaiting an old queue here would allow a newer command to run
      // a browser operation concurrently with this reconnect initializer.
      if (port !== connection) return;
      const mode = desiredMode;
      const generation = modeGeneration;
      if (mode === 'native' && (nativeLease === null || nativeLeaseDeadline <= Date.now())) {
        restoreProxy();
        return;
      }
      if (mode === 'native' && attached) {
        await browserModeOperation('detach');
        attached = false;
      } else if (mode === 'proxy' && !attached) {
        await browserModeOperation('attach');
        attached = true;
      }
      if (port !== connection || desiredMode !== mode || modeGeneration !== generation) return;
      if (desiredMode === 'proxy' && !attached) throw new Error('Proxy unavailable');
      if (browserModePending || (desiredMode === 'native' && (attached || nativeLease === null || nativeLeaseDeadline <= Date.now()))) return;
      connection.postMessage({type:'ready',extensionVersion,extensionBuild,protocolVersion,capabilities,mode:desiredMode,attached,leaseRemainingMs:Math.max(0,nativeLeaseDeadline-Date.now())});
      chrome.alarms.clear('proxy-reconnect');
    } catch (_) {
      loseConnection(connection);
    }
  });
}
chrome.alarms.onAlarm.addListener(alarm => { if (alarm.name === 'proxy-reconnect') connect(); });
chrome.runtime.onStartup.addListener(connect);
chrome.runtime.onInstalled.addListener(connect);
api.onRemoteSessionStateChange.addListener(connect);
connect();

// Only our packaged upgrade page may query worker metadata. This is not an
// externally_connectable API and never accepts mode or authentication commands.
chrome.runtime.onMessage.addListener((message,sender,respond) => {
  const page = 'chrome-extension://' + chrome.runtime.id + '/upgrade.html';
  if (message?.type !== 'broker_version' || sender.id !== chrome.runtime.id ||
      typeof sender.url !== 'string' || sender.url.split('?')[0] !== page) return;
  respond({extensionVersion,extensionBuild,protocolVersion,capabilities});
});
