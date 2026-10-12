/* Read-only top-level loopback navigation observer. No page script, fetch,
 * redirect interception, browsing history, or URL diagnostics. */
'use strict';
function createLocalNavigationObserver(browser, send) {
  const LIFETIME_MS = 5000;
  const MAX_TABS = 64;
  const MAX_URL_BYTES = 8192;
  const tabs = new Map();
  const navigationTimes = new Map();
  let scope = null;
  let generation = null;
  let scopeStartedAt = 0;
  let sequence = 0;
  let active = null;

  function localUrl(value) {
    if (typeof value !== 'string' || value.length > MAX_URL_BYTES || /[\s\\\u0000-\u001f\u007f]/.test(value)
      || new TextEncoder().encode(value).length > MAX_URL_BYTES
      || !/^https?:\/\/(?:localhost|127\.0\.0\.1)(?::[0-9]{1,5})?(?:[/?#]|$)/i.test(value)) return false;
    try {
      const url = new URL(value);
      return ['http:', 'https:'].includes(url.protocol) && ['localhost', '127.0.0.1'].includes(url.hostname)
        && !url.username && !url.password;
    } catch (_) { return false; }
  }
  function networkUrl(value) { try { return new URL(value).href.split('#')[0]; } catch (_) { return null; } }
  function topLevel(value) {
    return value && Number.isSafeInteger(value.tabId) && value.tabId >= 0 && value.frameId === 0
      && (!value.frameType || value.frameType === 'outermost_frame');
  }
  function freshEvent(details) {
    return Number.isFinite(details.timeStamp) && details.timeStamp >= scopeStartedAt
      && Date.now() - details.timeStamp < LIFETIME_MS && details.timeStamp <= Date.now() + 1000;
  }
  function navigationEvent(details) {
    if (!freshEvent(details)) return false;
    const prior = navigationTimes.get(details.tabId);
    if (prior && details.timeStamp < prior.at) return false;
    // URL-free high-water/announcement state survives a slow commit after the
    // five-second URL cache expires. Never evict it and accidentally replay an
    // old navigation; excess concurrent tabs fail closed until a tab closes.
    if (!prior && navigationTimes.size >= MAX_TABS) return false;
    navigationTimes.set(details.tabId, {...prior, at: details.timeStamp, announced: prior?.announced === true});
    return true;
  }
  function emit(type, url, observedAt = Date.now()) {
    if (!scope || !Number.isSafeInteger(sequence + 1)) return false;
    const message = {type, scope, mode_generation: generation, sequence: ++sequence, observed_at_ms: observedAt};
    if (url !== undefined) message.url = url;
    return send(message) === true;
  }
  function clear() {
    if (active !== null) emit('local_navigation_clear');
    active = null;
  }
  function forget(tabId) {
    const entry = tabs.get(tabId);
    if (entry) clearTimeout(entry.timer);
    tabs.delete(tabId);
    // URL-cache expiry is not UI dismissal. Retain only the URL-free active
    // tab marker so a later navigation/tab close clears even a hovered prompt.
  }
  function entryFor(tabId) {
    let entry = tabs.get(tabId);
    if (!entry) {
      if (tabs.size >= MAX_TABS) forget(tabs.keys().next().value);
      entry = {navigation: null, request: null, notified: null, timer: null};
      tabs.set(tabId, entry);
    }
    // Never renew retained URL lifetime merely because another event arrived.
    // No durable state survives worker/port/scope replacement.
    if (entry.timer === null) entry.timer = setTimeout(() => { if (tabs.get(tabId) === entry) forget(tabId); }, LIFETIME_MS);
    return entry;
  }
  function offer(tabId, url, observedAt) {
    if (!scope || !localUrl(url) || Date.now() - observedAt >= LIFETIME_MS) return;
    const entry = entryFor(tabId);
    if (entry.notified?.url === url && Date.now() < entry.notified.until) return;
    clear();
    if (emit('local_navigation', url, observedAt)) {
      entry.notified = {url, until: observedAt + LIFETIME_MS};
      active = {tabId};
      const metadata = navigationTimes.get(tabId);
      if (metadata) metadata.announced = true;
    }
  }
  function correlate(tabId, entry) {
    const navigation = entry.navigation; const request = entry.request;
    if (entry.ambiguous || !navigation || !request || !request.eligible || navigation.key !== request.key
      || !Number.isFinite(navigation.browserTime) || !Number.isFinite(request.browserTime)
      || request.browserTime < navigation.browserTime
      || request.browserTime - navigation.browserTime >= LIFETIME_MS
      || Math.abs(navigation.at - request.at) >= LIFETIME_MS) return;
    // A previous navigation's request must not authorize a later typed attempt
    // to the same URL. Browser event timestamps and one-use correlation bind it.
    entry.request = null; entry.navigation = null;
    offer(tabId, navigation.url, Math.min(navigation.at, request.at));
  }
  function reset() {
    for (const tabId of tabs.keys()) forget(tabId);
    navigationTimes.clear();
    active = null; scope = null; generation = null; sequence = 0;
  }

  browser.webNavigation.onBeforeNavigate.addListener(details => {
    if (!scope || !topLevel(details) || !navigationEvent(details)) return;
    const previous = tabs.get(details.tabId);
    const metadata = navigationTimes.get(details.tabId);
    const wasPending = metadata.inFlight === true;
    metadata.inFlight = true;
    if (!(previous?.created && previous.notified?.url === details.url)) navigationTimes.get(details.tabId).announced = false;
    if (active && (active.tabId !== details.tabId || previous?.notified?.url !== details.url || !previous?.created)) clear();
    if (!localUrl(details.url)) {
      forget(details.tabId);
      try {
        const url = new URL(details.url);
        if (['http:', 'https:'].includes(url.protocol) && !['localhost', '127.0.0.1'].includes(url.hostname)) {
          // Keep only nonlocal-origin evidence, never the remote URL itself.
          entryFor(details.tabId).externalStart = {at: Date.now(), browserTime: details.timeStamp};
        }
      } catch (_) {}
      return;
    }
    const entry = entryFor(details.tabId);
    // Overlapping unfinished navigations cannot be uniquely correlated by the
    // APIs' tab+URL fields. Suppress ambiguous reuse, especially script→typed.
    entry.ambiguous ||= entry.pending === true || wasPending;
    entry.pending = true; entry.created = false;
    entry.externalStart = null;
    entry.navigation = {url: details.url, key: networkUrl(details.url), at: Date.now(), browserTime: details.timeStamp};
    if (entry.request && entry.request.key !== entry.navigation.key) entry.request = null;
    correlate(details.tabId, entry);
  });
  browser.webNavigation.onCreatedNavigationTarget.addListener(details => {
    // The destination is a new top-level tab/window; sourceFrameId may describe
    // an iframe that opened it, rather than an embedded destination frame.
    if (!scope || !Number.isSafeInteger(details.tabId) || details.tabId < 0
      || !Number.isSafeInteger(details.sourceTabId) || details.sourceTabId < 0 || !localUrl(details.url) || !navigationEvent(details)) return;
    const entry = entryFor(details.tabId);
    entry.navigation = {url: details.url, key: networkUrl(details.url), at: Date.now(), browserTime: details.timeStamp};
    entry.created = true;
    if (!entry.ambiguous) offer(details.tabId, details.url, Date.now());
  });
  function completedNavigation(details, sameDocument = false) {
    if (!scope || !topLevel(details)) return;
    const prior = navigationTimes.get(details.tabId);
    if (sameDocument) {
      // These events have no preceding onBeforeNavigate in pinned Chromium.
      // Require their document identity and a fresh event, not the preceding
      // full navigation's announcement/cache. Never let an old document or
      // overlapping full navigation replace the current prompt.
      if (typeof details.documentId !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(details.documentId)
        || (prior?.documentId && prior.documentId !== details.documentId)
        || prior?.inFlight || prior?.sameDocumentAt === details.timeStamp) return;
    }
    if (!navigationEvent(details)) return;
    const metadata = navigationTimes.get(details.tabId);
    if (typeof details.documentId === 'string') metadata.documentId = details.documentId;
    metadata.inFlight = false;
    if (sameDocument) {
      metadata.sameDocumentAt = details.timeStamp;
      metadata.announced = false;
      clear(); forget(details.tabId);
    }
    if (tabs.get(details.tabId)?.ambiguous) { clear(); forget(details.tabId); return; }
    const qualifiers = Array.isArray(details.transitionQualifiers) ? details.transitionQualifiers : null;
    const external = tabs.get(details.tabId)?.externalStart;
    const redirect = Array.isArray(qualifiers) && qualifiers.some(q => ['client_redirect', 'server_redirect'].includes(q));
    const provenExternalRedirect = redirect && external && Date.now() - external.at < LIFETIME_MS
      && Number.isFinite(details.timeStamp) && Number.isFinite(external.browserTime)
      && details.timeStamp >= external.browserTime;
    const excluded = ['reload', 'keyword', 'keyword_generated'];
    const manual = ['typed', 'generated'].includes(details.transitionType) || qualifiers?.includes('from_address_bar');
    const forbidden = !Array.isArray(qualifiers) || qualifiers.includes('forward_back')
      || excluded.includes(details.transitionType) || (manual && !provenExternalRedirect);
    const allowed = !forbidden && (['link', 'form_submit', 'auto_bookmark'].includes(details.transitionType) || redirect);
    const alreadyOffered = tabs.get(details.tabId)?.notified?.url === details.url;
    if (forbidden || (!allowed && !alreadyOffered)) { clear(); forget(details.tabId); return; }
    if (!localUrl(details.url)) { clear(); forget(details.tabId); return; }
    if (navigationTimes.get(details.tabId)?.announced && !tabs.get(details.tabId)?.notified) return;
    const previous = tabs.get(details.tabId);
    if (previous) { previous.navigation = null; previous.request = null; previous.externalStart = null; previous.pending = false; previous.created = false; }
    // Created-target and early main-frame evidence can precede this event. The
    // same target is not offered again and its original five-second TTL is kept.
    offer(details.tabId, details.url, Date.now());
  }
  browser.webNavigation.onCommitted.addListener(details => completedNavigation(details));
  browser.webNavigation.onHistoryStateUpdated.addListener(details => completedNavigation(details, true));
  browser.webNavigation.onReferenceFragmentUpdated.addListener(details => completedNavigation(details, true));
  if (browser.webRequest?.onBeforeRequest) {
    browser.webRequest.onBeforeRequest.addListener(details => {
      if (!scope || !topLevel(details) || !freshEvent(details) || details.type !== 'main_frame' || !localUrl(details.url)) return;
      // Pinned Chromium redacts initiators without source-host permission, even
      // for admitted main-frame requests. Broad http(s) source permission is
      // declared solely to expose this field; the listener remains loopback-only.
      // Absence/opaque initiators never prove a script/link (including typed
      // public URLs which server-redirect to localhost).
      let eligible = false;
      try {
        const initiator = new URL(details.initiator);
        eligible = ['http:', 'https:'].includes(initiator.protocol) && initiator.origin !== 'null';
      } catch (_) {}
      const entry = entryFor(details.tabId);
      entry.request = {key: networkUrl(details.url), at: Date.now(), browserTime: details.timeStamp, eligible};
      correlate(details.tabId, entry);
    }, {urls: ['http://localhost/*', 'https://localhost/*', 'http://127.0.0.1/*', 'https://127.0.0.1/*'], types: ['main_frame']});
  }
  browser.tabs?.onRemoved?.addListener(tabId => {
    if (active?.tabId === tabId) clear();
    forget(tabId);
    navigationTimes.delete(tabId);
  });
  return {
    setScope(message) {
      if (typeof message.scope !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(message.scope)
        || !Number.isSafeInteger(message.mode_generation) || message.mode_generation < 0) return;
      if (scope === message.scope && generation === message.mode_generation) return;
      reset(); scope = message.scope; generation = message.mode_generation; scopeStartedAt = Date.now();
    },
    reset,
  };
}
