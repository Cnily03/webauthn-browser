/* Extension-owned recovery, not web-accessible. No profile or site data writes. */
'use strict';
(() => {
  const version = '1.0.29';
  const extensionBuild = '3070fc4f66da456b2ff5f03d0a2e6b8289f1fb369ddc5e39395074e5b3a4230c';
  const capabilities = ['heartbeat','mode_ack_generation','mode_progress','mode_lease'];
  const status = document.getElementById('status');
  const parameters = new URLSearchParams(location.search);
  const attempt = parameters.get('attempt');
  const expiresText = parameters.get('expires');
  const expires = Number(expiresText);
  // These contain no website Origin, credentials or authorization tokens.
  // A delayed tab from an older attempt cannot reload a newer, healthy worker.
  const validAttempt = [...parameters.keys()].length === 2 &&
    parameters.getAll('attempt').length === 1 && parameters.getAll('expires').length === 1 &&
    /^[a-f0-9]{32}-[12]$/.test(attempt || '') && /^[1-9][0-9]{12}$/.test(expiresText || '') &&
    Number.isSafeInteger(expires);
  const activeAttempt = () => validAttempt && Date.now() < expires && expires - Date.now() <= 15000;
  if (!activeAttempt()) {
    status.textContent = 'This extension update attempt is no longer active. Use browser Reconnect to request a new attempt; keep your browser profile.';
    return;
  }
  const marker = 'broker-upgrade-' + extensionBuild + '-' + attempt;
  let finished = false;
  function finish(response) {
    if (finished) return;
    finished = true;
    clearTimeout(timer);
    if (!activeAttempt()) {
      status.textContent = 'This extension update attempt expired. A later recovery attempt may already be active; keep your browser profile.';
      return;
    }
    const compatible = response && response.extensionVersion === version &&
      response.extensionBuild === extensionBuild &&
      response.protocolVersion === 1 && Array.isArray(response.capabilities) &&
      capabilities.every(capability => response.capabilities.includes(capability));
    if (compatible) {
      status.textContent = 'The current extension is loaded. Waiting for the browser connection to confirm readiness; you can close this tab.';
      return;
    }
    // Each issued attempt can reload once. The supervisor owns the separate,
    // bounded retry budget; refreshing or restoring this page adds no attempts.
    try {
      if (sessionStorage.getItem(marker)) {
        status.textContent = 'This extension update attempt has already run. Wait for recovery or use browser Reconnect after it fails. Do not delete your browser profile.';
        return;
      }
      sessionStorage.setItem(marker,'attempted');
    } catch (_) {
      status.textContent = 'Cannot safely track this reload attempt. Close this tab and reload the authentication extension from chrome://extensions, then retry sign-in.';
      return;
    }
    status.textContent = 'Reloading the authentication extension once. Existing sign-ins are canceled; browser data is preserved.';
    try { chrome.runtime.reload(); }
    catch (_) { status.textContent = 'The extension could not reload. Reload the authentication extension from chrome://extensions; keep your browser profile.'; }
  }
  const timer = setTimeout(() => finish(null), 2000);
  try {
    chrome.runtime.sendMessage({type:'broker_version'}, response => {
      const error = chrome.runtime.lastError;
      finish(error ? null : response);
    });
  } catch (_) { finish(null); }
})();
