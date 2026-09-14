/**
 * SafeClick 2.0 - Tab & Session State Manager
 * Open Source Browser Security Engine
 * 
 * Manages per-tab state, temp-allow windows, badge/icon rendering,
 * and frame messaging for active browser sessions.
 */

const TabManager = (function () {
  'use strict';

  // In-memory runtime caches
  const siteHistory = new Map();
  const tempAllowedHosts = new Map();     // tabId => Map(host => expiresAtMs)
  const tempAllowAllTabs = new Map();     // tabId => expiresAtMs
  const interstitialAllowlist = new Map();// tabId => Set(hostnames)
  const pendingDestinations = new Map();  // tabId => { url, host, time, reason }

  function markHostTempAllowed(tabId, host, ttlMs = 15000) {
    if (typeof tabId !== 'number' || !host) return;
    const h = String(host).toLowerCase().trim();
    let m = tempAllowedHosts.get(tabId);
    if (!m) {
      m = new Map();
      tempAllowedHosts.set(tabId, m);
    }
    m.set(h, Date.now() + ttlMs);
  }

  function isHostTempAllowed(tabId, host) {
    if (typeof tabId !== 'number' || !host) return false;
    const m = tempAllowedHosts.get(tabId);
    if (!m) return false;
    const h = String(host).toLowerCase().trim();
    const exp = m.get(h);
    if (!exp) return false;
    if (Date.now() > exp) {
      m.delete(h);
      return false;
    }
    return true;
  }

  function markTabTempAllowAll(tabId, ttlMs = 20000) {
    if (typeof tabId !== 'number') return;
    tempAllowAllTabs.set(tabId, Date.now() + ttlMs);
  }

  function isTabTempAllowAll(tabId) {
    if (typeof tabId !== 'number') return false;
    const exp = tempAllowAllTabs.get(tabId);
    if (!exp) return false;
    if (Date.now() > exp) {
      tempAllowAllTabs.delete(tabId);
      return false;
    }
    return true;
  }

  function cleanupTab(tabId) {
    tempAllowedHosts.delete(tabId);
    tempAllowAllTabs.delete(tabId);
    interstitialAllowlist.delete(tabId);
    pendingDestinations.delete(tabId);
    if (typeof SafeClickStorage !== 'undefined') {
      SafeClickStorage.removeSessionState(tabId).catch(() => {});
      SafeClickStorage.clearPendingRedirects(tabId).catch(() => {});
    }
  }

  function cleanExpiredTempAllowed(tabId) {
    const m = tempAllowedHosts.get(tabId);
    if (!m) return;
    const now = Date.now();
    for (const [host, exp] of Array.from(m.entries())) {
      if (now > exp) m.delete(host);
    }
    if (m.size === 0) tempAllowedHosts.delete(tabId);
  }

  async function saveSession(tabId) {
    if (typeof SafeClickStorage === 'undefined' || typeof tabId !== 'number') return;
    const set = interstitialAllowlist.get(tabId);
    const allow = set ? Array.from(set) : [];
    const pending = pendingDestinations.get(tabId) || null;
    await SafeClickStorage.saveSessionState(tabId, allow, pending);
  }

  async function loadSession(tabId) {
    if (typeof SafeClickStorage === 'undefined' || typeof tabId !== 'number') return;
    const state = await SafeClickStorage.loadSessionState(tabId);
    if (state.allowlist && state.allowlist.length) {
      interstitialAllowlist.set(tabId, new Set(state.allowlist));
    }
    if (state.pending) {
      pendingDestinations.set(tabId, state.pending);
    }
  }

  async function sendMessageToTabSafe(tabId, message) {
    if (typeof chrome === 'undefined' || !chrome.tabs || typeof tabId !== 'number' || tabId < 0) return;
    try {
      await chrome.tabs.sendMessage(tabId, message).catch(() => {});
    } catch (_) {}
  }

  async function broadcastTrustScoreToAllFrames(tabId, result) {
    if (typeof chrome === 'undefined' || !chrome.tabs || typeof tabId !== 'number' || tabId < 0) return;
    try {
      if (chrome.webNavigation && chrome.webNavigation.getAllFrames) {
        const frames = await chrome.webNavigation.getAllFrames({ tabId }).catch(() => []);
        if (Array.isArray(frames) && frames.length) {
          for (const f of frames) {
            try {
              await chrome.tabs.sendMessage(tabId, { type: 'TRUST_SCORE_RESULT', data: result }, { frameId: f.frameId }).catch(() => {});
            } catch (_) {}
          }
          return;
        }
      }
      await sendMessageToTabSafe(tabId, { type: 'TRUST_SCORE_RESULT', data: result });
    } catch (_) {}
  }

  function updateIcon(tabId, verdict, score) {
    if (typeof chrome === 'undefined' || !chrome.action || typeof tabId !== 'number' || tabId < 0) return;

    let badgeText = '';
    let badgeColor = '#10B981';
    let iconName = 'safe';

    switch (verdict) {
      case 'SAFE':
        badgeText = '';
        badgeColor = '#10B981';
        iconName = 'safe';
        break;
      case 'SUSPICIOUS':
        badgeText = '!';
        badgeColor = '#F59E0B';
        iconName = 'warning';
        break;
      case 'DANGEROUS':
        badgeText = '!';
        badgeColor = '#EF4444';
        iconName = 'danger';
        break;
      case 'LOADING':
        badgeText = '...';
        badgeColor = '#6B7280';
        iconName = 'unknown';
        break;
      case 'UNKNOWN':
      default:
        badgeText = '?';
        badgeColor = '#6B7280';
        iconName = 'unknown';
        break;
    }

    try {
      chrome.action.setBadgeText({ text: badgeText, tabId });
      chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
      if (chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({
          [`tab_${tabId}`]: {
            verdict,
            color: badgeColor,
            icon: iconName,
            score: typeof score === 'number' ? score : null,
            timestamp: Date.now()
          }
        });
      }
    } catch (_) {}
  }

  async function getPageContent(tabId) {
    const fallback = { text: '', html: '', forms: [], scripts: [], links: [] };
    if (typeof chrome === 'undefined' || !chrome.scripting || typeof tabId !== 'number' || tabId < 0) {
      return fallback;
    }
    try {
      const tab = await chrome.tabs.get(tabId).catch(() => null);
      const url = tab?.url || '';
      const blockedSchemes = ['chrome://', 'edge://', 'about:', 'chrome-error://', 'moz-extension://', 'chrome-extension://'];
      if (!url.startsWith('http://') && !url.startsWith('https://')) return fallback;
      if (blockedSchemes.some(s => url.startsWith(s))) return fallback;

      const results = await chrome.scripting.executeScript({
        target: { tabId },
        func: () => {
          try {
            return {
              text: document.body ? document.body.innerText.slice(0, 5000) : '',
              forms: Array.from(document.forms).slice(0, 20).map(form => ({
                action: form.action,
                method: form.method,
                hasPassword: form.querySelector('input[type="password"]') !== null
              })),
              scripts: Array.from(document.scripts).slice(0, 50).map(s => s.src).filter(Boolean),
              links: Array.from(document.links).slice(0, 50).map(l => l.href).filter(Boolean),
              domAnalysis: (typeof window !== 'undefined' && window.DOMAnalyzer && typeof window.DOMAnalyzer.analyze === 'function')
                ? window.DOMAnalyzer.analyze(document, window.location.href)
                : null
            };
          } catch (_) {
            return { text: '', forms: [], scripts: [], links: [], domAnalysis: null };
          }
        }
      });

      const first = Array.isArray(results) && results.length ? results[0]?.result : null;
      return first || fallback;
    } catch (_) {
      return fallback;
    }
  }

  return {
    siteHistory,
    tempAllowedHosts,
    tempAllowAllTabs,
    interstitialAllowlist,
    pendingDestinations,
    markHostTempAllowed,
    isHostTempAllowed,
    markTabTempAllowAll,
    isTabTempAllowAll,
    cleanupTab,
    cleanExpiredTempAllowed,
    saveSession,
    loadSession,
    sendMessageToTabSafe,
    broadcastTrustScoreToAllFrames,
    updateIcon,
    getPageContent
  };
})();

if (typeof self !== 'undefined') {
  self.TabManager = TabManager;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = TabManager;
}
