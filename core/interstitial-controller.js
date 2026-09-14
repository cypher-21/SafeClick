/**
 * SafeClick 2.0 - Interstitial Controller
 * Open Source Browser Security Engine
 * 
 * Manages pre-navigation interposition, search bypasses,
 * user block enforcement, and interstitial user decision actions.
 */

const InterstitialController = (function () {
  'use strict';

  function normalizeHost(urlOrHost) {
    try {
      return new URL(urlOrHost).hostname.toLowerCase();
    } catch (_) {
      return String(urlOrHost || '').toLowerCase().trim();
    }
  }

  function isHttpsUrl(u) {
    try { return new URL(u).protocol === 'https:'; } catch (_) { return false; }
  }

  function isTrustedReferrer(u) {
    try {
      const h = new URL(u).hostname.toLowerCase();
      const trusted = ['google.com', 'www.google.com', 'bing.com', 'www.bing.com', 'duckduckgo.com'];
      return trusted.some(t => h === t || h.endsWith('.' + t));
    } catch (_) {
      return false;
    }
  }

  // Handle user allowing a pending redirect
  async function handleAllowRedirect(tabId, url, options = {}) {
    if (typeof tabId !== 'number' || !url) {
      return { success: false, error: 'Invalid parameters' };
    }
    const host = normalizeHost(url);

    let list = typeof RedirectTracker !== 'undefined'
      ? (RedirectTracker.pendingRedirects.get(tabId) || [])
      : [];
    if (!list.length && typeof RedirectTracker !== 'undefined') {
      list = await RedirectTracker.hydratePendingFromStorage(tabId);
    }

    const item = list.find(r => normalizeHost(r.redirectedUrl) === host && r.status !== 'allowed');
    if (item) {
      item.status = 'allowed';
      if (typeof RedirectTracker !== 'undefined') {
        RedirectTracker.pendingRedirects.set(tabId, list);
      }
      if (typeof SafeClickStorage !== 'undefined') {
        await SafeClickStorage.setPendingRedirects(tabId, list);
        try {
          const fromApex = UrlUtils.getETLD1(item.originalUrl || '');
          const toApex = UrlUtils.getETLD1(item.redirectedUrl || url);
          if (fromApex && toApex) await SafeClickStorage.addTrustedPair(fromApex, toApex);
        } catch (_) {}
      }
    }

    const tabTtl = options.durationMs || 30000;
    const hostTtl = Math.min(tabTtl, 5000);

    if (typeof TabManager !== 'undefined') {
      TabManager.markHostTempAllowed(tabId, host, hostTtl);
      TabManager.pendingDestinations.delete(tabId);
    }

    if (options.openInNewTab && typeof chrome !== 'undefined' && chrome.tabs) {
      const newTab = await chrome.tabs.create({ url });
      if (newTab?.id != null && typeof TabManager !== 'undefined') {
        TabManager.markTabTempAllowAll(newTab.id, tabTtl);
        if (host) TabManager.markHostTempAllowed(newTab.id, host, hostTtl);
      }
    } else if (typeof chrome !== 'undefined' && chrome.tabs) {
      await chrome.tabs.update(tabId, { url }).catch(() => {});
    }

    if (typeof chrome !== 'undefined' && chrome.action) {
      try {
        chrome.action.setBadgeText({ tabId, text: 'OK' });
        chrome.action.setBadgeBackgroundColor({ tabId, color: '#10B981' });
        setTimeout(() => {
          chrome.action.setBadgeText({ tabId, text: '' });
        }, 2000);
      } catch (_) {}
    }

    return { success: true };
  }

  // Handle user blocking a pending redirect
  async function handleBlockRedirect(tabId, url) {
    if (typeof tabId !== 'number' || !url) {
      return { success: false, error: 'Invalid parameters' };
    }
    const host = normalizeHost(url);

    let list = typeof RedirectTracker !== 'undefined'
      ? (RedirectTracker.pendingRedirects.get(tabId) || [])
      : [];
    if (!list.length && typeof RedirectTracker !== 'undefined') {
      list = await RedirectTracker.hydratePendingFromStorage(tabId);
    }

    const item = list.find(r => normalizeHost(r.redirectedUrl) === host && r.status === 'pending');
    if (item) {
      item.status = 'blocked';
      if (typeof RedirectTracker !== 'undefined') {
        RedirectTracker.pendingRedirects.set(tabId, list);
      }
      if (typeof SafeClickStorage !== 'undefined') {
        await SafeClickStorage.setPendingRedirects(tabId, list);
      }
    }

    if (typeof TabManager !== 'undefined') {
      TabManager.pendingDestinations.delete(tabId);
    }

    return { success: true };
  }

  // Allow continue without prior pending record
  async function handleAllowContinue(tabId, url, options = {}) {
    if (typeof tabId !== 'number' || !url) {
      return { success: false, error: 'Invalid parameters' };
    }
    const host = normalizeHost(url);
    const ttl = options.durationMs || 20000;

    if (typeof TabManager !== 'undefined') {
      if (host) TabManager.markHostTempAllowed(tabId, host, ttl);
      TabManager.pendingDestinations.delete(tabId);
    }

    if (options.openInNewTab && typeof chrome !== 'undefined' && chrome.tabs) {
      const newTab = await chrome.tabs.create({ url });
      if (newTab?.id != null && typeof TabManager !== 'undefined') {
        TabManager.markTabTempAllowAll(newTab.id, ttl);
        if (host) TabManager.markHostTempAllowed(newTab.id, host, ttl);
      }
    } else if (!options.noNavigate && typeof chrome !== 'undefined' && chrome.tabs) {
      const tab = await chrome.tabs.get(tabId).catch(() => null);
      if (tab?.url !== url) {
        await chrome.tabs.update(tabId, { url }).catch(() => {});
      }
    }

    if (!options.quiet && typeof chrome !== 'undefined' && chrome.action) {
      try {
        chrome.action.setBadgeText({ tabId, text: 'OK' });
        chrome.action.setBadgeBackgroundColor({ tabId, color: '#10B981' });
        setTimeout(() => { chrome.action.setBadgeText({ tabId, text: '' }); }, 2000);
      } catch (_) {}
    }

    return { success: true };
  }

  async function handleClearAllRedirections() {
    if (typeof RedirectTracker !== 'undefined') {
      RedirectTracker.pendingRedirects.clear();
    }
    if (typeof SafeClickStorage !== 'undefined') {
      await SafeClickStorage.clearPendingRedirects();
    }
    return { success: true };
  }

  function initNavigationListeners(getSettings, repDB, phishDB) {
    if (typeof chrome === 'undefined' || !chrome.webNavigation) return;

    // Main frame navigation hook
    if (chrome.webNavigation.onBeforeNavigate) {
      chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
        try {
          if (!details || details.frameId !== 0 || typeof details.tabId !== 'number' || details.tabId < 0) return;
          const tabId = details.tabId;
          const url = details.url || '';
          if (!url.startsWith('http://') && !url.startsWith('https://')) return;
          if (url.includes('/interstitial.html')) return;

          // Always enforce hard-block for user-blocked sites
          if (typeof SafeClickStorage !== 'undefined' && (await SafeClickStorage.isUrlBlocked(url))) {
            const extUrl = chrome.runtime.getURL(`interstitial.html?tabId=${tabId}&target=${encodeURIComponent(url)}&reason=blocked_site`);
            await chrome.tabs.update(tabId, { url: extUrl }).catch(() => {});
            return;
          }

          const settings = typeof getSettings === 'function' ? getSettings() : { protectionEnabled: true };
          if (!settings.protectionEnabled) return;

          // Search engine results page or omnibox bypass
          const isSerp = typeof RedirectTracker !== 'undefined' && (RedirectTracker.isSearchEngineResults(url) || RedirectTracker.shouldBypassForSearch(tabId));
          if (isSerp) {
            // Guardrail: check if destination itself is known malicious before bypassing
            const isMalicious = (repDB && repDB.loaded && (repDB.isListedExact(url) || (typeof repDB.isListedExactUrl === 'function' && repDB.isListedExactUrl(url)))) ||
              (phishDB && phishDB.loaded && typeof phishDB.isListedExactUrl === 'function' && phishDB.isListedExactUrl(url));
            if (!isMalicious) return;
          }

          // Allowlist or temp-allow bypass
          if (typeof TabManager !== 'undefined' && TabManager.isTabTempAllowAll(tabId)) return;
          const host = normalizeHost(url);
          if (!host) return;
          if (typeof SafeClickStorage !== 'undefined' && (await SafeClickStorage.isDomainAllowed(host))) return;
          if (typeof TabManager !== 'undefined' && TabManager.isHostTempAllowed(tabId, host)) return;

          // Fast reputation check
          const isMultiTenant = typeof UrlUtils !== 'undefined' && typeof UrlUtils.isMultiTenantPlatform === 'function'
            ? UrlUtils.isMultiTenantPlatform(host)
            : ['github.com', 'google.com', 'gitlab.com', 'dropbox.com', 'onedrive.live.com', 'discord.com'].includes(host);

          const exactHit = (repDB && repDB.loaded && typeof repDB.isListedExactUrl === 'function' && repDB.isListedExactUrl(url)) ||
            (phishDB && phishDB.loaded && typeof phishDB.isListedExactUrl === 'function' && phishDB.isListedExactUrl(url));

          const repHit = !isMultiTenant && repDB && repDB.loaded && (
            repDB.isListedExact(url) || repDB.isListedExact(host) ||
            (typeof repDB.isListedApex === 'function' && (repDB.isListedApex(url) || repDB.isListedApex(host)))
          );

          if (exactHit || repHit) {
            const extUrl = chrome.runtime.getURL(`interstitial.html?tabId=${tabId}&target=${encodeURIComponent(url)}&reason=reputation`);
            await chrome.tabs.update(tabId, { url: extUrl }).catch(() => {});
            return;
          }

          // Pending redirect or shortener triggers
          let list = typeof RedirectTracker !== 'undefined' ? (RedirectTracker.pendingRedirects.get(tabId) || []) : [];
          if (!list.length && typeof RedirectTracker !== 'undefined') {
            list = await RedirectTracker.hydratePendingFromStorage(tabId);
          }
          const pendingItem = list.find(r => r && r.status === 'pending' && normalizeHost(r.redirectedUrl) === host);
          const pd = typeof TabManager !== 'undefined' ? TabManager.pendingDestinations.get(tabId) : null;
          const pdMatches = pd && normalizeHost(pd.url) === host;
          const isShortener = typeof RedirectTracker !== 'undefined' && RedirectTracker.isLikelyShortener(url);
          const openRedirectLike = typeof RedirectTracker !== 'undefined' && RedirectTracker.hasOpenRedirectParamCrossDomain(url);

          // Auto-allow check from previous URL
          try {
            const tab = await chrome.tabs.get(tabId).catch(() => null);
            const prevUrl = tab?.url || '';
            if (prevUrl && typeof RedirectTracker !== 'undefined') {
              const auto = await RedirectTracker.shouldAutoAllowRedirect(tabId, prevUrl, url);
              if (auto.allow) return;
            }
          } catch (_) {}

          if (pendingItem || pdMatches || isShortener || openRedirectLike) {
            let reason = 'pending';
            if (isShortener) reason = 'shortener';
            else if (openRedirectLike) reason = 'open_redirect';
            else if (pdMatches) reason = 'pending_match';

            const extUrl = chrome.runtime.getURL(`interstitial.html?tabId=${tabId}&target=${encodeURIComponent(url)}&reason=${encodeURIComponent(reason)}`);
            await chrome.tabs.update(tabId, { url: extUrl }).catch(() => {});
          }
        } catch (_) {}
      });
    }

    // Created navigation target (e.g. window.open, target="_blank")
    if (chrome.webNavigation.onCreatedNavigationTarget) {
      chrome.webNavigation.onCreatedNavigationTarget.addListener(async (details) => {
        try {
          if (!details || typeof details.tabId !== 'number' || details.tabId < 0) return;
          const newTabId = details.tabId;
          const url = details.url || '';
          if (!url.startsWith('http://') && !url.startsWith('https://')) return;
          if (url.includes('/interstitial.html')) return;

          if (typeof SafeClickStorage !== 'undefined' && (await SafeClickStorage.isUrlBlocked(url))) {
            const extUrl = chrome.runtime.getURL(`interstitial.html?tabId=${newTabId}&target=${encodeURIComponent(url)}&reason=blocked_site`);
            await chrome.tabs.update(newTabId, { url: extUrl }).catch(() => {});
            return;
          }

          const settings = typeof getSettings === 'function' ? getSettings() : { protectionEnabled: true };
          if (!settings.protectionEnabled) return;

          const isSerp = typeof RedirectTracker !== 'undefined' && (RedirectTracker.isSearchEngineResults(url) || RedirectTracker.shouldBypassForSearch(newTabId));
          if (isSerp) return;

          const host = normalizeHost(url);
          if (!host) return;
          if (typeof SafeClickStorage !== 'undefined' && (await SafeClickStorage.isDomainAllowed(host))) return;
          if (typeof TabManager !== 'undefined' && (TabManager.isHostTempAllowed(newTabId, host) || TabManager.isTabTempAllowAll(newTabId))) return;

          const isTargetMultiTenant = typeof UrlUtils !== 'undefined' && typeof UrlUtils.isMultiTenantPlatform === 'function'
            ? UrlUtils.isMultiTenantPlatform(host)
            : ['github.com', 'google.com', 'gitlab.com', 'dropbox.com', 'onedrive.live.com', 'discord.com'].includes(host);

          const exactHit = (repDB && repDB.loaded && typeof repDB.isListedExactUrl === 'function' && repDB.isListedExactUrl(url)) ||
            (phishDB && phishDB.loaded && typeof phishDB.isListedExactUrl === 'function' && phishDB.isListedExactUrl(url));

          const repHit = !isTargetMultiTenant && repDB && repDB.loaded && (
            repDB.isListedExact(url) || repDB.isListedExact(host)
          );
          const looksShortener = typeof RedirectTracker !== 'undefined' && RedirectTracker.isLikelyShortener(url);
          const openRedirect = typeof RedirectTracker !== 'undefined' && RedirectTracker.hasOpenRedirectParamCrossDomain(url);

          if (exactHit || repHit || looksShortener || openRedirect) {
            const reason = (exactHit || repHit) ? 'reputation' : (looksShortener ? 'shortener' : 'open_redirect');
            if (typeof TabManager !== 'undefined') {
              TabManager.pendingDestinations.set(newTabId, { url, host, time: Date.now(), reason });
            }
            const extUrl = chrome.runtime.getURL(`interstitial.html?tabId=${newTabId}&target=${encodeURIComponent(url)}&reason=${encodeURIComponent(reason)}`);
            await chrome.tabs.update(newTabId, { url: extUrl }).catch(() => {});
          }
        } catch (_) {}
      });
    }
  }

  return {
    handleAllowRedirect,
    handleBlockRedirect,
    handleAllowContinue,
    handleClearAllRedirections,
    initNavigationListeners
  };
})();

if (typeof self !== 'undefined') {
  self.InterstitialController = InterstitialController;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = InterstitialController;
}
