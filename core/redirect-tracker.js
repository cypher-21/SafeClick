/**
 * SafeClick 2.0 - Redirect Tracker & Shortener Engine
 * Open Source Browser Security Engine
 * 
 * Tracks multi-hop redirect chains, detects suspicious open redirects
 * and shorteners, and manages pending redirect evaluation state.
 */

const RedirectTracker = (function () {
  'use strict';

  const redirectChains = new Map();     // tabId => [{ fromUrl, toUrl, statusCode, time }]
  const pendingRedirects = new Map();   // tabId => [{ originalUrl, redirectedUrl, timestamp, status, method, statusCode }]
  const learnedShorteners = new Set();  // Set of host strings
  const redirectCounts = new Map();     // host => count
  const searchBypassMap = new Map();    // tabId => expiresAt

  function normalizeHost(urlOrHost) {
    try {
      return new URL(urlOrHost).hostname.toLowerCase();
    } catch (_) {
      return String(urlOrHost || '').toLowerCase().trim();
    }
  }

  function shortPathLooksLikeToken(pathname, search) {
    try {
      const p = (pathname || '').replace(/^\/+|\/+$/g, '');
      if (!p) return false;
      const segs = p.split('/');
      if (segs.length > 2) return false;
      const last = segs[segs.length - 1];
      if (/^[a-zA-Z0-9_\-]{3,16}$/.test(last)) return true;
      if (search && search.length > 1) {
        if (/[?&](id|u|url|r|target|to)=/i.test(search)) return true;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  function isLikelyShortener(url) {
    try {
      const u = new URL(url);
      const host = u.hostname.toLowerCase();
      if (typeof UrlUtils !== 'undefined' && UrlUtils.isKnownShortener && UrlUtils.isKnownShortener(host)) {
        return true;
      }
      if (learnedShorteners.has(host)) return true;
      if (shortPathLooksLikeToken(u.pathname, u.search)) {
        const segs = u.pathname.replace(/^\/+|\/+$/g, '').split('/').filter(Boolean);
        if (segs.length <= 1) return true;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  function hasOpenRedirectParamCrossDomain(url) {
    try {
      const u = new URL(url);
      const curHost = u.hostname.toLowerCase();
      const keys = ['url', 'redirect', 'target', 'next', 'dest', 'destination', 'return', 'r'];
      for (const k of keys) {
        const val = u.searchParams.get(k);
        if (val && (val.startsWith('http://') || val.startsWith('https://'))) {
          const targetHost = new URL(val).hostname.toLowerCase();
          if (targetHost && targetHost !== curHost) {
            return true;
          }
        }
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  function isSearchEngineResults(url) {
    try {
      const u = new URL(url);
      const host = u.hostname.toLowerCase();
      const searchHosts = ['google.com', 'www.google.com', 'bing.com', 'www.bing.com', 'duckduckgo.com', 'search.yahoo.com'];
      if (!searchHosts.some(sh => host === sh || host.endsWith('.' + sh))) return false;
      const q = u.searchParams.get('q') || u.searchParams.get('query') || u.searchParams.get('p');
      return !!q;
    } catch (_) {
      return false;
    }
  }

  function markSearchBypass(tabId, windowMs = 5000) {
    if (typeof tabId !== 'number') return;
    searchBypassMap.set(tabId, Date.now() + windowMs);
  }

  function shouldBypassForSearch(tabId) {
    if (typeof tabId !== 'number') return false;
    const exp = searchBypassMap.get(tabId);
    if (!exp) return false;
    if (Date.now() > exp) {
      searchBypassMap.delete(tabId);
      return false;
    }
    return true;
  }

  async function shouldAutoAllowRedirect(tabId, fromUrl, toUrl) {
    try {
      if (!fromUrl || !toUrl) return { allow: false };
      const fromHost = normalizeHost(fromUrl);
      const toHost = normalizeHost(toUrl);

      if (fromHost && toHost && fromHost === toHost) {
        return { allow: true, reason: 'same_host' };
      }

      if (typeof UrlUtils !== 'undefined') {
        if (UrlUtils.isSameETLD1(fromUrl, toUrl)) {
          return { allow: true, reason: 'same_etld1' };
        }
        if (UrlUtils.isKnownSafeDestination(toUrl)) {
          return { allow: true, reason: 'known_safe' };
        }
        const fApex = UrlUtils.getETLD1(fromUrl);
        const tApex = UrlUtils.getETLD1(toUrl);
        if (fApex && tApex && (await SafeClickStorage.isTrustedPair(fApex, tApex))) {
          return { allow: true, reason: 'trusted_pair' };
        }
      }

      return { allow: false };
    } catch (_) {
      return { allow: false };
    }
  }

  async function hydratePendingFromStorage(tabId) {
    if (typeof SafeClickStorage === 'undefined' || typeof tabId !== 'number') return [];
    const list = await SafeClickStorage.getPendingRedirects(tabId);
    if (list && list.length) {
      pendingRedirects.set(tabId, list);
    }
    return list || [];
  }

  async function addOrUpdatePendingRedirect(tabId, fromUrl, toUrl, mode = 'server', statusCode = 0) {
    const list = pendingRedirects.get(tabId) || [];
    const ts = new Date().toISOString();
    const destHost = normalizeHost(toUrl);

    let item = list.find(r => normalizeHost(r.redirectedUrl) === destHost);
    if (item) {
      item.originalUrl = item.originalUrl || fromUrl;
      item.timestamp = ts;
      if (!item.method && mode) item.method = mode;
      if (statusCode && !item.statusCode) item.statusCode = statusCode;
    } else {
      item = {
        originalUrl: fromUrl,
        redirectedUrl: toUrl,
        timestamp: ts,
        status: 'pending',
        method: mode,
        statusCode,
        notified: false
      };
      list.unshift(item);
      if (list.length > 20) list.splice(20);
    }

    let autoAllowed = false;
    let autoAllowReason = '';

    const isAllowed = (typeof SafeClickStorage !== 'undefined' && (await SafeClickStorage.isDomainAllowed(destHost))) ||
      (typeof TabManager !== 'undefined' && (TabManager.isHostTempAllowed(tabId, destHost) || TabManager.isTabTempAllowAll(tabId)));

    if (isAllowed) {
      autoAllowed = true;
      autoAllowReason = 'pre_allowed';
    } else {
      const verdict = await shouldAutoAllowRedirect(tabId, fromUrl, toUrl);
      if (verdict && verdict.allow) {
        autoAllowed = true;
        autoAllowReason = verdict.reason || '';
      }
    }

    if (autoAllowed) {
      item.status = 'allowed';
      if (typeof TabManager !== 'undefined') {
        const ttl = 3000;
        if (destHost) TabManager.markHostTempAllowed(tabId, destHost, ttl);
        if (autoAllowReason === 'same_host') TabManager.markTabTempAllowAll(tabId, ttl);
      }
    }

    pendingRedirects.set(tabId, list);
    if (typeof SafeClickStorage !== 'undefined') {
      await SafeClickStorage.setPendingRedirects(tabId, list);
    }

    if (!autoAllowed && typeof TabManager !== 'undefined') {
      TabManager.pendingDestinations.set(tabId, { url: toUrl, host: destHost, time: Date.now() });
    }

    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      try {
        chrome.runtime.sendMessage({ type: 'REDIRECTS_UPDATED', tabId }).catch(() => {});
      } catch (_) {}
    }

    return item;
  }

  function getRecentRedirections() {
    const all = [];
    for (const [tabId, list] of pendingRedirects.entries()) {
      (list || []).forEach(r => {
        all.push({
          tabId,
          originalUrl: r.originalUrl,
          redirectedUrl: r.redirectedUrl,
          status: r.status || 'pending',
          timestamp: r.timestamp || new Date().toISOString()
        });
      });
    }
    all.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    return all.slice(0, 50);
  }

  function resetTabChains(tabId) {
    redirectChains.delete(tabId);
    searchBypassMap.delete(tabId);
  }

  function initListeners() {
    if (typeof chrome === 'undefined') return;

    // Load persisted learned shorteners
    if (typeof SafeClickStorage !== 'undefined') {
      SafeClickStorage.getLearnedShorteners().then(hosts => {
        (hosts || []).forEach(h => learnedShorteners.add(h));
      }).catch(() => {});
    }

    // WebRequest redirect listener
    if (chrome.webRequest && chrome.webRequest.onBeforeRedirect) {
      try {
        chrome.webRequest.onBeforeRedirect.addListener(
          (details) => {
            if (!details || typeof details.tabId !== 'number' || details.tabId < 0) return;
            if (details.type !== 'main_frame') return;

            const entry = {
              fromUrl: details.url || '',
              toUrl: details.redirectUrl || '',
              statusCode: details.statusCode || 0,
              time: Date.now()
            };
            const chain = redirectChains.get(details.tabId) || [];
            chain.push(entry);
            if (chain.length > 20) chain.splice(0, chain.length - 20);
            redirectChains.set(details.tabId, chain);

            // Auto-learn shortener hosts
            try {
              const fromHost = normalizeHost(entry.fromUrl);
              const toHost = normalizeHost(entry.toUrl);
              if (fromHost && toHost && fromHost !== toHost) {
                const u = new URL(entry.fromUrl);
                if (shortPathLooksLikeToken(u.pathname, u.search)) {
                  const c = (redirectCounts.get(fromHost) || 0) + 1;
                  redirectCounts.set(fromHost, c);
                  if (c >= 3 && !learnedShorteners.has(fromHost)) {
                    learnedShorteners.add(fromHost);
                    SafeClickStorage.addLearnedShortener(fromHost).catch(() => {});
                  }
                }
              }
            } catch (_) {}

            addOrUpdatePendingRedirect(details.tabId, entry.fromUrl, entry.toUrl, 'server', entry.statusCode);
          },
          { urls: ['<all_urls>'], types: ['main_frame'] }
        );
      } catch (_) {}
    }

    // WebNavigation committed server redirects & search detection
    if (chrome.webNavigation && chrome.webNavigation.onCommitted) {
      try {
        chrome.webNavigation.onCommitted.addListener((details) => {
          if (!details || typeof details.tabId !== 'number' || details.tabId < 0) return;
          const tt = details.transitionType || '';
          const isSearch = tt === 'generated' || tt === 'keyword' || tt === 'keyword_generated';
          if (isSearch || isSearchEngineResults(details.url || '')) {
            markSearchBypass(details.tabId, 5000);
          }
          if (details.transitionQualifiers && details.transitionQualifiers.includes('server_redirect')) {
            const chain = redirectChains.get(details.tabId) || [];
            chain.push({ fromUrl: '', toUrl: details.url || '', statusCode: 0, time: Date.now() });
            if (chain.length > 20) chain.splice(0, chain.length - 20);
            redirectChains.set(details.tabId, chain);
          }
        });
      } catch (_) {}
    }
  }

  return {
    redirectChains,
    pendingRedirects,
    learnedShorteners,
    normalizeHost,
    shortPathLooksLikeToken,
    isLikelyShortener,
    hasOpenRedirectParamCrossDomain,
    isSearchEngineResults,
    markSearchBypass,
    shouldBypassForSearch,
    shouldAutoAllowRedirect,
    hydratePendingFromStorage,
    addOrUpdatePendingRedirect,
    getRecentRedirections,
    resetTabChains,
    initListeners
  };
})();

if (typeof self !== 'undefined') {
  self.RedirectTracker = RedirectTracker;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = RedirectTracker;
}
