/**
 * SafeClick 2.0 - Unified Storage Engine
 * Open Source Browser Security Engine
 * 
 * Provides centralized, consistent storage access across background,
 * popup, and content contexts with backwards-compatible schema support.
 */

const SafeClickStorage = (function () {
  'use strict';

  // Default settings
  const DEFAULT_SETTINGS = {
    protectionEnabled: true,
    scoreThreshold: 50,
    passwordStrengthEnabled: true,
    cookieAnalysisEnabled: true,
    socialEngineeringDetection: true,
    debug: false,
    cooldownEnabled: true,
    cooldownMinutes: 5,
    iframeScanEnabled: true,
    aiEnabled: false,
    aiEngine: 'chrome-ai',
    geminiApiKey: '',
    serpEnhancerEnabled: true
  };

  /**
   * Safe access to chrome.storage.local
   */
  function getLocalStorage() {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      return chrome.storage.local;
    }
    return null;
  }

  /**
   * Safe access to chrome.storage.session
   */
  function getSessionStorage() {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session) {
      return chrome.storage.session;
    }
    return null;
  }

  // ============================================================
  // SETTINGS
  // ============================================================

  async function getSettings() {
    const storage = getLocalStorage();
    if (!storage) return { ...DEFAULT_SETTINGS };
    try {
      const result = await storage.get(['settings']);
      return Object.assign({}, DEFAULT_SETTINGS, result.settings || {});
    } catch (e) {
      console.warn('[SafeClickStorage] getSettings error:', e);
      return { ...DEFAULT_SETTINGS };
    }
  }

  async function updateSettings(newSettings) {
    const storage = getLocalStorage();
    if (!storage) return { ...DEFAULT_SETTINGS, ...newSettings };
    try {
      const current = await getSettings();
      const merged = Object.assign({}, current, newSettings);
      await storage.set({ settings: merged });
      return merged;
    } catch (e) {
      console.warn('[SafeClickStorage] updateSettings error:', e);
      return null;
    }
  }

  // ============================================================
  // ALLOWLIST / WHITELIST (UNIFIED)
  // ============================================================

  /**
   * Returns all allowlisted domains (combining domainAllowlist and legacy whitelist)
   */
  async function getAllowedDomains() {
    const storage = getLocalStorage();
    if (!storage) return [];
    try {
      const result = await storage.get(['domainAllowlist', 'whitelist']);
      const combined = new Set();
      if (Array.isArray(result.domainAllowlist)) {
        result.domainAllowlist.forEach(d => {
          const s = String(d || '').toLowerCase().trim();
          if (s) combined.add(s);
        });
      }
      if (Array.isArray(result.whitelist)) {
        result.whitelist.forEach(d => {
          const s = String(d || '').toLowerCase().trim();
          if (s) combined.add(s);
        });
      }
      return Array.from(combined);
    } catch (_) {
      return [];
    }
  }

  async function addAllowedDomain(domain) {
    const storage = getLocalStorage();
    if (!storage || !domain) return [];
    try {
      const d = String(domain).toLowerCase().trim();
      if (!d) return await getAllowedDomains();

      const list = await getAllowedDomains();
      if (!list.includes(d)) {
        list.push(d);
      }
      // Write back to both keys for complete backward compatibility
      await storage.set({
        domainAllowlist: list,
        whitelist: list
      });
      return list;
    } catch (e) {
      console.warn('[SafeClickStorage] addAllowedDomain error:', e);
      return [];
    }
  }

  async function removeAllowedDomain(domain) {
    const storage = getLocalStorage();
    if (!storage || !domain) return [];
    try {
      const d = String(domain).toLowerCase().trim();
      let list = await getAllowedDomains();
      list = list.filter(item => item !== d);
      await storage.set({
        domainAllowlist: list,
        whitelist: list
      });
      return list;
    } catch (e) {
      console.warn('[SafeClickStorage] removeAllowedDomain error:', e);
      return [];
    }
  }

  async function isDomainAllowed(hostname) {
    if (!hostname) return false;
    const h = String(hostname).toLowerCase().trim();
    const list = await getAllowedDomains();
    return list.some(entry => h === entry || h.endsWith('.' + entry));
  }

  // ============================================================
  // BLOCKED SITES
  // ============================================================

  async function getBlockedSites() {
    const storage = getLocalStorage();
    if (!storage) return [];
    try {
      const result = await storage.get(['blockedSites']);
      const arr = Array.isArray(result.blockedSites) ? result.blockedSites : [];
      return arr.filter(s => typeof s === 'string' && s);
    } catch (_) {
      return [];
    }
  }

  async function setBlockedSites(list) {
    const storage = getLocalStorage();
    if (!storage) return false;
    try {
      const cleaned = Array.from(new Set((list || []).map(s => String(s || '').trim()).filter(Boolean)));
      if (cleaned.length > 500) cleaned.length = 500; // bounded cap
      await storage.set({ blockedSites: cleaned });
      return true;
    } catch (_) {
      return false;
    }
  }

  async function addBlockedSite(urlOrHost) {
    if (!urlOrHost) return [];
    const list = await getBlockedSites();
    const str = String(urlOrHost).trim();
    if (str && !list.includes(str)) {
      list.unshift(str);
      await setBlockedSites(list);
    }
    return list;
  }

  async function removeBlockedSite(urlOrHost) {
    if (!urlOrHost) return [];
    const list = await getBlockedSites();
    const str = String(urlOrHost).trim();
    const next = list.filter(item => item !== str);
    await setBlockedSites(next);
    return next;
  }

  async function isUrlBlocked(url) {
    if (!url) return false;
    const list = await getBlockedSites();
    if (!list.length) return false;

    let targetHost = '';
    try {
      targetHost = new URL(url).hostname.toLowerCase();
    } catch (_) {
      targetHost = String(url).toLowerCase().trim();
    }
    if (!targetHost) return false;

    for (const entry of list) {
      let entryHost = '';
      try {
        entryHost = new URL(entry).hostname.toLowerCase();
      } catch (_) {
        entryHost = String(entry).toLowerCase().trim();
      }
      if (entryHost && (targetHost === entryHost || targetHost.endsWith('.' + entryHost))) {
        return true;
      }
    }
    return false;
  }

  // ============================================================
  // TRUSTED PAIRS (FOR REDIRECTS)
  // ============================================================

  async function getTrustedPairs() {
    const storage = getLocalStorage();
    if (!storage) return {};
    try {
      const result = await storage.get(['trustedPairs']);
      return result && result.trustedPairs && typeof result.trustedPairs === 'object'
        ? result.trustedPairs
        : {};
    } catch (_) {
      return {};
    }
  }

  async function setTrustedPairs(obj) {
    const storage = getLocalStorage();
    if (!storage) return false;
    try {
      await storage.set({ trustedPairs: obj || {} });
      return true;
    } catch (_) {
      return false;
    }
  }

  async function addTrustedPair(fromETLD1, toETLD1) {
    if (!fromETLD1 || !toETLD1) return;
    const key = `${fromETLD1}→${toETLD1}`;
    const pairs = await getTrustedPairs();
    pairs[key] = {
      from: fromETLD1,
      to: toETLD1,
      lastUsedAt: Date.now(),
      count: ((pairs[key] && pairs[key].count) || 0) + 1
    };
    // Prune if over 300 entries
    const keys = Object.keys(pairs);
    if (keys.length > 300) {
      keys.sort((a, b) => (pairs[b].lastUsedAt || 0) - (pairs[a].lastUsedAt || 0));
      const pruned = {};
      keys.slice(0, 300).forEach(k => { pruned[k] = pairs[k]; });
      await setTrustedPairs(pruned);
      return;
    }
    await setTrustedPairs(pairs);
  }

  async function isTrustedPair(fromETLD1, toETLD1) {
    if (!fromETLD1 || !toETLD1) return false;
    const key = `${fromETLD1}→${toETLD1}`;
    const pairs = await getTrustedPairs();
    return !!pairs[key];
  }

  // ============================================================
  // SITE HISTORY
  // ============================================================

  async function getSiteHistory() {
    const storage = getLocalStorage();
    if (!storage) return [];
    try {
      const result = await storage.get(['siteHistory']);
      return Array.isArray(result.siteHistory) ? result.siteHistory : [];
    } catch (_) {
      return [];
    }
  }

  async function addSiteHistory(entry) {
    const storage = getLocalStorage();
    if (!storage || !entry) return [];
    try {
      const history = await getSiteHistory();
      history.unshift(entry);
      if (history.length > 100) history.length = 100;
      await storage.set({ siteHistory: history });
      return history;
    } catch (_) {
      return [];
    }
  }

  async function clearSiteHistory() {
    const storage = getLocalStorage();
    if (!storage) return false;
    try {
      await storage.set({ siteHistory: [] });
      return true;
    } catch (_) {
      return false;
    }
  }

  // ============================================================
  // PENDING REDIRECTS PER TAB
  // ============================================================

  async function getPendingRedirects(tabId) {
    const storage = getLocalStorage();
    if (!storage || typeof tabId !== 'number') return [];
    try {
      const key = `pending_redirects_${tabId}`;
      const res = await storage.get([key]);
      return Array.isArray(res[key]) ? res[key] : [];
    } catch (_) {
      return [];
    }
  }

  async function setPendingRedirects(tabId, list) {
    const storage = getLocalStorage();
    if (!storage || typeof tabId !== 'number') return false;
    try {
      const key = `pending_redirects_${tabId}`;
      await storage.set({ [key]: Array.isArray(list) ? list : [] });
      return true;
    } catch (_) {
      return false;
    }
  }

  async function clearPendingRedirects(tabId) {
    const storage = getLocalStorage();
    if (!storage) return false;
    try {
      if (typeof tabId === 'number') {
        await storage.remove([`pending_redirects_${tabId}`]);
      } else {
        const all = await storage.get(null);
        const keys = Object.keys(all).filter(k => k.startsWith('pending_redirects_'));
        if (keys.length) await storage.remove(keys);
      }
      return true;
    } catch (_) {
      return false;
    }
  }

  // ============================================================
  // LEARNED SHORTENERS
  // ============================================================

  async function getLearnedShorteners() {
    const storage = getLocalStorage();
    if (!storage) return [];
    try {
      const res = await storage.get(['learned_shorteners']);
      return Array.isArray(res.learned_shorteners) ? res.learned_shorteners : [];
    } catch (_) {
      return [];
    }
  }

  async function addLearnedShortener(host) {
    const storage = getLocalStorage();
    if (!storage || !host) return [];
    try {
      const list = await getLearnedShorteners();
      const h = String(host).toLowerCase().trim();
      if (h && !list.includes(h)) {
        list.push(h);
        if (list.length > 500) list.shift();
        await storage.set({ learned_shorteners: list });
      }
      return list;
    } catch (_) {
      return [];
    }
  }

  // ============================================================
  // SESSION STORAGE HELPERS (MV3 SAFE)
  // ============================================================

  async function saveSessionState(tabId, allowlistHosts, pendingItem) {
    const session = getSessionStorage();
    if (!session || typeof tabId !== 'number' || tabId < 0) return;
    try {
      const payload = {
        [`sc_tab_${tabId}_allowlist`]: Array.isArray(allowlistHosts) ? allowlistHosts : [],
        [`sc_tab_${tabId}_pending`]: pendingItem || null
      };
      await session.set(payload);
    } catch (_) {}
  }

  async function loadSessionState(tabId) {
    const session = getSessionStorage();
    if (!session || typeof tabId !== 'number' || tabId < 0) {
      return { allowlist: [], pending: null };
    }
    try {
      const aKey = `sc_tab_${tabId}_allowlist`;
      const pKey = `sc_tab_${tabId}_pending`;
      const data = await session.get([aKey, pKey]);
      return {
        allowlist: Array.isArray(data[aKey]) ? data[aKey] : [],
        pending: data[pKey] || null
      };
    } catch (_) {
      return { allowlist: [], pending: null };
    }
  }

  async function removeSessionState(tabId) {
    const session = getSessionStorage();
    if (!session || typeof tabId !== 'number' || tabId < 0) return;
    try {
      await session.remove([`sc_tab_${tabId}_allowlist`, `sc_tab_${tabId}_pending`]);
    } catch (_) {}
  }

  return {
    DEFAULT_SETTINGS,
    // Settings
    getSettings,
    updateSettings,
    // Allowlists
    getAllowedDomains,
    addAllowedDomain,
    removeAllowedDomain,
    isDomainAllowed,
    // Blocked sites
    getBlockedSites,
    setBlockedSites,
    addBlockedSite,
    removeBlockedSite,
    isUrlBlocked,
    // Trusted pairs
    getTrustedPairs,
    setTrustedPairs,
    addTrustedPair,
    isTrustedPair,
    // History
    getSiteHistory,
    addSiteHistory,
    clearSiteHistory,
    // Pending redirects
    getPendingRedirects,
    setPendingRedirects,
    clearPendingRedirects,
    // Learned shorteners
    getLearnedShorteners,
    addLearnedShortener,
    // Session state
    saveSessionState,
    loadSessionState,
    removeSessionState
  };
})();

// Export for environment
if (typeof self !== 'undefined') {
  self.SafeClickStorage = SafeClickStorage;
  // Backwards compatibility alias
  self.StorageHelpers = SafeClickStorage;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SafeClickStorage;
}
