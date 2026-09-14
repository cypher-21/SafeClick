/**
 * SafeClick 2.0 - Core Orchestrator
 * Open Source Browser Security Engine
 * 
 * Central coordinator for scoring, message routing, diagnostics,
 * and service worker lifecycle management.
 */

const Orchestrator = (function () {
  'use strict';

  let trustScorer = null;
  let repDB = null;
  let phishDB = null;
  let feedManager = null;
  let aiAdvisor = null;
  let aiRegistry = null;
  let geminiProvider = null;
  let currentSettings = { protectionEnabled: true, aiEnabled: false };

  function init({ scorer, rep, phish, feeds, aiAdvisor: advisor, aiRegistry: registry, geminiAI: gemini }) {
    trustScorer = scorer;
    repDB = rep;
    phishDB = phish;
    feedManager = feeds;
    aiAdvisor = advisor || null;
    aiRegistry = registry || null;
    geminiProvider = gemini || null;

    // Load initial settings
    if (typeof SafeClickStorage !== 'undefined') {
      SafeClickStorage.getSettings().then(s => {
        currentSettings = s;
        if (geminiProvider && s.geminiApiKey) {
          geminiProvider.setApiKey(s.geminiApiKey);
        }
        if (geminiProvider && s.geminiModel) {
          geminiProvider.setModel(s.geminiModel);
        }
      }).catch(() => {});
    }

    // Register tab updates and activation
    initTabEvents();

    // Register message dispatcher
    initMessageDispatcher();

    // Register lifecycle events
    initLifecycleEvents();
  }

  function getSettings() {
    return currentSettings;
  }

  async function analyzeUrlStandalone(url) {
    if (!url || typeof url !== 'string' || (!url.startsWith('http://') && !url.startsWith('https://'))) {
      return { error: 'Not a valid URL' };
    }
    const start = Date.now();
    try {
      const result = await trustScorer.calculateTrustScore(url, '');
      const domain = new URL(url).hostname;

      if (aiAdvisor && currentSettings?.aiEnabled && result.verdict === 'SUSPICIOUS') {
        try {
          const aiOpinion = await aiAdvisor.consult({
            url,
            domain,
            verdict: result.verdict,
            score: result.score,
            indicators: result.indicators || (result.details && result.details.indicators) || [],
            preferredEngine: currentSettings?.aiEngine || null
          });
          if (aiOpinion) {
            result.details = result.details || {};
            result.details.aiOpinion = aiOpinion;
          }
        } catch (e) {
          console.warn('[Orchestrator] AI consultation failed:', e);
        }
      }

      const final = {
        score: result.score,
        verdict: result.verdict,
        reasons: Array.isArray(result.reasons) ? result.reasons.slice(0, 10) : [String(result.reason || 'Analysis complete')],
        details: Object.assign({}, result.details || {}, { timestamp: Date.now(), analyzedMs: Date.now() - start })
      };
      if (typeof TabManager !== 'undefined') {
        TabManager.siteHistory.set(url, final);
      }
      return final;
    } catch (e) {
      return { error: 'Failed to analyze URL: ' + e.message };
    }
  }

  async function analyzeTab(tabId, url) {
    if (!url || !url.startsWith('http')) return;
    const domain = new URL(url).hostname;

    if (typeof TabManager !== 'undefined') {
      await TabManager.loadSession(tabId);
    }

    // Check allowlist
    const isAllowed = typeof SafeClickStorage !== 'undefined' && (await SafeClickStorage.isDomainAllowed(domain));
    if (isAllowed) {
      const now = Date.now();
      const result = {
        score: 100,
        verdict: 'SAFE',
        reasons: ['[OK] Domain is in your Allowlist'],
        details: {
          domain,
          timestamp: now,
          detailedInfo: {
            heuristic: { disabled: true },
            phishTank: { listed: false, reason: '[OK] No Phishing Detected' },
            redirects: { count: 0, hops: [], uniqueDomains: [] }
          }
        }
      };
      if (typeof TabManager !== 'undefined') {
        TabManager.siteHistory.set(url, { ...result, timestamp: now });
        TabManager.updateIcon(tabId, result.verdict, result.score);
        await TabManager.broadcastTrustScoreToAllFrames(tabId, result);
      }
      if (typeof SafeClickStorage !== 'undefined') {
        await SafeClickStorage.addSiteHistory({
          url,
          domain,
          score: result.score,
          verdict: result.verdict,
          timestamp: now,
          reasons: result.reasons
        });
      }
      return;
    }

    // Check cache (5 min validity)
    if (typeof TabManager !== 'undefined') {
      const cached = TabManager.siteHistory.get(url);
      if (cached && Date.now() - cached.timestamp < 300000) {
        TabManager.updateIcon(tabId, cached.verdict, cached.score);
        return;
      }
    }

    try {
      if (typeof TabManager !== 'undefined') {
        TabManager.updateIcon(tabId, 'LOADING');
      }

      // Early reputation exact-URL hard-hit (ONLY exact URL, never host-level)
      const repExactUrl = repDB && repDB.loaded && typeof repDB.isListedExactUrl === 'function' && repDB.isListedExactUrl(url);
      const ptExactUrl = phishDB && phishDB.loaded && typeof phishDB.isListedExactUrl === 'function' && phishDB.isListedExactUrl(url);

      if (repExactUrl || ptExactUrl) {
        const result = {
          score: 0,
          verdict: 'DANGEROUS',
          reasons: [repExactUrl ? '[X] URL listed in Local Threat Intelligence' : '[X] Exact URL confirmed as phishing in PhishTank'],
          criticalFailures: 1,
          details: {
            domain,
            url,
            timestamp: new Date().toISOString(),
            detailedInfo: { reputation: { exactUrlListed: !!repExactUrl }, phishTank: { exactUrlListed: !!ptExactUrl } },
            redirects: { count: 0, hops: [], uniqueDomains: [] }
          }
        };
        if (typeof TabManager !== 'undefined') {
          TabManager.siteHistory.set(url, { ...result, timestamp: Date.now() });
          TabManager.updateIcon(tabId, result.verdict, result.score);
          await TabManager.broadcastTrustScoreToAllFrames(tabId, result);
        }
        if (typeof SafeClickStorage !== 'undefined') {
          await SafeClickStorage.addSiteHistory({
            url,
            domain,
            score: result.score,
            verdict: result.verdict,
            timestamp: Date.now(),
            reasons: result.reasons
          });
        }
        return;
      }

      const content = typeof TabManager !== 'undefined' ? await TabManager.getPageContent(tabId) : { text: '', domAnalysis: null };

      // Redirect info
      let redirectInfo = { count: 0, uniqueDomains: [], maxHops: 0 };
      if (typeof RedirectTracker !== 'undefined') {
        const chain = RedirectTracker.redirectChains.get(tabId) || [];
        const domains = new Set();
        chain.forEach(e => {
          try { domains.add(new URL(e.fromUrl).hostname); } catch (_) {}
          try { domains.add(new URL(e.toUrl).hostname); } catch (_) {}
        });
        redirectInfo = {
          count: chain.length,
          uniqueDomains: Array.from(domains),
          maxHops: chain.length
        };
      }

      const result = await trustScorer.calculateTrustScore(url, content.text || '', redirectInfo, content.domAnalysis);

      // Advisory AI consultation on SUSPICIOUS verdicts
      if (aiAdvisor && currentSettings?.aiEnabled && result.verdict === 'SUSPICIOUS') {
        try {
          const aiOpinion = await aiAdvisor.consult({
            url,
            domain,
            verdict: result.verdict,
            score: result.score,
            indicators: result.indicators || (result.details && result.details.indicators) || []
          });
          if (aiOpinion) {
            result.details = result.details || {};
            result.details.aiOpinion = aiOpinion;
          }
        } catch (e) {
          console.warn('[Orchestrator] AI consultation failed:', e);
        }
      }

      if (typeof TabManager !== 'undefined') {
        TabManager.siteHistory.set(url, { ...result, timestamp: Date.now() });
        TabManager.updateIcon(tabId, result.verdict, result.score);
        await TabManager.broadcastTrustScoreToAllFrames(tabId, result);
      }
      if (typeof SafeClickStorage !== 'undefined') {
        await SafeClickStorage.addSiteHistory({
          url,
          domain,
          score: result.score,
          verdict: result.verdict,
          timestamp: Date.now(),
          reasons: (result.reasons || []).slice(0, 3)
        });
      }
    } catch (e) {
      console.warn('[Orchestrator] Tab analysis error:', e);
      if (typeof TabManager !== 'undefined') {
        TabManager.updateIcon(tabId, 'UNKNOWN');
      }
    }
  }

  function initTabEvents() {
    if (typeof chrome === 'undefined' || !chrome.tabs) return;

    chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
      if (changeInfo.status === 'loading') {
        if (typeof RedirectTracker !== 'undefined') RedirectTracker.resetTabChains(tabId);
        if (typeof TabManager !== 'undefined') {
          TabManager.pendingDestinations.delete(tabId);
          TabManager.cleanExpiredTempAllowed(tabId);
          await TabManager.saveSession(tabId);
        }
      }
      if (changeInfo.status === 'complete' && tab?.url && tab.url.startsWith('http')) {
        await analyzeTab(tabId, tab.url);
      }
    });

    chrome.tabs.onActivated.addListener(async (activeInfo) => {
      try {
        const tab = await chrome.tabs.get(activeInfo.tabId).catch(() => null);
        if (tab?.url && tab.url.startsWith('http')) {
          await analyzeTab(activeInfo.tabId, tab.url);
        }
      } catch (_) {}
    });

    chrome.tabs.onRemoved.addListener((tabId) => {
      if (typeof TabManager !== 'undefined') TabManager.cleanupTab(tabId);
      if (typeof RedirectTracker !== 'undefined') RedirectTracker.resetTabChains(tabId);
    });
  }

  function initMessageDispatcher() {
    if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.onMessage) return;

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      (async () => {
        try {
          const tabId = message.tabId || sender.tab?.id;
          switch (message.type) {
            case 'GET_TRUST_SCORE': {
              const url = message.url || sender.tab?.url;
              if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
                const cached = TabManager.siteHistory.get(url);
                if (cached) {
                  sendResponse(cached);
                  return;
                }
                const res = await analyzeUrlStandalone(url);
                sendResponse(res);
                return;
              }
              if (tabId) {
                const tab = await chrome.tabs.get(tabId).catch(() => null);
                if (tab?.url) {
                  await analyzeTab(tabId, tab.url);
                  sendResponse(TabManager.siteHistory.get(tab.url) || { error: 'Analysis incomplete' });
                  return;
                }
              }
              sendResponse({ error: 'Invalid URL or tab' });
              break;
            }
            case 'RESCAN_SITE': {
              if (tabId) {
                const tab = await chrome.tabs.get(tabId).catch(() => null);
                if (tab?.url) {
                  TabManager.siteHistory.delete(tab.url);
                  await analyzeTab(tabId, tab.url);
                  sendResponse(TabManager.siteHistory.get(tab.url) || { success: true });
                  return;
                }
              }
              sendResponse({ error: 'Tab not found' });
              break;
            }
            case 'ADD_TO_WHITELIST':
            case 'ADD_DOMAIN_TO_ALLOWLIST': {
              const domain = message.domain;
              if (domain && typeof SafeClickStorage !== 'undefined') {
                const list = await SafeClickStorage.addAllowedDomain(domain);
                sendResponse({ success: true, domains: list, whitelist: list });
              } else {
                sendResponse({ success: false, error: 'Missing domain' });
              }
              break;
            }
            case 'REMOVE_FROM_WHITELIST':
            case 'REMOVE_DOMAIN_FROM_ALLOWLIST': {
              const domain = message.domain;
              if (domain && typeof SafeClickStorage !== 'undefined') {
                const list = await SafeClickStorage.removeAllowedDomain(domain);
                sendResponse({ success: true, domains: list, whitelist: list });
              } else {
                sendResponse({ success: false, error: 'Missing domain' });
              }
              break;
            }
            case 'GET_DOMAIN_ALLOWLIST':
            case 'GET_WHITELIST': {
              const domains = typeof SafeClickStorage !== 'undefined' ? await SafeClickStorage.getAllowedDomains() : [];
              sendResponse({ domains, whitelist: domains });
              break;
            }
            case 'GET_BLOCKED_SITES': {
              const sites = typeof SafeClickStorage !== 'undefined' ? await SafeClickStorage.getBlockedSites() : [];
              sendResponse({ sites });
              break;
            }
            case 'ADD_BLOCKED_SITE': {
              const url = message.url || '';
              if (typeof SafeClickStorage !== 'undefined') {
                const sites = await SafeClickStorage.addBlockedSite(url);
                sendResponse({ success: true, sites });
              } else {
                sendResponse({ success: false });
              }
              break;
            }
            case 'REMOVE_BLOCKED_SITE': {
              const url = message.url || '';
              if (typeof SafeClickStorage !== 'undefined') {
                const sites = await SafeClickStorage.removeBlockedSite(url);
                sendResponse({ success: true, sites });
              } else {
                sendResponse({ success: false });
              }
              break;
            }
            case 'REMOVE_BLOCKED_BY_HOST': {
              const host = String(message.host || '').toLowerCase();
              if (typeof SafeClickStorage !== 'undefined' && host) {
                const list = await SafeClickStorage.getBlockedSites();
                const next = list.filter(item => {
                  try {
                    const h = new URL(item).hostname.toLowerCase();
                    return h !== host && !host.endsWith('.' + h);
                  } catch (_) {
                    return item !== host && !host.endsWith('.' + item);
                  }
                });
                await SafeClickStorage.setBlockedSites(next);
                sendResponse({ success: true, sites: next });
              } else {
                sendResponse({ success: false, error: 'Invalid host' });
              }
              break;
            }
            case 'GET_PENDING_REDIRECTS': {
              let list = typeof RedirectTracker !== 'undefined' ? (RedirectTracker.pendingRedirects.get(tabId) || []) : [];
              if (!list.length && typeof RedirectTracker !== 'undefined') {
                list = await RedirectTracker.hydratePendingFromStorage(tabId);
              }
              sendResponse({ redirects: list });
              break;
            }
            case 'CLIENT_REDIRECT_DETECTED': {
              if (typeof RedirectTracker !== 'undefined') {
                await RedirectTracker.addOrUpdatePendingRedirect(tabId, message.fromUrl, message.toUrl, message.method, 0);
              }
              sendResponse({ success: true });
              break;
            }
            case 'GET_RECENT_REDIRECTIONS': {
              const list = typeof RedirectTracker !== 'undefined' ? RedirectTracker.getRecentRedirections() : [];
              sendResponse({ redirections: list });
              break;
            }
            case 'ALLOW_REDIRECT': {
              const res = typeof InterstitialController !== 'undefined'
                ? await InterstitialController.handleAllowRedirect(tabId, message.url, message)
                : { success: false };
              sendResponse(res);
              break;
            }
            case 'BLOCK_REDIRECT': {
              const res = typeof InterstitialController !== 'undefined'
                ? await InterstitialController.handleBlockRedirect(tabId, message.url)
                : { success: false };
              sendResponse(res);
              break;
            }
            case 'ALLOW_CONTINUE': {
              const res = typeof InterstitialController !== 'undefined'
                ? await InterstitialController.handleAllowContinue(tabId, message.url, message)
                : { success: false };
              sendResponse(res);
              break;
            }
            case 'CLEAR_ALL_REDIRECTIONS': {
              const res = typeof InterstitialController !== 'undefined'
                ? await InterstitialController.handleClearAllRedirections()
                : { success: false };
              sendResponse(res);
              break;
            }
            case 'ANALYZE_SERP_LINK':
            case 'ANALYZE_URL': {
              const targetUrl = message.url;
              if (!targetUrl) {
                sendResponse({ success: false, error: 'No URL provided' });
                break;
              }
              try {
                const analysis = await analyzeUrlStandalone(targetUrl);
                sendResponse({ success: true, result: analysis });
              } catch (err) {
                sendResponse({ success: false, error: err.message });
              }
              break;
            }
            case 'REPDB_STATUS': {
              const url = message.url || sender.tab?.url || '';
              const listed = repDB && repDB.loaded ? (
                (typeof repDB.isListedExactUrl === 'function' && repDB.isListedExactUrl(url)) ||
                repDB.isListedExact(url) ||
                (typeof repDB.isListedApex === 'function' && repDB.isListedApex(url))
              ) : false;
              const count = repDB ? ((repDB.set?.size || 0) + (repDB.exact?.size || 0) + (repDB.urlsExact?.size || 0)) : 0;
              sendResponse({ data: { listed, count, updatedAt: repDB?.updatedAt || 0, loaded: !!repDB?.loaded } });
              break;
            }
            case 'GET_SITE_HISTORY': {
              const history = typeof SafeClickStorage !== 'undefined' ? await SafeClickStorage.getSiteHistory() : [];
              sendResponse({ history });
              break;
            }
            case 'CLEAR_HISTORY': {
              if (typeof SafeClickStorage !== 'undefined') await SafeClickStorage.clearSiteHistory();
              sendResponse({ success: true });
              break;
            }
            case 'EXPORT_HISTORY': {
              const history = typeof SafeClickStorage !== 'undefined' ? await SafeClickStorage.getSiteHistory() : [];
              const csvContent = [
                'URL,Domain,Score,Verdict,Timestamp,Reasons',
                ...history.map(e => `"${e.url}","${e.domain}",${e.score},"${e.verdict}","${e.timestamp}","${(e.reasons || []).join('; ')}"`)
              ].join('\n');
              sendResponse({ csvContent });
              break;
            }
            case 'GET_SETTINGS': {
              const settings = typeof SafeClickStorage !== 'undefined' ? await SafeClickStorage.getSettings() : currentSettings;
              sendResponse({ settings });
              break;
            }
            case 'UPDATE_SETTINGS': {
              if (typeof SafeClickStorage !== 'undefined') {
                currentSettings = await SafeClickStorage.updateSettings(message.settings || {});
              }
              if (geminiProvider && currentSettings?.geminiApiKey !== undefined) {
                geminiProvider.setApiKey(currentSettings.geminiApiKey);
              }
              if (geminiProvider && currentSettings?.geminiModel !== undefined) {
                geminiProvider.setModel(currentSettings.geminiModel);
              }
              sendResponse({ success: true, settings: currentSettings });
              break;
            }
            case 'TEST_GEMINI_KEY': {
              const key = message.key || currentSettings?.geminiApiKey;
              const model = message.model || currentSettings?.geminiModel;
              if (geminiProvider) {
                try {
                  const testRes = await geminiProvider.testConnection(key, model);
                  sendResponse({ success: true, result: testRes });
                } catch (err) {
                  sendResponse({ success: false, error: err.message });
                }
              } else {
                sendResponse({ success: false, error: 'Gemini provider not initialized' });
              }
              break;
            }
            case 'LIST_GEMINI_MODELS': {
              const key = message.key || currentSettings?.geminiApiKey;
              if (geminiProvider) {
                try {
                  const models = await geminiProvider.listAvailableModels(key);
                  sendResponse({ success: true, models });
                } catch (err) {
                  sendResponse({ success: false, error: err.message });
                }
              } else {
                sendResponse({ success: false, error: 'Gemini provider not initialized' });
              }
              break;
            }
            case 'CHECK_CHROME_AI_STATUS': {
              const chromeAI = aiRegistry ? aiRegistry.getProvider('chrome-builtin-ai') : null;
              if (chromeAI) {
                try {
                  const status = await chromeAI.checkAvailability();
                  sendResponse({ success: true, status });
                } catch (err) {
                  sendResponse({ success: false, error: err.message });
                }
              } else {
                sendResponse({ success: false, error: 'Chrome AI provider not registered' });
              }
              break;
            }
            case 'REQUEST_AI_OPINION': {
              const url = message.url;
              const domain = message.domain || (url ? new URL(url).hostname : '');
              const verdict = message.verdict;
              const score = message.score;
              const indicators = message.indicators || [];
              if (aiAdvisor) {
                try {
                  const opinion = await aiAdvisor.consult({
                    url,
                    domain,
                    verdict,
                    score,
                    indicators,
                    force: true
                  });
                  sendResponse({ success: !!opinion, opinion });
                } catch (err) {
                  sendResponse({ success: false, error: err.message });
                }
              } else {
                sendResponse({ success: false, error: 'AI Advisor not available' });
              }
              break;
            }
            case 'ASK_SAFECLICK_AI': {
              const query = message.query;
              const url = message.url;
              let domain = message.domain;
              if (!domain && url) {
                try { domain = new URL(url).hostname; } catch (_) { domain = ''; }
              }
              const context = {
                url,
                domain,
                verdict: message.verdict || 'UNKNOWN',
                score: typeof message.score === 'number' ? message.score : 50,
                indicators: message.indicators || [],
                reasons: message.reasons || [],
                details: message.details || {},
                preferredEngine: currentSettings?.aiEngine || null
              };

              // Enrich context from cached site history if present
              if (typeof TabManager !== 'undefined' && TabManager.siteHistory && url) {
                const cached = TabManager.siteHistory.get(url);
                if (cached) {
                  if (!context.indicators || context.indicators.length === 0) {
                    context.indicators = cached.indicators || (cached.details && cached.details.indicators) || [];
                  }
                  if (!context.reasons || context.reasons.length === 0) {
                    context.reasons = cached.reasons || [];
                  }
                  if (!context.details || Object.keys(context.details).length === 0) {
                    context.details = cached.details || {};
                  }
                  if (cached.score) context.score = cached.score;
                  if (cached.verdict) context.verdict = cached.verdict;
                }
              }

              if (aiAdvisor) {
                try {
                  const result = await aiAdvisor.chat(query, context);
                  sendResponse({ success: true, result });
                } catch (err) {
                  sendResponse({ success: false, error: err.message });
                }
              } else {
                sendResponse({ success: false, error: 'AI Advisor subsystem not initialized' });
              }
              break;
            }
            case 'ANALYZE_SOCIAL_ENGINEERING': {
              const snippets = message.snippets || [];
              let domain = message.domain;
              if (!domain && message.url) {
                try { domain = new URL(message.url).hostname; } catch (_) { domain = ''; }
              }
              if (aiAdvisor) {
                try {
                  const analysis = await aiAdvisor.analyzeSocialEngineering(snippets, domain);
                  sendResponse({ success: !!analysis, analysis });
                } catch (err) {
                  sendResponse({ success: false, error: err.message });
                }
              } else {
                sendResponse({ success: false, error: 'AI Advisor subsystem not initialized' });
              }
              break;
            }
            case 'GENERATE_IOC_REPORT': {
              let domain = message.domain;
              if (!domain && message.url) {
                try { domain = new URL(message.url).hostname; } catch (_) { domain = ''; }
              }
              const context = {
                url: message.url,
                domain,
                verdict: message.verdict,
                score: message.score,
                indicators: message.indicators || []
              };
              if (aiAdvisor) {
                const report = aiAdvisor.generateIoCReport(context);
                sendResponse({ success: true, report });
              } else {
                sendResponse({ success: false, error: 'AI Advisor subsystem not initialized' });
              }
              break;
            }
            case 'GET_CACHE_STATS': {
              sendResponse({
                stats: {
                  siteHistory: TabManager ? TabManager.siteHistory.size : 0,
                  trustScorer: trustScorer?.analysisStats || {}
                }
              });
              break;
            }
            case 'CLEAR_CACHE': {
              if (typeof TabManager !== 'undefined') TabManager.siteHistory.clear();
              if (trustScorer?.clearCache) trustScorer.clearCache();
              sendResponse({ success: true });
              break;
            }
            case 'GET_DIAGNOSTICS': {
              sendResponse({
                success: true,
                diagnostics: {
                  timestamp: new Date().toISOString(),
                  version: chrome.runtime.getManifest().version,
                  protection: currentSettings.protectionEnabled,
                  reputationDB: repDB?.getStats?.() || null,
                  feedManager: feedManager?.getStats?.() || null,
                  trustScorer: trustScorer?.getCacheStats?.() || null,
                  phishDB: phishDB ? { loaded: phishDB.loaded, size: phishDB.urls?.size || 0 } : null,
                  memory: {
                    pendingRedirects: RedirectTracker ? RedirectTracker.pendingRedirects.size : 0,
                    redirectChains: RedirectTracker ? RedirectTracker.redirectChains.size : 0,
                    siteHistory: TabManager ? TabManager.siteHistory.size : 0
                  }
                }
              });
              break;
            }
            default:
              sendResponse({ error: 'Unknown message type: ' + message.type });
          }
        } catch (err) {
          sendResponse({ error: 'Internal orchestrator error: ' + err.message });
        }
      })();
      return true; // Keep async channel open
    });
  }

  function initLifecycleEvents() {
    if (typeof chrome === 'undefined' || !chrome.runtime) return;

    chrome.runtime.onInstalled.addListener(async (details) => {
      console.log('[SafeClick] Extension installed/updated:', details.reason);
      if (details.reason === 'install') {
        try {
          const res = await chrome.storage.local.get(['onboardingShownOnce']);
          if (!res.onboardingShownOnce) {
            const url = chrome.runtime.getURL('onboarding.html');
            await chrome.tabs.create({ url }).catch(() => {});
            await chrome.storage.local.set({ onboardingShownOnce: true });
          }
        } catch (_) {}
      }
    });
  }

  return {
    init,
    getSettings,
    analyzeTab,
    analyzeUrlStandalone
  };
})();

if (typeof self !== 'undefined') {
  self.Orchestrator = Orchestrator;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = Orchestrator;
}
