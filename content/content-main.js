/**
 * SafeClick 2.0 - Content Script Main Coordinator
 * Open Source Browser Security Engine
 * 
 * Coordinates trust scoring requests, client redirect observation,
 * privacy heuristics, and in-page modal display.
 */

(function () {
  'use strict';

  let currentTrustScore = null;
  let protectionEnabled = true;
  let autoModalEvaluated = false;
  let scoreRetryTimer = null;
  let scoreRetryAttempts = 0;
  const MAX_SCORE_RETRIES = 5;

  let settings = {
    protectionEnabled: true,
    scoreThreshold: 50,
    passwordStrengthEnabled: true,
    cookieAnalysisEnabled: true,
    socialEngineeringDetection: true,
    debug: false,
    cooldownEnabled: true,
    cooldownMinutes: 5,
    iframeScanEnabled: true
  };

  let cachedDomainAllowlist = [];
  let cachedWhitelist = [];
  const lastShownByPath = new Map();

  function scDebug(...args) {
    if (settings.debug) {
      console.log('[SafeClick Content]', ...args);
    }
  }

  function debounce(fn, wait = 250) {
    let t;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), wait);
    };
  }

  function getPathKey() {
    return `${window.location.origin}${window.location.pathname}`;
  }

  function withinCooldown() {
    if (!settings.cooldownEnabled) return false;
    const key = getPathKey();
    const last = lastShownByPath.get(key) || 0;
    const cooldownMs = (settings.cooldownMinutes || 5) * 60 * 1000;
    return Date.now() - last < cooldownMs;
  }

  function markShownNow() {
    try { lastShownByPath.set(getPathKey(), Date.now()); } catch (_) {}
  }

  function loadAllowlistsCache() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['domainAllowlist', 'whitelist'], (res) => {
          cachedDomainAllowlist = Array.isArray(res?.domainAllowlist) ? res.domainAllowlist : [];
          cachedWhitelist = Array.isArray(res?.whitelist) ? res.whitelist : [];
        });
      }
    } catch (_) {}
  }

  function hostMatchesAllowlist(host, list) {
    const h = String(host || '').toLowerCase();
    if (!h) return false;
    return (list || []).some(entry => {
      const d = String(entry || '').toLowerCase();
      return d && (h === d || h.endsWith('.' + d));
    });
  }

  function isCurrentDomainWhitelisted() {
    const host = window.location.hostname;
    return hostMatchesAllowlist(host, cachedDomainAllowlist) || hostMatchesAllowlist(host, cachedWhitelist);
  }

  function isPrivateIPv4(host) {
    try {
      const parts = host.split('.').map(n => parseInt(n, 10));
      if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return false;
      if (parts[0] === 10) return true;
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
      if (parts[0] === 192 && parts[1] === 168) return true;
      if (parts[0] === 127) return true;
      return false;
    } catch (_) { return false; }
  }

  function isLocalDevHost(hostname) {
    const h = String(hostname || '').toLowerCase();
    if (!h) return false;
    if (h === 'localhost' || h.endsWith('.localhost') || h === '::1') return true;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(h) && isPrivateIPv4(h)) return true;
    if (h.endsWith('.local') || h.endsWith('.test') || h.endsWith('.invalid') || h.endsWith('.internal') || h.endsWith('.lan')) return true;
    return false;
  }

  function isAllowedOrSuppressed() {
    return SafeClickModalUI.isSuppressedNow() || isCurrentDomainWhitelisted() || isLocalDevHost(window.location.hostname);
  }

  // Auto-show warning modal for risky sites even without form interaction
  function maybeAutoShowSiteModal() {
    if (autoModalEvaluated || SafeClickModalUI.isModalShown()) return;
    if (SafeClickModalUI.justDismissedModal()) return;
    autoModalEvaluated = true;

    if (isAllowedOrSuppressed()) return;
    const score = currentTrustScore;
    if (!score) return;

    const ptListed = !!(score.details?.detailedInfo?.phishTank?.exactUrlListed === true);
    const rep = score.details?.detailedInfo?.reputation;
    const repListed = !!(rep && (rep.exactUrlListed || rep.exactHostListed || rep.apexListed));
    const riskyVerdict = (score.verdict === 'DANGEROUS') || (score.verdict === 'SUSPICIOUS' && score.score < settings.scoreThreshold);

    let repdbFlag = false;
    try {
      const reasons = Array.isArray(score.reasons) ? score.reasons.join(' ').toLowerCase() : '';
      repdbFlag = /reputationdb|reputation-db|listed in reputation/.test(reasons);
    } catch (_) {}

    if ((ptListed || repListed || repdbFlag || riskyVerdict) && !withinCooldown()) {
      scDebug('maybeAutoShowSiteModal triggered');
      triggerWarningModal();
    }
  }

  function triggerWarningModal() {
    SafeClickModalUI.showWarningModal(currentTrustScore, settings, {
      onShown: markShownNow,
      onWhitelistAdded: (list) => { if (list) cachedWhitelist = list; },
      onAllowlistAdded: (list) => { if (list) cachedDomainAllowlist = list; },
      summarizeFormSecurityRisks: SafeClickCredentialMonitor.summarizeFormSecurityRisks
    });
  }

  // Scan for sensitive fields and enforce gating
  function checkForSensitiveFields() {
    if (!protectionEnabled) return;
    if (isAllowedOrSuppressed() || SafeClickModalUI.justDismissedModal()) return;

    const sensitive = SafeClickCredentialMonitor.findSensitiveFields();
    if (sensitive.all.length > 0) {
      // Hard gate: HTTP + password inputs
      if (window.location.protocol === 'http:' && sensitive.passwords.length > 0 && !withinCooldown()) {
        scDebug('HTTP hard-gate triggered on password fields');
        triggerWarningModal();
        scheduleScoreRetryIfNeeded('http-hard-gate');
        return;
      }

      if (!currentTrustScore) {
        scheduleScoreRetryIfNeeded('sensitive-detected');
        return;
      }

      const shouldWarn = currentTrustScore.verdict === 'DANGEROUS' ||
        (currentTrustScore.verdict === 'SUSPICIOUS' && currentTrustScore.score < settings.scoreThreshold);

      if (shouldWarn && !withinCooldown()) {
        triggerWarningModal();
      }

      if (settings.passwordStrengthEnabled) {
        SafeClickCredentialMonitor.addPasswordStrengthCheckers(sensitive.passwords);
      }

      if (settings.cookieAnalysisEnabled) {
        analyzeCookiesAndPrivacy();
      }
    }
  }

  function analyzeCookiesAndPrivacy() {
    try {
      const cookies = document.cookie.split(';').filter(c => c.trim());
      const trackingPatterns = ['_ga', '_gid', '_fbp', '_fbc', 'utm_', '__utma', '__utmb', '__utmc', '__utmz'];
      let trackingCount = 0;
      cookies.forEach(cookie => {
        const name = cookie.split('=')[0].trim();
        if (trackingPatterns.some(p => name.includes(p))) trackingCount++;
      });
      if (trackingCount > 5 && currentTrustScore?.verdict !== 'SAFE') {
        SafeClickModalUI.showPrivacyWarning(trackingCount);
      }
    } catch (_) {}
  }

  function detectSocialEngineeringAttempts() {
    try {
      const content = document.body ? document.body.textContent.toLowerCase() : '';
      const socialTactics = [];

      const urgencyWords = ['urgent', 'immediate', 'expires today', 'act now', 'limited time'];
      if (urgencyWords.filter(w => content.includes(w)).length > 2) socialTactics.push('urgency pressure');

      const authorityWords = ['government', 'irs', 'fbi', 'police', 'official'];
      if (authorityWords.filter(w => content.includes(w)).length > 1) socialTactics.push('authority claims');

      const fearWords = ['suspended', 'terminated', 'blocked', 'frozen', 'restricted'];
      if (fearWords.filter(w => content.includes(w)).length > 1) socialTactics.push('fear tactics');

      if (socialTactics.length > 0 && currentTrustScore?.verdict !== 'SAFE') {
        SafeClickModalUI.showSocialEngineeringWarning(socialTactics);
      }
    } catch (_) {}
  }

  function initializePrivacyMonitoring() {
    try {
      const iframes = document.querySelectorAll('iframe');
      const pageHost = window.location.hostname;
      let externalFrames = 0;
      iframes.forEach(f => {
        try {
          if (f.src && new URL(f.src).hostname !== pageHost) externalFrames++;
        } catch (_) {}
      });
      if (externalFrames > 3 && currentTrustScore?.verdict !== 'SAFE') {
        SafeClickModalUI.showNotification(`Privacy Notice: ${externalFrames} third-party frames detected`, 'info', 5000);
      }
    } catch (_) {}
  }

  function setupDataBreachAlerts() {
    const domain = window.location.hostname;
    const knownBreachedDomains = ['equifax.com', 'yahoo.com', 'marriott.com'];
    if (knownBreachedDomains.includes(domain)) {
      SafeClickModalUI.showNotification('Notice: This domain has historical data breach disclosures', 'info', 6000);
    }
  }

  // Communication with background
  function computeMessageUrl() {
    try {
      const here = (typeof location !== 'undefined' && location.href) ? location.href : '';
      const ref = (typeof document !== 'undefined' && document.referrer) ? document.referrer : '';
      if (here && (here.startsWith('http://') || here.startsWith('https://'))) return here;
      if (ref && (ref.startsWith('http://') || ref.startsWith('https://'))) return ref;
    } catch (_) {}
    return undefined;
  }

  function requestTrustScore() {
    const msgUrl = computeMessageUrl();
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ type: 'GET_TRUST_SCORE', url: msgUrl }, (response) => {
          if (response && !response.error && typeof response.score === 'number') {
            currentTrustScore = response;
            scoreRetryAttempts = 0;
            if (scoreRetryTimer) { clearTimeout(scoreRetryTimer); scoreRetryTimer = null; }
            SafeClickModalUI.refreshWarningModal(currentTrustScore, settings, SafeClickCredentialMonitor.summarizeFormSecurityRisks);
            checkForSensitiveFields();
            SafeClickCredentialMonitor.addVisualIndicators(currentTrustScore, isAllowedOrSuppressed());
            maybeAutoShowSiteModal();
            SafeClickCredentialMonitor.monitorForms();
            if (settings.cookieAnalysisEnabled) analyzeCookiesAndPrivacy();
            if (settings.socialEngineeringDetection) detectSocialEngineeringAttempts();
          } else {
            scheduleScoreRetryIfNeeded('request-failed');
          }
        });
      }
    } catch (_) {
      scheduleScoreRetryIfNeeded('request-throw');
    }
  }

  function scheduleScoreRetryIfNeeded(reason) {
    if (scoreRetryAttempts >= MAX_SCORE_RETRIES) return;
    if (scoreRetryTimer) return;
    const delay = Math.min(4000, 250 * Math.pow(2, scoreRetryAttempts));
    scoreRetryAttempts++;
    scoreRetryTimer = setTimeout(() => {
      scoreRetryTimer = null;
      requestTrustScore();
    }, delay);
  }

  // Listen for messages from background
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((message) => {
      if (message.type === 'TRUST_SCORE_RESULT') {
        currentTrustScore = message.data;
        scoreRetryAttempts = 0;
        if (scoreRetryTimer) { clearTimeout(scoreRetryTimer); scoreRetryTimer = null; }
        SafeClickModalUI.refreshWarningModal(currentTrustScore, settings, SafeClickCredentialMonitor.summarizeFormSecurityRisks);
        checkForSensitiveFields();
        SafeClickCredentialMonitor.addVisualIndicators(currentTrustScore, isAllowedOrSuppressed());
        maybeAutoShowSiteModal();
        setTimeout(() => {
          SafeClickCredentialMonitor.addVisualIndicators(currentTrustScore, isAllowedOrSuppressed());
          SafeClickCredentialMonitor.monitorForms();
        }, 1000);
      } else if (message.type === 'SHOW_TOAST') {
        SafeClickModalUI.showNotification(message.text || 'Action completed', message.variant || 'info', message.duration || 2000);
      }
    });
  }

  // Form submit & focus interception
  document.addEventListener('submit', (event) => {
    if (!protectionEnabled || !currentTrustScore) return;
    if (isAllowedOrSuppressed() || SafeClickModalUI.justDismissedModal()) return;

    const form = event.target;
    if (!form || typeof form.querySelector !== 'function') return;
    const hasPassword = form.querySelector('input[type="password"], input[name*="password"]');
    const hasCard = form.querySelector('input[name*="card"], input[name*="cc"]');

    if ((hasPassword || hasCard) && currentTrustScore.verdict === 'DANGEROUS') {
      event.preventDefault();
      triggerWarningModal();
    }
  });

  document.addEventListener('focusin', (event) => {
    if (!protectionEnabled) return;
    const target = event.target;
    if (target && target.matches && target.matches('input[type="password"], input[name*="password"]')) {
      if (isAllowedOrSuppressed() || SafeClickModalUI.justDismissedModal()) return;

      if (window.location.protocol === 'http:' && !withinCooldown()) {
        triggerWarningModal();
        scheduleScoreRetryIfNeeded('password-focus-http');
        return;
      }
      if (!currentTrustScore) {
        scheduleScoreRetryIfNeeded('password-focus');
        return;
      }
      const shouldWarn = currentTrustScore.verdict === 'DANGEROUS' ||
        (currentTrustScore.verdict === 'SUSPICIOUS' && currentTrustScore.score < settings.scoreThreshold);

      if (shouldWarn && !withinCooldown()) {
        triggerWarningModal();
      }
    }
  });

  // Client-side redirect detection
  function reportClientRedirect(toUrl, method) {
    try {
      const fromUrl = window.location.href;
      if (!toUrl || toUrl === fromUrl) return;
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({
          type: 'CLIENT_REDIRECT_DETECTED',
          fromUrl,
          toUrl,
          method
        });
      }
    } catch (_) {}
  }

  function installClientRedirectDetectors() {
    try {
      const loc = window.location;
      if (!loc) return;

      const originalAssign = loc.assign.bind(loc);
      const originalReplace = loc.replace.bind(loc);
      loc.assign = function (url) {
        try { reportClientRedirect(String(url), 'location.assign'); } catch (_) {}
        return originalAssign(url);
      };
      loc.replace = function (url) {
        try { reportClientRedirect(String(url), 'location.replace'); } catch (_) {}
        return originalReplace(url);
      };

      try {
        const originalOpen = window.open.bind(window);
        window.open = function (url, ...rest) {
          try {
            if (typeof url === 'string' && url) reportClientRedirect(String(url), 'window.open');
          } catch (_) {}
          return originalOpen(url, ...rest);
        };
      } catch (_) {}

      try {
        const hrefDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
        if (hrefDesc && hrefDesc.set) {
          const originalSetter = hrefDesc.set;
          Object.defineProperty(Location.prototype, 'href', {
            configurable: true,
            enumerable: true,
            get: hrefDesc.get,
            set: function (v) {
              try { reportClientRedirect(String(v), 'location.href'); } catch (_) {}
              return originalSetter.call(this, v);
            }
          });
        }
      } catch (_) {}
    } catch (_) {}
  }

  // Mutation observer for dynamic content
  function setupAdvancedMutationObserver() {
    if (typeof MutationObserver === 'undefined' || !document.body) return;
    const observer = new MutationObserver((mutations) => {
      let shouldRecheck = false;
      mutations.forEach(m => {
        if (m.type === 'childList') {
          m.addedNodes.forEach(node => {
            if (node.nodeType === 1) {
              if (node.querySelector && node.querySelector('input[type="password"], input[type="email"], input[name*="card"]')) {
                shouldRecheck = true;
              }
              if (node.querySelector && node.querySelector('form')) {
                setTimeout(() => SafeClickCredentialMonitor.monitorForms(), 100);
              }
            }
          });
        }
      });
      if (shouldRecheck) {
        setTimeout(() => {
          checkForSensitiveFields();
          SafeClickCredentialMonitor.addVisualIndicators(currentTrustScore, isAllowedOrSuppressed());
        }, 100);
      }
    });

    if (document.body) {
      observer.observe(document.body, { childList: true, subtree: true });
    }
  }

  // Initialization
  function initializeSafeClick() {
    loadAllowlistsCache();
    SafeClickModalUI.loadSuppressionFromStorage();
    requestTrustScore();
    checkForSensitiveFields();
    SafeClickCredentialMonitor.addVisualIndicators(currentTrustScore, isAllowedOrSuppressed());

    setTimeout(() => {
      SafeClickCredentialMonitor.monitorForms();
      initializePrivacyMonitoring();
      setupDataBreachAlerts();
    }, 2000);

    setupAdvancedMutationObserver();
    installClientRedirectDetectors();

    const recheck = debounce(() => {
      autoModalEvaluated = false;
      requestTrustScore();
      checkForSensitiveFields();
      SafeClickCredentialMonitor.addVisualIndicators(currentTrustScore, isAllowedOrSuppressed());
    }, 250);

    try {
      const origPushState = history.pushState;
      history.pushState = function (...args) {
        const ret = origPushState.apply(this, args);
        window.dispatchEvent(new Event('sc-route-change'));
        return ret;
      };
    } catch (_) {}
    window.addEventListener('sc-route-change', recheck);
    window.addEventListener('popstate', recheck);
    window.addEventListener('hashchange', recheck);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeSafeClick);
  } else {
    initializeSafeClick();
  }
})();
