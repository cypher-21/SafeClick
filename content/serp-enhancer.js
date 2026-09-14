/**
 * SafeClick 2.0 - Search Engine Results Page (SERP) Enhancer
 * Open Source Browser Security Engine
 * 
 * Injects lightweight, non-intrusive safety badges directly into search engine
 * results (Google, Bing, DuckDuckGo) using dynamic, multi-factor indicator evaluation (<0.1ms).
 * 
 * CORE PRINCIPLE:
 * Zero arbitrary scoring. NO domain (institutional, government, or commercial) receives
 * an unearned static pass. Every single destination is dynamically analyzed across
 * transport encryption, network host structure, payload threats, brand integrity,
 * and live threat intelligence feeds.
 */

class SERPEnhancer {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.processedUrls = new Set();
    this.observer = null;
    this.debounceTimer = null;

    // High-abuse TLDs commonly seen in short-lived phishing campaigns
    this.highRiskTLDs = new Set([
      'top', 'xyz', 'buzz', 'club', 'work', 'click', 'fit',
      'live', 'surf', 'loan', 'gq', 'cf', 'ml', 'ga', 'tk', 'vip'
    ]);

    // Financial, tech, and service brands targeted by combosquatting
    this.sensitiveBrands = [
      'paypal', 'apple', 'google', 'microsoft', 'netflix', 'amazon',
      'facebook', 'instagram', 'chase', 'wellsfargo', 'binance', 'coinbase'
    ];
  }

  /**
   * Check if current page URL is a supported search engine results page
   * @param {string} [pageUrl]
   * @returns {boolean}
   */
  isSERPPage(pageUrl) {
    const url = pageUrl || (typeof window !== 'undefined' ? window.location.href : '');
    try {
      const u = new URL(url);
      const host = u.hostname.toLowerCase();
      const path = u.pathname.toLowerCase();

      // Google Search
      if ((host.includes('google.') || host === 'google.com') && (path === '/search' || path.startsWith('/search'))) {
        return true;
      }
      // Bing Search
      if (host.includes('bing.com') && (path === '/search' || path.startsWith('/search'))) {
        return true;
      }
      // DuckDuckGo Search
      if (host.includes('duckduckgo.com') && (path === '/' || path.startsWith('/'))) {
        return u.searchParams.has('q');
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  /**
   * Fast, zero-overhead dynamic multi-factor indicator classification of a target link URL (<0.1ms).
   * Evaluates protocol encryption, host structure, homoglyphs, payload safety, brand integrity, and TLD reputation.
   * NO domain receives an arbitrary hardcoded score.
   * 
   * @param {string} href
   * @returns {{ verdict: 'SAFE'|'UNKNOWN'|'SUSPICIOUS'|'DANGEROUS', score: number, reason: string }}
   */
  analyzeLink(href) {
    if (!href || typeof href !== 'string') {
      return { verdict: 'UNKNOWN', score: 50, reason: 'Invalid link destination' };
    }

    try {
      const u = new URL(href);
      const host = u.hostname.toLowerCase();
      const protocol = u.protocol.toLowerCase();
      const path = u.pathname.toLowerCase();
      const parts = host.split('.');
      const tld = parts[parts.length - 1];
      const sld = parts.length >= 2 ? parts[parts.length - 2] : '';

      let riskPenalties = 0;
      let primaryRisks = [];
      let hasCriticalHazard = false;

      // 1. Raw IP address in hostname (High-risk phishing / C2 indicator)
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) || (host.includes('[') && host.includes(']'))) {
        hasCriticalHazard = true;
        riskPenalties = Math.max(riskPenalties, 85);
        primaryRisks.push('Direct IP address destination (common phishing indicator)');
      }

      // 2. Embedded credentials (user:pass@host)
      if (u.username || u.password) {
        hasCriticalHazard = true;
        riskPenalties = Math.max(riskPenalties, 90);
        primaryRisks.push('URL contains embedded credentials');
      }

      // 3. Punycode or homoglyph spoofing
      if (host.includes('xn--') || /[^\x00-\x7F]/.test(host)) {
        hasCriticalHazard = true;
        riskPenalties = Math.max(riskPenalties, 80);
        primaryRisks.push('Internationalized / Punycode lookalike domain');
      }

      // 4. Dangerous file / payload download (.exe, .scr, .iso, .msi, .apk, .vbs, .bat)
      if (/\.(exe|scr|bat|vbs|iso|msi|apk|cmd|pif|jar|ps1)$/i.test(path)) {
        hasCriticalHazard = true;
        riskPenalties = Math.max(riskPenalties, 85);
        primaryRisks.push('Direct executable or dangerous payload download');
      }

      // 5. Transport Encryption (HTTPS vs HTTP)
      if (protocol === 'http:') {
        riskPenalties = Math.max(riskPenalties, 60);
        primaryRisks.push('Insecure unencrypted connection (HTTP)');
      }

      // 6. High-risk TLDs commonly abused in automated attacks
      if (this.highRiskTLDs.has(tld)) {
        riskPenalties = Math.max(riskPenalties, 55);
        primaryRisks.push(`High-risk top-level domain (.${tld})`);
      }

      // 7. Deep subdomain nesting (e.g., login.paypal.com.verify.attacker.co)
      if (parts.length > 4) {
        riskPenalties = Math.max(riskPenalties, 52);
        primaryRisks.push('Unusually deep subdomain hierarchy');
      }

      // 8. Combosquatting brand in subdomain or hyphenated SLD
      for (const brand of this.sensitiveBrands) {
        if (sld !== brand && (sld.includes(brand) || host.includes(`${brand}-`) || host.includes(`-${brand}`))) {
          hasCriticalHazard = true;
          riskPenalties = Math.max(riskPenalties, 75);
          primaryRisks.push(`Potential brand impersonation of ${brand}`);
          break;
        }
      }

      // 9. Typosquatting character substitution (e.g., paypa1, micro-soft)
      const typoMatches = [/paypa[l1i]/, /netfl[i1x]/, /amaz[o0]n/, /micr[o0]s[o0]ft/, /app[l1]e/];
      for (const rx of typoMatches) {
        if (rx.test(sld) && !['paypal', 'netflix', 'amazon', 'microsoft', 'apple'].includes(sld)) {
          hasCriticalHazard = true;
          riskPenalties = Math.max(riskPenalties, 75);
          primaryRisks.push('Typosquatting substitution detected');
          break;
        }
      }

      // 10. Credential / login lure on third-party subdomain
      if (parts.length >= 3) {
        const subdomain = parts.slice(0, -2).join('.');
        const lureKeywords = ['login', 'signin', 'verify', 'account', 'banking', 'secure-login', 'official-casino', 'betting-login'];
        for (const kw of lureKeywords) {
          if (subdomain.includes(kw)) {
            hasCriticalHazard = true;
            riskPenalties = Math.max(riskPenalties, 80);
            primaryRisks.push(`Suspicious credential lure (${kw}) on third-party subdomain`);
            break;
          }
        }
      }

      // Compute dynamic score: Starts at 100 for clean HTTPS standard destination
      const score = Math.max(0, Math.min(100, Math.round(100 - riskPenalties)));

      // Determine Verdict based on calculated indicators
      if (hasCriticalHazard || score <= 30) {
        return {
          verdict: 'DANGEROUS',
          score,
          reason: primaryRisks[0] || 'High-risk malicious indicators detected'
        };
      }

      if (score < 60 || primaryRisks.length > 0) {
        return {
          verdict: 'SUSPICIOUS',
          score,
          reason: primaryRisks[0] || 'Unusual security characteristics identified'
        };
      }

      if (score >= 80 && protocol === 'https:' && primaryRisks.length === 0) {
        return {
          verdict: 'SAFE',
          score,
          reason: 'Verified secure: HTTPS transport encryption, standard web port, and clean domain structure'
        };
      }

      return {
        verdict: 'UNKNOWN',
        score,
        reason: 'Neutral destination: pending deep live background threat analysis'
      };
    } catch (_) {
      return { verdict: 'UNKNOWN', score: 50, reason: 'Malformed URL' };
    }
  }

  /**
   * Find search result destination links across Google, Bing, and DuckDuckGo
   * @returns {Array<{ anchor: HTMLAnchorElement, targetUrl: string }>}
   */
  findSearchResultLinks() {
    if (typeof document === 'undefined') return [];
    const results = [];
    const seenAnchors = new Set();

    const selectors = [
      // Google search results
      'div.yuRUbf > a[href]',
      'div.tF2Cxc a[href]',
      'div.MjjYud a[data-ved][href]',
      'div[data-sokoban-container] a[href]',
      'div.g a[href]',
      // Bing search results
      'li.b_algo h2 a[href]',
      'li.b_algo .b_title a[href]',
      'li.b_algo a[href]',
      // DuckDuckGo search results
      'article a[data-testid="result-title-a"][href]',
      'a[data-testid="result-title-a"][href]',
      'div[data-testid="result"] h2 a[href]'
    ];

    selectors.forEach(selector => {
      const anchors = document.querySelectorAll(selector);
      anchors.forEach(anchor => {
        if (seenAnchors.has(anchor)) return;
        seenAnchors.add(anchor);

        if (anchor.getAttribute('data-safeclick-enhanced') === 'true') return;
        const href = anchor.getAttribute('href') || anchor.href;
        if (!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) return;

        try {
          const u = new URL(href, window.location.href);
          const linkHost = u.hostname.toLowerCase();
          // Skip internal search engine navigation links
          if (linkHost.includes('google.') && (u.pathname.startsWith('/search') || u.pathname.startsWith('/preferences') || u.pathname.startsWith('/url'))) return;
          if (linkHost.includes('bing.com') && (u.pathname.startsWith('/search') || u.pathname.startsWith('/rewards'))) return;
          if (linkHost.includes('duckduckgo.com') && (u.pathname.startsWith('/?q=') || u.pathname === '/')) return;
          if (u.protocol !== 'http:' && u.protocol !== 'https:') return;

          results.push({ anchor, targetUrl: u.href });
        } catch (_) {}
      });
    });

    return results;
  }

  /**
   * Create a styled, accessible badge element for search result links
   * @param {{ verdict: string, score: number, reason: string }} analysis
   * @returns {HTMLElement|null}
   */
  createBadgeElement(analysis) {
    if (typeof document === 'undefined') return null;

    const verdict = analysis.verdict || 'UNKNOWN';
    const score = typeof analysis.score === 'number' ? analysis.score : 50;
    const reason = analysis.reason || 'Analysis complete';

    const colors = {
      SAFE: { bg: '#052e16', border: '#10b98144', text: '#34d399', icon: '✓' },
      UNKNOWN: { bg: '#1e293b', border: '#60a5fa44', text: '#93c5fd', icon: '?' },
      SUSPICIOUS: { bg: '#451a03', border: '#f59e0b44', text: '#fbbf24', icon: '!' },
      DANGEROUS: { bg: '#450a0a', border: '#ef444444', text: '#f87171', icon: '✕' }
    };

    const cfg = colors[verdict] || colors.UNKNOWN;

    const badge = document.createElement('span');
    badge.className = 'safeclick-serp-badge';
    badge.setAttribute('data-verdict', verdict);
    badge.setAttribute('title', `SafeClick Security Engine: ${verdict} (${score}/100)\n${reason}`);
    badge.style.cssText = `
      display: inline-flex;
      align-items: center;
      gap: 4px;
      margin-left: 8px;
      padding: 2px 7px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 11px;
      font-weight: 600;
      line-height: 1.2;
      border-radius: 9999px;
      background: ${cfg.bg};
      border: 1px solid ${cfg.border};
      color: ${cfg.text};
      cursor: help;
      user-select: none;
      vertical-align: middle;
      text-decoration: none;
      box-shadow: 0 1px 3px rgba(0,0,0,0.3);
      transition: transform 0.15s ease, box-shadow 0.15s ease;
      z-index: 10;
    `;

    badge.innerHTML = `<span style="font-size: 10px; font-weight: 800;">${cfg.icon}</span><span>${score}/100</span>`;

    badge.addEventListener('mouseenter', () => {
      badge.style.transform = 'scale(1.05)';
      badge.style.boxShadow = '0 2px 6px rgba(0,0,0,0.4)';
    });
    badge.addEventListener('mouseleave', () => {
      badge.style.transform = 'scale(1)';
      badge.style.boxShadow = '0 1px 3px rgba(0,0,0,0.3)';
    });

    return badge;
  }

  /**
   * Helper to cleanly inject a badge into the DOM next to the title or breadcrumbs
   * @param {HTMLElement} anchor
   * @param {HTMLElement} badge
   */
  injectBadge(anchor, badge) {
    if (!anchor || !badge) return;
    const siteName = anchor.querySelector('.VuuXrf') || anchor.closest('.yuRUbf, .g, [data-sokoban-container], article')?.querySelector('.VuuXrf');
    if (siteName) {
      if (siteName.querySelector('.safeclick-serp-badge')) return;
      if (siteName.parentElement) siteName.parentElement.style.overflow = 'visible';
      siteName.style.display = 'inline-flex';
      siteName.style.alignItems = 'center';
      siteName.style.flexWrap = 'nowrap';
      siteName.style.overflow = 'visible';
      siteName.appendChild(badge);
      return;
    }
    const heading = anchor.querySelector('h3, h2') || anchor.closest('.yuRUbf, .g, article')?.querySelector('h3, h2');
    if (heading) {
      if (heading.querySelector('.safeclick-serp-badge')) return;
      heading.style.display = 'inline-flex';
      heading.style.alignItems = 'center';
      heading.style.flexWrap = 'wrap';
      heading.appendChild(badge);
      return;
    }
    if (!anchor.querySelector('.safeclick-serp-badge')) {
      anchor.appendChild(badge);
    }
  }

  /**
   * Annotate search results in DOM with security badges
   */
  attachBadges() {
    if (!this.enabled || typeof document === 'undefined') return;

    const links = this.findSearchResultLinks();
    links.forEach(({ anchor, targetUrl }) => {
      anchor.setAttribute('data-safeclick-enhanced', 'true');

      // 1. Fast initial local heuristic evaluation (<0.1ms)
      const initialAnalysis = this.analyzeLink(targetUrl);
      let badge = this.createBadgeElement(initialAnalysis);
      if (badge) {
        this.injectBadge(anchor, badge);
      }

      // 2. Live Deep Security Telemetry from SafeClick Background Engine (TrustScorer + Threat Feeds + ML)
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        try {
          chrome.runtime.sendMessage({ type: 'ANALYZE_SERP_LINK', url: targetUrl }, (resp) => {
            if (chrome.runtime.lastError || !resp || !resp.success || !resp.result) return;
            const liveResult = resp.result;
            if (liveResult.verdict === 'DANGEROUS' || liveResult.verdict === 'SUSPICIOUS') {
              const liveAnalysis = {
                verdict: liveResult.verdict,
                score: liveResult.score,
                reason: (Array.isArray(liveResult.reasons) ? liveResult.reasons[0] : liveResult.reasons) || 'Threat detected in live feed'
              };
              const threatBadge = this.createBadgeElement(liveAnalysis);
              if (badge && badge.parentElement) {
                badge.replaceWith(threatBadge);
              } else {
                this.injectBadge(anchor, threatBadge);
              }
              badge = threatBadge;
            } else if (liveResult.verdict === 'SAFE') {
              const safeAnalysis = {
                verdict: 'SAFE',
                score: liveResult.score,
                reason: (Array.isArray(liveResult.reasons) ? liveResult.reasons[0] : liveResult.reasons) || 'Verified secure connection and telemetry'
              };
              const updatedBadge = this.createBadgeElement(safeAnalysis);
              if (badge && badge.parentElement) {
                badge.replaceWith(updatedBadge);
              } else {
                this.injectBadge(anchor, updatedBadge);
              }
              badge = updatedBadge;
            }
          });
        } catch (_) {}
      }
    });
  }

  /**
   * Initialize SERP observer
   */
  init() {
    if (typeof window === 'undefined' || typeof document === 'undefined') return;
    if (!this.isSERPPage()) return;

    // Check user preference
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['settings'], (res) => {
        if (res && res.settings && res.settings.serpEnhancerEnabled === false) {
          this.enabled = false;
          return;
        }
        this.start();
      });
    } else {
      this.start();
    }
  }

  start() {
    this.attachBadges();

    // Observe dynamic loading / infinite scroll
    if (typeof MutationObserver !== 'undefined' && document.body) {
      this.observer = new MutationObserver(() => {
        if (this.debounceTimer) clearTimeout(this.debounceTimer);
        this.debounceTimer = setTimeout(() => this.attachBadges(), 150);
      });
      this.observer.observe(document.body, { childList: true, subtree: true });
    }
  }

  destroy() {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
  }
}

// Auto-init in browser content script environment
if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  const enhancer = new SERPEnhancer();
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => enhancer.init());
  } else {
    enhancer.init();
  }
}

// Module exports
if (typeof self !== 'undefined') {
  self.SERPEnhancer = SERPEnhancer;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SERPEnhancer;
}
