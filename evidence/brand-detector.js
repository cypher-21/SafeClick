/**
 * SafeClick 2.0 - Brand Impersonation & Typosquatting Detector
 * Open Source Browser Security Engine
 * 
 * Detects lookalikes, typosquatting, combosquatting, and subdomain brand spoofing
 * using local-only heuristics. Zero external APIs or cloud dependencies.
 */

(function () {
  'use strict';

  // Handle environments (Browser Service Worker vs Node.js)
  const _Indicator = (typeof Indicator !== 'undefined') ? Indicator : (function () {
    try { return require('./indicator.js').Indicator; } catch (_) { return null; }
  })();

  class BrandDetector {
  constructor(options = {}) {
    // High-value target brands and their official apex domains
    this.targetBrands = {
      'google': ['google.com', 'google.co.uk', 'google.ca', 'google.de', 'google.fr', 'google.co.jp', 'google.com.au', 'google.co.in'],
      'paypal': ['paypal.com', 'paypal.me'],
      'apple': ['apple.com', 'icloud.com'],
      'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com', 'azure.com'],
      'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.ca', 'amazon.co.jp', 'aws.amazon.com'],
      'netflix': ['netflix.com'],
      'facebook': ['facebook.com', 'meta.com', 'fb.com'],
      'instagram': ['instagram.com'],
      'linkedin': ['linkedin.com'],
      'twitter': ['twitter.com', 'x.com'],
      'github': ['github.com'],
      'dropbox': ['dropbox.com'],
      'stripe': ['stripe.com'],
      'coinbase': ['coinbase.com'],
      'binance': ['binance.com'],
      'chase': ['chase.com'],
      'bankofamerica': ['bankofamerica.com', 'bofa.com'],
      'wellsfargo': ['wellsfargo.com'],
      'citibank': ['citibank.com', 'citi.com']
    };

    // Sensitive intent keywords commonly attached in combosquatting attacks
    this.securityKeywords = new Set([
      'login', 'signin', 'auth', 'verify', 'verification', 'account', 'security',
      'update', 'billing', 'support', 'confirm', 'confirmation', 'wallet', 'recover',
      'recovery', 'portal', 'secure', 'alert', 'notice', 'service', 'help'
    ]);

    this.similarityThreshold = options.similarityThreshold || 0.82;
  }

  /**
   * Calculate Levenshtein distance between two strings
   */
  levenshteinDistance(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;

    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  /**
   * Normalized string similarity score (0 to 1)
   */
  stringSimilarity(a, b) {
    const dist = this.levenshteinDistance(a, b);
    const maxLen = Math.max(a.length, b.length);
    return maxLen === 0 ? 1 : 1 - (dist / maxLen);
  }

  /**
   * Approximate apex extraction (fallback if UrlUtils not available)
   */
  getApex(hostname) {
    if (typeof UrlUtils !== 'undefined' && typeof UrlUtils.getETLD1FromHost === 'function') {
      return UrlUtils.getETLD1FromHost(hostname);
    }
    const parts = String(hostname || '').toLowerCase().split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    return parts.slice(-2).join('.');
  }

  /**
   * Analyze target domain for brand spoofing
   * @param {string} hostname - Target hostname (e.g. 'paypal-security.com' or 'accounts.google.com')
   * @returns {Indicator[]}
   */
  analyze(hostname) {
    const indicators = [];
    const IndicatorClass = _Indicator || (typeof Indicator !== 'undefined' ? Indicator : null);
    if (!IndicatorClass || !hostname) return indicators;

    const host = String(hostname).toLowerCase().trim();
    const apex = this.getApex(host);
    const hostParts = host.split('.');
    const apexParts = apex.split('.');
    const sld = apexParts[0] || ''; // Second-level domain of the apex (e.g. 'paypal' in 'paypal.com')

    // Subdomain portion (everything before the apex)
    const subdomainParts = hostParts.slice(0, Math.max(0, hostParts.length - apexParts.length));
    const subdomain = subdomainParts.join('.');

    // Normalize common visual substitutions: 0->o, 1->l, @->a, vv->w, rn->m
    const sldNormalized = sld
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/@/g, 'a')
      .replace(/3/g, 'e')
      .replace(/5/g, 's')
      .replace(/vv/g, 'w')
      .replace(/rn/g, 'm');

    // 1. Check if domain is an official domain of a recognized brand
    for (const [brand, officialDomains] of Object.entries(this.targetBrands)) {
      if (officialDomains.includes(apex)) {
        indicators.push(new IndicatorClass({
          id: 'brand.official',
          source: 'brand-detector',
          category: 'reputation',
          polarity: 'positive',
          weight: 20,
          confidence: 'high',
          value: { brand, apex },
          detail: `[OK] Verified official domain for ${brand.toUpperCase()} (${apex})`
        }));
        return indicators; // Official domains are authentic, no need to flag false lookalikes
      }
    }

    // 2. Subdomain Spoofing Check
    // Example: paypal.com.verify-user.com (where apex is verify-user.com, but subdomain contains brand)
    for (const [brand, officialDomains] of Object.entries(this.targetBrands)) {
      for (const part of subdomainParts) {
        if (part === brand || officialDomains.some(od => part === od || part.startsWith(brand + '.'))) {
          indicators.push(new IndicatorClass({
            id: 'brand.subdomain_spoof',
            source: 'brand-detector',
            category: 'lexical',
            polarity: 'negative',
            weight: -35,
            confidence: 'high',
            value: { brand, subdomain, apex },
            detail: `[X] Brand spoofing: "${brand}" used in subdomain of unrelated site (${apex})`
          }));
          return indicators;
        }
      }
    }

    // 3. Combosquatting Check
    // Example: paypal-security.com, login-apple-verify.net
    for (const [brand, _] of Object.entries(this.targetBrands)) {
      if (sld.includes(brand)) {
        // Check if attached to security keywords
        for (const kw of this.securityKeywords) {
          if (sld.includes(kw)) {
            indicators.push(new IndicatorClass({
              id: 'brand.combosquat',
              source: 'brand-detector',
              category: 'lexical',
              polarity: 'negative',
              weight: -30,
              confidence: 'high',
              value: { brand, keyword: kw, sld },
              detail: `[X] Combosquatting: Brand "${brand}" combined with sensitive keyword "${kw}" in domain`
            }));
            return indicators;
          }
        }

        // Embedded brand name without keyword (e.g. paypal-update.com)
        indicators.push(new IndicatorClass({
          id: 'brand.embedded_brand',
          source: 'brand-detector',
          category: 'lexical',
          polarity: 'negative',
          weight: -20,
          confidence: 'medium',
          value: { brand, sld },
          detail: `[!] Domain embeds recognizable brand name "${brand}"`
        }));
        return indicators;
      }
    }

    // 4. Typosquatting / Visual Lookalike Check (Levenshtein Distance & Character Substitution)
    // Example: paypa1.com, gooogle.com, amazn.com
    for (const [brand, _] of Object.entries(this.targetBrands)) {
      // Do not compare very short brands with short slds if diff is large
      if (Math.abs(sldNormalized.length - brand.length) > 3) continue;

      const isSubstitutedMatch = (sldNormalized === brand && sld !== brand);
      const sim = this.stringSimilarity(sldNormalized, brand);
      if (isSubstitutedMatch || (sim >= this.similarityThreshold && sim < 1.0)) {
        const matchPct = isSubstitutedMatch ? 99 : Math.round(sim * 100);
        indicators.push(new IndicatorClass({
          id: 'brand.typosquat',
          source: 'brand-detector',
          category: 'lexical',
          polarity: 'negative',
          weight: -30,
          confidence: 'high',
          value: { brand, similarity: matchPct / 100, sld },
          detail: `[X] Possible typosquatting: Domain resembles brand "${brand}" (${matchPct}% visual match)`
        }));
        return indicators;
      }
    }

    return indicators;
  }
}

  // Environment exports
  if (typeof self !== 'undefined') {
    self.BrandDetector = BrandDetector;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = BrandDetector;
  }
})();
