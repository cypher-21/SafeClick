/**
 * SafeClick 2.0 - Local ML Feature Extractor
 * Open Source Browser Security Engine
 * 
 * Extracts a normalized 24-dimensional numerical feature vector from URL and DOM signals
 * for fast, offline, zero-latency machine learning inference.
 */

(function () {
  'use strict';

  // Handle environments (Browser vs Node.js)
  const _UrlUtils = (typeof UrlUtils !== 'undefined') ? UrlUtils : (function () {
    try { return require('../modules/url-utils.js'); } catch (_) { return null; }
  })();
  const _BrandDetector = (typeof BrandDetector !== 'undefined') ? BrandDetector : (function () {
    try { return require('../evidence/brand-detector.js'); } catch (_) { return null; }
  })();

  class FeatureExtractor {
  constructor() {
    this.highRiskTLDs = new Set([
      '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.click',
      '.download', '.link', '.work', '.date', '.racing', '.win',
      '.stream', '.gdn', '.review', '.accountant', '.loan', '.men',
      '.science', '.party', '.trade', '.webcam', '.bid', '.fit', '.club'
    ]);

    this.brandDetector = _BrandDetector ? new _BrandDetector() : null;

    this.FEATURE_NAMES = [
      'urlLength',             // 0
      'hostLength',            // 1
      'pathLength',            // 2
      'queryLength',           // 3
      'subdomainCount',        // 4
      'dotCount',              // 5
      'hyphenCount',           // 6
      'digitRatio',            // 7
      'subdomainEntropy',      // 8
      'pathEntropy',           // 9
      'isHttps',               // 10
      'isIpHost',              // 11
      'isSuspiciousTld',       // 12
      'isPunycode',            // 13
      'hasHomoglyphs',         // 14
      'hasNonStandardPort',    // 15
      'hasEmbeddedCredentials',// 16
      'brandSimilarity',       // 17
      'isCombosquat',          // 18
      'isSubdomainBrandSpoof', // 19
      'hasCrossOriginForm',    // 20
      'hasHiddenIframe',       // 21
      'hasBrowserInBrowser',   // 22
      'hasPasswordField'       // 23
    ];
  }

  calculateEntropy(str) {
    if (!str || typeof str !== 'string' || str.length === 0) return 0;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    const len = str.length;
    let entropy = 0;
    for (const ch in freq) {
      const p = freq[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  isIpAddress(host) {
    if (!host) return false;
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      return host.split('.').every(p => Number(p) >= 0 && Number(p) <= 255);
    }
    return /^0x[0-9a-fA-F]+$/.test(host) || /^\d{8,11}$/.test(host);
  }

  /**
   * Extract 24 normalized numerical features [0.0 - 1.0] from URL and DOM
   * @param {string} urlString - Target URL
   * @param {Object} [domAnalysis] - Optional DOM analysis findings
   * @returns {Float32Array} 24-dimensional feature vector
   */
  extract(urlString, domAnalysis = null) {
    const vector = new Float32Array(24);

    let urlObj = null;
    try {
      urlObj = new URL(urlString);
    } catch (_) {
      // In case of completely invalid URL, return default anomalies
      vector[0] = 1.0;
      return vector;
    }

    const host = urlObj.hostname.toLowerCase();
    const pathname = urlObj.pathname || '';
    const search = urlObj.search || '';
    const port = urlObj.port || '';

    // Check if domain is an established search portal or public reference platform
    const isSearchPortal = /(^|\.)(google\.[a-z.]+|bing\.com|duckduckgo\.com|yahoo\.[a-z.]+|youtube\.com|amazon\.[a-z.]+|wikipedia\.org)$/i.test(host);

    // 0. urlLength (structural path+host length, ignoring harmless search query string inflation)
    const effectiveUrlLength = isSearchPortal ? (host.length + pathname.length) : Math.min(urlString.length, (host.length + pathname.length + Math.min(search.length, 60)));
    vector[0] = Math.min(1.0, effectiveUrlLength / 250);

    // 1. hostLength (normalized up to 60 chars)
    vector[1] = Math.min(1.0, host.length / 60);

    // 2. pathLength (normalized up to 150 chars)
    vector[2] = Math.min(1.0, pathname.length / 150);

    // 3. queryLength (normalized up to 100 chars; zeroed on verified search portals)
    vector[3] = isSearchPortal ? 0.0 : Math.min(1.0, search.length / 100);

    // 4. subdomainCount
    const hostParts = host.split('.').filter(Boolean);
    const subdomains = hostParts.slice(0, Math.max(0, hostParts.length - 2));
    vector[4] = Math.min(1.0, subdomains.length / 5);

    // 5. dotCount in host
    const dots = (host.match(/\./g) || []).length;
    vector[5] = Math.min(1.0, dots / 5);

    // 6. hyphenCount in host
    const hyphens = (host.match(/-/g) || []).length;
    vector[6] = Math.min(1.0, hyphens / 4);

    // 7. digitRatio in host
    const digits = (host.match(/\d/g) || []).length;
    vector[7] = host.length > 0 ? digits / host.length : 0.0;

    // 8. subdomainEntropy (normalized up to 4.5)
    const subdomainStr = subdomains.join('.');
    const subEntropy = subdomainStr ? this.calculateEntropy(subdomainStr) : 0.0;
    vector[8] = Math.min(1.0, subEntropy / 4.5);

    // 9. pathEntropy (normalized up to 4.5)
    const pathEntropy = pathname ? this.calculateEntropy(pathname) : 0.0;
    vector[9] = Math.min(1.0, pathEntropy / 4.5);

    // 10. isHttps
    vector[10] = urlObj.protocol === 'https:' ? 1.0 : 0.0;

    // 11. isIpHost
    vector[11] = this.isIpAddress(host) ? 1.0 : 0.0;

    // 12. isSuspiciousTld
    const lastDot = host.lastIndexOf('.');
    const tld = lastDot !== -1 ? host.substring(lastDot) : '';
    vector[12] = this.highRiskTLDs.has(tld) ? 1.0 : 0.0;

    // 13. isPunycode
    vector[13] = host.includes('xn--') ? 1.0 : 0.0;

    // 14. hasHomoglyphs
    const confusables = /[аеорсхуіјѕԁԛԝɑɡɩɪⅼοαετιν٠১০０１]/;
    vector[14] = confusables.test(host) ? 1.0 : 0.0;

    // 15. hasNonStandardPort
    vector[15] = (port && port !== '80' && port !== '443') ? 1.0 : 0.0;

    // 16. hasEmbeddedCredentials
    vector[16] = (urlObj.username || urlObj.password) ? 1.0 : 0.0;

    // 17-19. Brand Analysis
    if (this.brandDetector) {
      const brandIndicators = this.brandDetector.analyze(host);
      const typosquat = brandIndicators.find(i => i.id === 'brand.typosquat');
      const combosquat = brandIndicators.find(i => i.id === 'brand.combosquat');
      const subSpoof = brandIndicators.find(i => i.id === 'brand.subdomain_spoof');

      vector[17] = typosquat && typosquat.value ? (typosquat.value.similarity || 0.9) : 0.0;
      vector[18] = combosquat ? 1.0 : 0.0;
      vector[19] = subSpoof ? 1.0 : 0.0;
    }

    // 20-23. DOM Analysis Features
    if (domAnalysis && typeof domAnalysis === 'object') {
      vector[20] = domAnalysis.hasSuspiciousForms ? 1.0 : 0.0;
      vector[21] = domAnalysis.hasHiddenIframes ? 1.0 : 0.0;
      vector[22] = domAnalysis.hasBrowserInBrowserPatterns ? 1.0 : 0.0;
      vector[23] = domAnalysis.hasCredentialFields ? 1.0 : 0.0;
    }

    return vector;
  }
}

  // Environment exports
  if (typeof self !== 'undefined') {
    self.FeatureExtractor = FeatureExtractor;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = FeatureExtractor;
  }
})();
