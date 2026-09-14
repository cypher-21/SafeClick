/**
 * SafeClick 2.0 - Local URL & Structural Analyzer
 * Open Source Browser Security Engine
 * 
 * Deep, zero-latency, local-only lexical and structural security analysis of URLs.
 * Emits structured Indicator instances.
 */

(function () {
  'use strict';

  // Handle environments (Browser Service Worker vs Node.js)
  const _Indicator = (typeof Indicator !== 'undefined') ? Indicator : (function () {
    try { return require('./indicator.js').Indicator; } catch (_) { return null; }
  })();

  class URLAnalyzer {
  constructor(options = {}) {
    this.highRiskTLDs = new Set([
      '.tk', '.ml', '.ga', '.cf', '.gq', // Free TLDs with extreme historical abuse
      '.top', '.xyz', '.click', '.download', '.link',
      '.work', '.date', '.racing', '.win', '.stream',
      '.gdn', '.review', '.accountant', '.loan', '.men',
      '.science', '.party', '.trade', '.webcam', '.bid',
      '.fit', '.club', '.rest', '.buzz', '.vip'
    ]);

    // Confusable Unicode characters (Latin lookalikes from Cyrillic, Greek, etc.)
    this.confusables = {
      'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i',
      'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'l',
      'ɪ': 'i', 'ⅼ': 'l', 'ο': 'o', 'α': 'a', 'ε': 'e', 'τ': 't', 'ι': 'i', 'ν': 'v',
      '٠': '0', '১': '1', '০': '0', '０': '0', '１': '1'
    };

    // Standard ports
    this.standardPorts = new Set(['', '80', '443']);

    this.options = {
      entropyThreshold: options.entropyThreshold || 3.5,
      maxSubdomainDepth: options.maxSubdomainDepth || 3,
      maxHyphens: options.maxHyphens || 3,
      maxUrlLength: options.maxUrlLength || 2048,
      maxPathLength: options.maxPathLength || 300,
      ...options
    };
  }

  /**
   * Calculate Shannon entropy of a string (bits per symbol)
   * @param {string} str
   * @returns {number}
   */
  calculateEntropy(str) {
    if (!str || typeof str !== 'string' || str.length === 0) return 0;
    const freq = {};
    for (const ch of str) {
      freq[ch] = (freq[ch] || 0) + 1;
    }
    const len = str.length;
    let entropy = 0;
    for (const ch in freq) {
      const p = freq[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 100) / 100;
  }

  /**
   * Check if a hostname is an IP address (IPv4, hex, or decimal)
   * @param {string} hostname
   */
  isIpAddress(hostname) {
    if (!hostname) return false;
    const host = hostname.trim();
    // Standard dotted-decimal IPv4
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      const parts = host.split('.').map(Number);
      return parts.every(p => p >= 0 && p <= 255);
    }
    // Hexadecimal or decimal IP formats often used in obfuscation
    if (/^0x[0-9a-fA-F]+$/.test(host)) return true;
    if (/^\d{8,11}$/.test(host)) return true;
    // IPv6 format
    if (host.startsWith('[') && host.endsWith(']')) return true;
    return false;
  }

  /**
   * Check for Punycode or Confusable Unicode homoglyphs
   * @param {string} hostname
   */
  detectHomoglyphs(hostname) {
    if (!hostname) return { isHomoglyph: false, isPunycode: false };
    const host = hostname.toLowerCase();

    const isPunycode = host.includes('xn--');
    let hasConfusables = false;
    let normalized = '';

    for (const ch of host) {
      if (this.confusables[ch]) {
        hasConfusables = true;
        normalized += this.confusables[ch];
      } else {
        normalized += ch;
      }
    }

    return {
      isHomoglyph: isPunycode || hasConfusables,
      isPunycode,
      hasConfusables,
      normalized
    };
  }

  /**
   * Analyze URL and return structured Indicator objects
   * @param {string} urlString - Target URL
   * @returns {Indicator[]} Array of structured security indicators
   */
  analyze(urlString) {
    const indicators = [];
    const IndicatorClass = _Indicator || (typeof Indicator !== 'undefined' ? Indicator : null);
    if (!IndicatorClass) return indicators;

    let urlObj = null;
    try {
      urlObj = new URL(urlString);
    } catch (_) {
      indicators.push(new IndicatorClass({
        id: 'url.malformed',
        source: 'url-analyzer',
        category: 'lexical',
        polarity: 'negative',
        weight: -20,
        confidence: 'high',
        detail: '[X] Malformed or unparseable URL'
      }));
      return indicators;
    }

    const host = urlObj.hostname.toLowerCase();
    const port = urlObj.port;
    const pathname = urlObj.pathname;
    const search = urlObj.search;

    let negativeCount = 0;

    // 1. Protocol / Encryption Check
    if (urlObj.protocol === 'https:') {
      indicators.push(new IndicatorClass({
        id: 'url.https',
        source: 'url-analyzer',
        category: 'network',
        polarity: 'positive',
        weight: 15,
        confidence: 'high',
        detail: '[OK] Encrypted HTTPS connection active'
      }));
    } else if (urlObj.protocol === 'http:') {
      negativeCount++;
      indicators.push(new IndicatorClass({
        id: 'url.no_https',
        source: 'url-analyzer',
        category: 'network',
        polarity: 'negative',
        weight: -25,
        confidence: 'high',
        detail: '[X] Connection is unencrypted (HTTP)'
      }));
    }

    // 2. IP Address in Hostname
    if (this.isIpAddress(host)) {
      negativeCount++;
      indicators.push(new IndicatorClass({
        id: 'url.ip_host',
        source: 'url-analyzer',
        category: 'structural',
        polarity: 'negative',
        weight: -30,
        confidence: 'high',
        value: host,
        detail: `[X] Hostname is a raw IP address (${host})`
      }));
    }

    // 3. Non-standard Port
    if (port && !this.standardPorts.has(port)) {
      negativeCount++;
      indicators.push(new IndicatorClass({
        id: 'url.non_standard_port',
        source: 'url-analyzer',
        category: 'network',
        polarity: 'negative',
        weight: -15,
        confidence: 'medium',
        value: port,
        detail: `[!] Non-standard port :${port} detected`
      }));
    }

    // 4. Embedded Credentials (e.g. user:pass@host)
    if (urlObj.username || urlObj.password) {
      negativeCount++;
      indicators.push(new IndicatorClass({
        id: 'url.embedded_credentials',
        source: 'url-analyzer',
        category: 'lexical',
        polarity: 'negative',
        weight: -30,
        confidence: 'high',
        detail: '[X] URL contains embedded credentials before hostname'
      }));
    }

    // 5. Homoglyphs & Punycode (IDN Spoofing)
    const homoglyphRes = this.detectHomoglyphs(host);
    if (homoglyphRes.isPunycode) {
      negativeCount++;
      indicators.push(new IndicatorClass({
        id: 'url.punycode',
        source: 'url-analyzer',
        category: 'lexical',
        polarity: 'negative',
        weight: -25,
        confidence: 'high',
        value: host,
        detail: `[!] Punycode IDN domain detected (${host})`
      }));
    } else if (homoglyphRes.hasConfusables) {
      negativeCount++;
      indicators.push(new IndicatorClass({
        id: 'url.homoglyph',
        source: 'url-analyzer',
        category: 'lexical',
        polarity: 'negative',
        weight: -30,
        confidence: 'high',
        value: { original: host, normalized: homoglyphRes.normalized },
        detail: `[X] Domain contains confusable/lookalike Unicode characters`
      }));
    }

    // 6. High-Risk / Suspicious TLD
    const lastDotIdx = host.lastIndexOf('.');
    if (lastDotIdx !== -1) {
      const tld = host.substring(lastDotIdx);
      if (this.highRiskTLDs.has(tld)) {
        negativeCount++;
        indicators.push(new IndicatorClass({
          id: 'url.suspicious_tld',
          source: 'url-analyzer',
          category: 'lexical',
          polarity: 'negative',
          weight: -20,
          confidence: 'medium',
          value: tld,
          detail: `[!] Domain uses high-abuse TLD (${tld})`
        }));
      }
    }

    // 7. Subdomain Depth & Entropy
    const hostParts = host.split('.').filter(Boolean);
    // Rough estimate of subdomain parts (assuming last 2 are apex for simple TLDs)
    if (hostParts.length > this.options.maxSubdomainDepth + 2 && !this.isIpAddress(host)) {
      negativeCount++;
      indicators.push(new IndicatorClass({
        id: 'url.high_subdomain_depth',
        source: 'url-analyzer',
        category: 'structural',
        polarity: 'negative',
        weight: -15,
        confidence: 'medium',
        value: hostParts.length,
        detail: `[!] Deeply nested subdomains detected (${hostParts.length} levels)`
      }));
    }

    const subdomainStr = hostParts.slice(0, Math.max(1, hostParts.length - 2)).join('.');
    if (subdomainStr && subdomainStr.length >= 6) {
      const entropy = this.calculateEntropy(subdomainStr);
      if (entropy >= this.options.entropyThreshold) {
        negativeCount++;
        indicators.push(new IndicatorClass({
          id: 'url.high_entropy',
          source: 'url-analyzer',
          category: 'lexical',
          polarity: 'negative',
          weight: -15,
          confidence: 'medium',
          value: entropy,
          detail: `[!] High randomness / entropy in subdomain (${entropy})`
        }));
      }
    }

    // 8. Excessive Hyphenation
    const hyphenCount = (host.match(/-/g) || []).length;
    if (hyphenCount >= this.options.maxHyphens) {
      negativeCount++;
      indicators.push(new IndicatorClass({
        id: 'url.hyphen_excess',
        source: 'url-analyzer',
        category: 'lexical',
        polarity: 'negative',
        weight: -10,
        confidence: 'low',
        value: hyphenCount,
        detail: `[!] Unusually high number of hyphens in domain (${hyphenCount})`
      }));
    }

    // 9. Excessive Path / Host Length Obfuscation (ignoring safe query params like ?q=...)
    const isSearchPortal = /(^|\.)(google\.[a-z.]+|bing\.com|duckduckgo\.com|yahoo\.[a-z.]+|youtube\.com|amazon\.[a-z.]+|wikipedia\.org)$/i.test(host);
    const pathAndHostLen = host.length + pathname.length;
    const isExcessivePath = pathname.length > (this.options.maxPathLength || 300);
    const isBeyondHttpStandard = urlString.length > (this.options.maxUrlLength || 2048);

    if (!isSearchPortal && (isExcessivePath || isBeyondHttpStandard)) {
      negativeCount++;
      indicators.push(new IndicatorClass({
        id: 'url.excessive_length',
        source: 'url-analyzer',
        category: 'structural',
        polarity: 'negative',
        weight: -10,
        confidence: 'low',
        value: urlString.length,
        detail: `[!] Obfuscated or excessively long URL path (${pathAndHostLen} characters)`
      }));
    }

    // 10. Clean Structural Reassurance (if zero negative indicators found)
    if (negativeCount === 0 && !this.isIpAddress(host)) {
      indicators.push(new IndicatorClass({
        id: 'url.clean_structure',
        source: 'url-analyzer',
        category: 'structural',
        polarity: 'positive',
        weight: 10,
        confidence: 'medium',
        detail: '[OK] Standard domain and URL structure'
      }));
    }

    return indicators;
  }
}

  // Environment exports
  if (typeof self !== 'undefined') {
    self.URLAnalyzer = URLAnalyzer;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = URLAnalyzer;
  }
})();
