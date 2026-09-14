/**
 * SafeClick 2.0 - Threat Intelligence Provider Abstraction
 * Open Source Browser Security Engine
 * 
 * Provides an extensible, zero-cost abstraction for threat intelligence.
 * Works 100% locally and offline. No paid API keys or proprietary backends.
 */

(function () {
  'use strict';

  // Handle environments (Browser Service Worker vs Node.js)
  const _Indicator = (typeof Indicator !== 'undefined') ? Indicator : (function () {
    try { return require('./indicator.js').Indicator; } catch (_) { return null; }
  })();

  class ThreatIntelProvider {
  /**
   * @param {Object} options
   * @param {string} options.id - Unique provider ID
   * @param {string} options.name - Human-readable provider name
   * @param {string} [options.feedUrl] - Remote feed URL for open updates
   * @param {string} [options.format] - 'json' | 'text' | 'csv'
   * @param {boolean} [options.enabled] - Whether this provider is active
   * @param {string} [options.confidence] - 'high' | 'medium'
   * @param {number} [options.updateIntervalMinutes] - Update frequency
   */
  constructor({
    id,
    name,
    feedUrl = '',
    format = 'text',
    enabled = true,
    confidence = 'high',
    updateIntervalMinutes = 60
  }) {
    if (!id) throw new Error('ThreatIntelProvider requires an id');
    this.id = id;
    this.name = name || id;
    this.feedUrl = feedUrl;
    this.format = format;
    this.enabled = enabled;
    this.confidence = confidence;
    this.updateIntervalMinutes = updateIntervalMinutes;

    this.lastUpdated = 0;
    this.entryCount = 0;
    this.lastError = null;

    // In-memory sets for exact URL matches and host matches
    this.exactUrls = new Set();
    this.hosts = new Set();
  }

  async init() {
    return true;
  }

  /**
   * Query this provider for indicators matching a target URL and domain
   * @param {string} url - Canonical target URL
   * @param {string} domain - Target hostname
   * @param {string} [apexDomain] - Target apex / eTLD+1
   * @returns {Indicator[]} Array of generated indicators
   */
  lookup(url, domain, apexDomain) {
    if (!this.enabled) return [];
    const results = [];
    const IndicatorClass = _Indicator || (typeof Indicator !== 'undefined' ? Indicator : null);
    if (!IndicatorClass) return [];

    const normUrl = String(url || '').trim();
    const normHost = String(domain || '').toLowerCase().trim();
    const normApex = String(apexDomain || '').toLowerCase().trim();

    // 1. Exact URL Match (Deterministic Hard-fail candidate)
    if (normUrl && this.exactUrls.has(normUrl)) {
      results.push(new IndicatorClass({
        id: `threat_feed.${this.id}.exact_url`,
        source: this.id,
        category: 'threat_feed',
        polarity: 'negative',
        weight: -100,
        confidence: this.confidence,
        value: { url: normUrl, provider: this.id },
        detail: `[X] Verified malicious URL in ${this.name} feed`
      }));
    }

    // 2. Exact Host Match (Weighted Negative Evidence, NEVER unconditional hard fail)
    if (normHost && this.hosts.has(normHost)) {
      results.push(new IndicatorClass({
        id: `threat_feed.${this.id}.host`,
        source: this.id,
        category: 'reputation',
        polarity: 'negative',
        weight: -35,
        confidence: 'medium',
        value: { host: normHost, provider: this.id },
        detail: `[!] Host listed in ${this.name} threat database`
      }));
    } else if (normApex && this.hosts.has(normApex)) {
      // Apex domain match
      results.push(new IndicatorClass({
        id: `threat_feed.${this.id}.apex`,
        source: this.id,
        category: 'reputation',
        polarity: 'negative',
        weight: -25,
        confidence: 'medium',
        value: { apex: normApex, provider: this.id },
        detail: `[!] Apex domain (${normApex}) listed in ${this.name} threat database`
      }));
    }

    return results;
  }

  /**
   * Add entries directly to provider memory
   * @param {string[]} exactUrls
   * @param {string[]} hosts
   */
  addEntries(exactUrls = [], hosts = []) {
    exactUrls.forEach(u => { if (u) this.exactUrls.add(String(u).trim()); });
    hosts.forEach(h => { if (h) this.hosts.add(String(h).toLowerCase().trim()); });
    this.entryCount = this.exactUrls.size + this.hosts.size;
    this.lastUpdated = Date.now();
  }

  clear() {
    this.exactUrls.clear();
    this.hosts.clear();
    this.entryCount = 0;
  }

  getStats() {
    return {
      id: this.id,
      name: this.name,
      enabled: this.enabled,
      exactUrls: this.exactUrls.size,
      hosts: this.hosts.size,
      totalEntries: this.entryCount,
      lastUpdated: this.lastUpdated,
      lastError: this.lastError
    };
  }
}

/**
 * URLhaus (abuse.ch) Provider - Zero-cost open malware and phishing URLs
 */
class URLhausProvider extends ThreatIntelProvider {
  constructor(options = {}) {
    super({
      id: 'urlhaus',
      name: 'URLhaus (abuse.ch)',
      feedUrl: 'https://urlhaus.abuse.ch/downloads/json_recent/',
      format: 'json',
      enabled: true,
      confidence: 'high',
      updateIntervalMinutes: 60,
      ...options
    });
  }

  async fetchAndParse(timeoutMs = 30000) {
    if (!this.feedUrl) return { exactUrls: [], hosts: [] };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const resp = await fetch(this.feedUrl, {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' }
      });
      clearTimeout(timer);

      if (!resp.ok) throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
      const data = await resp.json();

      const exactUrls = [];
      const hosts = [];

      // URLhaus JSON format: object with URLs or array of items
      if (Array.isArray(data)) {
        data.forEach(item => {
          if (item && item.url) exactUrls.push(item.url);
          if (item && item.host) hosts.push(item.host);
        });
      } else if (data && typeof data === 'object') {
        // Feed format often keyed by ID or array under 'urls'
        const entries = Array.isArray(data.urls) ? data.urls : Object.values(data);
        entries.forEach(item => {
          if (typeof item === 'string') {
            exactUrls.push(item);
          } else if (item && typeof item === 'object') {
            if (item.url) exactUrls.push(item.url);
            if (item.host) hosts.push(item.host);
          }
        });
      }

      this.lastError = null;
      return { exactUrls, hosts };
    } catch (err) {
      clearTimeout(timer);
      this.lastError = err.message;
      return { exactUrls: [], hosts: [] };
    }
  }
}

/**
 * OpenPhish Community Feed Provider - Zero-cost community phishing feed
 */
class OpenPhishProvider extends ThreatIntelProvider {
  constructor(options = {}) {
    super({
      id: 'openphish',
      name: 'OpenPhish Community Feed',
      feedUrl: 'https://openphish.com/feed.txt',
      format: 'text',
      enabled: true,
      confidence: 'high',
      updateIntervalMinutes: 60,
      ...options
    });
  }

  async fetchAndParse(timeoutMs = 30000) {
    if (!this.feedUrl) return { exactUrls: [], hosts: [] };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const resp = await fetch(this.feedUrl, {
        signal: controller.signal,
        headers: { 'Accept': 'text/plain' }
      });
      clearTimeout(timer);

      if (!resp.ok) throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
      const text = await resp.text();

      const exactUrls = [];
      const hosts = [];
      const lines = text.split(/\r?\n/);

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        exactUrls.push(trimmed);

        try {
          const u = new URL(trimmed);
          if (u.hostname) hosts.push(u.hostname.toLowerCase());
        } catch (_) {}
      }

      this.lastError = null;
      return { exactUrls, hosts };
    } catch (err) {
      clearTimeout(timer);
      this.lastError = err.message;
      return { exactUrls: [], hosts: [] };
    }
  }
}

/**
 * Threat Intelligence Registry
 * Coordinates all threat providers and aggregates indicator lookups.
 */
class ThreatIntelRegistry {
  constructor() {
    this.providers = new Map();
  }

  /**
   * Register a threat intel provider
   * @param {ThreatIntelProvider} provider
   */
  register(provider) {
    if (provider && provider.id) {
      this.providers.set(provider.id, provider);
    }
    return this;
  }

  get(id) {
    return this.providers.get(id) || null;
  }

  getAll() {
    return Array.from(this.providers.values());
  }

  /**
   * Query all registered providers for threat indicators
   * @param {string} url - Canonical URL
   * @param {string} domain - Domain / Hostname
   * @param {string} [apexDomain] - Apex domain
   * @returns {Indicator[]} Aggregated indicators from all active providers
   */
  lookup(url, domain, apexDomain) {
    const indicators = [];
    for (const provider of this.providers.values()) {
      if (provider.enabled) {
        try {
          const res = provider.lookup(url, domain, apexDomain);
          if (Array.isArray(res)) {
            indicators.push(...res);
          }
        } catch (err) {
          console.warn(`[ThreatIntel] Lookup error in ${provider.id}:`, err);
        }
      }
    }
    return indicators;
  }

  /**
   * Get aggregated summary statistics
   */
  getStats() {
    const stats = {};
    let totalEntries = 0;
    for (const [id, provider] of this.providers.entries()) {
      const pStats = provider.getStats();
      stats[id] = pStats;
      totalEntries += pStats.totalEntries;
    }
    return {
      providers: stats,
      providerCount: this.providers.size,
      totalEntries
    };
  }
}

// Environment exports
if (typeof self !== 'undefined') {
  self.ThreatIntelProvider = ThreatIntelProvider;
  self.URLhausProvider = URLhausProvider;
  self.OpenPhishProvider = OpenPhishProvider;
  self.ThreatIntelRegistry = ThreatIntelRegistry;
}
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      ThreatIntelProvider,
      URLhausProvider,
      OpenPhishProvider,
      ThreatIntelRegistry
    };
  }
})();
