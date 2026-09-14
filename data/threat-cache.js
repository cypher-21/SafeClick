/**
 * SafeClick 2.0 - Dynamic Threat Cache Layer
 * Open Source Browser Security Engine
 * 
 * Combines an in-memory Bloom filter for instant sub-millisecond fast-path checks
 * with IndexedDB (and storage fallback) for zero false-positive verification.
 * Replaces all bundled static blacklists with dynamic, auto-updating local cache.
 */

(function () {
  'use strict';

  // Handle environments (Browser vs Node.js)
  const _Bloom = (typeof BloomFilter !== 'undefined') ? BloomFilter : (function () {
    try { return require('../modules/bloom-filter.js'); } catch (_) { return null; }
  })();

  class ThreatCache {
  constructor(options = {}) {
    this.maxEntries = options.maxEntries || 30000;
    this.dbName = 'SafeClickThreatDB';
    this.dbVersion = 1;
    this.db = null;
    this.loaded = false;

    // Fast-path in-memory sets & Bloom filter
    this.exactUrls = new Set();
    this.hosts = new Set();
    this.bloom = null;

    this.STORAGE_KEY = 'threat_cache_meta';
  }

  /**
   * Initialize cache, IndexedDB connection, and rebuild in-memory Bloom filter
   */
  async init() {
    try {
      if (typeof indexedDB !== 'undefined') {
        await this._initIndexedDB();
        await this._loadFromIndexedDB();
      } else if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        await this._loadFromChromeStorage();
      }
    } catch (err) {
      console.warn('[ThreatCache] Storage init fallback to in-memory:', err);
    }

    this._rebuildBloomFilter();
    this.loaded = true;
    return true;
  }

  /**
   * Fast-path check for exact URL presence
   * @param {string} url - Exact URL
   * @returns {boolean}
   */
  hasExactUrl(url) {
    if (!url) return false;
    const norm = String(url).trim();
    if (!norm) return false;

    // Step 1: Sub-millisecond Bloom Filter fast path
    if (this.bloom && !this.bloom.mightContain(this.bloom, norm)) {
      return false; // Guaranteed 100% negative (zero false negatives)
    }

    // Step 2: Exact check to eliminate false positives
    return this.exactUrls.has(norm);
  }

  /**
   * Fast-path check for host presence
   * @param {string} host - Hostname
   * @returns {boolean}
   */
  hasHost(host) {
    if (!host) return false;
    const norm = String(host).toLowerCase().trim();
    if (!norm) return false;

    // Step 1: Sub-millisecond Bloom Filter fast path
    if (this.bloom && !this.bloom.mightContain(this.bloom, norm)) {
      return false; // Guaranteed 100% negative
    }

    // Step 2: Exact check
    return this.hosts.has(norm);
  }

  /**
   * Combined security lookup
   * @param {string} url - Target URL
   * @param {string} domain - Target hostname
   * @param {string} [apexDomain] - Target apex domain
   */
  lookup(url, domain, apexDomain) {
    const normUrl = String(url || '').trim();
    const normDomain = String(domain || '').toLowerCase().trim();
    const normApex = String(apexDomain || '').toLowerCase().trim();

    const isExactUrl = this.hasExactUrl(normUrl);
    const isHostListed = this.hasHost(normDomain);
    const isApexListed = normApex ? this.hasHost(normApex) : false;

    return {
      listed: isExactUrl || isHostListed || isApexListed,
      exactUrlListed: isExactUrl,
      hostListed: isHostListed,
      apexListed: isApexListed
    };
  }

  /**
   * Bulk ingest entries from a threat feed into cache
   * @param {string} feedId - Source identifier (e.g. 'urlhaus', 'openphish')
   * @param {Object} data - { exactUrls: string[], hosts: string[] }
   */
  async ingest(feedId, { exactUrls = [], hosts = [] }) {
    if (!Array.isArray(exactUrls) && !Array.isArray(hosts)) return;

    let addedCount = 0;
    const now = Date.now();

    // Ingest into in-memory sets
    for (const u of exactUrls) {
      if (u && typeof u === 'string') {
        const norm = u.trim();
        if (norm && !this.exactUrls.has(norm)) {
          this.exactUrls.add(norm);
          addedCount++;
        }
      }
    }

    for (const h of hosts) {
      if (h && typeof h === 'string') {
        const norm = h.toLowerCase().trim();
        if (norm && !this.hosts.has(norm)) {
          this.hosts.add(norm);
          addedCount++;
        }
      }
    }

    // Enforce max entry cap
    this._enforceCap();

    // Rebuild Bloom filter
    this._rebuildBloomFilter();

    // Persist to underlying store (non-blocking)
    this._persist(feedId, now).catch(err => {
      console.warn('[ThreatCache] Persist error:', err);
    });

    return { addedCount, totalUrls: this.exactUrls.size, totalHosts: this.hosts.size };
  }

  /**
   * Rebuild the in-memory Bloom filter from current sets
   */
  _rebuildBloomFilter() {
    const Bloom = _Bloom || (typeof BloomFilter !== 'undefined' ? BloomFilter : null);
    if (!Bloom || typeof Bloom.create !== 'function') return;

    const totalItems = Math.max(1000, this.exactUrls.size + this.hosts.size);
    // Target 1% false positive rate
    const filter = Bloom.create(totalItems, 0.01);

    for (const u of this.exactUrls) {
      Bloom.add(filter, u);
    }
    for (const h of this.hosts) {
      Bloom.add(filter, h);
    }

    filter.mightContain = Bloom.mightContain;
    this.bloom = filter;
  }

  _enforceCap() {
    if (this.exactUrls.size > this.maxEntries) {
      const dropCount = this.exactUrls.size - this.maxEntries;
      let dropped = 0;
      for (const u of this.exactUrls) {
        this.exactUrls.delete(u);
        dropped++;
        if (dropped >= dropCount) break;
      }
    }

    if (this.hosts.size > this.maxEntries) {
      const dropCount = this.hosts.size - this.maxEntries;
      let dropped = 0;
      for (const h of this.hosts) {
        this.hosts.delete(h);
        dropped++;
        if (dropped >= dropCount) break;
      }
    }
  }

  /**
   * Clear all cache entries
   */
  async clear() {
    this.exactUrls.clear();
    this.hosts.clear();
    this.bloom = null;

    try {
      if (this.db) {
        const tx = this.db.transaction(['exact_urls', 'hosts'], 'readwrite');
        tx.objectStore('exact_urls').clear();
        tx.objectStore('hosts').clear();
      }
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        await chrome.storage.local.remove([this.STORAGE_KEY]);
      }
    } catch (_) {}
  }

  getStats() {
    const Bloom = _Bloom || (typeof BloomFilter !== 'undefined' ? BloomFilter : null);
    const bloomStats = (Bloom && this.bloom && typeof Bloom.getStats === 'function')
      ? Bloom.getStats(this.bloom)
      : null;

    return {
      loaded: this.loaded,
      exactUrlsCount: this.exactUrls.size,
      hostsCount: this.hosts.size,
      totalEntries: this.exactUrls.size + this.hosts.size,
      maxEntries: this.maxEntries,
      bloomFilter: bloomStats
    };
  }

  // --- Storage Internals ---

  _initIndexedDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.dbName, this.dbVersion);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('exact_urls')) {
          db.createObjectStore('exact_urls', { keyPath: 'url' });
        }
        if (!db.objectStoreNames.contains('hosts')) {
          db.createObjectStore('hosts', { keyPath: 'host' });
        }
      };
      req.onsuccess = (e) => {
        this.db = e.target.result;
        resolve(this.db);
      };
      req.onerror = (e) => reject(e.target.error);
    });
  }

  _loadFromIndexedDB() {
    if (!this.db) return Promise.resolve();
    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction(['exact_urls', 'hosts'], 'readonly');
        const urlsReq = tx.objectStore('exact_urls').getAll();
        const hostsReq = tx.objectStore('hosts').getAll();

        tx.oncomplete = () => {
          if (Array.isArray(urlsReq.result)) {
            urlsReq.result.forEach(row => { if (row && row.url) this.exactUrls.add(row.url); });
          }
          if (Array.isArray(hostsReq.result)) {
            hostsReq.result.forEach(row => { if (row && row.host) this.hosts.add(row.host); });
          }
          resolve();
        };
        tx.onerror = () => resolve();
      } catch (_) {
        resolve();
      }
    });
  }

  async _loadFromChromeStorage() {
    try {
      const obj = await chrome.storage.local.get([this.STORAGE_KEY]);
      const data = obj[this.STORAGE_KEY];
      if (data && typeof data === 'object') {
        if (Array.isArray(data.urls)) {
          data.urls.forEach(u => this.exactUrls.add(u));
        }
        if (Array.isArray(data.hosts)) {
          data.hosts.forEach(h => this.hosts.add(h));
        }
      }
    } catch (_) {}
  }

  async _persist(feedId, timestamp) {
    if (this.db) {
      return new Promise((resolve) => {
        try {
          const tx = this.db.transaction(['exact_urls', 'hosts'], 'readwrite');
          const urlStore = tx.objectStore('exact_urls');
          const hostStore = tx.objectStore('hosts');

          // Batch put
          for (const u of this.exactUrls) {
            urlStore.put({ url: u, feedId, timestamp });
          }
          for (const h of this.hosts) {
            hostStore.put({ host: h, feedId, timestamp });
          }
          tx.oncomplete = () => resolve();
          tx.onerror = () => resolve();
        } catch (_) {
          resolve();
        }
      });
    }

    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      try {
        await chrome.storage.local.set({
          [this.STORAGE_KEY]: {
            urls: Array.from(this.exactUrls).slice(0, 5000), // Cap storage
            hosts: Array.from(this.hosts).slice(0, 5000),
            updated: timestamp
          }
        });
      } catch (_) {}
    }
  }
}

  // Environment exports
  if (typeof self !== 'undefined') {
    self.ThreatCache = ThreatCache;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = ThreatCache;
  }
})();
