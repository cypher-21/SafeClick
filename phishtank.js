// PhishTank local database module
// Responsible for downloading, parsing, storing and querying PhishTank dataset locally

(function(){
  class PhishTankDB {
    constructor(config) {
      this.config = (typeof SafeClickConfig !== 'undefined' ? SafeClickConfig : {}) || {};
      this.threatCache = (config && config.threatCache) || null;
      // Optional offline static dataset (if present in development)
      this.datasetUrl = (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL)
        ? chrome.runtime.getURL('phishtank-urls.txt')
        : null;
      this.urls = new Set(); // exact URL matches (scheme+host+path+query, no fragment)
      this.lastUpdated = null;
      this.loaded = false;
    }

    // Initialize database (dynamic-first, loads static file only if present)
    async init() {
      try {
        if (this.datasetUrl) {
          const success = await this.updateDataset().catch(() => false);
          if (!success) {
            console.log('[PhishTank] Bundled static file not present; using dynamic threat cache.');
          }
        }
        this.loaded = true;
        return true;
      } catch (e) {
        console.warn('[PhishTank] Init fallback to dynamic cache:', e);
        this.urls = new Set();
        this.loaded = true;
        return true;
      }
    }

    // Persist current set to storage (no-op for dynamic cache)
    async persist() {
      // Handled by ThreatCache
    }

    // Add URLs dynamically from live threat feeds
    addUrls(urls) {
      if (!Array.isArray(urls)) return;
      urls.forEach(u => {
        try {
          const norm = new URL(u);
          norm.hash = '';
          this.urls.add(norm.toString());
        } catch (_) {}
      });
      this.lastUpdated = new Date().toISOString();
    }

    // Update dataset from bundled TXT if available
    async updateDataset() {
      if (!this.datasetUrl) return false;
      try {
        const resp = await fetch(this.datasetUrl);
        if (!resp || !resp.ok) return false;
        const text = await resp.text();
        const urls = this.parseTxtUrls(text);
        this.urls = urls;
        this.lastUpdated = new Date().toISOString();
        return true;
      } catch (_) {
        return false;
      }
    }

    // Parse TXT with one URL per line; build exact URLs only
    parseTxtUrls(text) {
      const urls = new Set();
      const lines = String(text || '').split(/\r?\n/);
      for (const raw of lines) {
        if (!raw || typeof raw !== 'string') continue;
        let line = raw.trim();
        if (!line || line.startsWith('#') || line.startsWith('//') || line.startsWith('!')) continue;
        try {
          const u = new URL(line);
          u.hash = '';
          const normalized = u.toString();
          urls.add(normalized);
        } catch (_) {
          // if not a valid URL, skip
        }
      }
      return urls;
    }

    // Local-only lookup helpers
    // 1) Exact URL including path/query (no fragment)
    isListedExactUrl(url) {
      try {
        const u = new URL(url);
        u.hash = '';
        const norm = u.toString();
        if (this.urls.has(norm)) return true;
        if (this.threatCache && typeof this.threatCache.hasExactUrl === 'function') {
          return this.threatCache.hasExactUrl(norm);
        }
        return false;
      } catch (_) { return false; }
    }

    // 2) Host-only match
    isListedHost(urlOrHost) {
      return false;
    }

    // Backward-compat: delegate to exact URL only
    isListed(urlOrHost) {
      return this.isListedExactUrl(urlOrHost);
    }
  }

  // Expose globally
  if (typeof window !== 'undefined') {
    window.PhishTankDB = PhishTankDB;
  }
  
  // Make available globally for service worker
  if (typeof globalThis !== 'undefined') {
    globalThis.PhishTankDB = PhishTankDB;
  }
  
  if (typeof module !== 'undefined' && module.exports) module.exports = PhishTankDB;
})();
