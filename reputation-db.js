// ReputationDB: offline multi-source reputation loader
// Loads bundled datasets (CSV/TXT) into an in-memory Set of hostnames with storage persistence.

class ReputationDB {
  constructor() {
    // Static bundles (in-memory only)
    this.set = new Set();
    this.exact = new Set();
    this.urlsExact = new Set();

    // Live dynamic feeds (persisted)
    this.liveSet = new Set();
    this.liveExact = new Set();
    this.liveUrlsExact = new Set();

    this.loaded = false;
    this.updatedAt = 0;
    this.STORAGE_KEYS = {
      liveDomains: 'rep_live_domains',
      liveExact: 'rep_live_exact_hosts',
      liveUrlsExact: 'rep_live_exact_urls',
      updated: 'rep_updated'
    };
    // Dynamic ThreatCache instance (if provided)
    this.threatCache = null;

    // Production bundles: Bundled static blacklists are eliminated in SafeClick 2.0
    // in favor of dynamic runtime caching and open threat feeds.
    this.bundles = [];

    // Use UrlUtils for eTLD+1 extraction (single source of truth)

    // SECURITY NOTE: SAFE_ETLD1 list was removed.
    // Attackers routinely host phishing on Google Docs, GitHub Pages, Dropbox, etc.
    // Each URL must be evaluated on its own merits, not exempted by platform.
  }

  async init() {
    try {
      console.log('[ReputationDB] Hydrating live dynamic feeds from storage...');
      const obj = await chrome.storage.local.get([
        this.STORAGE_KEYS.liveDomains,
        this.STORAGE_KEYS.liveExact,
        this.STORAGE_KEYS.liveUrlsExact,
        this.STORAGE_KEYS.updated
      ]);
      const arr = Array.isArray(obj[this.STORAGE_KEYS.liveDomains]) ? obj[this.STORAGE_KEYS.liveDomains] : [];
      if (arr.length > 0) {
        arr.forEach(h => { if (h && !this._isSafe(h)) this.liveSet.add(String(h).toLowerCase()); });
      }
      const exactArr = Array.isArray(obj[this.STORAGE_KEYS.liveExact]) ? obj[this.STORAGE_KEYS.liveExact] : [];
      if (exactArr.length > 0) {
        exactArr.forEach(h => { if (h && !this._isSafe(h)) this.liveExact.add(String(h).toLowerCase()); });
      }
      const urlsExactArr = Array.isArray(obj[this.STORAGE_KEYS.liveUrlsExact]) ? obj[this.STORAGE_KEYS.liveUrlsExact] : [];
      if (urlsExactArr.length > 0) {
        urlsExactArr.forEach(u => { if (u) this.liveUrlsExact.add(String(u)); });
      }
      this.updatedAt = obj[this.STORAGE_KEYS.updated] || Date.now();
      console.log('[ReputationDB] Live feeds hydrated. Domains:', this.liveSet.size, 'Exact hosts:', this.liveExact.size, 'Exact URLs:', this.liveUrlsExact.size);
    } catch (_) { }

    try {
      // Always refresh from bundled files (fast + ensures availability on first run)
      console.log('[ReputationDB] Loading static bundles directly into memory...');
      await this.updateFromBundles();
      this.loaded = true;
      console.log('[ReputationDB] Static bundles loaded. Domains:', this.set.size, 'Exact hosts:', this.exact.size, 'Exact URLs:', this.urlsExact.size);
      return true;
    } catch (e) {
      console.warn('[ReputationDB] init/update failed:', e);
      // Keep whatever we have
      this.loaded = this.set.size >= 0;
      return false;
    }
  }

  async updateFromBundles() {
    const domains = new Set();
    const exactHosts = new Set();
    const exactUrls = new Set();
    for (const url of this.bundles) {
      try {
        const resp = await fetch(url);
        if (!resp.ok) continue;
        const text = await resp.text();
        this._parseIntoSet(text, url, domains, exactHosts, exactUrls);
      } catch (e) {
        console.warn('[ReputationDB] Failed to load bundle', url, e);
      }
    }
    // Replace existing with freshly built sets to avoid stale entries
    this.set = domains;
    this.exact = exactHosts;
    this.urlsExact = exactUrls;
    this.updatedAt = Date.now();
    // Do not call persist() here; static bundles are read-only and loaded from extension files on startup
  }

  _parseIntoSet(text, sourceUrl, outApexSet, outExactSet, outExactUrlSet) {
    if (!text) return;
    // Strip BOM if present
    const content = String(text).replace(/^\uFEFF/, '');
    const lowerSrc = String(sourceUrl || '').toLowerCase();
    const isCsv = lowerSrc.endsWith('.csv') || content.includes(',');
    const isUrlList = lowerSrc.endsWith('/data/urls.txt') || lowerSrc.endsWith('urls.txt');
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      let raw = lines[i];
      if (typeof raw !== 'string') continue;
      let line = raw.trim();
      if (!line) continue;
      // Skip full-line comments or section headers (including ABP '!' comments)
      if (line.startsWith('#') || line.startsWith('!') || line.startsWith('//') || line.startsWith(';') || /\[[^\]]+\]/.test(line)) continue;

      // Adblock Plus syntax handling (for OISD ABP lists)
      // Examples:
      //   ||example.com^
      //   |http://example.com/path
      //   @@||allowlisted.com^        (exception; ignore)
      //   example.com##.ad-banner     (cosmetic; ignore)
      //   example.com#@#.ad-banner    (cosmetic exception; ignore)
      if (line.includes('##') || line.includes('#@#')) continue; // cosmetic rules
      if (line.startsWith('@@')) continue; // exception rules (allowlist)
      if (line.startsWith('||') || line.startsWith('|')) {
        let t = line;
        // Remove leading anchors
        if (t.startsWith('||')) t = t.slice(2);
        else if (t.startsWith('|')) t = t.slice(1);
        // Stop at separator '^' if present
        if (t.includes('^')) t = t.split('^')[0];
        // If it looks like a URL after anchors, drop scheme and path
        t = t.replace(/^https?:\/\//i, '');
        if (t.includes('/')) t = t.split('/')[0];
        // Remove leading/trailing dots and wildcards
        t = t.replace(/^\*+\.?/, '').replace(/\.*$/, '').replace(/^\.+|\.+$/g, '');
        if (t) {
          const host = this._normalizeHost(t);
          if (host) {
            const apex = this._getETLD1FromHost(host);
            if (apex) {
              // ABP network rule: if rule targets a subdomain (host != apex), keep exact host; else add apex
              if (!this._isSafe(apex)) {
                if (host !== apex) outExactSet.add(host);
                else outApexSet.add(apex);
              }
            }
          }
          continue; // handled ABP line
        }
      }

      let candidate = '';
      if (isCsv) {
        // CSV: take the first cell that looks like a URL/host
        const cells = line.split(',');
        candidate = (cells[0] || '').trim();
      } else if (!isUrlList) {
        // ABP or plain host lists
        // ABP style: remove anchors like ||, |, and delimiters like ^
        // e.g., ||example.com^ maps to example.com
        let t = line;
        if (t.startsWith('!')) continue; // comment
        if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith('\'') && t.endsWith('\''))) {
          t = t.slice(1, -1);
        }
        if (!t) continue;
        if (/^https?:\/\//i.test(t) || /^[A-Za-z0-9.*-]+\.[A-Za-z]{2,}$/.test(t)) { candidate = t; break; }
      } else {
        // URL list (one URL per line). Keep only URL/host portion.
        candidate = line.split(/\s+/)[0];
      }
      // remove inline comments from candidate
      candidate = String(candidate).split(/\s+#|\s+;|\s+\/\//)[0].trim();
      const host = this._normalizeHost(candidate);
      if (host) {
        const apex = this._getETLD1FromHost(host);
        if (isCsv || isUrlList) {
          // For CSV feeds (e.g., URLhaus), only flag the exact host to avoid collateral on large platforms
          if (!this._isSafe(apex)) outExactSet.add(host);
          // Also track exact URL when source is a URL list
          if (isUrlList) {
            try {
              const u = new URL(candidate);
              u.hash = '';
              outExactUrlSet.add(u.toString());
            } catch (_) {
              // If candidate lacked scheme, attempt http
              try {
                const u2 = new URL(/^https?:\/\//i.test(candidate) ? candidate : ('http://' + candidate));
                u2.hash = '';
                outExactUrlSet.add(u2.toString());
              } catch (_) { }
            }
          }
        } else if (apex) {
          if (!this._isSafe(apex)) outApexSet.add(apex);
        }
      }
    }
  }

  _normalizeHost(urlOrDomain) {
    try {
      let s = String(urlOrDomain || '').trim();
      if (!s) return '';
      // Remove wildcards and surrounding quotes, trim dots
      s = s.replace(/^\*\./, '').replace(/^['\"]|['\"]$/g, '').replace(/^\.+|\.+$/g, '');
      let h = '';
      if (/^https?:\/\//i.test(s)) {
        h = new URL(s).hostname;
      } else {
        // Force through URL parser to get punycode-encoded hostname
        h = new URL('http://' + s.replace(/^\.+|\.+$/g, '')).hostname;
      }
      h = (h || '').toLowerCase().replace(/\.$/, '');
      // Skip IP literals
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(h)) return '';
      if (/^\[?[0-9a-f:]+\]?$/i.test(h)) return '';
      // Basic hostname sanity
      if (!/[a-z0-9-]\.[a-z]/.test(h)) return '';
      return h;
    } catch (_) { return ''; }
  }

  _getETLD1FromHost(host) {
    // Delegate to shared UrlUtils module
    return typeof UrlUtils !== 'undefined' ? UrlUtils.getETLD1FromHost(host) : (host || '');
  }

  async persist() {
    try {
      const arr = Array.from(this.liveSet);
      const exactArr = Array.from(this.liveExact);
      const exactUrlsArr = Array.from(this.liveUrlsExact);
      await chrome.storage.local.set({
        [this.STORAGE_KEYS.liveDomains]: arr,
        [this.STORAGE_KEYS.liveExact]: exactArr,
        [this.STORAGE_KEYS.liveUrlsExact]: exactUrlsArr,
        [this.STORAGE_KEYS.updated]: this.updatedAt
      });
    } catch (_) { }
  }

  // _isSafe method: protects multi-tenant platforms from whole-domain blacklisting
  _isSafe(host) {
    if (!host) return false;
    if (typeof UrlUtils !== 'undefined' && typeof UrlUtils.isMultiTenantPlatform === 'function') {
      return UrlUtils.isMultiTenantPlatform(host);
    }
    const h = String(host || '').toLowerCase().replace(/^www\./, '');
    const known = [
      'github.com', 'raw.githubusercontent.com', 'gist.github.com', 'gitlab.com',
      'google.com', 'drive.google.com', 'docs.google.com', 'sites.google.com',
      'dropbox.com', 'onedrive.live.com', 'discord.com', 'cloudflare.com',
      'pages.dev', 'workers.dev', 'vercel.app', 'netlify.app', 'amazonaws.com', 'azurewebsites.net'
    ];
    return known.some(d => h === d || h.endsWith('.' + d));
  }

  isListed(urlOrDomain) {
    try {
      if (!this.loaded) return false;
      // First, try exact URL match if input looks like a URL
      try {
        const u = new URL(urlOrDomain);
        u.hash = '';
        const uStr = u.toString();
        if (this.urlsExact.has(uStr) || this.liveUrlsExact.has(uStr) || (this.threatCache && this.threatCache.hasExactUrl(uStr))) return true;
      } catch (_) { }
      const host = this._normalizeHost(urlOrDomain);
      if (!host || this._isSafe(host)) return false;
      const apex = this._getETLD1FromHost(host);
      if (apex && this._isSafe(apex)) return false;
      // Check exact host match first, then apex
      if (this.exact.has(host) || this.liveExact.has(host) || (this.threatCache && this.threatCache.hasHost(host))) return true;
      if (apex && (this.set.has(apex) || this.liveSet.has(apex) || (this.threatCache && this.threatCache.hasHost(apex)))) return true;
      return false;
    } catch (_) { return false; }
  }

  // Exact-host match only (e.g., subdomain.example.com)
  isListedExact(urlOrDomain) {
    try {
      if (!this.loaded) return false;
      const host = this._normalizeHost(urlOrDomain);
      if (!host || this._isSafe(host)) return false;
      return this.exact.has(host) || this.liveExact.has(host) || (this.threatCache && this.threatCache.hasHost(host));
    } catch (_) { return false; }
  }

  // Exact URL match (scheme+host+path+query), fragment-insensitive
  isListedExactUrl(url) {
    try {
      if (!this.loaded) return false;
      const u = new URL(url);
      u.hash = '';
      const uStr = u.toString();
      return this.urlsExact.has(uStr) || this.liveUrlsExact.has(uStr) || (this.threatCache && this.threatCache.hasExactUrl(uStr));
    } catch (_) { return false; }
  }

  // Apex-only check (eTLD+1)
  isListedApex(urlOrDomain) {
    try {
      if (!this.loaded) return false;
      const host = this._normalizeHost(urlOrDomain);
      if (!host || this._isSafe(host)) return false;
      const apex = this._getETLD1FromHost(host);
      if (!apex || this._isSafe(apex)) return false;
      return this.set.has(apex) || this.liveSet.has(apex) || (this.threatCache && this.threatCache.hasHost(apex));
    } catch (_) { return false; }
  }

  /**
   * Merge live threat feed data into the database.
   * Called by UpdateManager to incorporate fresh threat intelligence.
   * @param {Object} feedData - Object with arrays: { domains: [], urls: [], hosts: [] }
   * @param {string} feedSource - Identifier for the feed (e.g., 'urlhaus', 'openphish')
   * @returns {Object} Stats about merged entries
   */
  mergeLiveFeed(feedData, feedSource = 'live') {
    const stats = { domains: 0, hosts: 0, urls: 0, source: feedSource };
    try {
      if (!feedData) return stats;

      // Merge apex domains
      if (Array.isArray(feedData.domains)) {
        for (const domain of feedData.domains) {
          const normalized = String(domain || '').toLowerCase().trim();
          if (normalized && !this._isSafe(normalized) && !this.set.has(normalized) && !this.liveSet.has(normalized)) {
            this.liveSet.add(normalized);
            stats.domains++;
          }
        }
      }

      // Merge exact hosts
      if (Array.isArray(feedData.hosts)) {
        for (const host of feedData.hosts) {
          const normalized = String(host || '').toLowerCase().trim();
          if (normalized && !this._isSafe(normalized) && !this.exact.has(normalized) && !this.liveExact.has(normalized)) {
            this.liveExact.add(normalized);
            stats.hosts++;
          }
        }
      }

      // Merge exact URLs
      if (Array.isArray(feedData.urls)) {
        for (const url of feedData.urls) {
          try {
            const u = new URL(url);
            u.hash = '';
            const normalized = u.toString();
            if (!this.urlsExact.has(normalized) && !this.liveUrlsExact.has(normalized)) {
              this.liveUrlsExact.add(normalized);
              stats.urls++;
            }
          } catch (_) { } // Skip invalid URLs
        }
      }

      // Update timestamp and persist
      this.updatedAt = Date.now();
      this.persist().catch(() => { });

      console.log(`[ReputationDB] Merged ${stats.domains} domains, ${stats.hosts} hosts, ${stats.urls} URLs from ${feedSource}`);
      return stats;
    } catch (e) {
      console.warn('[ReputationDB] mergeLiveFeed error:', e);
      return stats;
    }
  }

  /**
   * Get database statistics for diagnostics
   */
  getStats() {
    return {
      domains: this.set.size + this.liveSet.size,
      exactHosts: this.exact.size + this.liveExact.size,
      exactUrls: this.urlsExact.size + this.liveUrlsExact.size,
      loaded: this.loaded,
      lastUpdated: this.updatedAt,
      lastUpdatedISO: new Date(this.updatedAt).toISOString()
    };
  }
}

if (typeof self !== 'undefined') {
  self.ReputationDB = ReputationDB;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ReputationDB;
}

