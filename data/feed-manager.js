/**
 * SafeClick 2.0 - Unified Threat Feed Manager
 * Open Source Browser Security Engine
 * 
 * Manages automated, zero-cost, open threat feed ingestion.
 * All supported feeds are 100% free, require zero API keys,
 * and operate strictly without maintainer infrastructure.
 */

class FeedManager {
  constructor(repDB, options = {}, threatCache = null) {
    this.repDB = repDB;
    this.threatCache = threatCache || options.threatCache || null;
    this.options = {
      updateIntervalMinutes: options.updateIntervalMinutes || 60,
      alarmName: 'safeclick_feed_update',
      timeoutMs: options.timeoutMs || 30000,
      maxEntriesPerFeed: options.maxEntriesPerFeed || 10000,
      ...options
    };

    this.feeds = {
      urlhaus: {
        id: 'urlhaus',
        name: 'URLhaus (abuse.ch)',
        url: 'https://urlhaus.abuse.ch/downloads/json_recent/',
        format: 'json',
        enabled: true,
        description: 'Recent malicious and phishing URLs'
      },
      openphish: {
        id: 'openphish',
        name: 'OpenPhish Community Feed',
        url: 'https://openphish.com/feed.txt',
        format: 'text',
        enabled: true,
        description: 'Community phishing URL list'
      }
    };

    this.isUpdating = false;
    this.lastUpdateStats = {
      lastRunTime: null,
      successCount: 0,
      failureCount: 0,
      feedResults: {}
    };
  }

  /**
   * Initialize alarms and automatic refresh schedule
   */
  async init() {
    try {
      if (typeof chrome !== 'undefined' && chrome.alarms) {
        await chrome.alarms.clear(this.options.alarmName).catch(() => {});
        chrome.alarms.create(this.options.alarmName, {
          delayInMinutes: 2, // Give browser time to stabilize after startup
          periodInMinutes: this.options.updateIntervalMinutes
        });

        chrome.alarms.onAlarm.addListener((alarm) => {
          if (alarm && alarm.name === this.options.alarmName) {
            this.updateAllFeeds().catch(err => {
              console.warn('[FeedManager] Scheduled update error:', err);
            });
          }
        });
      }

      // Check if threatCache or reputation data is empty or stale (> 3 hours old)
      const cacheEmpty = !this.threatCache || (this.threatCache.exactUrls.size === 0 && this.threatCache.hosts.size === 0);
      const isStale = !this.repDB || !this.repDB.updatedAt || (this.repDB.updatedAt < (Date.now() - 3 * 60 * 60 * 1000));

      if (cacheEmpty || isStale) {
        console.log('[FeedManager] Threat cache is empty or stale. Triggering live threat feed ingestion...');
        setTimeout(() => {
          this.updateAllFeeds().catch(err => {
            console.warn('[FeedManager] Initial feed update error:', err);
          });
        }, 1500);
      }

      console.log(`[FeedManager] Initialized with interval ${this.options.updateIntervalMinutes}m`);
      return true;
    } catch (e) {
      console.warn('[FeedManager] Init failed:', e);
      return false;
    }
  }

  /**
   * Parse plain-text feed (one URL/domain per line)
   */
  /**
   * Check if a host belongs to a multi-tenant public platform
   * (e.g. github.com, drive.google.com, vercel.app).
   * Threats on these platforms must only be matched by exact URL, never by whole host.
   */
  isMultiTenant(host) {
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

  parseTextFeed(text) {
    const urls = [];
    const hosts = new Set();
    if (!text || typeof text !== 'string') return { urls, hosts: [] };

    const lines = text.split(/\r?\n/);
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#') || line.startsWith('//')) continue;

      try {
        const u = new URL(line);
        u.hash = '';
        urls.push(u.toString());
        if (u.hostname && !this.isMultiTenant(u.hostname)) {
          hosts.add(u.hostname.toLowerCase());
        }
      } catch (_) {
        // Fallback for hostnames without scheme
        const host = line.toLowerCase().replace(/^www\./, '');
        if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(host) && !this.isMultiTenant(host)) {
          hosts.add(host);
        }
      }
    }

    return { urls, hosts: Array.from(hosts) };
  }

  /**
   * Parse URLhaus JSON feed
   */
  parseUrlhausJson(jsonText) {
    const urls = [];
    const hosts = new Set();
    if (!jsonText) return { urls, hosts: [] };

    try {
      const data = typeof jsonText === 'string' ? JSON.parse(jsonText) : jsonText;
      let entries = [];
      if (Array.isArray(data)) {
        entries = data;
      } else if (data && typeof data === 'object') {
        if (Array.isArray(data.urls)) {
          entries = data.urls;
        } else {
          for (const val of Object.values(data)) {
            if (Array.isArray(val)) {
              for (const item of val) {
                if (item && item.url) entries.push(item);
              }
            } else if (val && val.url) {
              entries.push(val);
            }
          }
        }
      }

      for (const item of entries) {
        if (!item || !item.url) continue;
        try {
          const u = new URL(item.url);
          u.hash = '';
          urls.push(u.toString());
          if (u.hostname && !this.isMultiTenant(u.hostname)) {
            hosts.add(u.hostname.toLowerCase());
          }
        } catch (_) {}
      }
    } catch (e) {
      console.warn('[FeedManager] Failed to parse URLhaus JSON, attempting text fallback:', e);
      return this.parseTextFeed(typeof jsonText === 'string' ? jsonText : '');
    }

    return { urls, hosts: Array.from(hosts) };
  }

  /**
   * Fetch a single feed with timeout and error handling
   */
  async fetchFeed(feedConfig) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.options.timeoutMs);

    try {
      console.log(`[FeedManager] Fetching ${feedConfig.name}...`);
      const response = await fetch(feedConfig.url, {
        signal: controller.signal,
        headers: {
          'Accept': feedConfig.format === 'json' ? 'application/json, text/plain, */*' : 'text/plain, */*'
        }
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP status ${response.status}`);
      }

      const text = await response.text();
      let parsed = { urls: [], hosts: [] };

      if (feedConfig.format === 'json') {
        parsed = this.parseUrlhausJson(text);
      } else {
        parsed = this.parseTextFeed(text);
      }

      // Cap entries to prevent excessive memory usage
      if (parsed.urls.length > this.options.maxEntriesPerFeed) {
        parsed.urls = parsed.urls.slice(0, this.options.maxEntriesPerFeed);
      }
      if (parsed.hosts.length > this.options.maxEntriesPerFeed) {
        parsed.hosts = parsed.hosts.slice(0, this.options.maxEntriesPerFeed);
      }

      console.log(`[FeedManager] ${feedConfig.name}: parsed ${parsed.urls.length} URLs, ${parsed.hosts.length} hosts`);
      return parsed;
    } catch (e) {
      clearTimeout(timeoutId);
      console.warn(`[FeedManager] Fetch error for ${feedConfig.name}:`, e.message);
      return null;
    }
  }

  /**
   * Update all enabled feeds and integrate into reputation storage
   */
  async updateAllFeeds() {
    if (this.isUpdating) {
      console.log('[FeedManager] Update already in progress, skipping');
      return { skipped: true };
    }

    this.isUpdating = true;
    const startTime = Date.now();
    const results = {};
    let totalNewUrls = 0;
    let totalNewHosts = 0;

    try {
      for (const [id, feed] of Object.entries(this.feeds)) {
        if (!feed.enabled) continue;

        try {
          const data = await this.fetchFeed(feed);
          if (data) {
            results[id] = {
              success: true,
              urls: data.urls.length,
              hosts: data.hosts.length,
              timestamp: Date.now()
            };
            totalNewUrls += data.urls.length;
            totalNewHosts += data.hosts.length;

            // Ingest into ThreatCache if available (dynamic Bloom filter + IndexedDB)
            if (this.threatCache && typeof this.threatCache.ingest === 'function') {
              this.threatCache.ingest(id, { exactUrls: data.urls, hosts: data.hosts }).catch(() => {});
            }

            // Ingest into ReputationDB if available
            if (this.repDB) {
              if (typeof this.repDB.addUrls === 'function' && data.urls.length > 0) {
                this.repDB.addUrls(data.urls);
              }
              if (typeof this.repDB.addHosts === 'function' && data.hosts.length > 0) {
                this.repDB.addHosts(data.hosts);
              }
            }
          } else {
            results[id] = { success: false, error: 'Empty or failed fetch', timestamp: Date.now() };
          }
        } catch (feedErr) {
          results[id] = { success: false, error: feedErr.message, timestamp: Date.now() };
        }
      }

      this.lastUpdateStats = {
        lastRunTime: Date.now(),
        durationMs: Date.now() - startTime,
        totalUrlsProcessed: totalNewUrls,
        totalHostsProcessed: totalNewHosts,
        feedResults: results
      };

      console.log(`[FeedManager] Feed update completed in ${Date.now() - startTime}ms`);
      return this.lastUpdateStats;
    } finally {
      this.isUpdating = false;
    }
  }

  /**
   * Diagnostics stats
   */
  getStats() {
    return {
      isUpdating: this.isUpdating,
      feeds: Object.keys(this.feeds).map(k => ({
        id: k,
        name: this.feeds[k].name,
        enabled: this.feeds[k].enabled
      })),
      lastUpdate: this.lastUpdateStats
    };
  }
}

// Export and backwards compatibility
if (typeof self !== 'undefined') {
  self.FeedManager = FeedManager;
  // Backwards compatibility alias
  self.UpdateManager = FeedManager;
  self.ThreatFeeds = {
    fetchAllFeeds: (opts) => new FeedManager(null, opts).updateAllFeeds()
  };
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = FeedManager;
}
