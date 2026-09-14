/**
 * SafeClick 2.0 - Popup Security Dashboard
 * Open Source Browser Security Engine
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
// Enhanced SafeClick Popup with Security Dashboard
class SafeClickPopup {
  constructor() {
    this.currentTab = null;
    this.currentTrustScore = null;
    this.settings = {};
    this.whitelist = [];
    this.domainAllowlist = [];
    this.activeModalId = null;
    this.previouslyFocusedEl = null;
    this._modalKeydownHandler = null;
    this.currentTabView = 'main';
    this.initializeElements();
    this.bindEvents();
    this.loadSettings();
    this.initializePopup();
  }

  // ========== Blocked Sites ==========
  async loadBlockedSites() {
    try {
      const resp = await this.sendMessageWithTimeout({ type: 'GET_BLOCKED_SITES' }, 5000);
      if (resp && Array.isArray(resp.sites)) {
        // Normalize existing entries to canonical https://<host>
        const canon = Array.from(new Set(
          resp.sites
            .map(s => this.normalizeInputToUrl(s))
            .filter(Boolean)
        ));
        // Persist back if changed
        const changed = JSON.stringify(canon) !== JSON.stringify(resp.sites);
        if (changed) {
          try { await chrome.storage.local.set({ blockedSites: canon }); } catch (_) { }
        }
        this.blockedSites = canon;
      } else {
        // Fallback to direct storage if background doesn’t recognize the message
        const obj = await chrome.storage.local.get(['blockedSites']);
        const raw = Array.isArray(obj.blockedSites) ? obj.blockedSites : [];
        const canon = Array.from(new Set(raw.map(s => this.normalizeInputToUrl(s)).filter(Boolean)));
        if (JSON.stringify(canon) !== JSON.stringify(raw)) {
          try { await chrome.storage.local.set({ blockedSites: canon }); } catch (_) { }
        }
        this.blockedSites = canon;
      }
      this.renderBlockedSites();
    } catch (_) {
      this.blockedSites = [];
      this.renderBlockedSites();
    }
  }

  normalizeInputToUrl(input) {
    try {
      let s = String(input || '').trim();
      if (!s) return '';
      // If user pastes our interstitial URL, extract the real target
      try {
        const iu = new URL(s);
        if (iu.protocol === 'chrome-extension:' && /interstitial\.html$/i.test(iu.pathname) && iu.searchParams.has('target')) {
          s = iu.searchParams.get('target') || s;
        }
      } catch (_) { /* not a full URL yet, continue */ }

      // Ensure a scheme for URL parsing
      if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
      const u = new URL(s);
      // Only accept http/https
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
      const host = (u.hostname || '').toLowerCase();
      if (!host) return '';
      // Canonicalize: always store as https://<host>
      return `https://${host}`;
    } catch (_) { return ''; }
  }

  async addBlockedSite() {
    const raw = this.blockedUrlInput?.value || '';
    const url = this.normalizeInputToUrl(raw);
    if (!url) {
      this.showNotification('Please enter a valid website URL', 'error');
      return;
    }
    try {
      console.log('[Popup][Blocked] Adding', url);
      this.showNotification('Blocking site…', 'info');
      const resp = await this.sendMessageWithTimeout({ type: 'ADD_BLOCKED_SITE', url }, 5000);
      if (resp && resp.success) {
        this.blockedUrlInput.value = '';
        await this.loadBlockedSites();
        this.showNotification('Site blocked', 'success');
      } else {
        // Fallback: write directly to storage so the UI works even if background isn't updated yet
        console.warn('[Popup][Blocked] Add failed, falling back to storage:', resp);
        const obj = await chrome.storage.local.get(['blockedSites']);
        const list = Array.isArray(obj.blockedSites) ? obj.blockedSites : [];
        if (!list.includes(url)) list.unshift(url);
        await chrome.storage.local.set({ blockedSites: list });
        this.blockedUrlInput.value = '';
        await this.loadBlockedSites();
        this.showNotification('Site blocked (local)', 'success');
      }
    } catch (_) {
      console.error('[Popup][Blocked] Add error', _);
      // Final fallback
      try {
        const obj = await chrome.storage.local.get(['blockedSites']);
        const list = Array.isArray(obj.blockedSites) ? obj.blockedSites : [];
        if (!list.includes(url)) list.unshift(url);
        await chrome.storage.local.set({ blockedSites: list });
        this.blockedUrlInput.value = '';
        await this.loadBlockedSites();
        this.showNotification('Site blocked (local)', 'success');
      } catch (e) {
        this.showNotification('Failed to block site', 'error');
      }
    }
  }

  handleBlockedAction(e) {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const action = btn.getAttribute('data-action');
    const url = btn.getAttribute('data-url');
    if (action === 'unblock' && url) this.removeBlockedSite(url);
  }

  async removeBlockedSite(url) {
    try {
      console.log('[Popup][Blocked] Removing', url);
      const resp = await this.sendMessageWithTimeout({ type: 'REMOVE_BLOCKED_SITE', url }, 5000);
      if (resp && resp.success) {
        await this.loadBlockedSites();
        this.showNotification('Site unblocked', 'success');
      } else {
        console.warn('[Popup][Blocked] Remove failed, falling back to storage:', resp);
        const obj = await chrome.storage.local.get(['blockedSites']);
        const list = Array.isArray(obj.blockedSites) ? obj.blockedSites : [];
        const next = list.filter(u => u !== url);
        await chrome.storage.local.set({ blockedSites: next });
        await this.loadBlockedSites();
        this.showNotification('Site unblocked (local)', 'success');
      }
    } catch (_) {
      console.error('[Popup][Blocked] Remove error', _);
      try {
        const obj = await chrome.storage.local.get(['blockedSites']);
        const list = Array.isArray(obj.blockedSites) ? obj.blockedSites : [];
        const next = list.filter(u => u !== url);
        await chrome.storage.local.set({ blockedSites: next });
        await this.loadBlockedSites();
        this.showNotification('Site unblocked (local)', 'success');
      } catch (e) {
        this.showNotification('Failed to unblock', 'error');
      }
    }
  }

  renderBlockedSites() {
    if (this.blockedCountBadge) {
      const count = (this.blockedSites || []).length;
      this.blockedCountBadge.textContent = `${count} Site${count === 1 ? '' : 's'}`;
    }
    if (!this.blockedListEl) return;
    const items = (this.blockedSites || []).map((url) => {
      const host = this.safeHost(url);
      return `
      <li class="blocked-item">
        <div class="list-item-meta">
          <span class="badge-danger-tag">BLOCKED</span>
          <span class="blocked-url" title="${this.escapeAttr(url)}">${this.escapeAttr(host)}</span>
        </div>
        <button class="action-btn-mini danger-mini" data-action="unblock" data-url="${this.escapeAttr(url)}" title="Unblock site">Unblock</button>
      </li>`;
    }).join('');
    this.blockedListEl.innerHTML = items || `
      <li class="empty-list-card">
        <div class="empty-list-icon">
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>
          </svg>
        </div>
        <span class="empty-list-title">No Blocked Websites</span>
        <span class="empty-list-desc">Add URLs above to restrict access to unsafe or suspicious pages.</span>
      </li>`;
  }

  // Open About modal and set version dynamically
  openAbout() {
    try {
      const verEl = document.getElementById('about-version');
      const manifest = chrome.runtime.getManifest?.();
      if (verEl && manifest?.version) {
        verEl.textContent = `v${manifest.version}`;
      }
      // Set Privacy Policy link from config if available
      try {
        const link = document.getElementById('privacy-link');
        const url = (typeof SafeClickConfig !== 'undefined' && SafeClickConfig?.PRIVACY_URL) ? SafeClickConfig.PRIVACY_URL : '';
        if (link) {
          if (url) {
            link.href = url;
            link.style.display = 'inline';
          } else {
            link.style.display = 'none';
          }
        }
      } catch (_) { }
      this.openModal('about-modal');
    } catch (_) {
      this.openModal('about-modal');
    }
  }

  async loadRepdbStatus() {
    try {
      if (!this.currentTab || !this.currentTab.url) return;
      // Show loading state
      if (this.repdbStatusEl) this.repdbStatusEl.textContent = 'Loading...';
      const resp = await this.sendMessageWithTimeout({ type: 'REPDB_STATUS', url: this.currentTab.url }, 7000);
      if (!resp || resp.error) {
        if (this.repdbStatusEl) this.repdbStatusEl.textContent = 'Error';
        return;
      }
      const data = resp.data || {};
      const loaded = !!data.loaded;
      if (!loaded) {
        if (this.repdbStatusEl) {
          this.repdbStatusEl.textContent = 'Loading...';
          this.repdbStatusEl.style.color = '#6B7280';
        }
        return;
      }
      const listed = !!data.listed;
      const count = typeof data.count === 'number' ? data.count : 0;
      const updatedAt = data.updatedAt || 0;
      if (this.repdbStatusEl) {
        this.repdbStatusEl.textContent = listed ? 'Listed in ReputationDB' : 'Not listed';
        this.repdbStatusEl.style.color = listed ? '#EF4444' : '#10B981';
      }
      if (this.repdbCountEl) {
        const formatted = Number(count).toLocaleString();
        this.repdbCountEl.textContent = `${formatted} entr${count === 1 ? 'y' : 'ies'}`;
      }
      if (this.repdbUpdatedEl) this.repdbUpdatedEl.textContent = `Updated: ${this.formatTime(updatedAt)}`;
    } catch (_) {
      if (this.repdbStatusEl) this.repdbStatusEl.textContent = 'Error';
    }
  }

  // Update the small badge on the Redirections tab
  updateRedirectionsBadge(count) {
    // Removed badge UI; no-op
    return;
  }

  // ReputationDB manual reload removed

  switchTab(tabName) {
    this.currentTabView = tabName;

    // Update tab buttons
    document.querySelectorAll('.nav-tab').forEach(tab => {
      tab.classList.remove('active');
      tab.setAttribute('aria-selected', 'false');
    });
    const activeTab = document.getElementById(`${tabName}-tab`);
    if (activeTab) {
      activeTab.classList.add('active');
      activeTab.setAttribute('aria-selected', 'true');
    }

    // Update content visibility using CSS classes instead of inline styles
    document.querySelectorAll('.tab-content').forEach(content => {
      content.classList.remove('active');
    });
    const targetContent = document.getElementById(`${tabName}-content`);
    if (targetContent) {
      targetContent.classList.add('active');
    }

    // Focus chat input when AI tab is active
    if (tabName === 'ai' && this.aiChatInput) {
      setTimeout(() => this.aiChatInput.focus(), 80);
    }

    // Load data for the active tab
    if (tabName === 'redirections') {
      this.loadRedirectionsData();
    } else if (tabName === 'blocked') {
      this.loadBlockedSites();
    }
  }

  async loadRedirectionsData() {
    // Only maintain Domain Allowlist; tab redirections have been removed from UI
    try {
      await this.loadDomainAllowlist();
    } catch (error) {
      console.error('Failed to load allowlist data:', error);
    }
    return [];
  }

  async loadTabRedirections() {
    // Feature removed; no-op
    return [];
  }

  renderTabRedirections(redirects) {
    // Feature removed; ensure any existing list is cleared
    if (this.tabRedirectionsList) this.tabRedirectionsList.innerHTML = '';
  }

  async loadDomainAllowlist() {
    try {
      const resp = await this.sendMessageWithTimeout({ type: 'GET_DOMAIN_ALLOWLIST' }, 5000);
      this.domainAllowlist = (resp && Array.isArray(resp.domains)) ? resp.domains : [];
      this.renderDomainAllowlist();
    } catch (_) {
      this.domainAllowlist = [];
      this.renderDomainAllowlist();
    }
  }

  renderDomainAllowlist() {
    if (this.allowlistCountBadge) {
      const count = (this.domainAllowlist || []).length;
      this.allowlistCountBadge.textContent = `${count} Domain${count === 1 ? '' : 's'}`;
    }
    if (!this.domainAllowlistEl) return;
    const items = this.domainAllowlist.map(domain => `
      <li class="domain-item">
        <div class="list-item-meta">
          <span class="badge-success-tag">TRUSTED</span>
          <span class="domain-name">${domain}</span>
        </div>
        <button class="action-btn-mini" data-action="remove-domain" data-domain="${this.escapeAttr(domain)}" title="Remove domain">Remove</button>
      </li>
    `).join('');
    this.domainAllowlistEl.innerHTML = items || `
      <li class="empty-list-card">
        <div class="empty-list-icon success-icon">
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <polyline points="9 12 11 14 15 10"></polyline>
          </svg>
        </div>
        <span class="empty-list-title">No Custom Allowed Domains</span>
        <span class="empty-list-desc">Trust internal portals or work sites to bypass safety interstitials.</span>
      </li>`;
  }

  async runFullPageAudit() {
    this.switchTab('ai');
    const query = 'Perform a comprehensive security audit of this entire page, analyze all threat signals (SSL, domain integrity, forms, credentials, threat feeds, and heuristic signals), and provide an executive security report.';
    if (this.aiChatInput) this.aiChatInput.value = 'Full Page Security Audit';
    await this.handleAskAiSubmit(query);
  }

  async allowCurrentDomain() {
    let domain = this.currentTrustScore?.details?.domain;
    if (!domain && this.currentTab?.url) {
      try { domain = new URL(this.currentTab.url).hostname; } catch (_) {}
    }
    if (!domain) {
      this.showNotification('No active domain to allow', 'error');
      return;
    }
    if (this.newDomainInput) this.newDomainInput.value = domain;
    await this.addDomainToAllowlist();
  }

  async blockCurrentSite() {
    const url = this.currentTab?.url;
    if (!url) {
      this.showNotification('No active website to block', 'error');
      return;
    }
    if (this.blockedUrlInput) this.blockedUrlInput.value = url;
    await this.addBlockedSite();
  }

  async addDomainToAllowlist() {
    const domain = this.newDomainInput?.value?.trim();
    if (!domain) return;

    try {
      const resp = await this.sendMessageWithTimeout({ type: 'ADD_DOMAIN_TO_ALLOWLIST', domain }, 5000);
      if (resp && resp.success) {
        this.newDomainInput.value = '';
        await this.loadDomainAllowlist();
        this.showNotification(`Domain ${domain} added to allowlist`, 'success');
      } else {
        this.showError('Failed to add domain to allowlist');
      }
    } catch (_) {
      this.showError('Failed to add domain to allowlist');
    }
  }

  async removeDomainFromAllowlist(domain) {
    try {
      const resp = await this.sendMessageWithTimeout({ type: 'REMOVE_DOMAIN_FROM_ALLOWLIST', domain }, 5000);
      if (resp && resp.success) {
        await this.loadDomainAllowlist();
        this.showNotification(`Domain ${domain} removed from allowlist`, 'success');
      } else {
        this.showError('Failed to remove domain from allowlist');
      }
    } catch (_) {
      this.showError('Failed to remove domain from allowlist');
    }
  }



  handleRedirectionAction(e) {
    // Feature removed; no-op
    return;
  }

  handleDomainAllowlistAction(e) {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;

    const action = btn.getAttribute('data-action');
    const domain = btn.getAttribute('data-domain');

    if (action === 'remove-domain') {
      this.removeDomainFromAllowlist(domain);
    }
  }

  async allowRedirect(url) { /* removed */ }

  async blockRedirect(url) { /* removed */ }

  // Small helpers
  safeHost(u) {
    try { return new URL(u).hostname; } catch (_) { return u || ''; }
  }
  escapeAttr(s) {
    return String(s || '').replace(/"/g, '&quot;');
  }


  updateWarningBadge() {
    try {
      if (!this.currentTab || typeof this.currentTab.id !== 'number') return;
      const key = `tab_${this.currentTab.id}`;
      chrome.storage.local.get([key], (obj) => {
        const meta = obj && obj[key] ? obj[key] : null;
        const ts = meta && meta.lastWarningAt ? meta.lastWarningAt : null;
        const shown = !!ts;
        if (this.warningBadge) {
          this.warningBadge.style.display = shown ? 'inline-block' : 'none';
          this.warningBadge.title = shown ? `Last warning: ${this.formatTime(ts)}` : '';
        }
      });
    } catch (_) { }
  }

  openVirusTotalLookup() {
    try {
      let domain = this.currentTrustScore?.details?.domain;
      if (!domain && this.currentTab?.url) {
        try {
          const u = new URL(this.currentTab.url);
          if (u.protocol.startsWith('http')) {
            domain = u.hostname;
          }
        } catch (_) {}
      }
      if (!domain) {
        this.showNotification('No active domain to scan', 'error');
        return;
      }
      const vtUrl = `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`;
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
        chrome.tabs.create({ url: vtUrl });
      } else {
        window.open(vtUrl, '_blank', 'noopener,noreferrer');
      }
    } catch (err) {
      console.error('Failed to open VirusTotal lookup:', err);
      this.showNotification('Failed to open VirusTotal', 'error');
    }
  }

  initializeElements() {
    // Main sections
    this.trustScoreSection = document.getElementById('trust-score-section');
    this.loadingSection = document.getElementById('loading-section');
    this.errorSection = document.getElementById('error-section');
    this.reasonsSection = document.getElementById('reasons-section');
    // simplified info section
    this.infoSection = document.getElementById('info-section');
    // score breakdown section removed

    // Tab navigation
    this.mainTab = document.getElementById('main-tab');
    this.aiTab = document.getElementById('ai-tab');
    this.redirectionsTab = document.getElementById('redirections-tab');
    this.blockedTab = document.getElementById('blocked-tab');
    this.redirectionsBadge = null; // badge removed from UI
    this.mainContent = document.getElementById('main-content');
    this.aiContent = document.getElementById('ai-content');
    this.redirectionsContent = document.getElementById('redirections-content');
    this.blockedContent = document.getElementById('blocked-content');
    this.openAiTabBtn = document.getElementById('open-ai-tab-btn');
    this.exportIocAiBtn = document.getElementById('export-ioc-ai-btn');
    this.aiFullAuditBtn = document.getElementById('ai-full-audit-btn');
    this.allowCurrentDomainBtn = document.getElementById('allow-current-domain-btn');
    this.blockCurrentDomainBtn = document.getElementById('block-current-domain-btn');
    this.currentDomainLabelAllow = document.getElementById('current-domain-label-allow');
    this.currentDomainLabelBlock = document.getElementById('current-domain-label-block');
    this.allowlistCountBadge = document.getElementById('allowlist-count-badge');
    this.blockedCountBadge = document.getElementById('blocked-count-badge');

    // Redirections UI (Tab-specific list removed)
    this.tabRedirectionsList = null;
    this.domainAllowlistEl = document.getElementById('domain-allowlist');
    this.newDomainInput = document.getElementById('new-domain-input');
    this.addDomainBtn = document.getElementById('add-domain-btn');
    this.testRedirectBtn = null; // removed from UI

    // Trust score elements
    this.scoreNumber = document.getElementById('score-number');
    this.scoreBar = document.getElementById('score-bar');
    this.scoreFill = document.getElementById('score-fill');
    this.scoreText = document.getElementById('score-text');
    this.verdictText = document.getElementById('verdict-text');
    this.verdictIcon = document.getElementById('verdict-icon');
    this.domainName = document.getElementById('domain-name');
    this.scanTime = document.getElementById('scan-time');

    // Action buttons
    this.rescanBtn = document.getElementById('rescan-btn');
    this.whitelistBtn = document.getElementById('whitelist-btn');
    this.removeWhitelistBtn = document.getElementById('remove-whitelist-btn');

    // Simplified info panel elements
    this.ptStatus = document.getElementById('pt-status');
    // removed: heuristics-status (card removed from UI)
    this.redirectsCard = document.getElementById('redirects-card');
    this.redirectsSummary = document.getElementById('redirects-summary');
    // hosting country removed
    // ReputationDB card elements
    // 4-Pillar Security Inspection Grid
    this.transportStatusEl = document.getElementById('transport-status');
    this.transportDetailEl = document.getElementById('transport-detail');
    this.intelStatusEl = document.getElementById('intel-status');
    this.intelDetailEl = document.getElementById('intel-detail');
    this.identityStatusEl = document.getElementById('identity-status');
    this.identityDetailEl = document.getElementById('identity-detail');
    this.mlStatusEl = document.getElementById('ml-status');
    this.mlDetailEl = document.getElementById('ml-detail');

    // Action buttons
    this.vtBtn = document.getElementById('vt-btn');

    // Footer links
    this.settingsLink = document.getElementById('settings-btn');
    this.historyLink = document.getElementById('history-btn');
    this.helpLink = document.getElementById('help-btn');
    this.aboutLink = document.getElementById('about-btn');

    // Header warning badge
    this.warningBadge = document.getElementById('warning-badge');
    // Settings controls removed: reset-allowlist-btn, clear-warning-badge-btn

    // Domain copy elements
    this.domainNameEl = document.getElementById('domain-name');
    this.copyDomainBtn = document.getElementById('copy-domain-btn');

    // Blocked sites elements
    this.blockedListEl = document.getElementById('blocked-sites-list');
    this.blockedUrlInput = document.getElementById('blocked-url-input');
    this.blockSiteBtn = document.getElementById('block-site-btn');

    // AI Advisory UI elements
    this.aiAdvisorySection = document.getElementById('ai-advisory-section');
    this.aiProviderBadge = document.getElementById('ai-provider-badge');
    this.aiOpinionText = document.getElementById('ai-opinion-text');
    this.aiRecommendationText = document.getElementById('ai-recommendation-text');
    this.aiEnabledToggle = document.getElementById('ai-enabled');
    this.aiSettingsBlock = document.getElementById('ai-settings-block');
    this.aiEngineSelect = document.getElementById('ai-engine-select');
    this.chromeAiDiag = document.getElementById('chrome-ai-diag');
    this.chromeAiStatusIndicator = document.getElementById('chrome-ai-status-indicator');
    this.chromeAiStatusText = document.getElementById('chrome-ai-status-text');
    this.geminiKeyContainer = document.getElementById('gemini-key-container');
    this.geminiApiKeyInput = document.getElementById('gemini-api-key');
    this.testGeminiKeyBtn = document.getElementById('test-gemini-key-btn');
    this.geminiKeyStatus = document.getElementById('gemini-key-status');
    this.geminiModelSelect = document.getElementById('gemini-model-select');
    this.refreshGeminiModelsBtn = document.getElementById('refresh-gemini-models-btn');
    this.geminiModelHint = document.getElementById('gemini-model-hint');

    // Ask SafeClick AI & IoC elements
    this.askAiSection = document.getElementById('ask-ai-section');
    this.aiChatInput = document.getElementById('ai-chat-input');
    this.aiChatSendBtn = document.getElementById('ai-chat-send');
    this.aiChatResponse = document.getElementById('ai-chat-response');
    this.aiChatText = document.getElementById('ai-chat-text');
    this.aiChatSource = document.getElementById('ai-chat-source');
    this.aiChatCopyBtn = document.getElementById('ai-chat-copy-btn');
    this.socialEngineeringAlert = document.getElementById('social-engineering-alert');
    this.seTacticBadge = document.getElementById('se-tactic-badge');
    this.seDetailText = document.getElementById('se-detail-text');
    this.exportIocBtn = document.getElementById('export-ioc-btn');
  }

  bindEvents() {
    // Tab navigation
    this.mainTab?.addEventListener('click', () => this.switchTab('main'));
    this.aiTab?.addEventListener('click', () => this.switchTab('ai'));
    this.redirectionsTab?.addEventListener('click', () => this.switchTab('redirections'));
    this.blockedTab?.addEventListener('click', () => this.switchTab('blocked'));
    this.openAiTabBtn?.addEventListener('click', () => this.switchTab('ai'));
    this.exportIocAiBtn?.addEventListener('click', () => this.exportIoCReport());
    this.aiFullAuditBtn?.addEventListener('click', () => this.runFullPageAudit());
    this.allowCurrentDomainBtn?.addEventListener('click', () => this.allowCurrentDomain());
    this.blockCurrentDomainBtn?.addEventListener('click', () => this.blockCurrentSite());

    // Action buttons
    this.rescanBtn?.addEventListener('click', () => this.rescanSite());
    this.whitelistBtn?.addEventListener('click', () => this.addToWhitelist());
    this.removeWhitelistBtn?.addEventListener('click', () => this.removeFromWhitelist());
    // Copy domain button
    this.copyDomainBtn?.addEventListener('click', () => this.copyDomain());

    // Footer links
    this.settingsLink?.addEventListener('click', () => this.showSettings());
    this.historyLink?.addEventListener('click', () => this.showHistory());
    this.helpLink?.addEventListener('click', () => this.showHelp());
    this.aboutLink?.addEventListener('click', () => this.openAbout());

    // VirusTotal 1-click domain lookup
    this.vtBtn?.addEventListener('click', () => this.openVirusTotalLookup());

    // Ask SafeClick AI events
    this.aiChatSendBtn?.addEventListener('click', () => this.handleAskAiSubmit());
    this.aiChatInput?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.handleAskAiSubmit();
    });
    this.aiChatCopyBtn?.addEventListener('click', () => this.copyAiChatResponse());
    document.querySelectorAll('.ai-chip').forEach(chip => {
      chip.addEventListener('click', (e) => {
        const query = e.target.getAttribute('data-query');
        if (query) {
          if (this.aiChatInput) this.aiChatInput.value = query;
          this.handleAskAiSubmit(query);
        }
      });
    });

    // Export IoC brief
    this.exportIocBtn?.addEventListener('click', () => this.exportIoCReport());
    // ReputationDB reload removed

    // Redirections management (only allowlist retained)
    this.addDomainBtn?.addEventListener('click', () => this.addDomainToAllowlist());
    this.domainAllowlistEl?.addEventListener('click', (e) => this.handleDomainAllowlistAction(e));

    // Blocked sites
    this.blockSiteBtn?.addEventListener('click', () => this.addBlockedSite());
    this.blockedUrlInput?.addEventListener('keypress', (e) => { if (e.key === 'Enter') this.addBlockedSite(); });
    this.blockedListEl?.addEventListener('click', (e) => this.handleBlockedAction(e));


    // UPI toggle removed (payment section simplified)

    // Live updates for redirects removed (feature no longer shown in UI)

    // Enter key for domain input
    this.newDomainInput?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.addDomainToAllowlist();
    });

    // Modal close buttons
    document.getElementById('settings-close')?.addEventListener('click', () => this.hideSettings());
    document.getElementById('history-close')?.addEventListener('click', () => this.hideHistory());

    // Settings modal events
    document.getElementById('settings-modal')?.addEventListener('click', (e) => {
      if (e.target.id === 'settings-modal') this.hideSettings();
    });

    document.getElementById('history-modal')?.addEventListener('click', (e) => {
      if (e.target.id === 'history-modal') this.hideHistory();
    });

    // About modal events
    document.getElementById('about-close')?.addEventListener('click', () => this.closeModal('about-modal'));
    document.getElementById('about-modal')?.addEventListener('click', (e) => {
      if (e.target.id === 'about-modal') this.closeModal('about-modal');
    });

    // Settings controls
    document.getElementById('protection-enabled')?.addEventListener('change', (e) => {
      this.updateSetting('protectionEnabled', e.target.checked);
      // Setting updated
    });

    // AI Settings controls
    this.aiEnabledToggle?.addEventListener('change', (e) => {
      const enabled = e.target.checked;
      this.updateSetting('aiEnabled', enabled);
      if (this.aiSettingsBlock) {
        this.aiSettingsBlock.style.display = enabled ? 'block' : 'none';
      }
    });

    this.aiEngineSelect?.addEventListener('change', (e) => {
      const engine = e.target.value;
      this.updateSetting('aiEngine', engine);
      if (this.geminiKeyContainer) {
        this.geminiKeyContainer.style.display = engine === 'byok-gemini' ? 'block' : 'none';
      }
      this.checkChromeAiStatus();
    });

    this.geminiApiKeyInput?.addEventListener('change', (e) => {
      const key = e.target.value.trim();
      this.updateSetting('geminiApiKey', key);
    });

    this.geminiModelSelect?.addEventListener('change', (e) => {
      const model = e.target.value;
      this.updateSetting('geminiModel', model);
    });

    this.refreshGeminiModelsBtn?.addEventListener('click', () => this.fetchGeminiModels());

    this.testGeminiKeyBtn?.addEventListener('click', () => this.testGeminiApiKey());

    // Link to get Gemini API key
    const openAiStudioKeyPage = (e) => {
      e?.preventDefault();
      const url = 'https://aistudio.google.com/app/apikey';
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
        chrome.tabs.create({ url });
      } else {
        window.open(url, '_blank', 'noopener,noreferrer');
      }
    };
    document.getElementById('get-gemini-key-link')?.addEventListener('click', openAiStudioKeyPage);
    document.getElementById('get-gemini-key-link2')?.addEventListener('click', openAiStudioKeyPage);

    // Dark mode toggle removed; dark mode is always on

    // Export button
    document.getElementById('export-btn')?.addEventListener('click', () => this.exportHistory());
    // Clear history button
    document.getElementById('clear-history-btn')?.addEventListener('click', () => this.clearHistory());

    // Open Settings modal
    this.settingsLink?.addEventListener('click', () => this.showSettings());
  }

  // Copy current domain name to clipboard
  copyDomain() {
    try {
      const domain = this.domainNameEl?.textContent?.trim();
      if (!domain) {
        this.showNotification('No domain to copy', 'info');
        return;
      }
      const doNotify = () => this.showNotification('Domain copied to clipboard', 'success');
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(domain).then(doNotify).catch(() => doNotify());
      } else {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = domain;
        ta.setAttribute('readonly', '');
        ta.style.position = 'absolute';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch (_) { }
        document.body.removeChild(ta);
        doNotify();
      }
    } catch (_) {
      this.showNotification('Failed to copy domain', 'error');
    }
  }

  async initializePopup() {
    try {
      // Get the current active tab
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      this.currentTab = tabs[0];
      console.log('[Popup][initializePopup] Active tab:', this.currentTab?.id, this.currentTab?.url);

      if (!this.currentTab || !this.currentTab.url) {
        this.showError('No active tab found');
        return;
      }

      // Check if it's a valid HTTP/HTTPS URL
      if (!this.currentTab.url.startsWith('http')) {
        this.showError('Not a valid webpage');
        return;
      }

      // Update domain display
      const domain = new URL(this.currentTab.url).hostname;
      if (this.domainName) {
        this.domainName.textContent = domain;
      }
      if (this.currentDomainLabelAllow) {
        this.currentDomainLabelAllow.textContent = domain;
      }
      if (this.currentDomainLabelBlock) {
        this.currentDomainLabelBlock.textContent = domain;
      }

      // Update warning badge (if a warning was shown for this tab)
      this.updateWarningBadge();

      // Load domain allowlist
      await this.loadDomainAllowlist();
      // Load ReputationDB status for current tab
      await this.loadRepdbStatus();

      // Get trust score from background script
      await this.getTrustScore();

      // Load redirections data but keep the UI on the Main tab by default
      await this.loadRedirectionsData();

    } catch (error) {
      this.showError('Failed to initialize popup');
    }
  }

  async triggerTestRedirect() { /* removed */ }

  async getTrustScore() {
    try {
      this.showLoading();
      this.resetScoreDisplay();

      console.log('[Popup] Getting trust score for tab:', this.currentTab.id);

      // Send message to background script to get trust score
      const response = await this.sendMessageWithTimeout({
        type: 'GET_TRUST_SCORE',
        tabId: this.currentTab.id
      }, 20000);

      console.log('[Popup] Response received:', response);

      if (response && response.error) {
        console.error('[Popup] Error response:', response.error);
        this.showError(response.error);
        return;
      }

      if (!response || typeof response.score !== 'number') {
        console.error('[Popup] Invalid response:', response);
        this.showError('Invalid response from background script');
        return;
      }

      this.currentTrustScore = response;
      this.displayTrustScore();
      this.updateWhitelistButtons();

    } catch (error) {
      console.error('[Popup] getTrustScore error:', error);
      this.showError('Failed to get trust score: ' + error.message);
    }
  }

  displayTrustScore() {
    if (!this.currentTrustScore) return;

    const { score, verdict, reasons, details } = this.currentTrustScore;

    // Displaying trust score and verdict

    // Update score display
    if (this.scoreNumber) this.scoreNumber.textContent = score;
    if (this.scoreFill) {
      this.scoreFill.style.width = `${score}%`;
      this.scoreFill.style.backgroundColor = this.getScoreColor(score, verdict);
    }

    // Update score text (Trust Score: X/100)
    if (this.scoreText) {
      this.scoreText.textContent = `${score}/100`;
      // Score text updated
    }

    // Update verdict
    if (this.verdictText) this.verdictText.textContent = this.getVerdictText(verdict);
    if (this.verdictIcon) this.verdictIcon.innerHTML = this.getVerdictIconSvg(verdict, 18);

    // Update scan time
    if (this.scanTime && details.timestamp) {
      this.scanTime.textContent = this.formatTime(details.timestamp);
    }

    // Update status indicator to show completion
    this.updateStatusIndicator(verdict);

    // Display reasons (ordered by severity only; breakdown removed)
    this.displayReasons(reasons);

    // Display simplified info
    this.displayInfoPanel(details);

    // Display AI Advisory second opinion if present
    this.displayAIOpinion(details?.aiOpinion);
    this.checkSocialEngineeringDisplay(details);

    // Score breakdown removed from UI

    // Show main content
    this.hideLoading();
    this.hideError();
    this.showTrustScore();
  }

  displayReasons(reasons) {
    if (!this.reasonsSection || !reasons) return;
    const reasonsList = this.reasonsSection.querySelector('ul');
    if (!reasonsList) return;

    // Show ALL reasons (including positive). Users want to know why a site is safe (e.g., 100/98) or unsafe.
    // We only sanitize empty entries.
    const filteredReasons = (() => {
      try {
        const all = Array.isArray(reasons) ? reasons : [];
        const base = all.map(r => String(r || '').trim()).filter(Boolean);
        // Conditionally remove redirect-related reasons when assessment is below 'warn'
        try {
          const assessment = this.currentTrustScore?.details?.detailedInfo?.redirectAssessment;
          const level = assessment?.level || 'none';
          if (level === 'none' || level === 'info') {
            const norm = (s) => String(s || '').trim();
            const redirectReasons = Array.isArray(assessment?.reasons) ? assessment.reasons.flatMap(r => String(r).split(';').map(s => s.trim()).filter(Boolean)) : [];
            const redirectSet = new Set(redirectReasons.map(norm));
            return base.filter(r => !redirectSet.has(norm(r)));
          }
        } catch (_) { }
        return base;
      } catch (_) {
        return [];
      }
    })();

    // Split composite reasons like "Suspicious form action; Brand mentioned..."
    const splitReasons = [];
    filteredReasons.forEach(r => {
      const parts = String(r).split(';').map(s => s.trim()).filter(Boolean);
      if (parts.length > 1) splitReasons.push(...parts); else splitReasons.push(r);
    });

    const classify = (text) => {
      const t = String(text || '').toLowerCase();
      // First explicit danger patterns
      if (
        text.includes('[X]') ||
        t.includes('phishing url found') ||
        t.includes('blocked') ||
        t.includes('danger') ||
        t.includes('malicious') ||
        t.includes('threat feed listed')
      ) return 'danger';
      // Warnings
      if (
        text.includes('[!]') ||
        t.includes('suspicious') ||
        t.includes('mixed') ||
        t.includes('redirect') ||
        t.includes('scarcity') ||
        t.includes('urgency') ||
        t.includes('authority') ||
        t.includes('no https') ||
        t.includes('not encrypted') ||
        t.includes('invalid ssl')
      ) return 'warn';
      // Neutral / Unknown / Informational
      if (
        text.includes('[?]') ||
        text.includes('[i]') ||
        t.includes('unknown') ||
        t.includes('no threat feed match') ||
        t.includes('unverified') ||
        t.includes('no reputation history')
      ) return 'neutral';
      // Clean / Safe statements
      if (
        text.includes('[OK]') ||
        /^no\s+.+\s+detected\.?$/i.test(text) ||
        t.includes('no suspicious') ||
        t.includes('no phishing detected') ||
        t.includes('normal domain pattern') ||
        t.includes('direct url') ||
        t.includes('no redirects detected') ||
        t.includes('no manipulation detected') ||
        t.includes('no significant risks') ||
        t.includes('https enabled') ||
        t.includes('valid ssl certificate') ||
        t.includes('valid') ||
        t.includes('not flagged') ||
        t.includes('no issues') ||
        t.includes('passed') ||
        t.includes('clean')
      ) return 'success';
      return 'neutral';
    };

    const svgForClass = (cls, size = 14) => {
      switch (cls) {
        case 'danger':
          return `<svg class="sc-icon sc-icon-dangerous" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: #EF4444;"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
        case 'warn':
          return `<svg class="sc-icon sc-icon-suspicious" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: #F59E0B;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
        case 'success':
          return `<svg class="sc-icon sc-icon-safe" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: #10B981;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`;
        default:
          return `<svg class="sc-icon sc-icon-info" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: #3B82F6;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
      }
    };

    const items = splitReasons.map((reason) => {
      const cls = classify(reason);
      return { reason, cls };
    });
    const baseRank = { danger: 0, warn: 1, success: 2, neutral: 3 };
    items.sort((a, b) => {
      const ca = baseRank[a.cls] ?? 3;
      const cb = baseRank[b.cls] ?? 3;
      return ca - cb;
    });

    reasonsList.innerHTML = items.map(({ reason, cls }) => {
      const icon = svgForClass(cls, 14);
      return `<li class="reason-item is-${cls}"><span class="ri-icon" style="display: inline-flex; align-items: center; margin-right: 6px; vertical-align: middle;">${icon}</span><span class="ri-text">${reason.replace(/^(\[OK\]|\[X\]|\[!\]|\[i\]|\[\?\])\s*/, '')}</span></li>`;
    }).join('');
    this.reasonsSection.style.display = 'block';
  }

  displayInfoPanel(details) {
    if (!details) return;
    const url = this.currentTab?.url || '';
    const isHttps = url.startsWith('https://');

    // 1. Transport Security Pillar
    if (this.transportStatusEl && this.transportDetailEl) {
      if (isHttps) {
        this.transportStatusEl.textContent = 'TLS Secure';
        this.transportStatusEl.className = 'matrix-status status-safe';
        this.transportDetailEl.textContent = 'HTTPS Enforced';
      } else {
        this.transportStatusEl.textContent = 'Insecure';
        this.transportStatusEl.className = 'matrix-status status-warn';
        this.transportDetailEl.textContent = 'Unencrypted HTTP';
      }
    }

    // 2. Threat Intel Pillar
    if (this.intelStatusEl && this.intelDetailEl) {
      const isListed = details?.detailedInfo?.phishTank?.listed || (this.currentTrustScore?.score <= 15 && this.currentTrustScore?.verdict === 'DANGEROUS');
      if (isListed) {
        this.intelStatusEl.textContent = 'Malicious';
        this.intelStatusEl.className = 'matrix-status status-danger';
        this.intelDetailEl.textContent = 'Feed match detected';
      } else {
        this.intelStatusEl.textContent = 'Clean';
        this.intelStatusEl.className = 'matrix-status status-safe';
        this.intelDetailEl.textContent = '0 matches (URLhaus/OpenPhish)';
      }
    }

    // 3. Domain Integrity Pillar
    if (this.identityStatusEl && this.identityDetailEl) {
      const verdict = this.currentTrustScore?.verdict || 'UNKNOWN';
      const reasons = this.currentTrustScore?.reasons || [];
      const hasBrandIssue = reasons.some(r => /typo|homoglyph|combosquat|punycode|spoof/i.test(r));
      const hasEstablished = reasons.some(r => /verified|official|established/i.test(r));

      if (hasBrandIssue) {
        this.identityStatusEl.textContent = 'Suspicious';
        this.identityStatusEl.className = 'matrix-status status-danger';
        this.identityDetailEl.textContent = 'Potential brand lookalike';
      } else if (hasEstablished) {
        this.identityStatusEl.textContent = 'Verified';
        this.identityStatusEl.className = 'matrix-status status-safe';
        this.identityDetailEl.textContent = 'Established platform domain';
      } else {
        this.identityStatusEl.textContent = verdict === 'UNKNOWN' ? 'Unverified' : 'Standard';
        this.identityStatusEl.className = 'matrix-status status-neutral';
        this.identityDetailEl.textContent = 'No typosquatting detected';
      }
    }

    // 4. On-Device Machine Learning Pillar
    if (this.mlStatusEl && this.mlDetailEl) {
      const score = this.currentTrustScore?.score ?? 60;
      if (score >= 80) {
        this.mlStatusEl.textContent = 'Benign';
        this.mlStatusEl.className = 'matrix-status status-safe';
        this.mlDetailEl.textContent = 'High heuristic confidence';
      } else if (score <= 35) {
        this.mlStatusEl.textContent = 'High Risk';
        this.mlStatusEl.className = 'matrix-status status-danger';
        this.mlDetailEl.textContent = 'Phishing vector pattern';
      } else {
        this.mlStatusEl.textContent = 'Review';
        this.mlStatusEl.className = 'matrix-status status-warn';
        this.mlDetailEl.textContent = 'Mixed heuristic signals';
      }
    }
  }

  updateWhitelistButtons() {
    if (!this.currentTrustScore) return;

    const domain = this.currentTrustScore.details.domain;
    const isWhitelisted = this.whitelist.includes(domain);

    if (this.whitelistBtn) {
      this.whitelistBtn.style.display = isWhitelisted ? 'none' : 'block';
    }
    if (this.removeWhitelistBtn) {
      this.removeWhitelistBtn.style.display = isWhitelisted ? 'block' : 'none';
    }
  }

  async rescanSite() {
    try {
      this.showLoading();
      this.resetScoreDisplay();

      const response = await this.sendMessageWithTimeout({
        type: 'RESCAN_SITE',
        tabId: this.currentTab.id
      }, 30000);

      if (!response) {
        this.showError('No response from background. Please reload the extension and try again.');
        return;
      }
      if (response.error) {
        this.showError(response.error);
        return;
      }

      this.currentTrustScore = response;
      this.displayTrustScore();
      this.showNotification('Site rescanned successfully', 'success');
    } catch (error) {
      this.showError('Failed to rescan site');
    }
  }

  // Helper to send a runtime message with a timeout safeguard
  async sendMessageWithTimeout(message, timeoutMs = 20000) {
    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        resolve({ error: 'Request timeout' });
      }, timeoutMs);

      try {
        chrome.runtime.sendMessage(message, (response) => {
          clearTimeout(timeout);
          if (chrome.runtime.lastError) {
            resolve({ error: chrome.runtime.lastError.message });
          } else {
            resolve(response || { error: 'No response' });
          }
        });
      } catch (e) {
        clearTimeout(timeout);
        resolve({ error: e.message || 'Message failed' });
      }
    });
  }

  async addToWhitelist() {
    if (!this.currentTrustScore) return;

    const domain = this.currentTrustScore.details.domain;

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'ADD_TO_WHITELIST',
        domain: domain
      });

      if (response.success) {
        this.whitelist.push(domain);
        this.updateWhitelistButtons();
        this.showNotification('Site added to whitelist', 'success');
      } else {
        this.showError('Failed to add to whitelist');
      }
    } catch (error) {
      this.showError('Failed to add to whitelist');
    }
  }

  async removeFromWhitelist() {
    if (!this.currentTrustScore) return;

    const domain = this.currentTrustScore.details.domain;

    try {
      const response = await chrome.runtime.sendMessage({
        type: 'REMOVE_FROM_WHITELIST',
        domain: domain
      });

      if (response.success) {
        this.whitelist = this.whitelist.filter(d => d !== domain);
        this.updateWhitelistButtons();
        this.showNotification('Site removed from whitelist', 'success');
      } else {
        this.showError('Failed to remove from whitelist');
      }
    } catch (error) {
      this.showError('Failed to remove from whitelist');
    }
  }

  toggleAdvanced() {
    if (!this.advancedSection) return;

    const isVisible = this.advancedSection.style.display !== 'none';
    this.advancedSection.style.display = isVisible ? 'none' : 'block';

    const toggle = this.advancedToggle;
    if (toggle) {
      const toggleText = toggle.querySelector('.toggle-text');
      if (toggleText) {
        toggleText.textContent = isVisible ? 'Show Advanced Info' : 'Hide Advanced Info';
      }
    }
  }

  async showHistory() {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'GET_SITE_HISTORY' });

      if (response.error) {
        this.showError(response.error);
        return;
      }

      this.displayHistory(response.history);
      this.openModal('history-modal');
    } catch (error) {
      this.showError('Failed to load history');
    }
  }

  displayHistory(history) {
    const historyList = document.getElementById('history-list');
    if (!historyList) return;

    if (history.length === 0) {
      historyList.innerHTML = '<li class="no-history">No browsing history yet</li>';
      return;
    }

    historyList.innerHTML = history.map(entry => `
      <li class="history-item">
        <div class="history-domain">${entry.domain}</div>
        <div class="history-score">
          <span class="score-number">${entry.score}</span>
          <span class="verdict-badge ${entry.verdict.toLowerCase()}">${entry.verdict}</span>
        </div>
        <div class="history-time">${this.formatTime(entry.timestamp)}</div>
      </li>
    `).join('');
  }

  async clearHistory() {
    try {
      const confirmed = confirm('Clear all SafeClick site history? This cannot be undone.');
      if (!confirmed) return;
      const response = await chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' });
      if (response && response.success) {
        this.displayHistory([]);
        this.showNotification('History cleared', 'success');
      } else {
        this.showError(response?.error || 'Failed to clear history');
      }
    } catch (e) {
      this.showError('Failed to clear history');
    }
  }

  hideHistory() {
    this.closeModal('history-modal');
  }

  async showSettings() {
    this.loadSettingsIntoUI();
    this.openModal('settings-modal');
  }

  hideSettings() {
    this.closeModal('settings-modal');
  }

  // Modal helpers with accessibility (ESC to close and focus trap)
  openModal(modalId) {
    const overlay = document.getElementById(modalId);
    if (!overlay) return;
    overlay.style.display = 'flex';
    document.body.classList.add('modal-open');
    this.activeModalId = modalId;
    this.previouslyFocusedEl = document.activeElement;

    const dialog = overlay.querySelector('.modal-content');
    if (dialog) {
      // Focus the dialog container
      dialog.focus();
      // Setup keydown handler
      this._modalKeydownHandler = (e) => this._handleModalKeydown(e, overlay);
      overlay.addEventListener('keydown', this._modalKeydownHandler);
    }
  }

  closeModal(modalId) {
    const overlay = document.getElementById(modalId);
    if (!overlay) return;
    overlay.style.display = 'none';
    document.body.classList.remove('modal-open');
    if (this._modalKeydownHandler) {
      overlay.removeEventListener('keydown', this._modalKeydownHandler);
      this._modalKeydownHandler = null;
    }
    this.activeModalId = null;
    // Restore focus
    if (this.previouslyFocusedEl && typeof this.previouslyFocusedEl.focus === 'function') {
      try { this.previouslyFocusedEl.focus(); } catch (_) { }
    }
    this.previouslyFocusedEl = null;
  }

  _handleModalKeydown(e, overlay) {
    if (e.key === 'Escape') {
      // Close the active modal on ESC
      if (this.activeModalId === 'history-modal') this.hideHistory();
      else if (this.activeModalId === 'settings-modal') this.hideSettings();
      else if (this.activeModalId === 'about-modal') this.closeModal('about-modal');
      return;
    }
    if (e.key !== 'Tab') return;
    // Focus trap within the dialog
    const dialog = overlay.querySelector('.modal-content');
    if (!dialog) return;
    const focusable = dialog.querySelectorAll(
      'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])'
    );
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  loadSettings() {
    chrome.storage.local.get(['settings', 'whitelist'], (result) => {
      this.settings = result.settings || {
        protectionEnabled: false,
        aiEnabled: false,
        aiEngine: 'chrome-ai',
        geminiApiKey: '',
        geminiModel: 'gemini-3.8-flash'
      };
      this.whitelist = result.whitelist || [];

      // Force dark mode
      document.body.classList.add('dark-mode');
    });
  }

  loadSettingsIntoUI() {
    const protectionToggle = document.getElementById('protection-enabled');
    if (protectionToggle) protectionToggle.checked = !!this.settings.protectionEnabled;

    if (this.aiEnabledToggle) this.aiEnabledToggle.checked = !!this.settings.aiEnabled;
    if (this.aiSettingsBlock) this.aiSettingsBlock.style.display = this.settings.aiEnabled ? 'block' : 'none';
    if (this.aiEngineSelect) this.aiEngineSelect.value = this.settings.aiEngine || 'chrome-ai';
    if (this.geminiApiKeyInput) this.geminiApiKeyInput.value = this.settings.geminiApiKey || '';
    if (this.geminiModelSelect) this.geminiModelSelect.value = this.settings.geminiModel || 'gemini-3.8-flash';
    if (this.geminiKeyContainer) this.geminiKeyContainer.style.display = this.settings.aiEngine === 'byok-gemini' ? 'block' : 'none';
    if (this.geminiKeyStatus) this.geminiKeyStatus.textContent = '';
    this.checkChromeAiStatus();
  }

  async checkChromeAiStatus() {
    if (!this.chromeAiDiag || !this.chromeAiStatusText) return;
    const isChromeAi = (this.aiEngineSelect?.value || this.settings.aiEngine) === 'chrome-ai';
    this.chromeAiDiag.style.display = isChromeAi ? 'block' : 'none';
    if (!isChromeAi) return;

    // Check window.ai in the popup window context
    try {
      const aiObj = (typeof window !== 'undefined' && window.ai) || (typeof self !== 'undefined' && self.ai);
      if (aiObj && aiObj.languageModel) {
        let status = 'ready';
        if (typeof aiObj.languageModel.capabilities === 'function') {
          const caps = await aiObj.languageModel.capabilities();
          status = caps.available || 'no';
        } else if (typeof aiObj.languageModel.availability === 'function') {
          status = await aiObj.languageModel.availability();
        }
        if (status === 'readily' || status === 'ready') {
          if (this.chromeAiStatusIndicator) this.chromeAiStatusIndicator.style.background = '#10B981';
          this.chromeAiStatusText.textContent = 'Gemini Nano is active and ready on-device.';
          this.chromeAiStatusText.style.color = '#10B981';
          return;
        } else if (status === 'after-download') {
          if (this.chromeAiStatusIndicator) this.chromeAiStatusIndicator.style.background = '#F59E0B';
          this.chromeAiStatusText.textContent = 'Gemini Nano download pending (check chrome://components).';
          this.chromeAiStatusText.style.color = '#F59E0B';
          return;
        }
      }
    } catch (_) {}

    // Transparent notice when Chrome Prompt API flags are not enabled
    if (this.chromeAiStatusIndicator) this.chromeAiStatusIndicator.style.background = '#94A3B8';
    this.chromeAiStatusText.textContent = 'Gemini Nano not enabled in Chrome (requires chrome://flags). Switch to Google Gemini API (BYOK) for instant cloud AI, or local rules will apply.';
    this.chromeAiStatusText.style.color = '#CBD5E1';
  }

  async fetchGeminiModels() {
    const key = this.geminiApiKeyInput?.value?.trim() || this.settings.geminiApiKey;
    if (!key) {
      if (this.geminiModelHint) {
        this.geminiModelHint.textContent = 'Enter and test an API key to fetch available models.';
        this.geminiModelHint.style.color = '#F59E0B';
      }
      return;
    }

    if (this.geminiModelHint) {
      this.geminiModelHint.textContent = 'Fetching supported models from Google Cloud...';
      this.geminiModelHint.style.color = '#93C5FD';
    }

    try {
      const resp = await chrome.runtime.sendMessage({
        type: 'LIST_GEMINI_MODELS',
        key
      });

      if (resp && resp.success && Array.isArray(resp.models) && resp.models.length > 0) {
        const currentVal = this.geminiModelSelect?.value || this.settings.geminiModel || 'gemini-3.8-flash';
        if (this.geminiModelSelect) {
          this.geminiModelSelect.innerHTML = resp.models.map(m => {
            const isRec = m.id === 'gemini-3.8-flash' ? ' (Recommended)' : (m.id === 'gemini-3.5-flash' ? ' (Fast)' : '');
            return `<option value="${m.id}">${m.displayName || m.id}${isRec}</option>`;
          }).join('');

          const hasVal = resp.models.some(m => m.id === currentVal);
          if (hasVal) {
            this.geminiModelSelect.value = currentVal;
          } else {
            this.geminiModelSelect.value = resp.models[0].id;
            this.updateSetting('geminiModel', resp.models[0].id);
          }
        }
        if (this.geminiModelHint) {
          this.geminiModelHint.textContent = `Loaded ${resp.models.length} generation models available for your key.`;
          this.geminiModelHint.style.color = '#10B981';
        }
      } else {
        if (this.geminiModelHint) {
          this.geminiModelHint.textContent = 'Unable to fetch dynamic model list: ' + (resp?.error || 'Unknown error');
          this.geminiModelHint.style.color = '#EF4444';
        }
      }
    } catch (e) {
      if (this.geminiModelHint) {
        this.geminiModelHint.textContent = 'Error fetching models: ' + e.message;
        this.geminiModelHint.style.color = '#EF4444';
      }
    }
  }

  async testGeminiApiKey() {
    const key = this.geminiApiKeyInput?.value?.trim();
    const model = this.geminiModelSelect?.value || this.settings.geminiModel || 'gemini-3.8-flash';
    if (!key) {
      if (this.geminiKeyStatus) {
        this.geminiKeyStatus.textContent = 'Please enter an API key first.';
        this.geminiKeyStatus.style.color = '#EF4444';
      }
      return;
    }
    if (this.geminiKeyStatus) {
      this.geminiKeyStatus.textContent = `Testing connection with ${model}...`;
      this.geminiKeyStatus.style.color = '#93C5FD';
    }
    try {
      const resp = await chrome.runtime.sendMessage({
        type: 'TEST_GEMINI_KEY',
        key,
        model
      });
      if (resp && resp.success) {
        if (this.geminiKeyStatus) {
          this.geminiKeyStatus.textContent = `Connected successfully with ${resp.result?.model || model}!`;
          this.geminiKeyStatus.style.color = '#10B981';
        }
        await this.fetchGeminiModels();
      } else {
        if (this.geminiKeyStatus) {
          this.geminiKeyStatus.textContent = 'Connection failed: ' + (resp?.error || 'Unknown error');
          this.geminiKeyStatus.style.color = '#EF4444';
        }
      }
    } catch (e) {
      if (this.geminiKeyStatus) {
        this.geminiKeyStatus.textContent = 'Test failed: ' + e.message;
        this.geminiKeyStatus.style.color = '#EF4444';
      }
    }
  }

  displayAIOpinion(aiOpinion) {
    if (!this.aiAdvisorySection) return;
    if (aiOpinion && aiOpinion.summary) {
      this.aiAdvisorySection.style.display = 'block';
      if (this.aiProviderBadge) {
        this.aiProviderBadge.textContent = aiOpinion.providerName || (aiOpinion.isLocal ? 'Gemini Nano' : 'Gemini Cloud');
      }
      if (this.aiOpinionText) {
        this.aiOpinionText.textContent = aiOpinion.summary;
      }
      if (this.aiRecommendationText) {
        this.aiRecommendationText.textContent = aiOpinion.recommendation ? `Recommendation: ${aiOpinion.recommendation}` : '';
      }
    } else {
      this.aiAdvisorySection.style.display = 'none';
    }
  }

  checkSocialEngineeringDisplay(details) {
    if (!this.socialEngineeringAlert) return;
    const domAnalysis = details?.detailedInfo?.domAnalysis || details?.domAnalysis;
    const reasons = this.currentTrustScore?.reasons || [];
    const verdict = this.currentTrustScore?.verdict || 'UNKNOWN';
    const isThreatVerdict = verdict === 'SUSPICIOUS' || verdict === 'DANGEROUS';
    const hasUrgency = Boolean(domAnalysis?.hasUrgencyText) || reasons.some(r => /urgency|panic|coercion|social engineering/i.test(r));

    if (hasUrgency && isThreatVerdict && domAnalysis?.hasUrgencyText) {
      this.socialEngineeringAlert.style.display = 'block';
      if (this.seTacticBadge) {
        this.seTacticBadge.textContent = 'Psychological Pressure';
      }
      if (this.seDetailText) {
        const snippet = domAnalysis?.urgencySnippets && domAnalysis.urgencySnippets[0];
        this.seDetailText.textContent = snippet 
          ? `Urgency lure detected: "${snippet.slice(0, 100)}"` 
          : 'This page uses countdown or panic language to pressure user actions.';
      }
    } else {
      this.socialEngineeringAlert.style.display = 'none';
    }
  }

  runFullPageAudit() {
    const auditQuery = "Perform a full page security audit of this website and give me a complete breakdown report.";
    if (this.aiChatInput) this.aiChatInput.value = auditQuery;
    this.handleAskAiSubmit(auditQuery);
  }

  async handleAskAiSubmit(overrideQuery = null) {
    const query = (overrideQuery || this.aiChatInput?.value || '').trim();
    if (!query) return;

    // Ensure AI tab view is active
    this.switchTab('ai');

    if (!this.aiChatResponse || !this.aiChatText) return;

    this.aiChatResponse.style.display = 'block';
    this.aiChatText.textContent = 'Analyzing page security telemetry...';
    if (this.aiChatSource) this.aiChatSource.textContent = 'SafeClick AI (Analyzing...)';

    let domain = this.currentTrustScore?.details?.domain || this.currentTrustScore?.domain || '';
    if (!domain && this.currentTab?.url) {
      try { domain = new URL(this.currentTab.url).hostname; } catch (_) { domain = ''; }
    }

    try {
      const resp = await this.sendMessageWithTimeout({
        type: 'ASK_SAFECLICK_AI',
        query,
        url: this.currentTab?.url || '',
        domain,
        verdict: this.currentTrustScore?.verdict || 'UNKNOWN',
        score: typeof this.currentTrustScore?.score === 'number' ? this.currentTrustScore.score : 50,
        indicators: this.currentTrustScore?.indicators || (this.currentTrustScore?.details && this.currentTrustScore.details.indicators) || [],
        reasons: this.currentTrustScore?.reasons || [],
        details: this.currentTrustScore?.details || {}
      }, 15000);

      if (resp && resp.success && resp.result) {
        this.aiChatText.textContent = resp.result.answer;
        if (this.aiChatSource) {
          this.aiChatSource.textContent = `${resp.result.provider || 'SafeClick AI'}`;
        }
      } else {
        const errMsg = resp?.error || 'Unable to analyze query. Please try again.';
        this.aiChatText.textContent = errMsg;
        if (this.aiChatSource) this.aiChatSource.textContent = 'Notice';
      }
    } catch (err) {
      this.aiChatText.textContent = 'Request timed out or failed: ' + err.message;
      if (this.aiChatSource) this.aiChatSource.textContent = 'Notice';
    }
  }

  copyAiChatResponse() {
    const text = this.aiChatText?.textContent || '';
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        this.showNotification('AI response copied to clipboard', 'success');
      });
    }
  }

  async exportIoCReport() {
    try {
      const resp = await this.sendMessageWithTimeout({
        type: 'GENERATE_IOC_REPORT',
        url: this.currentTab?.url || '',
        domain: this.currentTrustScore?.details?.domain || '',
        verdict: this.currentTrustScore?.verdict || 'UNKNOWN',
        score: this.currentTrustScore?.score || 50,
        indicators: this.currentTrustScore?.indicators || []
      }, 5000);

      if (resp && resp.success && resp.report) {
        const report = resp.report;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(report);
        }
        const blob = new Blob([report], { type: 'text/markdown;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        const domain = this.currentTrustScore?.details?.domain || 'site';
        a.href = url;
        a.download = `safeclick-ioc-${domain}-${Date.now()}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        this.showNotification('Security Brief copied & downloaded!', 'success');
      } else {
        this.showNotification('Failed to generate report', 'error');
      }
    } catch (e) {
      this.showNotification('Error generating report: ' + e.message, 'error');
    }
  }

  async updateSetting(key, value) {
    this.settings[key] = value;
    await chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      settings: { [key]: value }
    });
  }

  // Dark mode is always enabled; theme toggle removed

  async exportHistory() {
    try {
      const response = await chrome.runtime.sendMessage({ type: 'EXPORT_HISTORY' });

      if (response.error) {
        this.showError(response.error);
        return;
      }

      // Create and download CSV file
      const blob = new Blob([response.csvContent], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'safeclick-history.csv';
      a.click();
      URL.revokeObjectURL(url);

      this.showNotification('History exported successfully', 'success');
    } catch (error) {
      this.showError('Failed to export history');
    }
  }

  showHelp() {
    window.open('https://github.com/cypher-21/SafeClick', '_blank');
  }

  // Utility methods
  getScoreColor(score, verdict) {
    if (verdict === 'UNKNOWN') return '#6B7280';
    if (score >= 80) return '#10B981';
    if (score >= 50) return '#F59E0B';
    return '#EF4444';
  }

  getVerdictText(verdict) {
    switch (verdict) {
      case 'SAFE': return 'Safe';
      case 'SUSPICIOUS': return 'Suspicious';
      case 'DANGEROUS': return 'Dangerous';
      case 'UNKNOWN': return 'Unknown / Caution';
      default: return 'Unknown';
    }
  }

  getVerdictIcon(verdict) {
    switch (verdict) {
      case 'SAFE': return '[OK]';
      case 'SUSPICIOUS': return '[!]';
      case 'DANGEROUS': return '[X]';
      default: return '[?]';
    }
  }

  getVerdictIconSvg(verdict, size = 16) {
    switch (verdict) {
      case 'SAFE':
        return `<svg class="sc-icon sc-icon-safe" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: #10B981; display: block;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`;
      case 'SUSPICIOUS':
        return `<svg class="sc-icon sc-icon-suspicious" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: #F59E0B; display: block;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
      case 'DANGEROUS':
        return `<svg class="sc-icon sc-icon-dangerous" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: #EF4444; display: block;"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
      case 'LOADING':
        return `<svg class="sc-icon sc-icon-loading" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: #6B7280; display: block; animation: spin 2s linear infinite;"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>`;
      default:
        return `<svg class="sc-icon sc-icon-unknown" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: #6B7280; display: block;"><circle cx="12" cy="12" r="10"></circle><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
    }
  }

  getVerdictColor(verdict) {
    switch (verdict) {
      case 'SAFE': return '#10B981';
      case 'SUSPICIOUS': return '#F59E0B';
      case 'DANGEROUS': return '#EF4444';
      default: return '#6B7280';
    }
  }

  getCountryRiskLevel(country) {
    const riskyCountries = ['RU', 'CN', 'KP', 'IR', 'SY', 'VE', 'CU', 'SD', 'LY', 'YE'];
    return riskyCountries.includes(country) ? 'High' : 'Low';
  }

  formatTime(timestamp) {
    if (!timestamp && timestamp !== 0) return '';
    const date = new Date(timestamp);
    if (isNaN(date.getTime())) return '';
    // Absolute time: e.g., "23:08 • Aug 23, 2025"
    const timePart = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: true });
    const datePart = date.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
    return `${timePart} • ${datePart}`;
  }

  updateStatusIndicator(verdict) {
    const statusIcon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');
    const statusIndicator = document.querySelector('.status-indicator');

    if (statusIcon && statusText && statusIndicator) {
      // Update icon and text based on verdict
      statusIcon.innerHTML = this.getVerdictIconSvg(verdict, 14);
      statusText.textContent = `Scan Complete - ${this.getVerdictText(verdict)}`;

      // Reset verdict classes then apply the current one
      statusIndicator.classList.remove('status--safe', 'status--suspicious', 'status--dangerous', 'status--unknown');
      switch (verdict) {
        case 'SAFE':
          statusIndicator.classList.add('status--safe');
          break;
        case 'SUSPICIOUS':
          statusIndicator.classList.add('status--suspicious');
          break;
        case 'DANGEROUS':
          statusIndicator.classList.add('status--dangerous');
          break;
        default:
          statusIndicator.classList.add('status--unknown');
          break;
      }
    }
  }

  updateStatus(color) {
    const statusIndicator = document.querySelector('.status-indicator');
    if (statusIndicator) {
      statusIndicator.style.backgroundColor = color;
    }
  }

  // Display methods
  showTrustScore() {
    if (this.trustScoreSection) this.trustScoreSection.style.display = 'block';
  }

  resetScoreDisplay() {
    // Reset score display elements to default state
    if (this.scoreNumber) this.scoreNumber.textContent = '0';
    if (this.scoreFill) {
      this.scoreFill.style.width = '0%';
      this.scoreFill.style.backgroundColor = '#e2e8f0';
    }
    if (this.scoreText) this.scoreText.textContent = '0/100';
    if (this.verdictText) this.verdictText.textContent = 'Analyzing...';
    if (this.verdictIcon) this.verdictIcon.innerHTML = this.getVerdictIconSvg('LOADING', 18);
  }

  showLoading() {
    if (this.loadingSection) this.loadingSection.style.display = 'block';
    if (this.trustScoreSection) this.trustScoreSection.style.display = 'none';
    if (this.errorSection) this.errorSection.style.display = 'none';
  }

  hideLoading() {
    if (this.loadingSection) this.loadingSection.style.display = 'none';
  }

  showError(message) {
    const errorText = document.getElementById('error-message');
    if (errorText) errorText.textContent = message;
    if (this.errorSection) this.errorSection.style.display = 'block';
    if (this.loadingSection) this.loadingSection.style.display = 'none';
    if (this.trustScoreSection) this.trustScoreSection.style.display = 'none';
  }

  hideError() {
    if (this.errorSection) this.errorSection.style.display = 'none';
  }

  showNotification(message, type = 'info') {
    // Reuse a single notification element to avoid stacking multiple popups
    if (!this._notificationEl) {
      this._notificationEl = document.createElement('div');
      this._notificationEl.className = 'notification';
      document.body.appendChild(this._notificationEl);
    }

    // Reset classes and apply the current type
    this._notificationEl.className = 'notification';
    this._notificationEl.classList.add(`notification-${type}`);
    this._notificationEl.textContent = String(message || '');

    // Ensure it's visible (in case CSS uses transitions)
    this._notificationEl.style.display = 'block';

    // Clear any existing hide timer and start a new one
    if (this._notificationTimer) {
      clearTimeout(this._notificationTimer);
      this._notificationTimer = null;
    }
    this._notificationTimer = setTimeout(() => {
      try {
        // Hide instead of remove so we can reuse the element
        this._notificationEl.style.display = 'none';
      } catch (_) { }
    }, 3000);
  }

  // Quick actions for common tasks
  async performQuickAction(action) {
    switch (action) {
      case 'scan-all-tabs':
        await this.scanAllTabs();
        break;
      case 'clear-cache':
        await this.clearAllCache();
        break;
      case 'export-report':
        await this.exportSecurityReport();
        break;
      case 'bulk-whitelist':
        this.showBulkWhitelistModal();
        break;
    }
  }

  async scanAllTabs() {
    try {
      const tabs = await chrome.tabs.query({});
      const httpTabs = tabs.filter(tab => tab.url && tab.url.startsWith('http'));

      this.showNotification(`Scanning ${httpTabs.length} tabs...`, 'info');

      for (const tab of httpTabs) {
        await chrome.runtime.sendMessage({
          type: 'RESCAN_SITE',
          tabId: tab.id
        });
      }

      this.showNotification('All tabs scanned successfully', 'success');
    } catch (error) {
      this.showError('Failed to scan all tabs');
    }
  }

  async clearAllCache() {
    try {
      await chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' });
      this.showNotification('Cache cleared successfully', 'success');
    } catch (error) {
      this.showError('Failed to clear cache');
    }
  }

  async exportSecurityReport() {
    try {
      // Create minimal, local-only security report
      const reportData = {
        timestamp: new Date().toISOString(),
        currentSite: this.currentTrustScore,
        settings: this.settings
      };

      const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `safeclick-security-report-${new Date().toISOString().split('T')[0]}.json`;
      a.click();
      URL.revokeObjectURL(url);

      this.showNotification('Security report exported successfully');
    } catch (error) {
      this.showError('Failed to export security report');
    }
  }

  showBulkWhitelistModal() {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.innerHTML = `
      <div class="modal-content">
        <div class="modal-header">
          <h2>Bulk Domain Management</h2>
          <button class="modal-close">×</button>
        </div>
        <div class="modal-body">
          <p>Enter domains (one per line):</p>
          <textarea id="bulk-domains" rows="8" placeholder="example.com&#10;trusted-site.org&#10;another-domain.net"></textarea>
          <div class="modal-actions">
            <button id="bulk-add" class="action-btn primary">Add to Whitelist</button>
            <button id="bulk-remove" class="action-btn secondary">Remove from Whitelist</button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    // Event handlers
    modal.querySelector('.modal-close').onclick = () => modal.remove();
    modal.querySelector('#bulk-add').onclick = () => this.processBulkDomains('add');
    modal.querySelector('#bulk-remove').onclick = () => this.processBulkDomains('remove');
  }

  async processBulkDomains(action) {
    const textarea = document.getElementById('bulk-domains');
    const domains = textarea.value.split('\n')
      .map(d => d.trim())
      .filter(d => d && d.includes('.'));

    if (domains.length === 0) {
      this.showError('Please enter valid domains');
      return;
    }

    try {
      for (const domain of domains) {
        const message = action === 'add'
          ? { type: 'ADD_TO_WHITELIST', domain }
          : { type: 'REMOVE_FROM_WHITELIST', domain };

        await chrome.runtime.sendMessage(message);
      }

      this.showNotification(`${domains.length} domains ${action === 'add' ? 'added to' : 'removed from'} whitelist`, 'success');
      document.querySelector('.modal-overlay').remove();

      // Refresh whitelist display
      await this.loadDomainAllowlist();
    } catch (error) {
      this.showError(`Failed to ${action} domains`);
    }
  }



  // Accessibility improvements
  setupAccessibility() {
    // Add ARIA labels and keyboard navigation
    document.querySelectorAll('.nav-tab').forEach((tab, index) => {
      tab.setAttribute('role', 'tab');
      tab.setAttribute('aria-selected', index === 0 ? 'true' : 'false');
      tab.setAttribute('tabindex', index === 0 ? '0' : '-1');
    });

    // Keyboard navigation for tabs
    document.addEventListener('keydown', (e) => {
      if (e.target.classList.contains('nav-tab')) {
        const tabs = Array.from(document.querySelectorAll('.nav-tab'));
        const currentIndex = tabs.indexOf(e.target);

        if (e.key === 'ArrowLeft' && currentIndex > 0) {
          tabs[currentIndex - 1].focus();
          tabs[currentIndex - 1].click();
        } else if (e.key === 'ArrowRight' && currentIndex < tabs.length - 1) {
          tabs[currentIndex + 1].focus();
          tabs[currentIndex + 1].click();
        }
      }
    });
  }
}



// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new SafeClickPopup();
});