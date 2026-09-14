(function(){
  function qs(name){
    const u = new URL(window.location.href);
    return u.searchParams.get(name);
  }
  function normalizeHost(u){ try { return new URL(u).hostname.toLowerCase(); } catch(_){ return ''; } }
  function isHttps(u){ try { return new URL(u).protocol === 'https:'; } catch(_){ return false; } }
  function isShortenerHost(host){
    try {
      const h = String(host||'').toLowerCase();
      const list = (SafeClickConfig && SafeClickConfig.Redirect && Array.isArray(SafeClickConfig.Redirect.shortenerHosts)) ? SafeClickConfig.Redirect.shortenerHosts : [];
      return !!h && list.includes(h);
    } catch(_) { return false; }
  }
  function shortPathLooksLikeToken(pathname, search){
    try {
      const p = (pathname || '/').replace(/^\/+/, '').replace(/\/+$/, '');
      if (!p) return false;
      const segs = p.split('/');
      if (segs.length !== 1) return false;
      const token = segs[0];
      if (token.length < 3 || token.length > 20) return false;
      if (!/^[A-Za-z0-9_-]+$/.test(token)) return false;
      if (search && /(?:^|[?&])(url|u|target|to)=/i.test(search)) return true;
      return true;
    } catch(_) { return false; }
  }
  function hasOpenRedirectParamCrossDomain(uStr){
    try {
      const u = new URL(uStr);
      const host = u.hostname.toLowerCase();
      const params = u.searchParams;
      const keys = ['redirect','redir','url','u','next','return','dest','continue','target','to','goto'];
      for (const k of keys){
        if (!params.has(k)) continue;
        const val = params.get(k) || '';
        try {
          const t = new URL(val, u);
          const th = (t.hostname||'').toLowerCase();
          const et1 = host.split('.').slice(-2).join('.');
          const et2 = th.split('.').slice(-2).join('.');
          if (th && th !== host && et1 && et2 && et1 !== et2) return true;
        } catch(_) { /* ignore */ }
      }
      return false;
    } catch(_) { return false; }
  }
  const target = qs('target') || '';
  const tabId = parseInt(qs('tabId') || '', 10);

  const elHost = document.getElementById('targetHost');
  const elUrl = document.getElementById('targetUrl');
  const elStatus = document.getElementById('status');
  const btnAllow = document.getElementById('allowBtn');
  const btnBlock = document.getElementById('blockBtn');
  const btnUnblockContinue = document.getElementById('unblockContinueBtn');
  const note = document.getElementById('note');
  const openNewTabChk = document.getElementById('openNewTabChk');
  const copyUrlBtn = document.getElementById('copyUrlBtn');
  const countdownWrap = document.getElementById('countdownWrap');
  const countdownEl = document.getElementById('countdown');
  const pauseBtn = document.getElementById('pauseTimerBtn');
  const durationSelect = document.getElementById('durationSelect');
  const durationCustom = document.getElementById('durationCustom');

  if (target) {
    elHost.textContent = normalizeHost(target) || 'Unknown';
    elUrl.href = target; elUrl.textContent = target;
  } else {
    elHost.textContent = 'Unknown';
    elUrl.removeAttribute('href'); elUrl.textContent = '—';
  }

  // Reason badge
  let blockedMode = false;
  (function(){
    try {
      const reason = String(qs('reason') || '').toLowerCase();
      const el = document.getElementById('reasonBadge');
      if (!el) return;
      const labelMap = {
        reputation: 'Listed in ReputationDB',
        shortener: 'URL Shortener',
        cross_domain: 'Cross-Domain Redirect',
        open_redirect: 'Open-Redirect Pattern',
        dnr: 'Network Rule Match',
        pending_match: 'Redirect Detected',
        pending: 'Redirect Detected',
        blocked_site: 'Blocked Website'
      };
      const text = labelMap[reason] || (reason ? reason.replace(/_/g, ' ') : 'Redirect Detected');
      el.textContent = text;
      el.classList.add('sc-badge','sc-badge-warn');
      el.style.display = 'inline-flex';
      // subtle color accents for severe reasons
      if (reason === 'open_redirect') {
        el.classList.remove('sc-badge-warn');
        el.classList.add('sc-badge-note');
      }

      // Hard block mode
      if (reason === 'blocked_site') {
        blockedMode = true;
        try {
          document.title = 'SafeClick — Website Blocked';
          const statusEl = document.getElementById('status');
          if (statusEl) statusEl.textContent = 'This website was blocked by you in SafeClick.';
          const headerH1 = document.querySelector('.sc-header h1');
          if (headerH1) headerH1.textContent = 'Website Blocked';
          const subEl = document.querySelector('.sc-sub');
          if (subEl) subEl.textContent = 'This website has been blocked by your settings in the SafeClick extension.';
          const blockBtn = document.getElementById('blockBtn');
          if (blockBtn) {
            blockBtn.textContent = 'Go Back';
            blockBtn.className = 'sc-btn sc-btn-primary';
          }
        } catch(_) {}
        // Hide the standard Allow button and advanced controls
        try { document.getElementById('allowBtn').style.display = 'none'; } catch(_) {}
        try { const c = document.querySelector('.sc-controls'); if (c) c.style.display = 'none'; } catch(_) {}
        // Hide countdown to avoid auto-block loop in hard-block mode
        try { const cd = document.getElementById('countdownWrap'); if (cd) cd.style.display = 'none'; } catch(_) {}
      }
    } catch(_) {}
  })();

  // Trust badge removed: interstitial focuses on redirect decision; details live in popup

  // Download risk badge for potentially harmful file types
  (function(){
    try {
      const wrap = document.getElementById('reasonWrap');
      if (!target || !wrap) return;
      const u = new URL(target);
      const pathname = (u.pathname || '').toLowerCase();
      // Common potentially harmful extensions
      const risky = [
        '.exe','.msi','.bat','.cmd','.js','.vbs','.ps1','.scr','.dll','.drv',
        '.apk','.ipa','.pkg','.dmg','.iso','.img','.xz','.7z','.rar','.zip','.tar','.gz'
      ];
      const hasRiskExt = risky.some(ext => pathname.endsWith(ext));
      if (hasRiskExt) {
        const badge = document.createElement('span');
        badge.className = 'sc-badge sc-badge-warn';
        badge.textContent = 'Download Risk';
        wrap.appendChild(badge);
      }
    } catch(_) {}
  })();

  function setBusy(b){
    if (b) {
      try { btnAllow && btnAllow.classList.add('sc-disabled'); } catch(_) {}
      try { btnBlock && btnBlock.classList.add('sc-disabled'); } catch(_) {}
      try { btnUnblockContinue && btnUnblockContinue.classList.add('sc-disabled'); } catch(_) {}
    } else {
      try { btnAllow && btnAllow.classList.remove('sc-disabled'); } catch(_) {}
      try { btnBlock && btnBlock.classList.remove('sc-disabled'); } catch(_) {}
      try { btnUnblockContinue && btnUnblockContinue.classList.remove('sc-disabled'); } catch(_) {}
    }
  }

  // Recent redirects UI removed

  // Countdown auto-block
  let timerId = null;
  let remaining = (window.SafeClickConfig && SafeClickConfig.Redirect && SafeClickConfig.Redirect.autoBlockTimeoutMs) ? SafeClickConfig.Redirect.autoBlockTimeoutMs : 15000;
  let paused = false;
  function tick(){
    if (paused) return;
    remaining -= 1000;
    countdownEl.textContent = `${Math.max(0, Math.ceil(remaining/1000))}s`;
    if (remaining <= 0) {
      // Auto-block
      btnBlock.click();
      clearInterval(timerId); timerId = null;
    }
  }
  if (!blockedMode && countdownWrap && countdownEl) {
    countdownWrap.style.display = 'flex';
    countdownEl.textContent = `${Math.ceil(remaining/1000)}s`;
    timerId = setInterval(tick, 1000);
  }
  if (pauseBtn) {
    pauseBtn.addEventListener('click', () => {
      paused = !paused;
      pauseBtn.textContent = paused ? 'Resume' : 'Pause';
      if (!paused && !timerId) { timerId = setInterval(tick, 1000); }
    });
  }

  // Clipboard copy
  if (copyUrlBtn) {
    copyUrlBtn.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(target || '');
        note.textContent = 'URL copied to clipboard';
      } catch(_) { note.textContent = 'Failed to copy URL'; }
    });
  }

  // Duration selector behavior
  function getSelectedDurationMs() {
    try {
      if (!durationSelect) return null;
      const val = durationSelect.value;
      if (val === 'off') return null;
      if (val === 'custom') {
        const sec = parseInt(durationCustom && durationCustom.value ? durationCustom.value : '0', 10);
        if (sec > 0) return sec * 1000;
        return null;
      }
      const ms = parseInt(val, 10);
      return isNaN(ms) ? null : ms;
    } catch (_) { return null; }
  }
  if (durationSelect) {
    try {
      // Default to Off
      durationSelect.value = 'off';
      if (durationCustom) durationCustom.style.display = 'none';
    } catch(_) {}
    durationSelect.addEventListener('change', () => {
      if (!durationCustom) return;
      if (durationSelect.value === 'custom') {
        durationCustom.style.display = 'inline-block';
        try { durationCustom.focus(); } catch(_) {}
      } else {
        durationCustom.style.display = 'none';
      }
    });
  }

  // Focus management: move initial focus to Allow for faster keyboard use
  try { btnAllow.focus(); } catch(_) {}

  btnAllow.addEventListener('click', async () => {
    if (!target || !tabId) return;
    setBusy(true);
    elStatus.textContent = 'Allowing and navigating…';
    try {
      const openInNewTab = !!(openNewTabChk && openNewTabChk.checked);
      const durationMs = getSelectedDurationMs();
      try {
        await chrome.runtime.sendMessage({ type: 'CLIENT_REDIRECT_DETECTED', tabId, fromUrl: '', toUrl: target, method: 'interstitial-allow' });
      } catch(_) {}
      // Persistently allowlist the destination domain unconditionally on user Allow
      try {
        const u = new URL(target);
        const host = (u.hostname || '').toLowerCase();
        if (host) {
          await chrome.runtime.sendMessage({ type: 'ADD_DOMAIN_TO_ALLOWLIST', domain: host });
        }
      } catch(_) {}
      const msg = { type: 'ALLOW_REDIRECT', tabId, url: target, openInNewTab };
      if (typeof durationMs === 'number' && durationMs > 0) msg.durationMs = durationMs;
      await chrome.runtime.sendMessage(msg);
      // Background will handle navigation. Only fallback-navigate this tab if NOT opening a new tab.
      if (!openInNewTab) {
        try { window.location.replace(target); } catch(_){ /* no-op */ }
      } else {
        // Optionally inform user
        try { elStatus.textContent = 'Opened in a new tab.'; } catch(_) {}
      }
    } catch (e) {
      elStatus.textContent = 'Failed to allow redirect: ' + (e && e.message ? e.message : 'unknown error');
      setBusy(false);
    }
  });

  btnBlock.addEventListener('click', async () => {
    if (!target || !tabId) return;
    setBusy(true);
    if (blockedMode) {
      if (note) note.textContent = 'Returning you to the previous page…';
      setTimeout(() => {
        try {
          if (window.history && window.history.length > 1) {
            window.history.back();
          } else {
            try { chrome.tabs.remove(tabId); return; } catch(_) {}
            try { window.close(); return; } catch(_) {}
            try { window.location.replace('about:blank'); } catch(_) {}
          }
        } catch (_) {
          try { chrome.tabs.remove(tabId); } catch(_) {}
          try { window.location.replace('about:blank'); } catch(_) {}
        }
      }, 300);
      return;
    }
    elStatus.textContent = 'Blocking…';
    try {
      await chrome.runtime.sendMessage({ type: 'BLOCK_REDIRECT', tabId, url: target });
      elStatus.textContent = 'Redirect blocked.';
      note.textContent = 'Returning you to the previous page…';
      // Leave the interstitial so the user isn’t stuck here
      setTimeout(() => {
        try {
          if (window.history && window.history.length > 1) {
            window.history.back();
          } else {
            // No history (likely a new tab): close the tab
            try { chrome.tabs.remove(tabId); return; } catch(_) {}
            try { window.close(); return; } catch(_) {}
            try { window.location.replace('about:blank'); } catch(_) {}
          }
        } catch (_) {
          try { chrome.tabs.remove(tabId); } catch(_) {}
          try { window.location.replace('about:blank'); } catch(_) {}
        }
      }, 600);
    } catch (e) {
      elStatus.textContent = 'Failed to block redirect: ' + (e && e.message ? e.message : 'unknown error');
      setBusy(false);
    }
  });

  // Accessibility: keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    const reason = String(qs('reason') || '').toLowerCase();
    if (e.key === 'Enter') {
      e.preventDefault();
      if (reason === 'blocked_site') { btnBlock.click(); } else { btnAllow.click(); }
    } else if (e.key === 'Escape') {
      e.preventDefault(); btnBlock.click();
    }
  });

  // Removed inert internal carrier blocks (no functional effect)
})();
