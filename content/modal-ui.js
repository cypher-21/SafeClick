/**
 * SafeClick 2.0 - Content Modal & Warning UI
 * Open Source Browser Security Engine
 * 
 * Handles user-facing warning modals, dismissals, toasts, and risk summaries.
 */

const SafeClickModalUI = (function () {
  'use strict';

  let modalShown = false;
  let modalDismissedAt = 0;
  let suppressUntilTs = 0;

  function isSuppressedNow() {
    try { return Date.now() < suppressUntilTs; } catch (_) { return false; }
  }

  function justDismissedModal(windowMs = 5000) {
    try { return (Date.now() - modalDismissedAt) < Math.max(250, windowMs); } catch (_) { return false; }
  }

  function setSuppressionWindow(ms) {
    try {
      const dur = Math.max(1000, Number(ms || 300000));
      suppressUntilTs = Date.now() + dur;
      try {
        const host = window.location.hostname || 'unknown';
        sessionStorage.setItem(`sc_suppress_until_${host}`, String(suppressUntilTs));
      } catch (_) {}
      removeVisualWarnings();
    } catch (_) {}
  }

  function loadSuppressionFromStorage() {
    try {
      const host = window.location.hostname || 'unknown';
      const v = sessionStorage.getItem(`sc_suppress_until_${host}`);
      const n = v ? Number(v) : 0;
      if (n && !isNaN(n)) {
        suppressUntilTs = n;
        if (isSuppressedNow()) {
          removeVisualWarnings();
        }
      }
    } catch (_) {}
  }

  function removeVisualWarnings() {
    try {
      document.querySelectorAll('.safeclick-warning-icon').forEach(el => {
        try { el.remove(); } catch (_) {}
      });
      const fields = document.querySelectorAll(
        'input[type="password"], input[name*="password"], input[name*="card"], input[name*="cc"], input[name*="ssn"], input[name*="social"]'
      );
      fields.forEach(field => {
        try {
          field.classList.remove('safeclick-warning');
          field.style.borderColor = '';
          field.style.borderWidth = '';
          field.style.borderStyle = '';
          field.style.boxShadow = '';
          if (field.style.paddingRight === '30px') field.style.paddingRight = '';
          delete field.dataset.safeclickIcon;
        } catch (_) {}
      });
    } catch (_) {}
  }

  function getScoreColor(score) {
    if (score >= 80) return '#10B981';
    if (score >= 50) return '#F59E0B';
    return '#EF4444';
  }

  function showNotification(message, type = 'info', duration = 3000) {
    const notification = document.createElement('div');
    notification.className = `safeclick-notification safeclick-notification-${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    setTimeout(() => {
      try { notification.remove(); } catch (_) {}
    }, Math.max(500, duration));
  }

  function generateRiskDetails(currentTrustScore, settings, summarizeFormSecurityRisks) {
    const scoreObj = currentTrustScore || {};
    const details = scoreObj?.details?.detailedInfo;
    if (!details) {
      const items = [];
      try {
        if (window.location.protocol === 'http:') {
          items.push('<div class="risk-item high">No HTTPS encryption</div>');
          items.push('<div class="risk-item high">SSL Certificate: Not present (HTTP)</div>');
        }
      } catch (_) {}
      return items.join('');
    }

    const riskItems = [];

    if (details.https && !details.https.secure) {
      riskItems.push('<div class="risk-item high">No HTTPS Encryption</div>');
    }

    if (details.ssl && !details.ssl.valid) {
      riskItems.push('<div class="risk-item high">Invalid SSL Certificate</div>');
    }

    if (details.domainPattern && details.domainPattern.pattern !== 'normal') {
      riskItems.push('<div class="risk-item medium">Suspicious Domain Pattern</div>');
    }

    if (details.phishTank) {
      try {
        if (details.phishTank.exactUrlListed) {
          riskItems.push('<div class="risk-item high">Exact URL Listed in PhishTank</div>');
        } else if (details.phishTank.hostListed || details.phishTank.listed) {
          riskItems.push('<div class="risk-item high">Host Listed in PhishTank (possible collateral)</div>');
        }
      } catch (_) {}
    }

    try {
      const rep = details.reputation || {};
      if (rep.exactUrlListed || rep.exactHostListed || rep.apexListed) {
        riskItems.push('<div class="risk-item high">Listed In Local Reputation Database</div>');
      } else {
        const reasonsText = Array.isArray(scoreObj.reasons) ? scoreObj.reasons.join(' ').toLowerCase() : '';
        if (/reputationdb|reputation-db|listed in reputation/.test(reasonsText)) {
          riskItems.push('<div class="risk-item medium">Listed In Local Reputation Database</div>');
        }
      }
    } catch (_) {}

    if (details.hostingCountry && details.hostingCountry.country) {
      const isRisky = ['RU', 'CN', 'KP', 'IR', 'SY', 'VE', 'CU', 'SD', 'LY', 'YE'].includes(details.hostingCountry.country);
      if (isRisky) {
        riskItems.push('<div class="risk-item medium">Hosted in High-risk region</div>');
      }
    }

    if (details.keywords && details.keywords.keywords?.length > 0) {
      riskItems.push('<div class="risk-item medium">Suspicious Content Detected</div>');
    }

    if (details.heuristic && details.heuristic.riskFactors?.length > 0) {
      riskItems.push('<div class="risk-item medium">Heuristic Analysis Flagged Risks</div>');
    }

    if (details.contentSecurity && Array.isArray(details.contentSecurity.issues) && details.contentSecurity.issues.length > 0) {
      riskItems.push('<div class="risk-item medium">Content Security Issues Detected</div>');
    }

    if (details.socialEngineering && Array.isArray(details.socialEngineering.tactics) && details.socialEngineering.tactics.length > 0) {
      riskItems.push('<div class="risk-item medium">Social Engineering Tactics Detected</div>');
    }

    if (typeof summarizeFormSecurityRisks === 'function') {
      try {
        const formRisk = summarizeFormSecurityRisks();
        if (formRisk && formRisk.count > 0) {
          if (formRisk.high > 0) {
            riskItems.push(`<div class="risk-item high">Form Security Risks: ${formRisk.high} High-Risk Form${formRisk.high > 1 ? 's' : ''}</div>`);
          } else if (formRisk.medium > 0) {
            riskItems.push(`<div class="risk-item medium">Form Security Risks: ${formRisk.medium} Form${formRisk.medium > 1 ? 's' : ''} Submits External</div>`);
          }
        }
      } catch (_) {}
    }

    if (riskItems.length === 0) {
      try {
        const verdict = scoreObj?.verdict || '';
        const scoreVal = typeof scoreObj?.score === 'number' ? scoreObj.score : 100;
        if (verdict === 'DANGEROUS' || (verdict === 'SUSPICIOUS' && scoreVal < (settings?.scoreThreshold || 50))) {
          riskItems.push('<div class="risk-item medium">Site flagged by security checks</div>');
        }
      } catch (_) {}
    }

    return riskItems.join('') || '<div class="risk-item safe">No Specific Risks Identified</div>';
  }

  function refreshWarningModal(currentTrustScore, settings, summarizeFormSecurityRisks) {
    try {
      const modal = document.getElementById('safeclick-warning-modal');
      if (!modal || !currentTrustScore) return;
      const scoreVal = typeof currentTrustScore.score === 'number' ? currentTrustScore.score : 0;
      const numEl = document.getElementById('safeclick-trust-number');
      const fillEl = document.getElementById('safeclick-trust-fill');
      const reasonsEl = document.getElementById('safeclick-reasons');
      const riskGrid = document.getElementById('safeclick-risk-grid');
      if (numEl) numEl.textContent = `Trust Score: ${scoreVal}/100`;
      if (fillEl) {
        fillEl.style.width = `${scoreVal}%`;
        fillEl.style.backgroundColor = getScoreColor(scoreVal);
      }
      if (reasonsEl) {
        const all = Array.isArray(currentTrustScore.reasons) ? currentTrustScore.reasons : [];
        const filtered = all.filter(r => r && !/^\[OK\]/.test(r) && !r.includes('Normal')).map(r => r.replace(/^(\[OK\]|\[X\]|\[!\]|\[i\]|\[\?\])\s*/, ''));
        const list = (filtered.length ? filtered.slice(0, 3) : ['Security Risks detected']).map(r => `<li>${r}</li>`).join('');
        reasonsEl.innerHTML = list;
      }
      if (riskGrid) {
        riskGrid.innerHTML = generateRiskDetails(currentTrustScore, settings, summarizeFormSecurityRisks);
      }
    } catch (_) {}
  }

  function showWarningModal(currentTrustScore, settings, callbacks = {}) {
    try { if (window.top !== window) return; } catch (_) {}
    if (modalShown) return;
    if (isSuppressedNow()) return;

    modalShown = true;
    if (typeof callbacks.onShown === 'function') {
      try { callbacks.onShown(); } catch (_) {}
    }

    const scoreObj = currentTrustScore || {
      score: 0,
      verdict: 'SUSPICIOUS',
      reasons: [window.location.protocol === 'http:' ? 'No HTTPS - connection is not encrypted' : 'Security Risks detected'],
      details: {}
    };

    let reasonsList = ['Security Risks detected'];
    try {
      const all = Array.isArray(scoreObj.reasons) ? scoreObj.reasons : [];
      const filtered = all.filter(r => r && !/^\[OK\]/.test(r) && !r.includes('Normal')).map(r => r.replace(/^(\[OK\]|\[X\]|\[!\]|\[i\]|\[\?\])\s*/, ''));
      if (filtered.length > 0) {
        reasonsList = filtered.slice(0, 3);
      }
    } catch (_) {}

    const previouslyFocused = document.activeElement;
    const modal = document.createElement('div');
    modal.id = 'safeclick-warning-modal';
    const headerIcon = scoreObj.verdict === 'DANGEROUS'
      ? `<svg class="sc-icon sc-icon-dangerous" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`
      : `<svg class="sc-icon sc-icon-suspicious" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
    const modalIconBg = scoreObj.verdict === 'DANGEROUS' ? '#FEE2E2' : '#FEF3C7';

    modal.innerHTML = `
      <div class="safeclick-modal-overlay" role="dialog" aria-modal="true" aria-labelledby="safeclick-modal-title">
        <div class="safeclick-modal-content" tabindex="-1">
          <div class="safeclick-modal-header">
            <div class="safeclick-modal-icon" style="background: ${modalIconBg};">${headerIcon}</div>
            <h2 id="safeclick-modal-title">Unsafe Website Detected</h2>
          </div>
          <div class="safeclick-modal-body">
            <p><strong>Do NOT Enter Your Credentials On This Website!</strong></p>
            <p>This site has been flagged as potentially dangerous due to:</p>
            <ul id="safeclick-reasons">
              ${reasonsList.map(reason => `<li>${reason}</li>`).join('')}
            </ul>
            <div class="safeclick-trust-score">
              <span id="safeclick-trust-number">Trust Score: ${typeof scoreObj.score === 'number' ? scoreObj.score : 0}/100</span>
              <div class="safeclick-score-bar">
                <div id="safeclick-trust-fill" class="safeclick-score-fill" style="width: ${typeof scoreObj.score === 'number' ? scoreObj.score : 0}%; background-color: ${getScoreColor(typeof scoreObj.score === 'number' ? scoreObj.score : 0)};"></div>
              </div>
            </div>
            <div class="safeclick-risk-details">
              <h4>Risk Analysis:</h4>
              <div id="safeclick-risk-grid" class="safeclick-risk-grid">${generateRiskDetails(currentTrustScore, settings, callbacks.summarizeFormSecurityRisks)}</div>
            </div>
          </div>
          <div class="safeclick-modal-footer">
            <button id="safeclick-leave-site" class="safeclick-btn safeclick-btn-danger">Leave Site</button>
            <button id="safeclick-continue" class="safeclick-btn safeclick-btn-secondary">Continue Anyway</button>
            <button id="safeclick-whitelist" class="safeclick-btn safeclick-btn-primary">Add to Whitelist</button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    document.getElementById('safeclick-leave-site').addEventListener('click', async () => {
      setSuppressionWindow(60 * 1000);
      modalDismissedAt = Date.now();
      removeVisualWarnings();
      if (window.history && window.history.length > 1) {
        window.history.back();
      } else {
        try { window.close(); } catch (_) {}
        try { window.location.replace('about:blank'); } catch (_) {}
      }
      try { modal.remove(); } catch (_) {}
      modalShown = false;
      try { previouslyFocused?.focus?.(); } catch (_) {}
    });

    document.getElementById('safeclick-continue').addEventListener('click', () => {
      const durationMs = 60 * 1000;
      setSuppressionWindow(durationMs);
      modalDismissedAt = Date.now();
      removeVisualWarnings();
      chrome.runtime.sendMessage({
        type: 'ALLOW_CONTINUE',
        url: window.location.href,
        durationMs,
        quiet: true,
        noNavigate: true
      });
      modal.remove();
      modalShown = false;
      try { previouslyFocused?.focus?.(); } catch (_) {}
    });

    document.getElementById('safeclick-whitelist').addEventListener('click', () => {
      const domain = new URL(window.location.href).hostname;
      chrome.runtime.sendMessage({ type: 'ADD_TO_WHITELIST', domain }, (r1) => {
        if (typeof callbacks.onWhitelistAdded === 'function') callbacks.onWhitelistAdded(r1?.whitelist);
      });
      chrome.runtime.sendMessage({ type: 'ADD_DOMAIN_TO_ALLOWLIST', domain }, (r2) => {
        if (typeof callbacks.onAllowlistAdded === 'function') callbacks.onAllowlistAdded(r2?.domains);
        modal.remove();
        modalShown = false;
        showNotification('Site added to whitelist', 'success');
        setSuppressionWindow(24 * 60 * 60 * 1000);
        modalDismissedAt = Date.now();
        removeVisualWarnings();
        try { previouslyFocused?.focus?.(); } catch (_) {}
      });
    });

    // ESC to close and focus trap
    try {
      const focusables = modal.querySelectorAll('button, [tabindex]:not([tabindex="-1"])');
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (first) first.focus();
      modal.addEventListener('keydown', (e) => {
        if (e.key === 'Tab') {
          if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
          else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
        } else if (e.key === 'Escape') {
          e.preventDefault();
          modal.remove();
          modalShown = false;
          try { previouslyFocused?.focus?.(); } catch (_) {}
        }
      });
    } catch (_) {}
  }

  function showPrivacyWarning(cookieCount) {
    if (document.getElementById('safeclick-privacy-banner')) return;
    const banner = document.createElement('div');
    banner.id = 'safeclick-privacy-banner';
    banner.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0;
      background: #FEF3C7; color: #92400E; padding: 8px 16px;
      font-size: 14px; font-weight: 500; z-index: 999999;
      border-bottom: 2px solid #F59E0B; text-align: center;
    `;
    banner.innerHTML = `
      Privacy Alert: This site uses ${cookieCount || 'multiple'} tracking cookies and has security concerns.
      <button onclick="this.parentElement.remove()" style="margin-left: 10px; background: #92400E; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer;">Dismiss</button>
    `;
    document.body.insertBefore(banner, document.body.firstChild);
  }

  function showSocialEngineeringWarning(tactics) {
    if (document.getElementById('safeclick-social-warning')) return;
    const warning = document.createElement('div');
    warning.id = 'safeclick-social-warning';
    warning.style.cssText = `
      position: fixed; bottom: 20px; right: 20px;
      background: #FEE2E2; color: #991B1B; padding: 12px 16px;
      border-radius: 8px; border: 2px solid #EF4444; max-width: 300px;
      font-size: 13px; z-index: 999998; box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    `;
    warning.innerHTML = `
      <strong>[!] Social Engineering Alert</strong><br>
      Detected tactics: ${(tactics || []).join(', ')}<br>
      <small>Be cautious of pressure to act quickly</small>
      <button onclick="this.parentElement.remove()" style="float: right; background: none; border: none; font-size: 16px; cursor: pointer; color: #991B1B;">×</button>
    `;
    document.body.appendChild(warning);
    setTimeout(() => { try { warning.remove(); } catch (_) {} }, 10000);
  }

  return {
    isSuppressedNow,
    justDismissedModal,
    setSuppressionWindow,
    loadSuppressionFromStorage,
    removeVisualWarnings,
    getScoreColor,
    showNotification,
    generateRiskDetails,
    refreshWarningModal,
    showWarningModal,
    showPrivacyWarning,
    showSocialEngineeringWarning,
    isModalShown: () => modalShown,
    setModalShown: (val) => { modalShown = !!val; }
  };
})();

if (typeof window !== 'undefined') {
  window.SafeClickModalUI = SafeClickModalUI;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SafeClickModalUI;
}
