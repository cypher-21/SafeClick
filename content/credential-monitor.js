/**
 * SafeClick 2.0 - Content Credential & Form Monitor
 * Open Source Browser Security Engine
 * 
 * Inspects sensitive inputs, form actions, and password strength,
 * applying in-page warning indicators and submit protections.
 */

const SafeClickCredentialMonitor = (function () {
  'use strict';

  const SAFECLICK_TRUSTED_APEX = new Set([
    'stripe.com',
    'paypal.com',
    'microsoftonline.com',
    'google.com',
    'auth0.com',
    'okta.com'
  ]);

  function getApex(hostname) {
    try {
      const parts = (hostname || '').split('.').filter(Boolean);
      if (parts.length <= 2) return hostname || '';
      const last = parts[parts.length - 1];
      const second = parts[parts.length - 2];
      const third = parts[parts.length - 3];
      const secondLevelSet = new Set(['co', 'com', 'org', 'gov', 'net']);
      if (last.length === 2 && secondLevelSet.has(second) && third) {
        return `${third}.${second}.${last}`;
      }
      return `${second}.${last}`;
    } catch (_) {
      return hostname || '';
    }
  }

  function findSensitiveFields(root = document) {
    const passwordFields = root.querySelectorAll(
      'input[type="password"], input[name*="password" i], input[name*="passwd" i], input[id*="password" i], input[id*="passwd" i], input[autocomplete~="current-password" i], input[autocomplete~="new-password" i]'
    );
    const emailFields = root.querySelectorAll('input[type="email"], input[name*="email" i], input[id*="email" i], input[autocomplete~="email" i]');
    const usernameFields = root.querySelectorAll('input[name*="username" i], input[name*="user" i], input[id*="username" i], input[id*="user" i], input[autocomplete~="username" i]');
    const creditCardFields = root.querySelectorAll('input[name*="card"], input[name*="cc"]');
    const ssnFields = root.querySelectorAll('input[name*="ssn"], input[name*="social"]');

    return {
      passwords: Array.from(passwordFields),
      emails: Array.from(emailFields),
      usernames: Array.from(usernameFields),
      creditCards: Array.from(creditCardFields),
      ssns: Array.from(ssnFields),
      all: [...passwordFields, ...emailFields, ...usernameFields, ...creditCardFields, ...ssnFields]
    };
  }

  function addWarningIcon(field) {
    if (field.dataset.safeclickIcon) return;
    field.dataset.safeclickIcon = 'true';

    const icon = document.createElement('span');
    icon.className = 'safeclick-warning-icon';
    icon.style.cssText = `
      position: absolute; right: 8px; top: 50%;
      transform: translateY(-50%); font-size: 16px;
      pointer-events: none; z-index: 10;
    `;
    icon.innerHTML = `<svg class="sc-icon sc-icon-field-warning" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="display:block;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;

    field.style.position = 'relative';
    field.style.paddingRight = '30px';
    if (field.parentNode) {
      field.parentNode.style.position = 'relative';
      field.parentNode.appendChild(icon);
    }
  }

  function addVisualIndicators(currentTrustScore, isAllowedOrSuppressed) {
    if (isAllowedOrSuppressed || !currentTrustScore || currentTrustScore.verdict === 'SAFE') {
      return;
    }

    const sensitive = findSensitiveFields();
    sensitive.all.forEach(field => {
      if (!field.classList.contains('safeclick-warning')) {
        field.classList.add('safeclick-warning');
        const isDangerous = currentTrustScore.verdict === 'DANGEROUS';
        field.style.borderColor = isDangerous ? '#EF4444' : '#F59E0B';
        field.style.borderWidth = '2px';
        field.style.borderStyle = 'solid';
        field.style.boxShadow = `0 0 0 1px ${isDangerous ? '#EF4444' : '#F59E0B'}`;

        const risks = currentTrustScore.reasons ? currentTrustScore.reasons.slice(0, 2).join(', ') : 'Unknown risks';
        field.title = `SafeClick Security Warning: ${currentTrustScore.verdict.toLowerCase()} site (Score: ${currentTrustScore.score}/100)\nRisks: ${risks}`;
        addWarningIcon(field);
      }
    });
  }

  function calculatePasswordStrength(password) {
    if (!password) return { score: 0, level: 'none', feedback: [] };

    let score = 0;
    const feedback = [];

    if (password.length >= 12) score += 25;
    else if (password.length >= 8) score += 15;
    else feedback.push('Use at least 8 characters');

    if (/[a-z]/.test(password)) score += 15;
    else feedback.push('Add lowercase letters');

    if (/[A-Z]/.test(password)) score += 15;
    else feedback.push('Add uppercase letters');

    if (/[0-9]/.test(password)) score += 15;
    else feedback.push('Add numbers');

    if (/[^a-zA-Z0-9]/.test(password)) score += 20;
    else feedback.push('Add special characters');

    if (/(.)\1{2,}/.test(password)) {
      score -= 10;
      feedback.push('Avoid repeated characters');
    }

    if (/123|abc|qwe|password|admin/i.test(password)) {
      score -= 15;
      feedback.push('Avoid common patterns');
    }

    const level = score >= 80 ? 'strong' : score >= 60 ? 'medium' : score >= 40 ? 'weak' : 'very-weak';
    return { score: Math.max(0, Math.min(100, score)), level, feedback };
  }

  function updateStrengthIndicator(indicator, strength) {
    if (strength.level === 'none') {
      indicator.style.display = 'none';
      return;
    }

    indicator.style.display = 'block';
    const colors = {
      'very-weak': '#EF4444',
      'weak': '#F59E0B',
      'medium': '#3B82F6',
      'strong': '#10B981'
    };

    indicator.style.backgroundColor = (colors[strength.level] || '#6B7280') + '20';
    indicator.style.color = colors[strength.level] || '#6B7280';
    indicator.style.border = `1px solid ${colors[strength.level] || '#6B7280'}`;

    const strengthText = strength.level.charAt(0).toUpperCase() + strength.level.slice(1).replace('-', ' ');
    indicator.textContent = `Password Strength: ${strengthText} (${strength.score}/100)`;

    if (strength.feedback.length > 0 && strength.level !== 'strong') {
      indicator.title = 'Suggestions: ' + strength.feedback.join(', ');
    }
  }

  function addPasswordStrengthCheckers(passwordFields) {
    (passwordFields || []).forEach(field => {
      if (field.dataset.safeclickStrength) return;
      field.dataset.safeclickStrength = 'true';

      const strengthIndicator = document.createElement('div');
      strengthIndicator.className = 'safeclick-strength-indicator';
      strengthIndicator.style.cssText = `
        margin-top: 4px; padding: 4px 8px; border-radius: 4px;
        font-size: 12px; font-weight: 500; display: none;
      `;
      field.parentNode?.insertBefore(strengthIndicator, field.nextSibling);

      field.addEventListener('input', () => {
        const strength = calculatePasswordStrength(field.value);
        updateStrengthIndicator(strengthIndicator, strength);
      });
    });
  }

  function analyzeFormSecurity(form) {
    const analysis = {
      hasPassword: false,
      hasCreditCard: false,
      suspiciousAction: false,
      mixedContent: false,
      externalAction: false,
      riskLevel: 'low'
    };

    analysis.hasPassword = form.querySelector('input[type="password"]') !== null;
    analysis.hasCreditCard = form.querySelector('input[name*="card"], input[name*="cc"]') !== null;

    if (form.action && typeof form.action === 'string' && form.action.trim() !== '') {
      try {
        const actionUrl = new URL(form.action, window.location.href);
        const actionHost = actionUrl.hostname || '';
        const pageHost = window.location.hostname || '';
        const actionApex = getApex(actionHost);
        const pageApex = getApex(pageHost);

        analysis.suspiciousAction = actionUrl.protocol === 'javascript:' || actionUrl.protocol === 'data:';
        analysis.mixedContent = window.location.protocol === 'https:' && actionUrl.protocol === 'http:';

        const isTrustedExternal = SAFECLICK_TRUSTED_APEX.has(actionApex);
        const isSameApex = actionApex && pageApex && actionApex === pageApex;
        analysis.externalAction = !isSameApex && !isTrustedExternal;
      } catch (_) {}
    }

    if (analysis.suspiciousAction || analysis.mixedContent) {
      analysis.riskLevel = 'high';
    } else if ((analysis.hasPassword || analysis.hasCreditCard) && analysis.externalAction) {
      analysis.riskLevel = 'medium';
    } else {
      analysis.riskLevel = 'low';
    }

    return analysis;
  }

  function summarizeFormSecurityRisks() {
    try {
      const forms = Array.from(document.querySelectorAll('form'));
      let high = 0, medium = 0;
      for (const form of forms) {
        const a = analyzeFormSecurity(form);
        if (a.riskLevel === 'high') high++;
        else if (a.riskLevel === 'medium') medium++;
      }
      return { high, medium, count: high + medium };
    } catch (_) {
      return { high: 0, medium: 0, count: 0 };
    }
  }

  function monitorForms() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      const analysis = analyzeFormSecurity(form);
      if (analysis.riskLevel !== 'low') {
        if (!form.classList.contains('safeclick-form-warning')) {
          form.classList.add('safeclick-form-warning');
          form.style.border = '2px solid #F59E0B';
          form.style.borderRadius = '4px';
          form.style.padding = '8px';
        }
        if (!form.querySelector('.safeclick-form-warning-indicator')) {
          const warning = document.createElement('div');
          warning.className = 'safeclick-form-warning-indicator';
          warning.innerHTML = analysis.riskLevel === 'high'
            ? '[!] Form Security Warning: high risk (suspicious or insecure action)'
            : '[!] Heads up: This sensitive form submits to a different domain';
          warning.style.cssText = `
            background: #FEF3C7; color: #92400E; padding: 4px 8px;
            border-radius: 4px; font-size: 12px; margin-bottom: 8px; font-weight: 500;
          `;
          form.insertBefore(warning, form.firstChild);
        }
      }
    });
  }

  return {
    findSensitiveFields,
    addWarningIcon,
    addVisualIndicators,
    calculatePasswordStrength,
    addPasswordStrengthCheckers,
    analyzeFormSecurity,
    summarizeFormSecurityRisks,
    monitorForms
  };
})();

if (typeof window !== 'undefined') {
  window.SafeClickCredentialMonitor = SafeClickCredentialMonitor;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SafeClickCredentialMonitor;
}
