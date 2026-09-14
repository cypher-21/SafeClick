/**
 * SafeClick 2.0 - Four-State Verdict Engine
 * Open Source Browser Security Engine
 * 
 * Fuses multi-source indicators into an explainable four-state security verdict:
 * SAFE | UNKNOWN | SUSPICIOUS | DANGEROUS
 * 
 * Key Principles:
 * 1. Absence of evidence is NOT evidence of safety (unlisted = UNKNOWN, not SAFE).
 * 2. Host-level matches are weighted indicators, NEVER automatic hard fails.
 * 3. Only verified exact URL matches in threat feeds trigger hard fail to DANGEROUS.
 */

const VerdictEngine = (function () {
  'use strict';

  const THRESHOLDS = {
    SAFE_MIN_SCORE: 75,
    UNKNOWN_MIN_SCORE: 55,
    SUSPICIOUS_MIN_SCORE: 35
  };

  /**
   * Evaluate indicators and compute four-state verdict
   * @param {IndicatorRegistry|Array} indicators
   * @param {Object} [options]
   * @param {string} [options.url]
   * @param {string} [options.domain]
   * @param {boolean} [options.isAllowlisted]
   */
  function evaluate(indicators, options = {}) {
    const list = Array.isArray(indicators)
      ? indicators
      : (indicators && typeof indicators.getAll === 'function' ? indicators.getAll() : []);

    // 1. Check Allowlist override
    if (options.isAllowlisted) {
      const safeScore = 100;
      const verdict = 'SAFE';
      const reasons = ['[OK] Domain is explicitly present in your Allowlist'];
      return {
        score: safeScore,
        verdict,
        hardFailed: false,
        reasons,
        indicators: list,
        explanation: {
          verdict,
          score: safeScore,
          summary: 'Domain is user-allowlisted.',
          topReasons: reasons,
          risks: [],
          assurances: [{ id: 'user.allowlist', category: 'user', text: reasons[0] }],
          informational: []
        }
      };
    }

    // 2. Exact-URL Hard Fail Check
    // ONLY exact URL matches trigger hard fail. Host/apex matches are handled as weighted evidence.
    let hardFailed = false;
    let hardFailReason = '';

    const exactUrlThreat = list.find(i =>
      i.polarity === 'negative' &&
      i.confidence === 'high' &&
      (i.id === 'reputation.exact_url' || i.id === 'phishtank.exact_url')
    );

    if (exactUrlThreat) {
      hardFailed = true;
      hardFailReason = exactUrlThreat.detail || 'URL confirmed as malicious in threat feed';
    }

    // Insecure HTTP + credential form is also a deterministic hard fail
    const hasHttp = list.some(i => i.id === 'url.no_https');
    const hasPassword = list.some(i => i.id === 'dom.password_form' || i.id === 'dom.credential_fields');
    if (hasHttp && hasPassword) {
      hardFailed = true;
      hardFailReason = '[X] Insecure connection: Password submission over unencrypted HTTP';
    }

    if (hardFailed) {
      const score = 0;
      const verdict = 'DANGEROUS';
      const explanation = typeof Explainer !== 'undefined'
        ? Explainer.explain(list, verdict, score, { hardFailed: true, domain: options.domain })
        : { summary: hardFailReason, topReasons: [hardFailReason], risks: [] };

      return {
        score,
        verdict,
        hardFailed: true,
        reasons: [hardFailReason],
        indicators: list,
        explanation
      };
    }

    // 3. Evidence-Based Scoring from Neutral Base (50)
    let baseScore = 50;
    let positiveWeight = 0;
    let negativeWeight = 0;

    let hasHighSeverityNegative = false;
    let hasMediumSeverityNegative = false;

    list.forEach(indicator => {
      if (indicator.polarity === 'positive') {
        // Add positive weight
        positiveWeight += Math.max(0, indicator.weight);
      } else if (indicator.polarity === 'negative') {
        // Subtract negative weight (indicator.weight is stored as negative number)
        const pen = Math.abs(indicator.weight);
        negativeWeight += pen;
        if (indicator.confidence === 'high' || pen >= 25) {
          hasHighSeverityNegative = true;
        } else if (indicator.confidence === 'medium' || pen >= 15) {
          hasMediumSeverityNegative = true;
        }
      }
    });

    let rawScore = baseScore + positiveWeight - negativeWeight;
    const finalScore = Math.max(0, Math.min(100, Math.round(rawScore)));

    // 4. Four-State Verdict Determination
    let verdict = 'UNKNOWN';

    if (finalScore <= 34 || hasHighSeverityNegative) {
      verdict = 'DANGEROUS';
    } else if (finalScore < THRESHOLDS.UNKNOWN_MIN_SCORE || hasMediumSeverityNegative) {
      // Score 35-54 or noticeable medium risk indicators
      verdict = 'SUSPICIOUS';
    } else if (finalScore >= THRESHOLDS.SAFE_MIN_SCORE && positiveWeight >= 20 && !hasMediumSeverityNegative) {
      // Must have earned score >= 75 WITH verified positive signals and zero high/medium risks
      verdict = 'SAFE';
    } else {
      // Score 55-74 (neutral / unverified clean site): Honesty rule -> UNKNOWN
      verdict = 'UNKNOWN';
    }

    const explanation = typeof Explainer !== 'undefined'
      ? Explainer.explain(list, verdict, finalScore, { hardFailed: false, domain: options.domain })
      : { summary: 'Analysis complete', topReasons: [] };

    return {
      score: finalScore,
      verdict,
      hardFailed: false,
      reasons: explanation.topReasons || [],
      indicators: list,
      explanation
    };
  }

  function getVerdictColor(verdict) {
    switch (verdict) {
      case 'SAFE': return '#10B981';       // Emerald Green
      case 'UNKNOWN': return '#6B7280';    // Neutral Slate Grey
      case 'SUSPICIOUS': return '#F59E0B'; // Amber Warning
      case 'DANGEROUS': return '#EF4444';  // Crimson Danger
      default: return '#6B7280';
    }
  }

  function getVerdictIcon(verdict) {
    switch (verdict) {
      case 'SAFE': return '[OK]';
      case 'UNKNOWN': return '[?]';
      case 'SUSPICIOUS': return '[!]';
      case 'DANGEROUS': return '[X]';
      default: return '[?]';
    }
  }

  return {
    evaluate,
    getVerdictColor,
    getVerdictIcon,
    THRESHOLDS
  };
})();

if (typeof self !== 'undefined') {
  self.VerdictEngine = VerdictEngine;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = VerdictEngine;
}
