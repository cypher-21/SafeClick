/**
 * SafeClick 2.0 - Explainability Engine
 * Open Source Browser Security Engine
 * 
 * Transforms structured security indicators into clear, human-readable
 * rationales, risk lists, and actionable explanations.
 */

const Explainer = (function () {
  'use strict';

  /**
   * Generate an explainability report from an IndicatorRegistry or indicator array
   * @param {IndicatorRegistry|Array} indicators
   * @param {string} verdict - 'SAFE' | 'UNKNOWN' | 'SUSPICIOUS' | 'DANGEROUS'
   * @param {number} score - 0 to 100
   * @param {Object} [meta] - additional context (e.g. domain, hardFailed)
   */
  function explain(indicators, verdict, score, meta = {}) {
    const list = Array.isArray(indicators)
      ? indicators
      : (indicators && typeof indicators.getAll === 'function' ? indicators.getAll() : []);

    const negative = list.filter(i => i.polarity === 'negative')
      .sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));
    const positive = list.filter(i => i.polarity === 'positive')
      .sort((a, b) => b.weight - a.weight);
    const info = list.filter(i => i.polarity === 'info');

    // Generate concise verdict summary
    let summary = '';
    switch (verdict) {
      case 'DANGEROUS':
        summary = meta.hardFailed
          ? 'This URL was verified as malicious or phishing by threat intelligence.'
          : 'High risk detected. This site exhibits critical threat signals; do not submit credentials.';
        break;
      case 'SUSPICIOUS':
        summary = 'Caution recommended. Multiple risk indicators or abnormal structures were detected.';
        break;
      case 'UNKNOWN':
        summary = 'Insufficient evidence to verify safety. No known threats were found, but the site lacks established trust signals.';
        break;
      case 'SAFE':
        summary = 'Verified safe. Secure connection, clean structure, and verified trust indicators confirmed.';
        break;
      default:
        summary = 'Analysis complete.';
    }

    // Generate top bullet points for UI display (up to 4 reasons)
    const topReasons = [];
    if (meta.hardFailed) {
      const exactMatch = negative.find(i => i.id.startsWith('reputation.exact') || i.id.startsWith('phishtank.exact'));
      topReasons.push(exactMatch ? exactMatch.detail : 'Confirmed malicious in threat intelligence');
    }

    negative.forEach(item => {
      if (topReasons.length < 4 && !topReasons.includes(item.detail)) {
        topReasons.push(item.detail);
      }
    });

    if (topReasons.length === 0) {
      if (verdict === 'SAFE') {
        topReasons.push('Encrypted HTTPS connection active');
        topReasons.push('Clean domain structure and verified destination');
      } else if (verdict === 'UNKNOWN') {
        topReasons.push('No known threat records found');
        topReasons.push('Site lacks established positive trust signals');
      }
    }

    return {
      verdict,
      score,
      summary,
      topReasons,
      risks: negative.map(i => ({
        id: i.id,
        category: i.category,
        confidence: i.confidence,
        weight: i.weight,
        text: i.detail
      })),
      assurances: positive.map(i => ({
        id: i.id,
        category: i.category,
        confidence: i.confidence,
        weight: i.weight,
        text: i.detail
      })),
      informational: info.map(i => ({
        id: i.id,
        category: i.category,
        text: i.detail
      })),
      indicatorCount: list.length,
      timestamp: Date.now()
    };
  }

  return {
    explain
  };
})();

if (typeof self !== 'undefined') {
  self.Explainer = Explainer;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = Explainer;
}
