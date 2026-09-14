/**
 * SafeClick 2.0 - Local Machine Learning Classifier
 * Open Source Browser Security Engine
 * 
 * Lightweight, calibrated, interpretable linear/logistic classifier compiled into pure JS.
 * Zero cloud dependency, zero external API keys, sub-millisecond execution.
 */

(function () {
  'use strict';

  // Handle environments (Browser vs Node.js)
  const _Indicator = (typeof Indicator !== 'undefined') ? Indicator : (function () {
    try { return require('../evidence/indicator.js').Indicator; } catch (_) { return null; }
  })();
  const _FeatureExtractor = (typeof FeatureExtractor !== 'undefined') ? FeatureExtractor : (function () {
    try { return require('./feature-extractor.js'); } catch (_) { return null; }
  })();

  class LocalClassifier {
  constructor() {
    this.extractor = _FeatureExtractor ? new _FeatureExtractor() : null;

    // Feature weights calibrated against benchmark dataset
    // Index matches FeatureExtractor.FEATURE_NAMES (0-23)
    this.weights = new Float32Array([
      1.10,  // 0:  urlLength
      0.90,  // 1:  hostLength
      0.80,  // 2:  pathLength
      0.70,  // 3:  queryLength
      1.40,  // 4:  subdomainCount
      1.20,  // 5:  dotCount
      1.30,  // 6:  hyphenCount
      1.50,  // 7:  digitRatio
      1.60,  // 8:  subdomainEntropy
      0.90,  // 9:  pathEntropy
      -1.80, // 10: isHttps (strong protective negative weight)
      2.50,  // 11: isIpHost
      2.20,  // 12: isSuspiciousTld
      2.10,  // 13: isPunycode
      2.40,  // 14: hasHomoglyphs
      1.60,  // 15: hasNonStandardPort
      2.60,  // 16: hasEmbeddedCredentials
      2.40,  // 17: brandSimilarity
      2.70,  // 18: isCombosquat
      3.00,  // 19: isSubdomainBrandSpoof
      2.80,  // 20: hasCrossOriginForm
      2.20,  // 21: hasHiddenIframe
      3.20,  // 22: hasBrowserInBrowser
      1.10   // 23: hasPasswordField
    ]);

    // Calibrated intercept
    this.bias = -2.10;
  }

  /**
   * Sigmoid activation function
   */
  sigmoid(z) {
    if (z > 20) return 1.0;
    if (z < -20) return 0.0;
    return 1.0 / (1.0 + Math.exp(-z));
  }

  /**
   * Predict phishing probability and explainable decision from feature vector
   * @param {Float32Array} vector - 24 numerical features
   * @returns {Object} Prediction details
   */
  predictVector(vector) {
    let z = this.bias;
    const contributions = [];

    const featureNames = (this.extractor && this.extractor.FEATURE_NAMES) || [
      'urlLength', 'hostLength', 'pathLength', 'queryLength',
      'subdomainCount', 'dotCount', 'hyphenCount', 'digitRatio',
      'subdomainEntropy', 'pathEntropy', 'isHttps', 'isIpHost',
      'isSuspiciousTld', 'isPunycode', 'hasHomoglyphs', 'hasNonStandardPort',
      'hasEmbeddedCredentials', 'brandSimilarity', 'isCombosquat',
      'isSubdomainBrandSpoof', 'hasCrossOriginForm', 'hasHiddenIframe',
      'hasBrowserInBrowser', 'hasPasswordField'
    ];

    for (let i = 0; i < this.weights.length; i++) {
      const val = vector[i] || 0;
      const term = this.weights[i] * val;
      z += term;

      if (val > 0.05 && term !== 0) {
        contributions.push({
          feature: featureNames[i],
          value: Math.round(val * 100) / 100,
          contribution: Math.round(term * 100) / 100
        });
      }
    }

    const probability = Math.round(this.sigmoid(z) * 1000) / 1000;

    // Sort contributions by impact
    contributions.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));

    let decision = 'BENIGN';
    if (probability >= 0.75) {
      decision = 'MALICIOUS';
    } else if (probability >= 0.45) {
      decision = 'SUSPICIOUS';
    }

    return {
      probability,
      decision,
      rawLogit: Math.round(z * 100) / 100,
      topFeatures: contributions.slice(0, 4)
    };
  }

  /**
   * Classify URL and DOM, and emit structured security Indicator instances
   * @param {string} url - Target URL
   * @param {Object} [domAnalysis] - DOM analysis findings
   * @returns {Object} { prediction, indicators: Indicator[] }
   */
  classify(url, domAnalysis = null) {
    if (!this.extractor) {
      this.extractor = _FeatureExtractor ? new _FeatureExtractor() : null;
    }
    const vector = this.extractor.extract(url, domAnalysis);
    const prediction = this.predictVector(vector);

    const indicators = [];
    const IndicatorClass = _Indicator || (typeof Indicator !== 'undefined' ? Indicator : null);

    if (IndicatorClass) {
      if (prediction.decision === 'MALICIOUS') {
        indicators.push(new IndicatorClass({
          id: 'ml.high_risk',
          source: 'ml-classifier',
          category: 'structural',
          polarity: 'negative',
          weight: -35,
          confidence: 'high',
          value: prediction,
          detail: `[X] Local ML model detected attack pattern (${Math.round(prediction.probability * 100)}% risk)`
        }));
      } else if (prediction.decision === 'SUSPICIOUS') {
        indicators.push(new IndicatorClass({
          id: 'ml.suspicious',
          source: 'ml-classifier',
          category: 'structural',
          polarity: 'negative',
          weight: -20,
          confidence: 'medium',
          value: prediction,
          detail: `[!] Local ML model flagged anomalies (${Math.round(prediction.probability * 100)}% risk)`
        }));
      } else if (prediction.probability < 0.15) {
        indicators.push(new IndicatorClass({
          id: 'ml.benign',
          source: 'ml-classifier',
          category: 'structural',
          polarity: 'positive',
          weight: 10,
          confidence: 'medium',
          value: prediction,
          detail: '[OK] Machine learning structural profile consistent with legitimate websites'
        }));
      }
    }

    return {
      prediction,
      vector,
      indicators
    };
  }
}

  // Environment exports
  if (typeof self !== 'undefined') {
    self.LocalClassifier = LocalClassifier;
    self.Classifier = LocalClassifier;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = LocalClassifier;
  }
})();
