/**
 * SafeClick 2.0 - Trust Scorer
 * Open Source Browser Security Engine
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
// Enhanced TrustScorer with comprehensive security analysis
class TrustScorer {
  constructor(options = {}) {
    // Load configuration
    this.config = typeof SafeClickConfig !== 'undefined' ? SafeClickConfig : this.getDefaultConfig();
    this.phishDB = options?.phishDB || null;
    this.repDB = options?.repDB || null;

    this.scoringFactors = {
      https: { weight: this.config.Scoring.weights.https, critical: this.config.Scoring.criticalFailures.includes('https') },
      sslCertificate: { weight: 0, critical: false }, // Disabled: cannot validate cert chain from extension
      domainPattern: { weight: this.config.Scoring.weights.domainPattern, critical: false },
      phishTank: { weight: this.config.Scoring.weights.phishTank, critical: this.config.Scoring.criticalFailures.includes('phishTank') },
      suspiciousKeywords: { weight: this.config.Scoring.weights.suspiciousKeywords, critical: false },
      heuristicAnalysis: { weight: 0, critical: false },
      urlShortener: { weight: this.config.Scoring.weights.urlShortener || 15, critical: false },
      subdomainAnalysis: { weight: this.config.Scoring.weights.subdomainAnalysis || 10, critical: false },
      contentSecurity: { weight: this.config.Scoring.weights.contentSecurity || 8, critical: false },
      socialEngineering: { weight: this.config.Scoring.weights.socialEngineering || 12, critical: false },
      redirectRisk: { weight: (this.config.Scoring.weights.redirectRisk || 12), critical: false }
    };

    this.riskyCountries = this.config.Security.riskyCountries;
    this.suspiciousKeywords = this.config.Security.suspiciousKeywords;
    this.phishingPatterns = this.config.Security.phishingPatterns;
    this.suspiciousTlds = this.config.Security.suspiciousTlds;
    this.brandNames = this.config.Security.brandNames;
    this.urlShorteners = this.config.Security.urlShorteners || ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link', 'tiny.cc'];
    this.socialEngineeringKeywords = this.config.Security.socialEngineeringKeywords || [
      'urgent action required', 'immediate action required', 'verify your account now', 'suspended account', 'click here immediately to verify',
      'act fast to prevent suspension', 'confirm identity immediately', 'update payment method now'
    ];
    this.suspiciousSubdomainPatterns = this.config.Security.suspiciousSubdomainPatterns || [
      /^(www\d+|secure\d+|login\d+|auth\d+|verify\d+)\./,
      /^(account|security|support|service|update|confirm)[-.].*\./,
      /^.*[-_](login|auth|secure|verify|account)\./
    ];

    // Enhanced cache with LRU eviction
    this.cache = new Map();
    this.cacheTimeout = this.config.Performance.cacheTimeout;
    this.maxCacheSize = this.config.Performance.maxCacheSize || 1000;
    this.cacheAccessOrder = new Map(); // For LRU tracking

    // Performance monitoring
    this.analysisStats = {
      totalAnalyses: 0,
      cacheHits: 0,
      averageTime: 0,
      lastCleanup: Date.now()
    };
  }

  // Local ReputationDB lookup with exact URL and exact host signals (apex ignored by design)
  checkReputation(urlOrDomain) {
    try {
      if (!this.repDB || !this.repDB.loaded) {
        return { exactUrlListed: false, exactHostListed: false, apexListed: false, reason: 'ReputationDB not loaded' };
      }
      let exactUrl = false, exactHost = false, apex = false;
      try {
        if (typeof this.repDB.isListedExactUrl === 'function') {
          exactUrl = this.repDB.isListedExactUrl(urlOrDomain);
        }
      } catch (_) { }
      try {
        exactHost = this.repDB.isListedExact(urlOrDomain);
      } catch (_) { }
      try {
        if (typeof this.repDB.isListedApex === 'function') {
          apex = this.repDB.isListedApex(urlOrDomain);
        }
      } catch (_) { }
      return { exactUrlListed: !!exactUrl, exactHostListed: !!exactHost, apexListed: !!apex };
    } catch (_) {
      return { exactUrlListed: false, exactHostListed: false, apexListed: false, reason: 'ReputationDB check failed' };
    }
  }

  calculateShannonEntropy(str) {
    // Delegate to shared UrlUtils module
    return typeof UrlUtils !== 'undefined' ? UrlUtils.calculateEntropy(str) : 0;
  }

  // Removed non-functional static getters (mapKey, _hint, _hx)

  // Informational brand lookalike check: eTLD+1 + Levenshtein similarity + basic IDN awareness
  checkBrandLookalike(domain) {
    try {
      const apex = this._getETLD1FromHost(domain);
      const labels = apex.split('.').filter(Boolean);
      const sld = labels.length >= 2 ? labels[labels.length - 2] : labels[0] || '';

      if (!sld) return { score: 0, reason: '' };

      const brands = Array.isArray(this.brandNames) && this.brandNames.length ? this.brandNames : [
        'google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix'
      ];

      const normalized = (s) => String(s).toLowerCase().replace(/[^a-z0-9]/g, '');
      const sldNorm = normalized(sld);
      const reasons = [];

      // Basic IDN indicator (punycode). We don't decode here; just surface signal.
      if (sld.startsWith('xn--')) {
        reasons.push('[i] IDN Domain Detected (punycode)');
      }

      let flagged = false;
      for (const brand of brands) {
        const b = normalized(brand);
        if (!b) continue;
        if (sldNorm === b) {
          // Exact brand SLD but apex is not the official brand domain (informational)
          flagged = true;
          reasons.push(`[i] Domain Resembles Brand Name “${brand}”`);
          break;
        }
        const sim = this.calculateSimilarity(sldNorm, b);
        // Tight threshold to reduce false positives
        if (sim >= 0.84) {
          flagged = true;
          reasons.push(`[i] Possible Brand Lookalike: Similar to “${brand}”`);
          break;
        }
      }

      return {
        score: 0,
        isLookalike: flagged,
        reason: reasons.join('; ')
      };
    } catch (_) {
      return { score: 0, isLookalike: false, reason: '' };
    }
  }

  _getETLD1FromHost(host) {
    // Delegate to shared UrlUtils module
    return typeof UrlUtils !== 'undefined' ? UrlUtils.getETLD1FromHost(host) : (host || '');
  }

  getDefaultConfig() {
    return {
      Scoring: {
        weights: {
          https: 18,
          sslCertificate: 12,
          domainPattern: 15,
          phishTank: 30,
          suspiciousKeywords: 5,
          heuristicAnalysis: 5,
          urlShortener: 10,
          subdomainAnalysis: 8,
          contentSecurity: 7,
          socialEngineering: 10,
          redirectRisk: 12
        },
        thresholds: { safe: 80, suspicious: 50, dangerous: 0 },
        criticalFailures: ['https', 'phishTank']
      },
      Security: {
        suspiciousKeywords: ['verify your account', 'update password', 'suspended', 'locked out'],
        phishingPatterns: [/bank.*login/i, /paypal.*verify/i, /amazon.*security/i, /microsoft.*signin/i],
        suspiciousTlds: ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.download'],
        riskyCountries: ['RU', 'CN', 'KP', 'IR', 'SY', 'VE', 'CU'],
        brandNames: ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'netflix'],
        urlShorteners: ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link', 'tiny.cc', 'is.gd', 'buff.ly'],
        socialEngineeringKeywords: [
          'urgent', 'immediate action', 'verify now', 'suspended account', 'click here now',
          'limited time', 'act fast', 'expires today', 'confirm identity', 'update payment',
          'security alert', 'unusual activity', 'temporary suspension', 'reactivate now'
        ],
        suspiciousSubdomainPatterns: [
          /^(www\d+|secure\d+|login\d+|auth\d+|verify\d+)\./,
          /^(account|security|support|service|update|confirm)[-.].*\./,
          /^.*[-_](login|auth|secure|verify|account)\./
        ]
      },
      Performance: {
        cacheTimeout: 300000,
        maxCacheSize: 1000,
        cleanupInterval: 3600000 // 1 hour
      }
    };
  }

  async calculateTrustScore(url, pageContent = '', redirectInfo = null, domAnalysis = null) {
    console.log('[TrustScorer] Calculating trust score for:', url);
    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname;
      const cacheKey = url;
      console.log('[TrustScorer] Domain:', domain, 'PhishDB available:', !!this.phishDB);

      // Check cache first
      const cached = this.cache.get(cacheKey);
      if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
        return cached.result;
      }

      // Initialize structured evidence registry
      const registry = typeof IndicatorRegistry !== 'undefined' ? new IndicatorRegistry() : {
        list: [],
        add(i) { this.list.push(i); },
        getAll() { return this.list; }
      };

      const detailedInfo = {};

      // 1. PhishTank Check (Zero bonus points on clean!)
      const phishTankResult = this.checkPhishTank(url);
      detailedInfo.phishTank = phishTankResult;
      if (phishTankResult.exactUrlListed) {
        registry.add(new Indicator({
          id: 'phishtank.exact_url',
          source: 'phishtank',
          category: 'reputation',
          polarity: 'negative',
          weight: -100,
          confidence: 'high',
          value: true,
          detail: '[X] URL confirmed as phishing in PhishTank'
        }));
      } else if (phishTankResult.hostListed) {
        registry.add(new Indicator({
          id: 'phishtank.host_match',
          source: 'phishtank',
          category: 'reputation',
          polarity: 'negative',
          weight: -30,
          confidence: 'medium',
          value: true,
          detail: '[i] Domain has reported phishing records'
        }));
      }

      // 2. ReputationDB Check (Exact URL vs Host vs Apex distinction)
      const repResult = this.checkReputation(url);
      detailedInfo.reputation = repResult;
      if (repResult.exactUrlListed) {
        registry.add(new Indicator({
          id: 'reputation.exact_url',
          source: 'reputation-db',
          category: 'reputation',
          polarity: 'negative',
          weight: -100,
          confidence: 'high',
          value: true,
          detail: '[X] URL listed in local threat intelligence'
        }));
      } else if (repResult.exactHostListed) {
        // Weighted negative indicator, NOT a hard fail!
        registry.add(new Indicator({
          id: 'reputation.host_match',
          source: 'reputation-db',
          category: 'reputation',
          polarity: 'negative',
          weight: -30,
          confidence: 'medium',
          value: true,
          detail: '[!] Domain flagged in threat intelligence'
        }));
      } else if (repResult.apexListed) {
        registry.add(new Indicator({
          id: 'reputation.apex_match',
          source: 'reputation-db',
          category: 'reputation',
          polarity: 'negative',
          weight: -15,
          confidence: 'low',
          value: true,
          detail: '[!] Parent apex domain flagged in threat intelligence'
        }));
      }

      // 3. URL Lexical & Structural Security Analysis
      if (typeof URLAnalyzer !== 'undefined') {
        const urlAnalyzer = new URLAnalyzer();
        const urlIndicators = urlAnalyzer.analyze(url);
        if (Array.isArray(urlIndicators)) {
          registry.addAll(urlIndicators);
        }
      } else {
        // Fallback to legacy checks
        const httpsResult = this.checkHTTPS(url);
        detailedInfo.https = httpsResult;
        if (httpsResult.score > 0) {
          registry.add(new Indicator({
            id: 'url.https',
            source: 'url-analyzer',
            category: 'network',
            polarity: 'positive',
            weight: 15,
            confidence: 'high',
            value: true,
            detail: '[OK] Encrypted HTTPS connection active'
          }));
        } else {
          registry.add(new Indicator({
            id: 'url.no_https',
            source: 'url-analyzer',
            category: 'network',
            polarity: 'negative',
            weight: -25,
            confidence: 'high',
            value: true,
            detail: '[X] No HTTPS - Connection is not encrypted'
          }));
        }

        const patternResult = this.analyzeDomainPattern(domain);
        detailedInfo.domainPattern = patternResult;
        if (patternResult.score >= this.scoringFactors.domainPattern.weight * 0.8) {
          registry.add(new Indicator({
            id: 'domain.clean_structure',
            source: 'url-analyzer',
            category: 'structural',
            polarity: 'positive',
            weight: 10,
            confidence: 'medium',
            value: true,
            detail: '[OK] Clean domain structure'
          }));
        }
      }

      // 4. URL Shortener Detection
      const shortenerResult = this.checkURLShortener(url);
      detailedInfo.urlShortener = shortenerResult;
      if (shortenerResult.isShortener) {
        registry.add(new Indicator({
          id: 'url.shortener',
          source: 'url-analyzer',
          category: 'redirect',
          polarity: 'negative',
          weight: -15,
          confidence: 'medium',
          value: true,
          detail: '[!] URL shortener detected - destination unknown'
        }));
      }

      // 5. Brand Impersonation & Typosquatting Analysis
      if (typeof BrandDetector !== 'undefined') {
        const brandDetector = new BrandDetector();
        const brandIndicators = brandDetector.analyze(domain);
        if (Array.isArray(brandIndicators)) {
          registry.addAll(brandIndicators);
        }
      } else {
        const brandLookalike = this.checkBrandLookalike(domain);
        detailedInfo.brandLookalike = brandLookalike;
        if (brandLookalike.isLookalike) {
          registry.add(new Indicator({
            id: 'domain.typosquat',
            source: 'brand-detector',
            category: 'lexical',
            polarity: 'negative',
            weight: -20,
            confidence: 'medium',
            value: brandLookalike.reason,
            detail: brandLookalike.reason || '[!] Domain resembles known brand'
          }));
        }
      }

      // 6. Local Machine Learning Inference (Zero Latency)
      if (typeof LocalClassifier !== 'undefined') {
        const classifier = new LocalClassifier();
        const mlResult = classifier.classify(url, domAnalysis);
        if (mlResult && Array.isArray(mlResult.indicators)) {
          registry.addAll(mlResult.indicators);
          detailedInfo.machineLearning = mlResult.prediction;
        }
      }

      // 7. Content & Social Engineering
      if (pageContent && pageContent.length > 0) {
        const socialResult = this.detectSocialEngineering(pageContent);
        detailedInfo.socialEngineering = socialResult;
        if (socialResult.score < this.scoringFactors.socialEngineering.weight * 0.5) {
          registry.add(new Indicator({
            id: 'content.social_engineering',
            source: 'content-analyzer',
            category: 'content',
            polarity: 'negative',
            weight: -15,
            confidence: 'medium',
            value: socialResult.reason,
            detail: socialResult.reason || '[!] Social engineering tactics detected'
          }));
        }

        const keywordsResult = this.checkSuspiciousKeywords(pageContent);
        detailedInfo.keywords = keywordsResult;
        if (keywordsResult.score < this.scoringFactors.suspiciousKeywords.weight * 0.5) {
          registry.add(new Indicator({
            id: 'content.suspicious_keywords',
            source: 'content-analyzer',
            category: 'content',
            polarity: 'negative',
            weight: -10,
            confidence: 'medium',
            value: keywordsResult.keywords,
            detail: keywordsResult.reason || '[!] Suspicious content detected'
          }));
        }

        const cspResult = this.analyzeContentSecurity(pageContent);
        detailedInfo.contentSecurity = cspResult;
        if (cspResult.score >= this.scoringFactors.contentSecurity.weight * 0.8) {
          registry.add(new Indicator({
            id: 'content.good_security',
            source: 'content-analyzer',
            category: 'content',
            polarity: 'positive',
            weight: 5,
            confidence: 'low',
            value: true,
            detail: '[OK] Content security practices observed'
          }));
        }
      }

      // 6. Redirect Risks
      if (redirectInfo && typeof redirectInfo.count === 'number') {
        try {
          const assessment = this.assessRedirectRisk(redirectInfo, domain);
          detailedInfo.redirectAssessment = assessment;
          if (assessment && assessment.level === 'danger') {
            registry.add(new Indicator({
              id: 'redirect.high_risk_chain',
              source: 'redirect-tracker',
              category: 'redirect',
              polarity: 'negative',
              weight: -15,
              confidence: 'medium',
              value: assessment,
              detail: '[!] High-risk redirect chain detected'
            }));
          } else if (assessment && assessment.level === 'warn') {
            registry.add(new Indicator({
              id: 'redirect.suspicious_pattern',
              source: 'redirect-tracker',
              category: 'redirect',
              polarity: 'negative',
              weight: -8,
              confidence: 'low',
              value: assessment,
              detail: '[!] Suspicious redirect pattern'
            }));
          }
        } catch (_) {}
      }

      // 7. DOM Analyzer Integration
      if (domAnalysis) {
        detailedInfo.domAnalysis = domAnalysis;
        if (domAnalysis.hasCredentialFields) {
          registry.add(new Indicator({
            id: 'dom.password_form',
            source: 'dom-analyzer',
            category: 'content',
            polarity: 'info',
            weight: 0,
            value: true,
            detail: '[i] Sensitive credential inputs detected on page'
          }));
        }
        if (domAnalysis.hasSuspiciousForms) {
          registry.add(new Indicator({
            id: 'dom.cross_origin_form',
            source: 'dom-analyzer',
            category: 'content',
            polarity: 'negative',
            weight: -25,
            confidence: 'high',
            value: true,
            detail: '[!] Credential form submits to an external domain'
          }));
        }
        if (domAnalysis.hasClickjackingOverlay) {
          registry.add(new Indicator({
            id: 'dom.clickjacking_overlay',
            source: 'dom-analyzer',
            category: 'content',
            polarity: 'negative',
            weight: -30,
            confidence: 'high',
            value: true,
            detail: '[X] Transparent clickjacking overlay detected'
          }));
        } else if (domAnalysis.hasHiddenIframes) {
          registry.add(new Indicator({
            id: 'dom.hidden_iframe',
            source: 'dom-analyzer',
            category: 'content',
            polarity: 'negative',
            weight: -8,
            confidence: 'low',
            value: true,
            detail: '[!] Suspicious hidden iframe with untrusted source detected'
          }));
        }
        if (domAnalysis.hasBrowserInBrowserPatterns) {
          registry.add(new Indicator({
            id: 'dom.browser_in_browser',
            source: 'dom-analyzer',
            category: 'content',
            polarity: 'negative',
            weight: -35,
            confidence: 'high',
            value: true,
            detail: '[!] Browser-in-Browser spoofed UI detected'
          }));
        }
        if (domAnalysis.hasFaviconSpoof) {
          registry.add(new Indicator({
            id: 'dom.favicon_spoof',
            source: 'dom-analyzer',
            category: 'content',
            polarity: 'negative',
            weight: -25,
            confidence: 'medium',
            value: true,
            detail: '[!] Page icon mimics brand but host does not match'
          }));
        }
      }

      // 8. Verdict Engine Evaluation
      const verdictEvaluation = typeof VerdictEngine !== 'undefined'
        ? VerdictEngine.evaluate(registry, { url, domain })
        : { score: 50, verdict: 'UNKNOWN', hardFailed: false, reasons: [] };

      const result = {
        score: verdictEvaluation.score,
        verdict: verdictEvaluation.verdict,
        reasons: verdictEvaluation.reasons || [],
        indicators: registry.getAll(),
        criticalFailures: verdictEvaluation.hardFailed ? 1 : 0,
        details: {
          domain,
          url,
          timestamp: new Date().toISOString(),
          detailedInfo,
          scoringModel: 'evidence-fusion-v2',
          explanation: verdictEvaluation.explanation || null,
          hardFailed: verdictEvaluation.hardFailed
        }
      };

      // Cache result
      this.cache.set(cacheKey, { result, timestamp: Date.now() });
      return result;

    } catch (error) {
      console.error('Error calculating trust score:', error);
      const domain = error.url ? new URL(error.url).hostname : 'unknown';
      return {
        score: 50,
        verdict: 'UNKNOWN',
        reasons: ['[?] Error analyzing site - insufficient evidence'],
        criticalFailures: 0,
        details: { domain, url, timestamp: new Date().toISOString(), error: error.message, scoringModel: 'evidence-fusion-v2' }
      };
    }
  }

  checkHTTPS(url) {
    const isHttps = url.startsWith('https://');
    return {
      score: isHttps ? this.scoringFactors.https.weight : 0,
      secure: isHttps,
      protocol: isHttps ? 'HTTPS' : 'HTTP'
    };
  }

  async checkSSLCertificate(url) {
    // SSL certificate validation cannot be done from extension context.
    // The browser handles certificate chain validation natively.
    // HTTPS presence is already scored via checkHTTPS().
    // This factor is disabled to avoid providing false confidence.
    return {
      score: 0,
      reason: 'SSL validation handled by browser',
      valid: null,
      note: 'Browser validates certificate chain; extension cannot verify independently'
    };
  }

  // Domain age/WHOIS removed

  analyzeDomainPattern(domain) {
    // Use apex (eTLD+1) for pattern and typosquatting checks (handles multi-part suffixes)
    const apex = this._getETLD1FromHost(domain);
    const labels = apex.split('.').filter(Boolean);
    const sld = labels.length >= 2 ? labels[labels.length - 2] : labels[0] || '';

    const suspiciousPatterns = [
      /[a-z]{2,}-[a-z]{2,}-[a-z]{2,}/, // Multiple hyphens
      /[0-9]{4,}/, // Many numbers
      /[a-z]{20,}/, // Very long domain
      /[a-z]+[0-9]+[a-z]+/, // Mixed alphanumeric
      /^[0-9]/, // Starts with number
      /[a-z]{1,2}\.[a-z]{1,2}\.[a-z]{1,2}/, // Very short subdomains
      /[a-z]+[0-9]{3,}[a-z]+/, // Numbers in middle
      /[a-z]+[0-9]+[a-z]+[0-9]+/ // Alternating letters/numbers
    ];

    // Check for suspicious TLDs
    if (this.suspiciousTlds.some(tld => apex.endsWith(tld))) {
      return { score: 5, reason: 'Suspicious TLD detected', pattern: 'suspicious_tld' };
    }

    // Check for typosquatting patterns
    const commonDomains = ['google', 'facebook', 'amazon', 'paypal', 'apple', 'microsoft'];
    for (let commonDomain of commonDomains) {
      const target = commonDomain + '.com';
      if (sld && sld.includes(commonDomain) && apex !== target) {
        const similarity = this.calculateSimilarity(sld, commonDomain);
        if (similarity > 0.8) {
          return { score: 3, reason: 'Possible typosquatting detected', pattern: 'typosquatting' };
        }
      }
    }

    // Check for suspicious patterns on apex only
    for (let pattern of suspiciousPatterns) {
      if (pattern.test(apex)) {
        return { score: 5, reason: 'Suspicious domain pattern detected', pattern: 'suspicious_pattern' };
      }
    }

    // Lightweight SLD heuristics (conservative):
    try {
      const sl = String(sld || '');
      const len = sl.length;
      const hyphenCount = (sl.match(/-/g) || []).length;
      const digitCount = (sl.match(/\d/g) || []).length;
      const digitRatio = len > 0 ? digitCount / len : 0;
      const hasLetters = /[a-z]/i.test(sl);
      const hasDigits = /\d/.test(sl);

      // Too many hyphens often used in deceptive SLDs
      if (hyphenCount >= 3 && len >= 8) {
        return { score: 5, reason: 'Suspicious domain pattern detected', pattern: 'suspicious_pattern' };
      }

      // High digit ratio in moderately long SLDs
      if (len >= 8 && digitRatio >= 0.4 && hasLetters) {
        return { score: 5, reason: 'Suspicious domain pattern detected', pattern: 'suspicious_pattern' };
      }

      // Very long mixed SLDs
      if (len >= 20 && hasLetters && hasDigits) {
        return { score: 5, reason: 'Suspicious domain pattern detected', pattern: 'suspicious_pattern' };
      }

      // Entropy-based nudge (avoid false positives on brand-like names)
      if (len >= 12) {
        const ent = this.calculateShannonEntropy(sl.toLowerCase());
        if (ent >= 3.6 && hasLetters && hasDigits) {
          return { score: 5, reason: 'Suspicious domain pattern detected', pattern: 'suspicious_pattern' };
        }
      }
    } catch (_) { }

    // IDN informational flag (no scoring impact)
    try {
      const idn = labels.some(l => l.startsWith('xn--'));
      if (idn) {
        return { score: this.scoringFactors.domainPattern.weight, reason: 'Normal Domain Pattern', pattern: 'normal', idn: true };
      }
    } catch (_) { }

    // Full credit for normal domain pattern to allow reaching 100
    return { score: this.scoringFactors.domainPattern.weight, reason: 'Normal Domain Pattern', pattern: 'normal' };
  }

  calculateSimilarity(str1, str2) {
    // Simple Levenshtein distance calculation
    const matrix = [];
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }
    const distance = matrix[str2.length][str1.length];
    return 1 - (distance / Math.max(str1.length, str2.length));
  }

  // Local PhishTank lookup with exact URL only (no host-only to avoid collateral)
  checkPhishTank(urlOrDomain) {
    try {
      if (!this.phishDB || !this.phishDB.loaded) {
        return { score: 0, exactUrlListed: false, hostListed: false, reason: 'PhishTank DB not loaded' };
      }
      let exact = false;
      if (typeof this.phishDB.isListedExactUrl === 'function') {
        exact = this.phishDB.isListedExactUrl(urlOrDomain);
      }
      if (exact) return { score: 0, exactUrlListed: true, hostListed: false, reason: 'Exact URL match in PhishTank' };
      return { score: 0, exactUrlListed: false, hostListed: false };
    } catch (_) {
      return { score: 0, exactUrlListed: false, hostListed: false, reason: 'PhishTank check failed' };
    }
  }

  // VirusTotal integration removed from automated scoring



  checkSuspiciousKeywords(content) {
    const lowerContent = content.toLowerCase();
    const foundKeywords = this.suspiciousKeywords.filter(keyword =>
      lowerContent.includes(keyword.toLowerCase())
    );

    // Revert to less aggressive penalty for suspicious keywords
    if (foundKeywords.length > 0) {
      return { score: 3, reason: `Found ${foundKeywords.length} suspicious keywords`, keywords: foundKeywords };
    }
    return { score: 5, reason: 'No suspicious keywords detected', keywords: [] };
  }

  async performHeuristicAnalysis(url, content, domain) {
    try {
      let score = 10;
      let reasons = [];
      let riskFactors = [];

      // 1. Check for phishing patterns
      const phishingScore = this.checkPhishingPatterns(url, content, domain);
      if (phishingScore.score < 10) {
        score -= (10 - phishingScore.score); // Single penalty
        reasons.push(phishingScore.reason);
        riskFactors.push('phishing_pattern');
      }

      // 2. Check for form analysis
      const formScore = this.analyzeForms(content);
      if (formScore.score < 10) {
        score -= (10 - formScore.score); // Single penalty
        reasons.push(formScore.reason);
        riskFactors.push('suspicious_form');
      }

      // 3. Check for external resource analysis
      const resourceScore = await this.analyzeExternalResources(url, content);
      if (resourceScore.score < 10) {
        score -= (10 - resourceScore.score); // Single penalty
        reasons.push(resourceScore.reason);
        riskFactors.push('suspicious_resources');
      }

      // 4. Check for brand impersonation
      const brandScore = this.checkBrandImpersonation(domain, content);
      if (brandScore.score < 10) {
        score -= (10 - brandScore.score); // Single penalty
        reasons.push(brandScore.reason);
        riskFactors.push('brand_impersonation');
      }

      return {
        score: Math.max(0, score),
        reason: reasons.length > 0 ? reasons.join('; ') : 'Heuristic analysis passed',
        riskFactors: riskFactors,
        details: {
          phishing: phishingScore,
          forms: formScore,
          resources: resourceScore,
          brand: brandScore
        }
      };

    } catch (error) {
      return { score: 5, reason: 'Heuristic analysis failed', riskFactors: [] };
    }
  }

  checkPhishingPatterns(url, content, domain) {
    let score = 10;
    let reasons = [];

    // Check for phishing patterns in URL
    for (let pattern of this.phishingPatterns) {
      if (pattern.test(url)) {
        score -= 3;
        reasons.push('Phishing pattern in URL');
      }
    }

    // Check for urgency indicators (less sensitive)
    const urgencyWords = ['urgent', 'immediate', 'now', 'quick', 'fast', 'hurry'];
    const urgencyCount = urgencyWords.filter(word => content.toLowerCase().includes(word));
    if (urgencyCount.length > 6) {
      score -= 1; // reduced penalty
      reasons.push('Some urgency language present (informational)');
    }

    // Check for authority impersonation (less sensitive)
    const authorityWords = ['government', 'police', 'bank', 'irs', 'fbi', 'security'];
    const authorityCount = authorityWords.filter(word => content.toLowerCase().includes(word));
    if (authorityCount.length > 4) {
      score -= 1; // reduced penalty
      reasons.push('Authority terms present (informational)');
    }

    return {
      score: Math.max(0, score),
      reason: reasons.length > 0 ? reasons.join('; ') : 'No phishing patterns detected'
    };
  }

  analyzeForms(content) {
    let score = 10;
    let reasons = [];

    // Check for multiple password fields
    const passwordFields = (content.match(/type=["']password["']/gi) || []).length;
    if (passwordFields > 2) {
      score -= 3;
      reasons.push('Multiple password fields detected');
    }

    // Check for suspicious form actions (single penalty/reason even if multiple patterns match)
    const suspiciousActions = ['http://', 'javascript:', 'data:'];
    const hasSuspiciousAction = suspiciousActions.some(a => content.includes(a));
    if (hasSuspiciousAction) {
      score -= 2;
      reasons.push('Suspicious form action');
    }

    // Check for hidden fields
    const hiddenFields = (content.match(/type=["']hidden["']/gi) || []).length;
    if (hiddenFields > 5) {
      score -= 1;
      reasons.push('Excessive hidden fields');
    }

    return {
      score: Math.max(0, score),
      reason: reasons.length > 0 ? reasons.join('; ') : 'Forms appear legitimate'
    };
  }

  async analyzeExternalResources(url, content) {
    let score = 10;
    let reasons = [];

    try {
      // Extract external resources
      const externalScripts = content.match(/src=["'](https?:\/\/[^"']+)["']/g) || [];
      const externalStyles = content.match(/href=["'](https?:\/\/[^"']+)["']/g) || [];

      // Check for resources from suspicious domains
      const suspiciousDomains = ['cdn.example.com', 'static.suspicious.com'];
      for (let script of externalScripts) {
        for (let domain of suspiciousDomains) {
          if (script.includes(domain)) {
            score -= 2;
            reasons.push('Suspicious external script');
          }
        }
      }

      // Check for mixed content (HTTPS page with HTTP resources)
      if (url.startsWith('https://')) {
        const httpResources = [...externalScripts, ...externalStyles].filter(resource => resource.includes('http://'));
        // Be less sensitive: only penalize if there are 3 or more HTTP resources
        if (httpResources.length >= 3) {
          score -= 1;
          reasons.push(`Mixed content detected (${httpResources.length} HTTP resources)`);
        }
      }
    } catch (error) {
      // External resource analysis failed
    }

    return {
      score: Math.max(0, score),
      reason: reasons.length > 0 ? reasons.join('; ') : 'No external resource issues detected'
    };
  }

  // Brand impersonation detection
  checkBrandImpersonation(url, content) {
    let score = 10;
    let reasons = [];

    try {
      const domain = new URL(url).hostname;

      // Check for brand names in content but not in domain
      const brands = ['google', 'facebook', 'amazon', 'paypal', 'apple', 'microsoft', 'netflix'];
      const lowerContent = content.toLowerCase();
      const lowerDomain = domain.toLowerCase();
      const brandInContent = brands.filter(brand => lowerContent.includes(brand));
      const brandInDomain = brands.filter(brand => lowerDomain.includes(brand));

      // Context words to ensure relevant scenarios (login/payment/etc.)
      const contextWords = ['login', 'sign in', 'signin', 'verify', 'password', 'otp', 'payment', 'billing'];
      const hasContext = contextWords.some(w => lowerContent.includes(w));

      // Less sensitive: require at least 4 brand mentions, unrelated domain, and context
      if (brandInContent.length >= 4 && brandInDomain.length === 0 && hasContext) {
        score -= 2; // reduced penalty
        reasons.push(`Brand mentions (${brandInContent.length}) with unrelated domain (informational)`);
      }

      // Check for logo usage without proper attribution
      const logoIndicators = ['logo', 'brand', 'official'];
      const logoCount = logoIndicators.filter(indicator => lowerContent.includes(indicator));
      if (logoCount.length > 2 && brandInDomain.length === 0 && brandInContent.length >= 1) {
        score -= 2;
        reasons.push('Possible brand impersonation');
      }
    } catch (error) {
      // Brand analysis failed
    }

    return {
      score: Math.max(0, score),
      reason: reasons.length > 0 ? reasons.join('; ') : 'No brand impersonation detected'
    };
  }

  getVerdict(score, criticalFailures) {
    if (typeof VerdictEngine !== 'undefined' && typeof VerdictEngine.getVerdictIcon === 'function') {
      if (criticalFailures > 0) return 'DANGEROUS';
      if (score >= VerdictEngine.THRESHOLDS.SAFE_MIN_SCORE) return 'SAFE';
      if (score >= VerdictEngine.THRESHOLDS.UNKNOWN_MIN_SCORE) return 'UNKNOWN';
      if (score >= VerdictEngine.THRESHOLDS.SUSPICIOUS_MIN_SCORE) return 'SUSPICIOUS';
      return 'DANGEROUS';
    }
    if (criticalFailures > 0) return 'DANGEROUS';
    if (score >= 75) return 'SAFE';
    if (score >= 55) return 'UNKNOWN';
    if (score >= 35) return 'SUSPICIOUS';
    return 'DANGEROUS';
  }

  getVerdictColor(verdict) {
    if (typeof VerdictEngine !== 'undefined' && typeof VerdictEngine.getVerdictColor === 'function') {
      return VerdictEngine.getVerdictColor(verdict);
    }
    switch (verdict) {
      case 'SAFE': return '#10B981';
      case 'UNKNOWN': return '#6B7280';
      case 'SUSPICIOUS': return '#F59E0B';
      case 'DANGEROUS': return '#EF4444';
      default: return '#6B7280';
    }
  }

  getVerdictIcon(verdict) {
    if (typeof VerdictEngine !== 'undefined' && typeof VerdictEngine.getVerdictIcon === 'function') {
      return VerdictEngine.getVerdictIcon(verdict);
    }
    switch (verdict) {
      case 'SAFE': return '[OK]';
      case 'UNKNOWN': return '[?]';
      case 'SUSPICIOUS': return '[!]';
      case 'DANGEROUS': return '[X]';
      default: return '[?]';
    }
  }

  // No API key or external rate limiting logic (local-only)

  // Redirect risk assessment (informational; scorer applies penalty only for warn/danger)
  assessRedirectRisk(redirects, destinationDomain = '') {
    try {
      if (!redirects || typeof redirects.count !== 'number') {
        return { level: 'none', reasons: [], details: { redirects } };
      }
      const count = redirects.count;
      const uniqueDomains = Array.isArray(redirects.uniqueDomains) ? redirects.uniqueDomains : [];
      const domainHops = uniqueDomains.length;

      const reasons = [];
      let level = 'none';

      if (count === 0) {
        return { level, reasons, details: { count, domainHops } };
      }

      // Group by eTLD+1 to distinguish internal redirects from cross-domain chains
      let apexCount = 0;
      try {
        const apexSet = new Set(uniqueDomains.map(d => this._getETLD1FromHost(d)));
        apexCount = apexSet.size;
      } catch (_) { apexCount = domainHops; }

      // Default: informational for small internal chains
      level = 'info';
      let baseReason = 'One OR More Redirects Observed';

      if (apexCount <= 1) {
        // Internal/canonicalization/SSO within same eTLD+1
        if (count >= 5) {
          level = 'danger';
          baseReason = '[X] Excessive Internal Redirects';
        } else if (count >= 3) {
          level = 'warn';
          baseReason = '[!] Multiple Internal Redirects';
        } else {
          level = 'info';
          baseReason = 'Internal Redirect(s) observed';
        }
      } else {
        // Cross-domain chains are riskier
        if (count >= 5 || apexCount >= 3) {
          level = 'danger';
          baseReason = '[X] Excessive Redirects Across Multiple Domains';
        } else if (count >= 3 || apexCount >= 2) {
          level = 'warn';
          baseReason = '[!] Multiple Redirects OR Cross-Domain Hops Detected';
        } else {
          level = 'info';
          baseReason = 'Cross-Domain Redirect Observed';
        }
      }
      reasons.push(baseReason);

      // Final-destination mismatch (compare eTLD+1) escalates at least to warn
      try {
        if (Array.isArray(redirects.hops) && redirects.hops.length > 0 && destinationDomain) {
          const last = redirects.hops[redirects.hops.length - 1];
          const finalHost = new URL(last.to).hostname;
          const destApex = this._getETLD1FromHost(destinationDomain);
          const finalApex = this._getETLD1FromHost(finalHost);
          if (finalHost && finalApex && finalApex !== destApex) {
            reasons.push('[!] Final destination differs from displayed domain');
            if (level === 'info') level = 'warn';
            // If already warn and cross-domain chain exists, escalate to danger
            if (level === 'warn' && apexCount >= 2) level = 'danger';
          }
        }
      } catch (_) { }

      return { level, reasons, details: { count, domainHops, apexGroups: apexCount } };
    } catch (_) {
      return { level: 'none', reasons: [], details: { error: 'redirect assessment failed' } };
    }
  }

  // New security analysis methods
  checkURLShortener(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();

      const isShortener = this.urlShorteners.some(shortener =>
        hostname === shortener || hostname.endsWith('.' + shortener)
      );

      if (isShortener) {
        return {
          score: 3,
          reason: '[!] URL shortener detected - destination unknown',
          isShortener: true,
          service: hostname
        };
      }

      return {
        score: this.scoringFactors.urlShortener.weight,
        reason: '[OK] Direct URL - No Shortener',
        isShortener: false
      };
    } catch (_) {
      return { score: this.scoringFactors.urlShortener.weight, reason: 'URL shortener check failed', isShortener: false };
    }
  }

  analyzeSubdomain(domain) {
    try {
      const parts = domain.split('.');
      if (parts.length <= 2) {
        return {
          score: this.scoringFactors.subdomainAnalysis.weight,
          reason: '[OK] Root domain - No Subdomain Risks',
          level: 'safe'
        };
      }

      const subdomain = parts.slice(0, -2).join('.');
      // Benign single-label subdomains (common patterns)
      try {
        const benign = new Set(['www', 'm', 'app', 'cdn', 'static', 'img']);
        const labels = subdomain.split('.').filter(Boolean);
        if (labels.length === 1 && benign.has(labels[0])) {
          return {
            score: this.scoringFactors.subdomainAnalysis.weight,
            reason: '[OK] Normal Subdomain Structure',
            level: 'safe'
          };
        }
      } catch (_) { }

      // Check against suspicious patterns
      for (const pattern of this.suspiciousSubdomainPatterns) {
        if (pattern.test(subdomain + '.')) {
          return {
            score: 2,
            reason: '[!] Suspicious Subdomain Pattern Detected',
            level: 'suspicious',
            subdomain: subdomain
          };
        }
      }

      // Check for excessive subdomain depth
      if (parts.length > 4) {
        return {
          score: 4,
          reason: '[!] Deep Subdomain Structure Detected',
          level: 'warn',
          depth: parts.length
        };
      }

      // Check for numeric subdomains
      if (/^\d+$/.test(parts[0])) {
        return {
          score: 5,
          reason: '[!] Numeric Subdomain Detected',
          level: 'warn',
          subdomain: subdomain
        };
      }

      return {
        score: this.scoringFactors.subdomainAnalysis.weight,
        reason: '[OK] Normal Subdomain Structure',
        level: 'safe'
      };
    } catch (_) {
      return { score: this.scoringFactors.subdomainAnalysis.weight, reason: 'Subdomain Analysis Failed', level: 'unknown' };
    }
  }

  analyzeContentSecurity(content) {
    try {
      let score = this.scoringFactors.contentSecurity.weight;
      const issues = [];

      // Check for inline scripts (security risk)
      const inlineScripts = (content.match(/<script[^>]*>[\s\S]*?<\/script>/gi) || []).length;
      if (inlineScripts > 5) {
        score -= 2;
        issues.push('excessive inline scripts');
      }

      // Check for eval() usage
      if (content.toLowerCase().includes('eval(')) {
        score -= 3;
        issues.push('eval() usage detected');
      }

      // Check for document.write usage
      if (content.toLowerCase().includes('document.write')) {
        score -= 1;
        issues.push('document.write usage');
      }

      // Check for obfuscated JavaScript
      const obfuscationIndicators = [
        /\\x[0-9a-f]{2}/gi, // hex encoding
        /\\u[0-9a-f]{4}/gi, // unicode encoding
        /eval\s*\(\s*unescape/gi, // eval with unescape
        /String\.fromCharCode/gi // character code conversion
      ];

      const obfuscationCount = obfuscationIndicators.reduce((count, pattern) =>
        count + (content.match(pattern) || []).length, 0
      );

      if (obfuscationCount > 10) {
        score -= 4;
        issues.push('heavily obfuscated JavaScript');
      } else if (obfuscationCount > 3) {
        score -= 2;
        issues.push('some JavaScript obfuscation');
      }

      const reason = issues.length > 0
        ? `[!] Content Security Issues: ${issues.join(', ')}`
        : '[OK] No significant Content Security Issues';

      return {
        score: Math.max(0, score),
        reason,
        issues: issues,
        inlineScripts: inlineScripts,
        obfuscationLevel: obfuscationCount > 10 ? 'high' : obfuscationCount > 3 ? 'medium' : 'low'
      };
    } catch (_) {
      return { score: this.scoringFactors.contentSecurity.weight, reason: 'Content security analysis failed', issues: [] };
    }
  }

  detectSocialEngineering(content) {
    try {
      let score = this.scoringFactors.socialEngineering.weight;
      const lowerContent = (content || '').toLowerCase();
      const detectedTactics = [];

      // Check for urgency tactics with multi-word phishing phrases
      const urgencyMatches = (this.socialEngineeringKeywords || []).filter(keyword =>
        lowerContent.includes(keyword.toLowerCase())
      );

      if (urgencyMatches.length >= 2) {
        score -= 4;
        detectedTactics.push('urgency pressure');
      } else if (urgencyMatches.length === 1) {
        score -= 2;
        detectedTactics.push('some urgency language');
      }

      // Check for authority impersonation
      const authorityTerms = ['official security notice', 'federal tax alert', 'government agency notice', 'fbi cyber division alert', 'internal revenue service alert'];
      const authorityCount = authorityTerms.filter(term => lowerContent.includes(term)).length;
      if (authorityCount >= 1) {
        score -= 3;
        detectedTactics.push('authority impersonation');
      }

      // Check for fear tactics
      const fearTerms = ['account is suspended', 'account has been suspended', 'account will be terminated', 'funds have been frozen', 'account permanently restricted'];
      const fearCount = fearTerms.filter(term => lowerContent.includes(term)).length;
      if (fearCount >= 1) {
        score -= 3;
        detectedTactics.push('fear tactics');
      }

      // Check for scarcity tactics
      const scarcityTerms = ['last chance to verify', 'final notice before suspension', 'expires in 10 minutes', 'expires in 15 minutes', 'immediate action required to prevent closure'];
      const scarcityCount = scarcityTerms.filter(term => lowerContent.includes(term)).length;
      if (scarcityCount >= 1) {
        score -= 2;
        detectedTactics.push('scarcity pressure');
      }

      const reason = detectedTactics.length > 0
        ? `[!] Social Engineering Tactics: ${detectedTactics.join(', ')}`
        : '[OK] No Social Engineering Tactics Detected';

      return {
        score: Math.max(0, score),
        reason,
        tactics: detectedTactics,
        urgencyLevel: urgencyMatches.length >= 2 ? 'high' : urgencyMatches.length === 1 ? 'medium' : 'low'
      };
    } catch (_) {
      return { score: this.scoringFactors.socialEngineering.weight, reason: 'Social engineering analysis failed', tactics: [] };
    }
  }

  // Enhanced cache management with LRU eviction
  manageCacheSize() {
    if (this.cache.size <= this.maxCacheSize) return;

    // Sort by access time and remove oldest entries
    const sortedEntries = Array.from(this.cacheAccessOrder.entries())
      .sort((a, b) => a[1] - b[1])
      .slice(0, Math.floor(this.maxCacheSize * 0.2)); // Remove 20% of cache

    sortedEntries.forEach(([key]) => {
      this.cache.delete(key);
      this.cacheAccessOrder.delete(key);
    });
  }

  // Performance monitoring
  updateAnalysisStats(startTime) {
    this.analysisStats.totalAnalyses++;
    const duration = Date.now() - startTime;
    this.analysisStats.averageTime =
      (this.analysisStats.averageTime * (this.analysisStats.totalAnalyses - 1) + duration) /
      this.analysisStats.totalAnalyses;

    // Cleanup old cache entries periodically
    if (Date.now() - this.analysisStats.lastCleanup > this.config.Performance.cleanupInterval) {
      this.manageCacheSize();
      this.analysisStats.lastCleanup = Date.now();
    }
  }

  // Cache management
  clearCache() {
    this.cache.clear();
    this.cacheAccessOrder.clear();
    this.analysisStats = {
      totalAnalyses: 0,
      cacheHits: 0,
      averageTime: 0,
      lastCleanup: Date.now()
    };
  }

  getCacheStats() {
    return {
      size: this.cache.size,
      maxSize: this.maxCacheSize,
      hitRate: this.analysisStats.totalAnalyses > 0 ?
        (this.analysisStats.cacheHits / this.analysisStats.totalAnalyses * 100).toFixed(1) + '%' : '0%',
      averageTime: Math.round(this.analysisStats.averageTime) + 'ms',
      entries: Array.from(this.cache.keys())
    };
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = TrustScorer;
}