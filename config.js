// SafeClick Configuration File
// Customize settings here. No external API keys are used.

const SafeClickConfig = {
  // External APIs removed. Local-only PhishTank dataset used for phishing detection.

  // Public links
  PRIVACY_URL: 'https://github.com/cypher-21/SafeClick/blob/main/PRIVACY.md',

  // PhishTank dataset settings (offline-only; seed file bundled)
  PhishTank: {
    // Offline mode: dataset is loaded from bundled 'phishtank-seed.csv' only
    datasetUrl: '',
    updateIntervalHours: 24
  },

  // Redirect flow settings
  Redirect: {
    // Time window to temporarily allow the host and all redirects for the tab (ms)
    tempAllowMs: 30000,
    // How long to wait for user action before auto-blocking a pending redirect (ms)
    autoBlockTimeoutMs: 15000,
    // Duration to keep the allow toast/feedback visible (ms)
    allowToastMs: 2000,
    // Interpose cross eTLD+1 navigations by default even without a recorded pending redirect
    strictCrossDomainInterpose: false,
    // When treating known-safe destination families as auto-allow, require HTTPS
    requireHttpsForKnownSafe: true,
    // Do not auto-allow known-safe family if the path/search looks like a tokenized click-through
    rejectTokenPathsForKnownSafe: true,
    // After user presses Allow, apply a short host-level temp allow in the target tab to avoid bouncing back
    postAllowHostTempMs: 5000,
    // Emit lightweight debug logs for redirect decisions
    debugLogging: false,
    // SERP hosts (treated as search results origins). Extend as needed.
    serpHosts: [
      // Google (include regional via wildcard logic in code)
      'google.com', 'www.google.com', 'google.co.in', 'www.google.co.in',
      // Bing
      'bing.com', 'www.bing.com',
      // DuckDuckGo
      'duckduckgo.com', 'start.duckduckgo.com',
      // Yahoo
      'search.yahoo.com', 'www.yahoo.com',
      // Brave Search
      'search.brave.com',
      // Ecosia
      'ecosia.org', 'www.ecosia.org',
      // Qwant
      'qwant.com', 'www.qwant.com',
      // Startpage
      'startpage.com', 'www.startpage.com',
      // Yandex
      'yandex.ru', 'yandex.com', 'www.yandex.com', 'www.yandex.ru',
      // Baidu
      'baidu.com', 'www.baidu.com',
      // Naver
      'naver.com', 'www.naver.com',
      // Seznam
      'seznam.cz', 'www.seznam.cz',
      // Sogou and 360 SO
      'sogou.com', 'www.sogou.com', 'so.com', 'www.so.com',
      // You.com
      'you.com', 'www.you.com',
      // MetaGer & Swisscows
      'metager.org', 'www.metager.org', 'swisscows.com', 'www.swisscows.com',
      // Ask & AOL
      'ask.com', 'www.ask.com', 'aol.com', 'search.aol.com'
    ],
    // Automatically add destination domain to persistent allowlist when user presses Allow (subject to guardrails)
    autoAllowlistOnAllow: true,
    // Trusted referrer sources (by eTLD+1). When navigation originates from these, we may bypass interpose with guardrails.
    trustedReferrersETLD1: [
      // Global search engines
      'google.com', 'bing.com', 'duckduckgo.com', 'yahoo.com', 'ecosia.org', 'startpage.com', 'qwant.com', 'brave.com', 'ask.com', 'aol.com', 'mojeek.com', 'you.com', 'metager.org', 'swisscows.com',
      // Common Google regional eTLD+1s
      'google.co.in', 'google.co.uk', 'google.ca', 'google.com.au', 'google.co.za', 'google.co.nz', 'google.co.jp', 'google.de', 'google.fr', 'google.it', 'google.es', 'google.com.br', 'google.com.mx',
      'google.com.sg', 'google.com.hk', 'google.com.tr', 'google.com.ar', 'google.com.co', 'google.com.eg', 'google.com.sa', 'google.com.pk', 'google.com.ng', 'google.com.ph', 'google.com.my', 'google.com.vn', 'google.com.tw',
      // Regional search engines
      'yandex.ru', 'yandex.com', 'baidu.com', 'naver.com', 'seznam.cz', 'sogou.com', 'so.com', 'yahoo.co.jp',
      // Knowledge/reference
      'wikipedia.org', 'wiktionary.org', 'wikidata.org', 'stackexchange.com', 'stackoverflow.com',
      // Developer docs
      'developer.mozilla.org', 'learn.microsoft.com', 'docs.python.org', 'docs.oracle.com', 'developer.android.com', 'developer.apple.com', 'nodejs.org', 'golang.org', 'rust-lang.org', 'kotlinlang.org', 'php.net', 'ruby-lang.org', 'doc.qt.io', 'docs.aws.amazon.com', 'cloud.google.com', 'developer.chrome.com', 'web.dev', 'firebase.google.com', 'dev.mysql.com', 'dev.to', 'kubernetes.io', 'helm.sh', 'istio.io', 'nginx.org', 'httpd.apache.org', 'mariadb.org', 'redis.io', 'docs.mongodb.com', 'www.postgresql.org', 'ngrx.io', 'react.dev', 'vuejs.org', 'angular.io', 'svelte.dev', 'nuxt.com', 'vitejs.dev', 'webpack.js.org', 'babeljs.io', 'eslint.org', 'jestjs.io', 'cypress.io', 'playwright.dev', 'docs.docker.com', 'docs.gitlab.com', 'docs.microsoft.com', 'learn.microsoft.com',
      // Package registries
      'npmjs.com', 'pypi.org', 'rubygems.org', 'crates.io', 'packagist.org', 'mvnrepository.com',
      // News portals
      'bbc.com', 'nytimes.com', 'theguardian.com', 'reuters.com', 'apnews.com', 'washingtonpost.com', 'cnn.com', 'bloomberg.com', 'ft.com', 'aljazeera.com', 'timesofindia.com', 'thehindu.com', 'ndtv.com', 'wsj.com', 'cnbc.com', 'forbes.com', 'theverge.com', 'arstechnica.com', 'techcrunch.com', 'engadget.com', 'wired.com', 'latimes.com', 'thetimes.co.uk',
      // Learning/education
      'coursera.org', 'edx.org', 'khanacademy.org', 'udemy.com', 'udacity.com', 'pluralsight.com',
      // Portals/community
      'reddit.com', 'quora.com', 'medium.com', 'producthunt.com', 'hacks.mozilla.org',
      // Productivity/dev hosting
      'github.com', 'gitlab.com', 'bitbucket.org', 'gist.github.com',
      // Video platforms
      'youtube.com', 'vimeo.com', 'dailymotion.com',
      // Shopping/marketplaces
      'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.co.jp', 'amazon.com.au',
      'flipkart.com', 'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com', 'alibaba.com', 'aliexpress.com', 'etsy.com', 'myntra.com', 'ajio.com', 'rakuten.co.jp', 'jd.com', 'mercadolibre.com', 'shopify.com'
    ],
    // Known URL shorteners and redirector hosts to pre-interpose on paste-and-go
    shortenerHosts: [
      'tinyurl.com',
      'bit.ly',
      't.co',
      'goo.gl',
      'ow.ly',
      'lnkd.in',
      'amzn.to',
      'is.gd',
      'buff.ly',
      's.id',
      // Popular modern shorteners
      't.ly', 'cutt.ly', 'rebrand.ly', 'bit.do', 'shorturl.at', 'shrtco.de', 'v.gd', 'rb.gy', 'tiny.cc', 'x.co', 'lnk.to',
      // Affiliate/redirect domains commonly used as short hops
      'aka.ms', 'go.microsoft.com', 'apple.co', 'fb.me', 'geni.us', 'wp.me', 'youtu.be', 'ift.tt',
      // Social/network redirectors
      'l.facebook.com', 'lm.facebook.com', 'l.instagram.com', 'l.messenger.com', 'out.reddit.com', 'disq.us', 'trib.al',
      // Ad/monetization shorteners (risky)
      'adf.ly', 'sh.st', 'bc.vc', 'ouo.io',
      // Regional/common
      'clck.ru', 'surl.li'
    ]
    ,
    // Domains that are always allowed for redirection (permanent allowlist, by eTLD+1)
    permanentAllowlistETLD1: [
      // Payments
      'paypal.com', 'stripe.com', 'razorpay.com', 'gumroad.com', 'patreon.com', 'squareup.com', 'cash.app',
      'adyen.com', 'checkout.com', 'authorize.net', 'braintreepayments.com', '2checkout.com', 'paystack.com',

      // Identity and SSO
      'okta.com', 'auth0.com', 'microsoftonline.com', 'onelogin.com', 'pingidentity.com', 'duosecurity.com',

      // Major platforms and productivity
      'google.com', 'youtube.com', 'github.com', 'gitlab.com', 'bitbucket.org', 'mozilla.org', 'apple.com',
      'microsoft.com', 'office.com', 'live.com', 'outlook.com', 'zoom.us', 'slack.com', 'atlassian.com',
      'notion.so', 'dropbox.com', 'box.com', 'shopify.com',

      // Social / login providers
      'facebook.com', 'instagram.com', 'linkedin.com', 'twitter.com', 'x.com', 'reddit.com',

      // Commerce/marketplaces commonly used for order flows
      'amazon.com', 'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com', 'aliexpress.com', 'alibaba.com',

      // Cloud/CDN and common asset hosts for auth/consent hops
      'amazonaws.com', 'cloudflare.com', 'gstatic.com',

      // Regional variants (Google)
      'google.co.in', 'google.co.uk', 'google.ca', 'google.com.au', 'google.co.za', 'google.co.nz',
      'google.co.jp', 'google.de', 'google.fr', 'google.it', 'google.es', 'google.com.br', 'google.com.mx', 'google.com.sg', 'google.com.hk', 'google.com.tr', 'google.com.ar', 'google.com.co',

      // Regional variants (Amazon)
      'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.co.jp', 'amazon.com.au', 'amazon.ca', 'amazon.in', 'amazon.com.br', 'amazon.com.mx',

      // Additional productivity/dev tools
      'trello.com', 'asana.com', 'figma.com', 'adobe.com', 'canva.com', 'linear.app',

      // Messaging / communication
      'whatsapp.com', 'skype.com', 'discord.com'
    ]
  },

  // Trust Scoring Configuration
  Scoring: {
    // Weights for different factors (total should be 100)
    weights: {
      // Connection security
      https: 18,
      sslCertificate: 10,

      // Reputation/intelligence
      phishTank: 35,

      // URL/host structure
      domainPattern: 15,
      urlShortener: 10,
      subdomainAnalysis: 8,

      // Page/content risk
      contentSecurity: 6,
      socialEngineering: 5,
      suspiciousKeywords: 5,

      // Flow/redirect risk
      redirectRisk: 12,

      // Reserved for future heuristics block (kept for compatibility)
      heuristicAnalysis: 5
    },

    // Thresholds for verdicts (aligned with neutral-start model)
    // Neutral start = 50, sites earn/lose points based on evidence
    thresholds: {
      safe: 70,        // Strong positive evidence required
      suspicious: 40,  // Neutral to weak evidence
      dangerous: 0     // Hard-fail or significant negative evidence
    },

    // Critical failures that immediately mark as dangerous
    criticalFailures: ['https', 'phishTank']
  },

  // Security Settings
  Security: {
    // Suspicious keywords to detect
    suspiciousKeywords: [
      'verify your account', 'update password', 'confirm your identity',
      'security alert', 'account suspended', 'verify your email',
      'unusual activity', 'login attempt', 'secure your account',
      'verify your information', 'confirm your details', 'urgent action required',
      'account verification', 'suspicious login', 'security breach',
      'password reset', 'account locked', 'verify now', 'immediate action',
      'account compromised', 'security threat', 'unauthorized access'
    ],

    // Phishing patterns to detect
    phishingPatterns: [
      /bank.*login/i,
      /paypal.*verify/i,
      /amazon.*account/i,
      /google.*security/i,
      /facebook.*login/i,
      /netflix.*billing/i,
      /apple.*id/i,
      /microsoft.*account/i,
      /irs.*tax/i,
      /government.*verify/i
    ],

    // Suspicious TLDs
    suspiciousTlds: ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.online', '.site'],

    // High-risk countries
    riskyCountries: ['RU', 'CN', 'KP', 'IR', 'SY', 'VE', 'CU', 'SD', 'LY', 'YE'],

    // Common brand names for impersonation detection
    brandNames: ['google', 'facebook', 'amazon', 'paypal', 'apple', 'microsoft', 'netflix', 'twitter', 'instagram', 'linkedin']
  },

  // Performance Settings
  Performance: {
    // Cache timeout in milliseconds (5 minutes)
    cacheTimeout: 300000,

    // Analysis timeout in milliseconds (30 seconds)
    analysisTimeout: 30000,

    // Maximum cache size
    maxCacheSize: 100,

    // Cleanup interval for cache maintenance (1 hour)
    cleanupInterval: 3600000
  },

  // User Interface Settings
  UI: {
    // Default settings for new users
    defaultSettings: {
      protectionEnabled: false,
      autoWhitelist: false
    },
    // Show a small toast when a redirect is allowed
    showAllowToast: true,

    // Colors for different trust levels
    colors: {
      safe: '#10B981',
      suspicious: '#F59E0B',
      dangerous: '#EF4444',
      unknown: '#6B7280'
    },

    // Icons for different trust levels
    icons: {
      safe: '[OK]',
      suspicious: '[!]',
      dangerous: '[X]',
      unknown: '[?]',
      loading: '...'
    }
  },

  // Privacy Settings
  Privacy: {
    // Data retention settings
    retention: {
      siteHistory: 30, // days
      cache: 1, // days
      logs: 7 // days
    },

    // What data to collect
    dataCollection: {
      pageContent: true, // for keyword analysis
      formData: false, // never collect form data
      userBehavior: false, // never track user behavior
      analytics: false // never send analytics
    }
  }
};

// Export configuration
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SafeClickConfig;
}

// Make available globally for browser extension
if (typeof window !== 'undefined') {
  window.SafeClickConfig = SafeClickConfig;
}