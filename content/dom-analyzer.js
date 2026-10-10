/**
 * DOM Analyzer Module for SafeClick Extension
 * Detects phishing indicators in page DOM structure.
 * 
 * All detection runs locally - no external calls.
 */

const DOMAnalyzer = (function () {

    /**
     * Analyze forms for cross-origin submission
     * Detects credential harvesting where form submits to a different domain
     * @param {Document} doc - Document to analyze
     * @param {string} pageUrl - Current page URL
     * @returns {Object} Analysis result
     */
    function analyzeFormActions(doc, pageUrl) {
        const result = {
            hasSuspiciousForms: false,
            forms: [],
            risks: []
        };

        try {
            const pageHost = new URL(pageUrl).hostname.toLowerCase();
            const pageETLD1 = typeof UrlUtils !== 'undefined'
                ? UrlUtils.getETLD1FromHost(pageHost)
                : pageHost;

            const forms = doc.querySelectorAll('form');

            for (const form of forms) {
                const action = form.getAttribute('action') || '';
                const method = (form.getAttribute('method') || 'GET').toUpperCase();
                const hasPasswordField = form.querySelector('input[type="password"]') !== null;
                const hasEmailField = form.querySelector('input[type="email"], input[name*="email"], input[name*="user"]') !== null;

                const formInfo = {
                    action: action,
                    method: method,
                    hasCredentialFields: hasPasswordField || hasEmailField,
                    isCrossOrigin: false,
                    actionHost: null
                };

                // Check if form action is cross-origin
                if (action && !action.startsWith('#') && !action.startsWith('javascript:')) {
                    try {
                        const actionUrl = new URL(action, pageUrl);
                        const actionHost = actionUrl.hostname.toLowerCase();
                        const actionETLD1 = typeof UrlUtils !== 'undefined'
                            ? UrlUtils.getETLD1FromHost(actionHost)
                            : actionHost;

                        formInfo.actionHost = actionHost;

                        if (actionETLD1 !== pageETLD1) {
                            formInfo.isCrossOrigin = true;

                            if (hasPasswordField) {
                                result.hasSuspiciousForms = true;
                                result.risks.push({
                                    type: 'CROSS_ORIGIN_CREDENTIAL_FORM',
                                    severity: 'HIGH',
                                    message: `Password form submits to different domain: ${actionHost}`
                                });
                            } else if (hasEmailField) {
                                result.risks.push({
                                    type: 'CROSS_ORIGIN_EMAIL_FORM',
                                    severity: 'MEDIUM',
                                    message: `Email form submits to different domain: ${actionHost}`
                                });
                            }
                        }
                    } catch (_) {
                        // Invalid URL, skip
                    }
                }

                // Also flag POST forms with password on suspicious domains
                if (hasPasswordField && method === 'POST') {
                    formInfo.isCredentialHarvester = true;
                }

                result.forms.push(formInfo);
            }
        } catch (e) {
            console.warn('[DOMAnalyzer] Form analysis error:', e);
        }

        return result;
    }

    /**
     * Known legitimate domains that legitimately embed hidden, 0x0, or offscreen helper iframes
     * for captchas, authentication, payments, analytics, tag management, or chat widgets.
     */
    const BENIGN_IFRAME_DOMAINS = [
        // Captcha & Anti-bot
        'google.com', 'recaptcha.net', 'gstatic.com', 'cloudflare.com', 'challenges.cloudflare.com',
        'cloudflareinsights.com', 'hcaptcha.com', 'arkoselabs.com', 'arkose.com', 'geetest.com',
        'perimeterx.net', 'humansecurity.com', 'datadome.co',
        // SSO, Identity & Major Tech Platforms
        'accounts.google.com', 'smartlock.google.com', 'appleid.apple.com', 'apple.com',
        'login.microsoftonline.com', 'live.com', 'microsoft.com', 'facebook.com', 'github.com',
        'amazon.com', 'okta.com', 'auth0.com',
        // Analytics, Tracking & Tag Managers
        'googletagmanager.com', 'google-analytics.com', 'doubleclick.net', 'googleadservices.com',
        'clarity.ms', 'segment.com', 'segment.io', 'hotjar.com', 'newrelic.com', 'sentry.io',
        'datadoghq.com', 'mixpanel.com', 'amplitude.com', 'optimizely.com',
        // Payment Gateways
        'stripe.com', 'paypal.com', 'braintreegateway.com', 'adyen.com', 'squareup.com',
        'squareupsandbox.com', 'klarna.com', 'shopify.com',
        // Customer Support & Chat
        'intercom.io', 'zendesk.com', 'crisp.chat', 'hubspot.com', 'tidio.co', 'drift.com',
        'livechatinc.com', 'salesforce.com',
        // Media & Social Widgets
        'twitter.com', 'x.com', 'linkedin.com', 'youtube.com', 'vimeo.com',
        // CDNs & Cloud Infrastructure
        'cloudflare.net', 'cloudfront.net', 'fastly.net', 'akamaihd.net', 'akamaized.net'
    ];

    const SUSPICIOUS_IFRAME_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.click', '.download',
        '.link', '.work', '.date', '.racing', '.win', '.stream', '.gdn', '.loan',
        '.bid', '.buzz', '.vip'
    ];

    const CREDENTIAL_URL_PATTERNS = [
        /\/login/i, /\/signin/i, /\/auth/i, /\/credential/i, /\/password/i, /\/verify/i, /\/account/i
    ];

    /**
     * Detect hidden iframes that might be used for credential harvesting or clickjacking
     * @param {Document} doc - Document to analyze
     * @param {string} [pageUrl] - Current page URL
     * @param {Object} [options] - Configuration options
     * @returns {Object} Analysis result
     */
    function detectHiddenIframes(doc, pageUrl = '', options = {}) {
        const result = {
            hasHiddenIframes: false,
            hasClickjackingOverlay: false,
            suspiciousIframes: [],
            risks: []
        };

        if (options && options.iframeScanEnabled === false) {
            return result;
        }

        try {
            let pageHost = '';
            let pageETLD1 = '';
            try {
                if (pageUrl) {
                    pageHost = new URL(pageUrl).hostname.toLowerCase();
                } else if (typeof window !== 'undefined' && window.location) {
                    pageHost = window.location.hostname.toLowerCase();
                }
                pageETLD1 = typeof UrlUtils !== 'undefined' && typeof UrlUtils.getETLD1FromHost === 'function'
                    ? UrlUtils.getETLD1FromHost(pageHost)
                    : pageHost;
            } catch (_) {}

            const iframes = doc.querySelectorAll('iframe');

            for (const iframe of iframes) {
                const src = iframe.getAttribute('src') || iframe.src || '';
                if (!src || src.startsWith('javascript:') || src.startsWith('about:blank') || src.startsWith('data:')) {
                    continue;
                }

                let srcUrl;
                try {
                    srcUrl = new URL(src, pageUrl || (typeof window !== 'undefined' ? window.location.href : 'http://localhost'));
                } catch (_) {
                    continue;
                }

                if (srcUrl.protocol !== 'http:' && srcUrl.protocol !== 'https:') {
                    continue;
                }

                const srcHost = srcUrl.hostname.toLowerCase();
                const srcETLD1 = typeof UrlUtils !== 'undefined' && typeof UrlUtils.getETLD1FromHost === 'function'
                    ? UrlUtils.getETLD1FromHost(srcHost)
                    : srcHost;

                // 1. Same-origin or same eTLD+1 is an internal site component - benign
                if (pageETLD1 && srcETLD1 && pageETLD1 === srcETLD1) {
                    continue;
                }

                // 2. Known benign third-party service (captcha, sso, analytics, payment, etc.)
                const isBenign = BENIGN_IFRAME_DOMAINS.some(d => srcHost === d || srcHost.endsWith('.' + d));
                if (isBenign) {
                    continue;
                }

                const style = (typeof window !== 'undefined' && window.getComputedStyle) ? window.getComputedStyle(iframe) : {};
                const rect = iframe.getBoundingClientRect ? iframe.getBoundingClientRect() : { width: 0, height: 0, top: 0, left: 0 };
                const opacity = parseFloat(style.opacity);

                // Clickjacking Overlay: transparent/invisible iframe covering interactive viewport content
                const isClickjackingOverlay = (
                    !Number.isNaN(opacity) && opacity < 0.1 &&
                    rect.width >= 100 && rect.height >= 100 &&
                    style.pointerEvents !== 'none' &&
                    (style.position === 'absolute' || style.position === 'fixed') &&
                    parseInt(style.zIndex, 10) > 0
                );

                if (isClickjackingOverlay) {
                    result.hasClickjackingOverlay = true;
                    result.hasHiddenIframes = true;
                    result.suspiciousIframes.push({
                        src: src,
                        host: srcHost,
                        reason: 'Transparent clickjacking overlay'
                    });
                    result.risks.push({
                        type: 'CLICKJACKING_OVERLAY',
                        severity: 'HIGH',
                        message: `Transparent clickjacking overlay loading: ${srcHost}`
                    });
                    continue;
                }

                const isHidden = (
                    style.display === 'none' ||
                    style.visibility === 'hidden' ||
                    opacity === 0 ||
                    rect.width <= 1 ||
                    rect.height <= 1 ||
                    rect.left < -1000 ||
                    rect.top < -1000
                );

                if (!isHidden) {
                    continue;
                }

                // Only flag hidden frames with genuine threat indicators (IP host, high-abuse TLD, or credential path)
                const isRawIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(srcHost);
                const hasSuspiciousTld = SUSPICIOUS_IFRAME_TLDS.some(tld => srcHost.endsWith(tld));
                const hasCredentialPath = CREDENTIAL_URL_PATTERNS.some(rx => rx.test(srcUrl.pathname));

                if (isRawIp || hasSuspiciousTld || hasCredentialPath) {
                    result.hasHiddenIframes = true;
                    result.suspiciousIframes.push({
                        src: src,
                        host: srcHost,
                        reason: isRawIp ? 'Hidden iframe on raw IP' : (hasCredentialPath ? 'Hidden credential form iframe' : 'Hidden iframe on suspicious TLD')
                    });
                    result.risks.push({
                        type: 'HIDDEN_IFRAME',
                        severity: 'MEDIUM',
                        message: `Suspicious hidden iframe loading: ${srcHost}`
                    });
                }
            }
        } catch (e) {
            console.warn('[DOMAnalyzer] Iframe analysis error:', e);
        }

        return result;
    }

    /**
     * Detect Browser-in-Browser (BiB) attack patterns
     * These are fake browser windows rendered in the DOM
     * @param {Document} doc - Document to analyze
     * @returns {Object} Analysis result
     */
    function detectBrowserInBrowser(doc) {
        const result = {
            hasBiBPatterns: false,
            patterns: [],
            risks: []
        };

        try {
            // Look for elements that mimic browser chrome
            const suspiciousClasses = [
                'browser-window', 'chrome-window', 'browser-frame', 'window-frame',
                'fake-browser', 'modal-browser', 'popup-window', 'login-popup',
                'address-bar', 'url-bar', 'browser-header', 'window-header'
            ];

            for (const className of suspiciousClasses) {
                const elements = doc.getElementsByClassName(className);
                if (elements.length > 0) {
                    result.patterns.push(`Found elements with class: ${className}`);
                }
            }

            // Look for elements with window control icons (minimize, maximize, close)
            const controlPatterns = [
                '[class*="window-controls"]',
                '[class*="title-bar"]',
                '[class*="window-buttons"]'
            ];

            for (const pattern of controlPatterns) {
                try {
                    if (doc.querySelector(pattern)) {
                        result.patterns.push(`Found element matching: ${pattern}`);
                    }
                } catch (_) { }
            }

            // Check for suspicious combinations: address bar + close button + login form
            const hasAddressBar = doc.querySelector('[class*="address"], [class*="url-bar"], [id*="address"]');
            const hasCloseBtn = doc.querySelector('[class*="close"], [class*="window-close"]');
            const hasLoginForm = doc.querySelector('input[type="password"]');

            if (hasAddressBar && hasCloseBtn && hasLoginForm) {
                result.hasBiBPatterns = true;
                result.risks.push({
                    type: 'BROWSER_IN_BROWSER',
                    severity: 'HIGH',
                    message: 'Possible browser-in-browser attack: fake browser window with login form'
                });
            }

            // Also flag if many patterns found
            if (result.patterns.length >= 3) {
                result.hasBiBPatterns = true;
                result.risks.push({
                    type: 'BROWSER_IN_BROWSER',
                    severity: 'MEDIUM',
                    message: 'Multiple browser-like UI elements detected'
                });
            }
        } catch (e) {
            console.warn('[DOMAnalyzer] BiB detection error:', e);
        }

        return result;
    }

    /**
     * Check for credential fields on the page
     * @param {Document} doc - Document to analyze
     * @returns {Object} Credential field information
     */
    function detectCredentialFields(doc) {
        const result = {
            hasPasswordField: false,
            hasEmailField: false,
            hasUsernameField: false,
            fields: []
        };

        try {
            // Find password fields
            const passwordFields = doc.querySelectorAll('input[type="password"]');
            if (passwordFields.length > 0) {
                result.hasPasswordField = true;
                result.fields.push(...Array.from(passwordFields).map(f => ({
                    type: 'password',
                    name: f.name || f.id || 'unnamed',
                    autocomplete: f.autocomplete
                })));
            }

            // Find email fields
            const emailFields = doc.querySelectorAll('input[type="email"]');
            if (emailFields.length > 0) {
                result.hasEmailField = true;
            }

            // Find username-like fields
            const usernamePatterns = ['user', 'login', 'email', 'account', 'username'];
            const allInputs = doc.querySelectorAll('input[type="text"], input:not([type])');
            for (const input of allInputs) {
                const name = (input.name || input.id || '').toLowerCase();
                const placeholder = (input.placeholder || '').toLowerCase();

                for (const pattern of usernamePatterns) {
                    if (name.includes(pattern) || placeholder.includes(pattern)) {
                        result.hasUsernameField = true;
                        break;
                    }
                }
            }
        } catch (e) {
            console.warn('[DOMAnalyzer] Credential field detection error:', e);
        }

        return result;
    }

    /**
     * Detect Favicon Brand Spoofing
     * Detects when a non-brand site uses official brand logos in favicon
     */
    function detectFaviconSpoofing(doc, pageUrl) {
        const result = { isSpoofed: false, brand: null, risks: [] };
        try {
            const pageHost = new URL(pageUrl).hostname.toLowerCase();
            const iconLink = doc.querySelector('link[rel*="icon"]');
            if (!iconLink) return result;

            const iconHref = (iconLink.getAttribute('href') || '').toLowerCase();
            const brandFaviconTokens = {
              'google': ['google.com/favicon', 'google.ico', 'gstatic.com'],
              'microsoft': ['microsoft.com/favicon', 'microsoft.ico'],
              'apple': ['apple.com/favicon', 'apple-touch-icon'],
              'paypal': ['paypal.com/favicon', 'paypal.ico']
            };

            for (const [brand, tokens] of Object.entries(brandFaviconTokens)) {
              if (tokens.some(t => iconHref.includes(t)) && !pageHost.includes(brand)) {
                result.isSpoofed = true;
                result.brand = brand;
                result.risks.push({
                  type: 'FAVICON_BRAND_SPOOF',
                  severity: 'MEDIUM',
                  message: `Page uses ${brand.toUpperCase()} icon but is hosted on ${pageHost}`
                });
                break;
              }
            }
        } catch (_) {}
        return result;
    }

    /**
     * Extract visible urgency snippets for social engineering detection
     * Scans headers, banners, alerts, buttons, and callout text
     * @param {Document} doc
     * @param {Object} [context]
     * @returns {string[]}
     */
    function extractUrgencySnippets(doc, context = {}) {
        const snippets = [];
        if (!doc) return snippets;

        // Skip urgency scans on pure media / streaming / video platforms where titles like "Food Challenge" or "First fail" exist
        const pageHost = (typeof window !== 'undefined' && window.location ? window.location.hostname.toLowerCase() : '');
        const isMediaPlatform = /^(www\.)?(youtube\.com|youtu\.be|vimeo\.com|twitch\.tv|netflix\.com|reddit\.com|wikipedia\.org)$/i.test(pageHost);
        if (isMediaPlatform) {
            return snippets;
        }

        // Strict phishing urgency patterns using word boundaries to prevent false matches (e.g. "first" matching "irs", "sandwich" matching "lock")
        const urgencyPatterns = [
            /\b(urgent action required|immediate action required|action required to prevent)\b/i,
            /\b(account (has been |is )?suspended|verify (your )?account now)\b/i,
            /\b(account (is |has been )?locked|card (is |has been )?locked)\b/i,
            /\b(session expired|password expires today|expires within \d+ (minutes|hours))\b/i,
            /\b(unusual (sign-in|login|activity) detected.{0,30}(verify|unlock))\b/i,
            /\b(security alert: verify|confirm your identity immediately)\b/i,
            /\b(claim (your )?(lottery prize|crypto reward|reward money))\b/i,
            /\b(irs tax refund.{0,30}(claim|enter details|ssn))\b/i,
            /\b(law enforcement notice: immediate)\b/i
        ];

        try {
            // Only inspect headers or alert banners that are NOT part of video, article, or comment feeds
            const elements = doc.querySelectorAll('.alert, .banner, .notice, .warning, [role="alert"], h1, h2');
            for (const el of elements) {
                // Skip if inside media/video/comment containers
                if (el.closest && el.closest('ytd-rich-item-renderer, ytd-video-renderer, ytd-compact-video-renderer, #video-title, article, video, .ytp-chrome-bottom, #comments, .feed-item, .post')) {
                    continue;
                }
                const text = (el.textContent || '').trim().replace(/\s+/g, ' ');
                if (text.length >= 10 && text.length <= 200) {
                    if (urgencyPatterns.some(rx => rx.test(text))) {
                        snippets.push(text);
                        if (snippets.length >= 5) break;
                    }
                }
            }
        } catch (_) {}

        return snippets;
    }

    /**
     * Perform comprehensive DOM analysis
     * @param {Document} doc - Document to analyze
     * @param {string} pageUrl - Current page URL
     * @param {Object} [options] - Options
     * @returns {Object} Complete analysis result
     */
    function analyze(doc, pageUrl, options = {}) {
        const formAnalysis = analyzeFormActions(doc, pageUrl);
        const iframeAnalysis = detectHiddenIframes(doc, pageUrl, options);
        const bibAnalysis = detectBrowserInBrowser(doc);
        const credentialAnalysis = detectCredentialFields(doc);
        const faviconAnalysis = detectFaviconSpoofing(doc, pageUrl);
        const urgencySnippets = extractUrgencySnippets(doc, { credentialAnalysis, formAnalysis, pageUrl });

        // Combine all risks
        const allRisks = [
            ...formAnalysis.risks,
            ...iframeAnalysis.risks,
            ...bibAnalysis.risks,
            ...faviconAnalysis.risks
        ];

        // Calculate risk score contribution
        let riskScore = 0;
        for (const risk of allRisks) {
            switch (risk.severity) {
                case 'HIGH': riskScore += 30; break;
                case 'MEDIUM': riskScore += 15; break;
                case 'LOW': riskScore += 5; break;
            }
        }

        return {
            pageUrl: pageUrl,
            timestamp: Date.now(),

            // Individual analyses
            forms: formAnalysis,
            iframes: iframeAnalysis,
            browserInBrowser: bibAnalysis,
            credentials: credentialAnalysis,
            favicon: faviconAnalysis,
            urgencySnippets: urgencySnippets,

            // Summary
            risks: allRisks,
            riskScore: Math.min(riskScore, 100),
            hasCriticalRisks: allRisks.some(r => r.severity === 'HIGH'),

            // Quick flags
            hasSuspiciousForms: formAnalysis.hasSuspiciousForms,
            hasHiddenIframes: iframeAnalysis.hasHiddenIframes,
            hasClickjackingOverlay: iframeAnalysis.hasClickjackingOverlay,
            hasBrowserInBrowserPatterns: bibAnalysis.hasBiBPatterns,
            hasCredentialFields: credentialAnalysis.hasPasswordField,
            hasFaviconSpoof: faviconAnalysis.isSpoofed,
            hasUrgencyText: urgencySnippets.length > 0
        };
    }

    /**
     * Convert DOM analysis result into structured Indicator instances
     * @param {Object} domResult - Return value of analyze()
     * @returns {Array} Array of Indicator parameter objects
     */
    function toIndicatorSpecs(domResult) {
        if (!domResult) return [];
        const specs = [];

        if (domResult.hasSuspiciousForms) {
            specs.push({
                id: 'dom.cross_origin_form',
                source: 'dom-analyzer',
                category: 'content',
                polarity: 'negative',
                weight: -35,
                confidence: 'high',
                detail: '[X] Password form submits credentials to a different origin'
            });
        }

        if (domResult.hasClickjackingOverlay) {
            specs.push({
                id: 'dom.clickjacking_overlay',
                source: 'dom-analyzer',
                category: 'content',
                polarity: 'negative',
                weight: -30,
                confidence: 'high',
                detail: '[X] Transparent clickjacking overlay detected'
            });
        }

        if (domResult.hasHiddenIframes && !domResult.hasClickjackingOverlay) {
            specs.push({
                id: 'dom.hidden_iframe',
                source: 'dom-analyzer',
                category: 'content',
                polarity: 'negative',
                weight: -8,
                confidence: 'low',
                detail: '[!] Suspicious hidden iframe loading untrusted external source'
            });
        }

        if (domResult.hasBrowserInBrowserPatterns) {
            specs.push({
                id: 'dom.browser_in_browser',
                source: 'dom-analyzer',
                category: 'content',
                polarity: 'negative',
                weight: -35,
                confidence: 'high',
                detail: '[X] Browser-in-the-Browser simulated window detected'
            });
        }

        if (domResult.hasFaviconSpoof) {
            specs.push({
                id: 'dom.favicon_spoof',
                source: 'dom-analyzer',
                category: 'content',
                polarity: 'negative',
                weight: -25,
                confidence: 'medium',
                detail: `[!] Page icon mimics brand but host does not match`
            });
        }

        if (domResult.hasCredentialFields) {
            specs.push({
                id: 'dom.password_form',
                source: 'dom-analyzer',
                category: 'content',
                polarity: 'info',
                weight: 0,
                confidence: 'high',
                detail: '[i] Password or credential input fields present'
            });
        }

        if (domResult.hasUrgencyText && Array.isArray(domResult.urgencySnippets) && domResult.urgencySnippets.length > 0) {
            specs.push({
                id: 'dom.urgency_keywords',
                source: 'dom-analyzer',
                category: 'content',
                polarity: 'negative',
                weight: -15,
                confidence: 'medium',
                detail: `[!] High-urgency panic language detected ("${domResult.urgencySnippets[0].slice(0, 60)}")`
            });
        }

        return specs;
    }

    // Public API
    return {
        analyze,
        analyzeFormActions,
        detectHiddenIframes,
        detectBrowserInBrowser,
        detectCredentialFields,
        detectFaviconSpoofing,
        extractUrgencySnippets,
        toIndicatorSpecs
    };
})();

// Export for content script and Node environments
if (typeof window !== 'undefined') {
    window.DOMAnalyzer = DOMAnalyzer;
}
if (typeof self !== 'undefined') {
    self.DOMAnalyzer = DOMAnalyzer;
}
if (typeof module !== 'undefined' && module.exports) {
    module.exports = DOMAnalyzer;
}
