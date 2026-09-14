/**
 * URL Utilities Module for SafeClick Extension
 * SINGLE SOURCE OF TRUTH for all URL operations.
 * 
 * All other files should import from here - no duplicate implementations.
 */

const UrlUtils = (function () {

    // ========== CONSTANTS ==========

    // Multi-part public suffixes (for accurate eTLD+1 extraction)
    const MULTI_PART_SUFFIXES = new Set([
        'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk',
        'com.au', 'net.au', 'org.au', 'edu.au',
        'co.in', 'net.in', 'org.in', 'gen.in', 'ind.in',
        'com.br', 'net.br', 'org.br',
        'com.mx', 'org.mx', 'gob.mx',
        'co.jp', 'ne.jp', 'or.jp', 'ac.jp',
        'com.sg', 'org.sg', 'edu.sg',
        'com.tr', 'org.tr', 'edu.tr',
        'com.ar', 'org.ar', 'edu.ar',
        'com.pl', 'net.pl', 'org.pl',
        'co.nz', 'net.nz', 'org.nz',
        'co.za', 'org.za', 'web.za'
    ]);

    // High-risk TLDs based on abuse statistics
    const HIGH_RISK_TLDS = new Set([
        '.tk', '.ml', '.ga', '.cf', '.gq',  // Free TLDs with high abuse
        '.top', '.xyz', '.click', '.download', '.link',
        '.work', '.date', '.racing', '.win', '.stream',
        '.gdn', '.review', '.accountant', '.loan', '.men',
        '.science', '.party', '.trade', '.webcam', '.bid'
    ]);

    // Known URL shortener domains
    const KNOWN_SHORTENERS = new Set([
        'bit.ly', 'bitly.com', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly',
        'short.link', 'tiny.cc', 'is.gd', 'v.gd', 'buff.ly', 'j.mp',
        'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.one', 'rotf.lol',
        'lnkd.in', 'amzn.to', 'youtu.be', 'fb.me', 'surl.li', 'clck.ru',
        'adf.ly', 'sh.st', 'bc.vc', 'ouo.io'  // Ad/monetization shorteners (risky)
    ]);

    // Known safe destination families for frequent benign redirects
    const KNOWN_SAFE_DEST_ETLD1 = new Set([
        'paypal.com', 'stripe.com', 'razorpay.com', 'gumroad.com', 'patreon.com',
        'google.com', 'youtube.com', 'gmail.com', 'github.com', 'gitlab.com',
        'microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com',
        'apple.com', 'icloud.com', 'amazon.com', 'aws.amazon.com',
        'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com',
        'okta.com', 'auth0.com', 'onelogin.com',
        'buymeacoffee.com', 'ko-fi.com'
    ]);

    // Multi-tenant and shared user-content platforms
    // CRITICAL: Threats on these platforms must ONLY be matched as exact URLs.
    // The base domain/hostname must NEVER be blacklisted, to prevent collateral outages.
    const MULTI_TENANT_PLATFORMS = new Set([
        'github.com', 'raw.githubusercontent.com', 'gist.github.com', 'github.io',
        'gitlab.com', 'gitlab.io', 'bitbucket.org',
        'google.com', 'drive.google.com', 'docs.google.com', 'sites.google.com', 'storage.googleapis.com',
        'firebaseapp.com', 'web.app',
        'pages.dev', 'workers.dev', 'cloudflare.com',
        'vercel.app', 'netlify.app', 'render.com', 'onrender.com',
        'dropbox.com', 'dropboxusercontent.com',
        'onedrive.live.com', '1drv.ms', 'sharepoint.com',
        'amazonaws.com', 's3.amazonaws.com',
        'azurewebsites.net', 'blob.core.windows.net',
        'discord.com', 'discordapp.com', 'cdn.discordapp.com',
        'telegram.org', 't.me',
        'notion.site', 'notion.so',
        'medium.com', 'substack.com',
        'wikipedia.org', 'wikimedia.org',
        'youtube.com', 'twitter.com', 'x.com', 'facebook.com', 'linkedin.com',
        'microsoft.com', 'apple.com'
    ]);

    // Common brand names for typosquatting detection
    const BRAND_NAMES = [
        'google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal',
        'netflix', 'instagram', 'twitter', 'linkedin', 'github', 'dropbox',
        'spotify', 'adobe', 'zoom', 'slack', 'stripe', 'coinbase', 'binance',
        'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'americanexpress'
    ];

    // Confusable characters (homoglyphs) - Latin lookalikes
    const CONFUSABLES = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', // Cyrillic
        'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
        'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'l', 'ɪ': 'i', 'ⅼ': 'l', 'ⅿ': 'm', // IPA/Special
        '٠': '0', '১': '1', '২': '2', '০': '0', // Numerals
        'ο': 'o', 'α': 'a', 'ε': 'e', 'τ': 't', 'ι': 'i', 'ν': 'v', // Greek
        '𝐚': 'a', '𝐛': 'b', '𝐜': 'c', '𝐝': 'd', '𝐞': 'e', // Mathematical
        '0': 'o', '1': 'l', '!': 'i', '$': 's', '@': 'a' // Common substitutions
    };

    // ========== CORE URL FUNCTIONS ==========

    /**
     * Extract eTLD+1 from a hostname
     */
    function getETLD1FromHost(host) {
        try {
            const parts = String(host || '').toLowerCase().split('.').filter(Boolean);
            if (parts.length < 2) return host || '';
            
            const last2 = parts.slice(-2).join('.');
            if (MULTI_PART_SUFFIXES.has(last2) && parts.length >= 3) {
                return parts.slice(-3).join('.');
            }
            return last2;
        } catch (_) { return host || ''; }
    }

    /**
     * Extract eTLD+1 from a URL
     */
    function getETLD1(url) {
        try {
            const u = new URL(url);
            return getETLD1FromHost(u.hostname);
        } catch (_) { return ''; }
    }

    /**
     * Check if two URLs share the same eTLD+1
     */
    function isSameETLD1(urlA, urlB) {
        try {
            const a = getETLD1(urlA);
            const b = getETLD1(urlB);
            return !!a && !!b && a === b;
        } catch (_) { return false; }
    }

    /**
     * Normalize hostname from URL or string
     */
    function normalizeHost(urlOrHost) {
        try {
            return new URL(urlOrHost).hostname.toLowerCase();
        } catch (_) {
            return String(urlOrHost || '').toLowerCase().trim();
        }
    }

    /**
     * Check if URL is HTTPS
     */
    function isHttps(url) {
        try {
            return new URL(url).protocol === 'https:';
        } catch (_) { return false; }
    }

    // ========== ENTROPY CALCULATION ==========

    /**
     * Calculate Shannon entropy of a string
     * Higher entropy = more randomness = potentially suspicious
     */
    function calculateEntropy(str) {
        if (!str || str.length === 0) return 0;
        
        const freq = {};
        for (const ch of str) {
            freq[ch] = (freq[ch] || 0) + 1;
        }
        
        const len = str.length;
        let entropy = 0;
        for (const ch in freq) {
            const p = freq[ch] / len;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    /**
     * Check if subdomain has suspiciously high entropy
     */
    function hasHighEntropySubdomain(url, threshold = 3.5) {
        try {
            const u = new URL(url);
            const parts = u.hostname.toLowerCase().split('.');
            if (parts.length <= 2) return { suspicious: false, entropy: 0 };
            
            // Get subdomain (everything before eTLD+1)
            const etld1Parts = getETLD1FromHost(u.hostname).split('.').length;
            const subdomain = parts.slice(0, parts.length - etld1Parts).join('.');
            
            if (!subdomain || subdomain.length < 6) {
                return { suspicious: false, entropy: 0, subdomain };
            }
            
            const entropy = calculateEntropy(subdomain);
            return {
                suspicious: entropy >= threshold,
                entropy: Math.round(entropy * 100) / 100,
                subdomain
            };
        } catch (_) {
            return { suspicious: false, entropy: 0 };
        }
    }

    // ========== HOMOGRAPH/IDN DETECTION ==========

    /**
     * Check if domain contains confusable/homograph characters
     * Returns true if the domain uses non-ASCII that looks like ASCII
     */
    function hasHomographChars(str) {
        for (const char of str) {
            if (CONFUSABLES[char]) return true;
        }
        return false;
    }

    /**
     * Convert confusable characters to their ASCII equivalents
     */
    function normalizeConfusables(str) {
        let result = '';
        for (const char of str) {
            result += CONFUSABLES[char] || char;
        }
        return result;
    }

    /**
     * Detect homograph/IDN attack
     * Returns details if the domain appears to spoof a brand using lookalike chars
     */
    function detectHomograph(url) {
        try {
            const u = new URL(url);
            const hostname = u.hostname.toLowerCase();
            
            // Check for punycode (xn--) - indicates IDN
            const isPunycode = hostname.includes('xn--');
            
            // Check for mixed scripts or confusable chars
            const hasConfusables = hasHomographChars(hostname);
            
            if (!isPunycode && !hasConfusables) {
                return { isHomograph: false };
            }
            
            // Normalize and check against brands
            const normalized = normalizeConfusables(hostname);
            const etld1 = getETLD1FromHost(normalized);
            const sld = etld1.split('.')[0] || '';
            
            for (const brand of BRAND_NAMES) {
                if (sld === brand || sld.includes(brand)) {
                    return {
                        isHomograph: true,
                        originalDomain: hostname,
                        normalizedDomain: normalized,
                        targetBrand: brand,
                        reason: isPunycode ? 'Punycode IDN spoofing' : 'Confusable characters'
                    };
                }
            }
            
            // Even without brand match, flag punycode with confusable patterns
            if (isPunycode || hasConfusables) {
                return {
                    isHomograph: true,
                    originalDomain: hostname,
                    normalizedDomain: normalized,
                    reason: 'Contains lookalike characters'
                };
            }
            
            return { isHomograph: false };
        } catch (_) {
            return { isHomograph: false };
        }
    }

    // ========== TYPOSQUATTING DETECTION ==========

    /**
     * Calculate Levenshtein distance between two strings
     */
    function levenshteinDistance(a, b) {
        if (a.length === 0) return b.length;
        if (b.length === 0) return a.length;
        
        const matrix = [];
        for (let i = 0; i <= b.length; i++) {
            matrix[i] = [i];
        }
        for (let j = 0; j <= a.length; j++) {
            matrix[0][j] = j;
        }
        
        for (let i = 1; i <= b.length; i++) {
            for (let j = 1; j <= a.length; j++) {
                if (b.charAt(i - 1) === a.charAt(j - 1)) {
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
        return matrix[b.length][a.length];
    }

    /**
     * Calculate string similarity (0-1)
     */
    function stringSimilarity(a, b) {
        const distance = levenshteinDistance(a, b);
        const maxLen = Math.max(a.length, b.length);
        return maxLen === 0 ? 1 : 1 - (distance / maxLen);
    }

    /**
     * Detect brand typosquatting
     * Catches domains like paypa1.com, amaz0n.com, gooogle.com
     */
    function detectTyposquatting(url, threshold = 0.85) {
        try {
            const u = new URL(url);
            const etld1 = getETLD1FromHost(u.hostname);
            const parts = etld1.split('.');
            const sld = parts[0] || '';
            
            if (sld.length < 4) return { isTyposquat: false };
            
            // Normalize common substitutions
            const normalized = sld
                .replace(/0/g, 'o')
                .replace(/1/g, 'l')
                .replace(/\$/g, 's')
                .replace(/@/g, 'a')
                .replace(/3/g, 'e')
                .replace(/4/g, 'a')
                .replace(/5/g, 's')
                .replace(/7/g, 't');
            
            for (const brand of BRAND_NAMES) {
                // Skip exact matches (legitimate)
                if (sld === brand) continue;
                
                const similarity = stringSimilarity(normalized, brand);
                if (similarity >= threshold && similarity < 1) {
                    return {
                        isTyposquat: true,
                        domain: etld1,
                        targetBrand: brand,
                        similarity: Math.round(similarity * 100) / 100
                    };
                }
                
                // Also check if brand is embedded (e.g., paypal-secure)
                if (sld.includes(brand) && sld !== brand) {
                    return {
                        isTyposquat: true,
                        domain: etld1,
                        targetBrand: brand,
                        reason: 'Brand name embedded in domain'
                    };
                }
            }
            
            return { isTyposquat: false };
        } catch (_) {
            return { isTyposquat: false };
        }
    }

    // ========== TLD RISK SCORING ==========

    /**
     * Check if URL has a high-risk TLD
     */
    function hasHighRiskTLD(url) {
        try {
            const u = new URL(url);
            const hostname = u.hostname.toLowerCase();
            
            for (const tld of HIGH_RISK_TLDS) {
                if (hostname.endsWith(tld)) {
                    return { isHighRisk: true, tld };
                }
            }
            return { isHighRisk: false };
        } catch (_) {
            return { isHighRisk: false };
        }
    }

    // ========== SHORTENER & REDIRECT DETECTION ==========

    /**
     * Check if URL is a known shortener
     */
    function isKnownShortener(url) {
        try {
            const host = normalizeHost(url);
            const etld1 = getETLD1FromHost(host);
            return KNOWN_SHORTENERS.has(host) || KNOWN_SHORTENERS.has(etld1);
        } catch (_) { return false; }
    }

    /**
     * Check if URL path looks like a shortener token
     */
    function pathLooksLikeToken(url) {
        try {
            const u = new URL(url);
            const pathname = u.pathname;
            const search = u.search;

            // Shortener-like: short path, alphanumeric-heavy
            if (pathname.length > 1 && pathname.length < 20) {
                const pathPart = pathname.replace(/^\/+/, '');
                if (/^[a-zA-Z0-9]{4,12}$/.test(pathPart)) return true;
                if (/^[a-zA-Z0-9_-]{4,16}$/.test(pathPart) && !pathPart.includes('/')) return true;
            }

            // Check for redirect-like query params
            if (search.includes('url=') || search.includes('redirect=') ||
                search.includes('next=') || search.includes('goto=')) {
                return true;
            }

            return false;
        } catch (_) { return false; }
    }

    /**
     * Check if destination is known safe
     */
    function isKnownSafeDestination(url) {
        try {
            const etld1 = getETLD1(url);
            return !!etld1 && KNOWN_SAFE_DEST_ETLD1.has(etld1);
        } catch (_) { return false; }
    }

    /**
     * Check if a URL or host belongs to a multi-tenant public platform
     * (e.g. github.com, drive.google.com, vercel.app).
     * These platforms must NEVER have their base domain or hostname blocked.
     */
    function isMultiTenantPlatform(urlOrHost) {
        try {
            if (!urlOrHost) return false;
            let host = '';
            if (/^https?:\/\//i.test(urlOrHost)) {
                host = new URL(urlOrHost).hostname.toLowerCase();
            } else {
                host = String(urlOrHost).toLowerCase().split('/')[0].split(':')[0].trim();
            }
            if (!host) return false;
            if (MULTI_TENANT_PLATFORMS.has(host)) return true;
            const etld1 = getETLD1FromHost(host);
            if (etld1 && MULTI_TENANT_PLATFORMS.has(etld1)) return true;
            return false;
        } catch (_) {
            return false;
        }
    }

    /**
     * Detect common open-redirect parameter patterns
     */
    function hasOpenRedirectParam(url) {
        try {
            const u = new URL(url);
            const search = u.search.toLowerCase();
            const params = ['url=', 'redirect=', 'next=', 'goto=', 'return=',
                'returnurl=', 'destination=', 'redir=', 'continue='];

            for (const param of params) {
                if (search.includes(param)) {
                    const match = u.search.match(new RegExp(`[?&]${param.slice(0, -1)}=([^&]+)`, 'i'));
                    if (match) {
                        try {
                            const redirectUrl = decodeURIComponent(match[1]);
                            if (redirectUrl.startsWith('http')) {
                                const redirectHost = new URL(redirectUrl).hostname;
                                if (redirectHost !== u.hostname) {
                                    return true;
                                }
                            }
                        } catch (_) { }
                    }
                }
            }
            return false;
        } catch (_) { return false; }
    }

    // ========== COMPREHENSIVE URL ANALYSIS ==========

    /**
     * Normalize URL for comparison (strip tracking params, lowercase, etc.)
     */
    function normalizeUrlForComparison(url) {
        try {
            const u = new URL(url);
            u.hash = '';
            // Remove common tracking params
            const trackingParams = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
                'fbclid', 'gclid', 'ref', 'source', 'mc_eid'];
            trackingParams.forEach(p => u.searchParams.delete(p));
            return u.toString().toLowerCase();
        } catch (_) {
            return url.toLowerCase();
        }
    }

    /**
     * Extract comprehensive domain info from URL
     */
    function getDomainInfo(url) {
        try {
            const u = new URL(url);
            const host = u.hostname.toLowerCase();
            const etld1 = getETLD1FromHost(host);
            const parts = host.split('.');

            return {
                protocol: u.protocol,
                hostname: host,
                etld1: etld1,
                subdomain: parts.length > 2 ? parts.slice(0, -2).join('.') : null,
                port: u.port || null,
                path: u.pathname,
                query: u.search,
                isHttps: u.protocol === 'https:',
                isShortener: isKnownShortener(url)
            };
        } catch (e) {
            return { error: e.message };
        }
    }

    /**
     * Perform complete URL security analysis
     * Returns all risk signals in one call
     */
    function analyzeUrl(url) {
        const result = {
            url: url,
            isValid: false,
            risks: [],
            signals: {}
        };
        
        try {
            new URL(url);
            result.isValid = true;
        } catch (_) {
            result.risks.push('Invalid URL');
            return result;
        }
        
        // Check HTTPS
        result.signals.https = isHttps(url);
        if (!result.signals.https) {
            result.risks.push('No HTTPS encryption');
        }
        
        // Check homograph
        const homograph = detectHomograph(url);
        result.signals.homograph = homograph;
        if (homograph.isHomograph) {
            result.risks.push(`Homograph attack: ${homograph.reason}`);
        }
        
        // Check typosquatting
        const typosquat = detectTyposquatting(url);
        result.signals.typosquatting = typosquat;
        if (typosquat.isTyposquat) {
            result.risks.push(`Possible typosquatting of ${typosquat.targetBrand}`);
        }
        
        // Check TLD risk
        const tldRisk = hasHighRiskTLD(url);
        result.signals.highRiskTLD = tldRisk;
        if (tldRisk.isHighRisk) {
            result.risks.push(`High-risk TLD: ${tldRisk.tld}`);
        }
        
        // Check entropy
        const entropy = hasHighEntropySubdomain(url);
        result.signals.entropy = entropy;
        if (entropy.suspicious) {
            result.risks.push(`Suspicious subdomain: high entropy (${entropy.entropy})`);
        }
        
        // Check shortener
        result.signals.isShortener = isKnownShortener(url);
        if (result.signals.isShortener) {
            result.risks.push('URL shortener - destination unknown');
        }
        
        // Check open redirect
        result.signals.openRedirect = hasOpenRedirectParam(url);
        if (result.signals.openRedirect) {
            result.risks.push('Open redirect parameter detected');
        }
        
        return result;
    }

    // ========== PUBLIC API ==========

    return {
        // Core URL functions
        getETLD1FromHost,
        getETLD1,
        isSameETLD1,
        normalizeHost,
        isHttps,
        normalizeUrlForComparison,
        getDomainInfo,
        
        // Detection functions
        calculateEntropy,
        hasHighEntropySubdomain,
        detectHomograph,
        detectTyposquatting,
        hasHighRiskTLD,
        levenshteinDistance,
        stringSimilarity,
        
        // Shortener/redirect functions
        isKnownShortener,
        pathLooksLikeToken,
        isKnownSafeDestination,
        isMultiTenantPlatform,
        hasOpenRedirectParam,
        
        // Comprehensive analysis
        analyzeUrl,
        
        // Constants (exposed for other modules)
        MULTI_PART_SUFFIXES,
        KNOWN_SHORTENERS,
        KNOWN_SAFE_DEST_ETLD1,
        MULTI_TENANT_PLATFORMS,
        HIGH_RISK_TLDS,
        BRAND_NAMES
    };
})();

// Export for use in service worker and Node.js
if (typeof self !== 'undefined') {
    self.UrlUtils = UrlUtils;
}
if (typeof module !== 'undefined' && module.exports) {
    module.exports = UrlUtils;
}

