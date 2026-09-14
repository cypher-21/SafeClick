/**
 * Tests for RedirectTracker (core/redirect-tracker.js)
 */

const assert = require('assert');

// Mock chrome and storage for RedirectTracker
global.chrome = {
  runtime: { sendMessage: async () => {} },
  webRequest: { onBeforeRedirect: { addListener: () => {} } },
  webNavigation: { onCommitted: { addListener: () => {} } }
};
global.SafeClickStorage = require('../data/storage.js');
global.UrlUtils = require('../modules/url-utils.js');

const RedirectTracker = require('../core/redirect-tracker.js');

async function runRedirectTests() {
  console.log('[Test] Running RedirectTracker Tests...');

  // 1. Token-like path heuristic
  assert.strictEqual(RedirectTracker.shortPathLooksLikeToken('/r8xK2', ''), true, 'Short token path detected');
  assert.strictEqual(RedirectTracker.shortPathLooksLikeToken('/articles/2026/09/security-guide-long-title', ''), false, 'Long article path is not token');
  assert.strictEqual(RedirectTracker.shortPathLooksLikeToken('/out', '?url=https://evil.com'), true, 'Query with url= target is token-like');

  // 2. Likely shorteners
  assert.strictEqual(RedirectTracker.isLikelyShortener('https://bit.ly/3xYz'), true, 'bit.ly is a recognized shortener');
  assert.strictEqual(RedirectTracker.isLikelyShortener('https://tinyurl.com/abc'), true, 'tinyurl is a recognized shortener');
  assert.strictEqual(RedirectTracker.isLikelyShortener('https://github.com/cypher-21/SafeClick'), false, 'github repo is not a shortener');

  // 3. Open redirect parameter detection
  assert.strictEqual(
    RedirectTracker.hasOpenRedirectParamCrossDomain('https://legit-portal.com/login?dest=https://phish.net/steal'),
    true,
    'Cross-domain destination parameter detected'
  );
  assert.strictEqual(
    RedirectTracker.hasOpenRedirectParamCrossDomain('https://legit-portal.com/login?dest=https://legit-portal.com/dashboard'),
    false,
    'Same-domain redirect parameter should not trigger open redirect warning'
  );

  // 4. Search engine query detection
  assert.strictEqual(RedirectTracker.isSearchEngineResults('https://www.google.com/search?q=open+source'), true, 'Google search detected');
  assert.strictEqual(RedirectTracker.isSearchEngineResults('https://duckduckgo.com/?q=privacy'), true, 'DuckDuckGo search detected');
  assert.strictEqual(RedirectTracker.isSearchEngineResults('https://www.google.com/about/careers'), false, 'Google about page is not SERP');

  // 5. Search bypass lifecycle
  RedirectTracker.markSearchBypass(42, 1000);
  assert.strictEqual(RedirectTracker.shouldBypassForSearch(42), true, 'Active search bypass should return true');
  assert.strictEqual(RedirectTracker.shouldBypassForSearch(99), false, 'Non-marked tab should not bypass');

  console.log('  ✓ All RedirectTracker tests passed!');
}

module.exports = runRedirectTests;
if (require.main === module) {
  runRedirectTests().catch(err => {
    console.error('RedirectTracker test failure:', err);
    process.exit(1);
  });
}
