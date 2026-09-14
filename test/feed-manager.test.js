/**
 * Tests for FeedManager (data/feed-manager.js)
 */

const assert = require('assert');
const FeedManager = require('../data/feed-manager.js');

async function runFeedTests() {
  console.log('[Test] Running FeedManager Tests...');

  const fm = new FeedManager(null, { maxEntriesPerFeed: 5 });

  // 1. Text feed parsing
  const rawText = `
# Comment line
https://malware-url.com/payload.exe
https://phishing.site/login.html
invalid_url_line
safe-host.com
`;
  const parsedText = fm.parseTextFeed(rawText);
  assert.strictEqual(parsedText.urls.length, 2, 'Should parse 2 valid URLs');
  assert(parsedText.urls.includes('https://malware-url.com/payload.exe'), 'Parsed URL contains malware-url');
  assert(parsedText.hosts.includes('malware-url.com'), 'Extracted hosts contain malware-url.com');
  assert(parsedText.hosts.includes('safe-host.com'), 'Extracted hosts contain valid hostname');

  // 2. URLhaus JSON parsing
  const rawJson = JSON.stringify({
    urls: [
      { url: 'https://evil1.com/drop' },
      { url: 'https://evil2.com/trojan' }
    ]
  });
  const parsedJson = fm.parseUrlhausJson(rawJson);
  assert.strictEqual(parsedJson.urls.length, 2, 'Should parse 2 URLs from JSON');
  assert(parsedJson.hosts.includes('evil1.com'), 'Hosts should include evil1.com');
  assert(parsedJson.hosts.includes('evil2.com'), 'Hosts should include evil2.com');

  // 3. Stats initialization
  const stats = fm.getStats();
  assert.strictEqual(stats.isUpdating, false, 'isUpdating should initially be false');
  assert.strictEqual(stats.feeds.length, 2, 'Should track 2 feeds (urlhaus, openphish)');

  console.log('  ✓ All FeedManager tests passed!');
}

module.exports = runFeedTests;
if (require.main === module) {
  runFeedTests().catch(err => {
    console.error('FeedManager test failure:', err);
    process.exit(1);
  });
}
