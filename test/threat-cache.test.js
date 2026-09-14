/**
 * Unit Tests for ThreatCache (Dynamic Runtime Cache with Bloom Filter Fast-Path)
 */
const assert = require('assert');
const BloomFilter = require('../modules/bloom-filter.js');
global.BloomFilter = BloomFilter;

const ThreatCache = require('../data/threat-cache.js');

async function run() {
  console.log('--- Running threat-cache.test.js ---');

  // 1. Creation and in-memory init
  const cache = new ThreatCache({ maxEntries: 100 });
  await cache.init();
  assert.strictEqual(cache.loaded, true);
  assert.strictEqual(cache.exactUrls.size, 0);
  assert.strictEqual(cache.hosts.size, 0);
  console.log('  ✓ ThreatCache initialized cleanly in memory');

  // 2. Fast-path lookup on empty cache
  assert.strictEqual(cache.hasExactUrl('https://example.com/test'), false);
  assert.strictEqual(cache.hasHost('example.com'), false);
  const emptyRes = cache.lookup('https://example.com/test', 'example.com');
  assert.strictEqual(emptyRes.listed, false);
  console.log('  ✓ Empty cache lookups return false with zero overhead');

  // 3. Ingestion and Bloom Filter integration
  await cache.ingest('urlhaus', {
    exactUrls: [
      'https://malicious.ru/trojan.exe',
      'https://phish.xyz/login.html'
    ],
    hosts: [
      'evil-tracker.com',
      'malicious.ru'
    ]
  });

  assert.strictEqual(cache.exactUrls.size, 2);
  assert.strictEqual(cache.hosts.size, 2);
  assert.ok(cache.bloom, 'Bloom filter should be generated');

  // Positive lookups
  assert.strictEqual(cache.hasExactUrl('https://malicious.ru/trojan.exe'), true);
  assert.strictEqual(cache.hasExactUrl('https://phish.xyz/login.html'), true);
  assert.strictEqual(cache.hasHost('evil-tracker.com'), true);
  assert.strictEqual(cache.hasHost('malicious.ru'), true);

  // Negative lookups (unlisted items)
  assert.strictEqual(cache.hasExactUrl('https://google.com/search'), false);
  assert.strictEqual(cache.hasHost('google.com'), false);
  console.log('  ✓ Ingested entries verified via Bloom filter fast-path');

  // 4. Combined lookup
  const hit1 = cache.lookup('https://malicious.ru/trojan.exe', 'malicious.ru');
  assert.strictEqual(hit1.listed, true);
  assert.strictEqual(hit1.exactUrlListed, true);
  assert.strictEqual(hit1.hostListed, true);

  const hit2 = cache.lookup('https://evil-tracker.com/safe-path', 'evil-tracker.com');
  assert.strictEqual(hit2.listed, true);
  assert.strictEqual(hit2.exactUrlListed, false);
  assert.strictEqual(hit2.hostListed, true);
  console.log('  ✓ Combined security lookups distinguish exact URL vs host');

  // 5. Cap enforcement
  const manyUrls = [];
  for (let i = 0; i < 150; i++) {
    manyUrls.push(`https://bulk-threat.net/path/${i}`);
  }
  await cache.ingest('bulk', { exactUrls: manyUrls });
  assert.ok(cache.exactUrls.size <= 100, `Cache size (${cache.exactUrls.size}) must not exceed maxEntries (100)`);
  console.log('  ✓ Memory cap enforcement successfully caps cache capacity');

  // 6. Stats & Clear
  const stats = cache.getStats();
  assert.ok(stats.totalEntries > 0);
  assert.ok(stats.bloomFilter);

  await cache.clear();
  assert.strictEqual(cache.exactUrls.size, 0);
  assert.strictEqual(cache.hosts.size, 0);
  assert.strictEqual(cache.hasExactUrl('https://malicious.ru/trojan.exe'), false);
  console.log('  ✓ Clear operation resets cache and lookups');

  console.log('All threat-cache.test.js tests passed!');
}

if (require.main === module) {
  run().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
  });
}

module.exports = run;
