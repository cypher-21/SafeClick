/**
 * Unit Tests for ThreatIntelProvider and ThreatIntelRegistry
 */
const assert = require('assert');
const { Indicator } = require('../evidence/indicator.js');
global.Indicator = Indicator;

const {
  ThreatIntelProvider,
  URLhausProvider,
  OpenPhishProvider,
  ThreatIntelRegistry
} = require('../evidence/threat-intel-provider.js');

async function run() {
  console.log('--- Running threat-intel.test.js ---');

  // 1. ThreatIntelProvider creation & properties
  const provider = new ThreatIntelProvider({
    id: 'test_feed',
    name: 'Test Threat Feed',
    confidence: 'high'
  });

  assert.strictEqual(provider.id, 'test_feed');
  assert.strictEqual(provider.name, 'Test Threat Feed');
  assert.strictEqual(provider.enabled, true);
  console.log('  ✓ ThreatIntelProvider creation and options work');

  // 2. Offline / Empty Provider lookup
  const emptyLookup = provider.lookup('https://example.com/login', 'example.com', 'example.com');
  assert.strictEqual(Array.isArray(emptyLookup), true);
  assert.strictEqual(emptyLookup.length, 0);
  console.log('  ✓ Provider returns empty array when clean/offline');

  // 3. Exact URL match produces critical threat indicator
  provider.addEntries(['https://malicious.example.com/steal-creds'], ['malicious-host.com']);
  const exactIndicators = provider.lookup('https://malicious.example.com/steal-creds', 'malicious.example.com', 'example.com');
  assert.strictEqual(exactIndicators.length, 1);
  assert.strictEqual(exactIndicators[0].id, 'threat_feed.test_feed.exact_url');
  assert.strictEqual(exactIndicators[0].polarity, 'negative');
  assert.strictEqual(exactIndicators[0].weight, -100);
  assert.strictEqual(exactIndicators[0].confidence, 'high');
  console.log('  ✓ Exact URL match generates critical negative indicator');

  // 4. Host match produces weighted negative evidence (not hard-fail)
  const hostIndicators = provider.lookup('https://malicious-host.com/innocent-page', 'malicious-host.com', 'malicious-host.com');
  assert.strictEqual(hostIndicators.length, 1);
  assert.strictEqual(hostIndicators[0].id, 'threat_feed.test_feed.host');
  assert.strictEqual(hostIndicators[0].weight, -35);
  console.log('  ✓ Host match generates weighted negative indicator (-35)');

  // 5. Built-in provider instances
  const urlhaus = new URLhausProvider();
  assert.strictEqual(urlhaus.id, 'urlhaus');
  assert.ok(urlhaus.feedUrl.includes('abuse.ch'));

  const openphish = new OpenPhishProvider();
  assert.strictEqual(openphish.id, 'openphish');
  assert.ok(openphish.feedUrl.includes('openphish.com'));
  console.log('  ✓ URLhaus and OpenPhish provider instances configured');

  // 6. ThreatIntelRegistry coordination
  const registry = new ThreatIntelRegistry();
  registry.register(provider);
  registry.register(urlhaus);
  registry.register(openphish);

  assert.strictEqual(registry.getAll().length, 3);
  assert.ok(registry.get('urlhaus'));

  // Aggregated lookup
  const aggMatches = registry.lookup('https://malicious.example.com/steal-creds', 'malicious.example.com');
  assert.strictEqual(aggMatches.length, 1);
  assert.strictEqual(aggMatches[0].source, 'test_feed');

  const stats = registry.getStats();
  assert.strictEqual(stats.providerCount, 3);
  assert.strictEqual(stats.totalEntries, 2);
  console.log('  ✓ ThreatIntelRegistry aggregated lookups and statistics work');

  console.log('All threat-intel.test.js tests passed!');
}

if (require.main === module) {
  run().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
  });
}

module.exports = run;
