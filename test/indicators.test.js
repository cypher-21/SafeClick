/**
 * Unit Tests for Indicator and IndicatorRegistry
 */
const assert = require('assert');
const { Indicator, IndicatorRegistry } = require('../evidence/indicator.js');

async function run() {
  console.log('--- Running indicators.test.js ---');

  assert.ok(Indicator, 'Indicator class must be exported');
  assert.ok(IndicatorRegistry, 'IndicatorRegistry class must be exported');

  // 1. Indicator creation and properties
  const ind1 = new Indicator({
    id: 'phish.exact_match',
    category: 'threat_feed',
    polarity: 'negative',
    weight: -100,
    confidence: 'high',
    value: true,
    detail: 'Exact URL found in PhishTank database'
  });

  assert.strictEqual(ind1.id, 'phish.exact_match');
  assert.strictEqual(ind1.category, 'threat_feed');
  assert.strictEqual(ind1.polarity, 'negative');
  assert.strictEqual(ind1.confidence, 'high');
  assert.strictEqual(ind1.weight, -100);
  assert.strictEqual(ind1.value, true);
  assert.strictEqual(ind1.detail, 'Exact URL found in PhishTank database');
  console.log('  ✓ Indicator properties work');

  // 2. Indicator defaults
  const indDefault = new Indicator({
    id: 'test.default'
  });
  assert.strictEqual(indDefault.category, 'structural');
  assert.strictEqual(indDefault.polarity, 'info');
  assert.strictEqual(indDefault.confidence, 'medium');
  assert.strictEqual(indDefault.weight, 0);
  console.log('  ✓ Indicator default values work');

  // 3. Positive indicator
  const indPos = new Indicator({
    id: 'ssl.valid',
    category: 'network',
    polarity: 'positive',
    weight: 20,
    confidence: 'high',
    detail: 'Valid SSL Certificate'
  });
  assert.strictEqual(indPos.polarity, 'positive');
  console.log('  ✓ Positive indicator detection works');

  // 4. IndicatorRegistry operations
  const registry = new IndicatorRegistry();
  assert.strictEqual(registry.size, 0);

  registry.add(ind1);
  registry.add(indPos);
  assert.strictEqual(registry.size, 2);
  assert.strictEqual(registry.has('phish.exact_match'), true);
  assert.strictEqual(registry.has('non_existent'), false);
  console.log('  ✓ IndicatorRegistry add, size, has work');

  // 5. Filtering and queries
  const threatFeeds = registry.getByCategory('threat_feed');
  assert.strictEqual(threatFeeds.length, 1);
  assert.strictEqual(threatFeeds[0].id, 'phish.exact_match');

  const negatives = registry.getNegative();
  assert.strictEqual(negatives.length, 1);
  assert.strictEqual(negatives[0].id, 'phish.exact_match');

  const positives = registry.getPositive();
  assert.strictEqual(positives.length, 1);
  assert.strictEqual(positives[0].id, 'ssl.valid');
  console.log('  ✓ IndicatorRegistry filtering works');

  // 6. JSON serialization & deserialization
  const json = registry.toJSON();
  assert.strictEqual(Array.isArray(json), true);
  assert.strictEqual(json.length, 2);
  assert.strictEqual(json[0].id, 'phish.exact_match');

  const restored = IndicatorRegistry.fromJSON(json);
  assert.strictEqual(restored.size, 2);
  assert.strictEqual(restored.has('ssl.valid'), true);
  console.log('  ✓ JSON serialization and deserialization work');

  console.log('All indicators.test.js tests passed!');
}

if (require.main === module) {
  run().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
  });
}

module.exports = run;
