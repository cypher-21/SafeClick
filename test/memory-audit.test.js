/**
 * SafeClick 2.0 - Memory Footprint Audit Test
 * 
 * Verifies that SafeClick 2.0 maintains a lean memory footprint (<25 MB target)
 * even under full operational load with 10,000 ingested threat indicators,
 * Bloom filter indices, ML models, heuristic engines, and caches.
 */

const assert = require('assert');

// Core utilities & modules
const ThreatCache = require('../data/threat-cache.js');
const BloomFilter = require('../modules/bloom-filter.js');
const URLAnalyzer = require('../evidence/url-analyzer.js');
const BrandDetector = require('../evidence/brand-detector.js');
const FeatureExtractor = require('../ml/feature-extractor.js');
const LocalClassifier = require('../ml/classifier.js');
const { Indicator, IndicatorRegistry } = require('../evidence/indicator.js');
const { AIProvider, AIRegistry } = require('../ai/ai-provider.js');
const AIAdvisor = require('../ai/ai-advisor.js');
const SERPEnhancer = require('../content/serp-enhancer.js');
const VerdictEngine = require('../scoring/verdict-engine.js');
const Explainer = require('../scoring/explainer.js');

async function run() {
  console.log('--- Running memory-audit.test.js ---');

  if (global.gc) {
    global.gc();
  }

  const baselineMemory = process.memoryUsage();

  // 1. Instantiate Threat Cache with 10,000 threat entries
  const cache = new ThreatCache({ maxEntries: 20000 });
  await cache.init();

  const exactUrls = [];
  const hosts = [];
  for (let i = 0; i < 5000; i++) {
    exactUrls.push(`https://phishing-site-${i}.evil.top/login`);
    hosts.push(`phishing-site-${i}.evil.top`);
  }
  await cache.ingest('benchmark-feed', { exactUrls, hosts });

  // 2. Instantiate Feature Extractor & ML Classifier
  const extractor = new FeatureExtractor();
  const classifier = new LocalClassifier();

  // 3. Instantiate Heuristic Engines
  const urlAnalyzer = new URLAnalyzer();
  const brandDetector = new BrandDetector();

  // 4. Instantiate AI Advisory Subsystem
  const aiRegistry = new AIRegistry();
  const aiAdvisor = new AIAdvisor(aiRegistry);

  // 5. Instantiate SERP Enhancer
  const serpEnhancer = new SERPEnhancer();

  // 6. Run a cycle of analyses to exercise runtime objects
  for (let i = 0; i < 100; i++) {
    const testUrl = `https://login.paypal.com-verify-${i}.security-check.top/auth`;
    const indicators = urlAnalyzer.analyze(testUrl);
    const brandInds = brandDetector.analyze(new URL(testUrl).hostname);
    const reg = new IndicatorRegistry();
    reg.addAll(indicators);
    reg.addAll(brandInds);

    const verdict = VerdictEngine.evaluate(reg, { url: testUrl, domain: new URL(testUrl).hostname });
    const mlResult = classifier.classify(testUrl, null);
    const explanation = Explainer.explain(verdict, reg.getAll());
  }

  if (global.gc) {
    global.gc();
  }

  const currentMemory = process.memoryUsage();
  const heapUsedMB = currentMemory.heapUsed / (1024 * 1024);
  const memoryDeltaMB = (currentMemory.heapUsed - baselineMemory.heapUsed) / (1024 * 1024);

  console.log(`  📊 Baseline Heap Used:    ${(baselineMemory.heapUsed / (1024 * 1024)).toFixed(2)} MB`);
  console.log(`  📊 Active Engine Heap:     ${heapUsedMB.toFixed(2)} MB`);
  console.log(`  📊 Engine Subsystem Delta: ${memoryDeltaMB.toFixed(2)} MB`);
  console.log(`  📊 Ingested Threat Items:  10,000 live entries`);

  // Target requirement: Memory footprint < 25 MB
  const MEMORY_LIMIT_MB = 25.0;
  assert.ok(
    heapUsedMB < MEMORY_LIMIT_MB,
    `Heap used (${heapUsedMB.toFixed(2)} MB) exceeded maximum budget of ${MEMORY_LIMIT_MB} MB`
  );

  console.log(`  ✓ Memory footprint is ${(heapUsedMB).toFixed(2)} MB, well within the 25 MB target limit!`);
}

module.exports = run;
if (require.main === module) {
  run().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
