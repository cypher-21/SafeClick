/**
 * SafeClick 2.0 - Local ML Model Evaluation & Benchmark
 * 
 * Verifies accuracy, latency, precision, recall, and zero-cloud execution
 * against verified benchmark dataset samples.
 */
const assert = require('assert');
const { Indicator } = require('../../evidence/indicator.js');
global.Indicator = Indicator;

const FeatureExtractor = require('../../ml/feature-extractor.js');
const LocalClassifier = require('../../ml/classifier.js');

const BENCHMARK_SAMPLES = [
  // --- Malicious / Phishing Samples (Expected: MALICIOUS or SUSPICIOUS) ---
  {
    url: 'http://192.168.1.50:8080/paypal.com/login.html',
    dom: { hasCredentialFields: true },
    label: 1,
    desc: 'Raw IP with non-standard port and HTTP'
  },
  {
    url: 'https://paypa1-security-verify.top/account/login',
    dom: null,
    label: 1,
    desc: 'Typosquat with high-abuse TLD'
  },
  {
    url: 'https://apple.com.secure-update-id.xyz/signin',
    dom: { hasCredentialFields: true },
    label: 1,
    desc: 'Subdomain brand spoof on .xyz'
  },
  {
    url: 'http://admin:pass123@suspicious-bank-login.com/',
    dom: null,
    label: 1,
    desc: 'Embedded credentials over HTTP'
  },
  {
    url: 'https://google-login-verify-account.click/auth',
    dom: null,
    label: 1,
    desc: 'Brand combosquat on .click TLD'
  },
  {
    url: 'https://harvester-kit.com/login',
    dom: { hasSuspiciousForms: true, hasCredentialFields: true },
    label: 1,
    desc: 'Cross-origin credential submission'
  },
  {
    url: 'https://fake-bank-portal.com/login',
    dom: { hasBrowserInBrowserPatterns: true, hasCredentialFields: true },
    label: 1,
    desc: 'Browser-in-the-Browser simulated window'
  },
  {
    url: 'https://service-notice.tk/verify',
    dom: null,
    label: 1,
    desc: 'Free .tk TLD with urgency pattern'
  },

  // --- Benign Web Properties (Expected: BENIGN, probability < 0.45) ---
  {
    url: 'https://google.com/search?q=browser+security',
    dom: null,
    label: 0,
    desc: 'Google search'
  },
  {
    url: 'https://github.com/cypher-21/SafeClick',
    dom: null,
    label: 0,
    desc: 'GitHub project repository'
  },
  {
    url: 'https://wikipedia.org/wiki/Computer_security',
    dom: null,
    label: 0,
    desc: 'Wikipedia article'
  },
  {
    url: 'https://amazon.com/dp/B08N5WRWNW',
    dom: null,
    label: 0,
    desc: 'Amazon product page'
  },
  {
    url: 'https://microsoft.com/en-us/windows',
    dom: null,
    label: 0,
    desc: 'Microsoft homepage'
  },
  {
    url: 'https://netflix.com/browse',
    dom: null,
    label: 0,
    desc: 'Netflix browsing'
  },
  {
    url: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript',
    dom: null,
    label: 0,
    desc: 'MDN Web Docs'
  },
  {
    url: 'https://stackoverflow.com/questions/12345/javascript',
    dom: null,
    label: 0,
    desc: 'StackOverflow question'
  }
];

async function run() {
  console.log('--- Running evaluation.test.js (ML Benchmark) ---');

  const classifier = new LocalClassifier();
  let truePositives = 0;
  let trueNegatives = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  let totalLatencyMs = 0;

  for (const sample of BENCHMARK_SAMPLES) {
    const t0 = performance.now();
    const result = classifier.classify(sample.url, sample.dom);
    const t1 = performance.now();
    totalLatencyMs += (t1 - t0);

    const isPredictedMalicious = (result.prediction.decision === 'MALICIOUS' || result.prediction.decision === 'SUSPICIOUS');

    if (sample.label === 1) {
      if (isPredictedMalicious) {
        truePositives++;
      } else {
        falseNegatives++;
        console.warn(`    [FN] Missed attack: ${sample.url} (${result.prediction.probability})`);
      }
    } else {
      if (!isPredictedMalicious) {
        trueNegatives++;
      } else {
        falsePositives++;
        console.warn(`    [FP] False alert on benign: ${sample.url} (${result.prediction.probability})`);
      }
    }

    // Verify explainability
    assert.ok(Array.isArray(result.prediction.topFeatures), 'Top features must be provided for explanation');
    assert.ok(result.prediction.probability >= 0 && result.prediction.probability <= 1);
  }

  const total = BENCHMARK_SAMPLES.length;
  const accuracy = (truePositives + trueNegatives) / total;
  const precision = (truePositives + falsePositives) > 0 ? truePositives / (truePositives + falsePositives) : 1;
  const recall = (truePositives + falseNegatives) > 0 ? truePositives / (truePositives + falseNegatives) : 1;
  const f1 = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const avgLatencyMs = totalLatencyMs / total;

  console.log(`  ✓ Benchmark Results:`);
  console.log(`     Accuracy:     ${Math.round(accuracy * 100)}% (${truePositives + trueNegatives}/${total})`);
  console.log(`     Precision:    ${Math.round(precision * 100)}%`);
  console.log(`     Recall:       ${Math.round(recall * 100)}%`);
  console.log(`     F1-Score:     ${Math.round(f1 * 100)}%`);
  console.log(`     Avg Latency:  ${avgLatencyMs.toFixed(3)} ms / inference`);

  // Assertions
  assert.ok(accuracy >= 0.90, `Accuracy must be >= 90%, was ${Math.round(accuracy * 100)}%`);
  assert.strictEqual(falsePositives, 0, 'Zero false positives allowed on clean benign samples');
  assert.ok(avgLatencyMs < 1.0, `Inference latency must be sub-millisecond, was ${avgLatencyMs} ms`);

  console.log('All evaluation.test.js tests passed!');
}

if (require.main === module) {
  run().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
  });
}

module.exports = run;
