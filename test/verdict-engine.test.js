/**
 * Unit Tests for SafeClick 2.0 VerdictEngine and Explainer
 */
const assert = require('assert');
const { Indicator, IndicatorRegistry } = require('../evidence/indicator.js');
const Explainer = require('../scoring/explainer.js');
const VerdictEngine = require('../scoring/verdict-engine.js');

// In browser, Explainer is a global; in node, wire it if not on global
global.Explainer = Explainer;

async function run() {
  console.log('--- Running verdict-engine.test.js ---');

  // 1. User Allowlist Override
  const regAllow = new IndicatorRegistry();
  const resAllow = VerdictEngine.evaluate(regAllow, { isAllowlisted: true });
  assert.strictEqual(resAllow.verdict, 'SAFE');
  assert.strictEqual(resAllow.score, 100);
  assert.strictEqual(resAllow.hardFailed, false);
  console.log('  ✓ Allowlist override produces SAFE 100');

  // 2. Exact URL Hard Fail
  const regExact = new IndicatorRegistry();
  regExact.add(new Indicator({
    id: 'phishtank.exact_url',
    source: 'phishtank',
    category: 'threat_feed',
    polarity: 'negative',
    confidence: 'high',
    weight: -100,
    detail: '[X] Exact URL confirmed phishing in PhishTank'
  }));
  const resExact = VerdictEngine.evaluate(regExact, { url: 'https://evil-phish.com/login' });
  assert.strictEqual(resExact.hardFailed, true, 'Exact URL match MUST hard fail');
  assert.strictEqual(resExact.score, 0, 'Exact URL match score MUST be 0');
  assert.strictEqual(resExact.verdict, 'DANGEROUS', 'Exact URL match verdict MUST be DANGEROUS');
  console.log('  ✓ Exact URL match triggers hard-fail to DANGEROUS (score 0)');

  // 3. Insecure HTTP with Password Form Hard Fail
  const regInsecureLogin = new IndicatorRegistry();
  regInsecureLogin.add(new Indicator({
    id: 'url.no_https',
    category: 'network',
    polarity: 'negative',
    weight: -20,
    detail: 'No HTTPS'
  }));
  regInsecureLogin.add(new Indicator({
    id: 'dom.password_form',
    category: 'content',
    polarity: 'negative',
    weight: -15,
    detail: 'Password form detected'
  }));
  const resInsecure = VerdictEngine.evaluate(regInsecureLogin);
  assert.strictEqual(resInsecure.hardFailed, true);
  assert.strictEqual(resInsecure.score, 0);
  assert.strictEqual(resInsecure.verdict, 'DANGEROUS');
  console.log('  ✓ Insecure HTTP + password form triggers deterministic hard-fail to DANGEROUS');

  // 4. Host-Level Match is NOT a Hard Fail (False Positive Prevention)
  const regHostMatch = new IndicatorRegistry();
  regHostMatch.add(new Indicator({
    id: 'reputation.host_match',
    source: 'reputation-db',
    category: 'reputation',
    polarity: 'negative',
    confidence: 'medium',
    weight: -30,
    detail: '[!] Domain listed in blocklist, but path unverified'
  }));
  regHostMatch.add(new Indicator({
    id: 'network.https_valid',
    category: 'network',
    polarity: 'positive',
    weight: 10,
    detail: '[OK] Valid HTTPS'
  }));
  // Base 50 + 10 (https) - 30 (host penalty) = 30 -> SUSPICIOUS / DANGEROUS based on pen, but NOT hardFailed: true with score 0
  const resHost = VerdictEngine.evaluate(regHostMatch, { url: 'https://raw.githubusercontent.com/user/project' });
  assert.strictEqual(resHost.hardFailed, false, 'Host match must NOT be treated as a hard-fail');
  assert.ok(resHost.score > 0, 'Host match score should be weighted, not clamped to 0 unconditionally');
  console.log('  ✓ Host-level match is weighted evidence, NOT an unconditional hard-fail');

  // 5. Absence of Evidence Rule: Clean Unverified Site -> UNKNOWN (NOT SAFE)
  const regCleanUnverified = new IndicatorRegistry();
  regCleanUnverified.add(new Indicator({
    id: 'network.https_valid',
    category: 'network',
    polarity: 'positive',
    weight: 10,
    detail: '[OK] Valid HTTPS'
  }));
  // Base 50 + 10 = 60. Positive weight is only 10 (< 20 required for SAFE), no threats found.
  const resClean = VerdictEngine.evaluate(regCleanUnverified);
  assert.strictEqual(resClean.hardFailed, false);
  assert.strictEqual(resClean.verdict, 'UNKNOWN', 'Unverified clean site must be UNKNOWN, never blindly SAFE');
  assert.strictEqual(resClean.score, 60);
  console.log('  ✓ Absence of evidence rule verified: Unverified clean site receives UNKNOWN (60)');

  // 6. Established Trust Signals -> SAFE
  const regSafe = new IndicatorRegistry();
  regSafe.add(new Indicator({
    id: 'network.https_valid',
    category: 'network',
    polarity: 'positive',
    weight: 10,
    detail: '[OK] Valid HTTPS'
  }));
  regSafe.add(new Indicator({
    id: 'reputation.high_trust',
    category: 'reputation',
    polarity: 'positive',
    weight: 15,
    detail: '[OK] Established high domain reputation'
  }));
  regSafe.add(new Indicator({
    id: 'domain.mature_age',
    category: 'lexical',
    polarity: 'positive',
    weight: 10,
    detail: '[OK] Domain age > 2 years'
  }));
  // Base 50 + 10 + 15 + 10 = 85. Positive weight = 35 (>= 20), no negative indicators.
  const resSafe = VerdictEngine.evaluate(regSafe);
  assert.strictEqual(resSafe.hardFailed, false);
  assert.strictEqual(resSafe.score, 85);
  assert.strictEqual(resSafe.verdict, 'SAFE', 'Established trust signals must yield SAFE');
  console.log('  ✓ Established trust signals yield SAFE (score 85)');

  // 7. Suspicious Signals -> SUSPICIOUS
  const regSuspicious = new IndicatorRegistry();
  regSuspicious.add(new Indicator({
    id: 'url.suspicious_tld',
    category: 'lexical',
    polarity: 'negative',
    confidence: 'medium',
    weight: -15,
    detail: '[!] Free or high-abuse TLD (.top/.xyz)'
  }));
  regSuspicious.add(new Indicator({
    id: 'network.https_valid',
    category: 'network',
    polarity: 'positive',
    weight: 10,
    detail: '[OK] Valid HTTPS'
  }));
  // Base 50 + 10 - 15 = 45. Medium risk indicator present.
  const resSuspicious = VerdictEngine.evaluate(regSuspicious);
  assert.strictEqual(resSuspicious.verdict, 'SUSPICIOUS');
  assert.strictEqual(resSuspicious.score, 45);
  console.log('  ✓ Suspicious indicators yield SUSPICIOUS (score 45)');

  // 8. Explainer Integration
  const explanation = Explainer.explain(regSuspicious, resSuspicious.verdict, resSuspicious.score);
  assert.ok(explanation.summary, 'Explainer must provide summary');
  assert.ok(Array.isArray(explanation.topReasons), 'Explainer must provide topReasons');
  assert.strictEqual(explanation.verdict, 'SUSPICIOUS');
  assert.strictEqual(explanation.score, 45);
  console.log('  ✓ Explainer generates structured reasoning');

  console.log('All verdict-engine.test.js tests passed!');
}

if (require.main === module) {
  run().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
  });
}

module.exports = run;
