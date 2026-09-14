/**
 * Unit Tests for BrandDetector (evidence/brand-detector.js)
 */
const assert = require('assert');
const { Indicator } = require('../evidence/indicator.js');
global.Indicator = Indicator;

const BrandDetector = require('../evidence/brand-detector.js');

async function run() {
  console.log('--- Running brand-detector.test.js ---');

  const detector = new BrandDetector();

  // 1. Verified Official Brand Domain
  const googleOfficial = detector.analyze('accounts.google.com');
  assert.ok(googleOfficial.some(i => i.id === 'brand.official' && i.polarity === 'positive'));
  assert.ok(!googleOfficial.some(i => i.polarity === 'negative'));

  const paypalOfficial = detector.analyze('www.paypal.com');
  assert.ok(paypalOfficial.some(i => i.id === 'brand.official' && i.polarity === 'positive'));
  console.log('  ✓ Official brand domains verified with positive indicator');

  // 2. Subdomain Brand Spoofing
  // Attacker puts paypal.com in subdomain of their own domain
  const subSpoof = detector.analyze('paypal.com.account-verify.xyz');
  assert.ok(subSpoof.some(i => i.id === 'brand.subdomain_spoof' && i.weight === -35));
  console.log('  ✓ Subdomain brand spoofing detected');

  // 3. Combosquatting (Brand + Security/Login Keywords)
  const combo1 = detector.analyze('paypal-security-update.com');
  assert.ok(combo1.some(i => i.id === 'brand.combosquat' && i.weight === -30));

  const combo2 = detector.analyze('apple-id-verify.net');
  assert.ok(combo2.some(i => i.id === 'brand.combosquat'));
  console.log('  ✓ Combosquatting attacks detected');

  // 4. Typosquatting / Visual Lookalike (Levenshtein & Substitutions)
  const typo1 = detector.analyze('paypa1.com'); // 1 substituted for l
  assert.ok(typo1.some(i => i.id === 'brand.typosquat'));

  const typo2 = detector.analyze('gooogle.com'); // double o insertion
  assert.ok(typo2.some(i => i.id === 'brand.typosquat'));
  console.log('  ✓ Typosquatting and substitution lookalikes detected');

  // 5. Unrelated Safe Site (Zero False Positives)
  const safeSite = detector.analyze('wikipedia.org');
  assert.strictEqual(safeSite.length, 0);

  const safeSite2 = detector.analyze('mycompanyblog.net');
  assert.strictEqual(safeSite2.length, 0);
  console.log('  ✓ Unrelated safe sites produce zero false-positive alerts');

  console.log('All brand-detector.test.js tests passed!');
}

if (require.main === module) {
  run().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
  });
}

module.exports = run;
