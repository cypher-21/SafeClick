/**
 * SafeClick 2.0 - Search Engine Results Page (SERP) Enhancer Tests
 * 
 * Tests instantaneous heuristic evaluation and safety badge creation for SERPs:
 * - Google, Bing, DuckDuckGo SERP page detection
 * - Fast local heuristic classification (<0.1ms)
 * - Badge structure, colors, tooltips, and security labels
 */

const assert = require('assert');
const SERPEnhancer = require('../content/serp-enhancer.js');

async function run() {
  console.log('--- Running serp-enhancer.test.js ---');

  const enhancer = new SERPEnhancer();

  // 1. SERP URL detection
  assert.strictEqual(enhancer.isSERPPage('https://www.google.com/search?q=paypal+login'), true);
  assert.strictEqual(enhancer.isSERPPage('https://www.google.co.uk/search?q=safeclick'), true);
  assert.strictEqual(enhancer.isSERPPage('https://www.google.co.in/search?q=cybersecurity'), true);
  assert.strictEqual(enhancer.isSERPPage('https://www.bing.com/search?q=antivirus'), true);
  assert.strictEqual(enhancer.isSERPPage('https://duckduckgo.com/?q=privacy'), true);
  assert.strictEqual(enhancer.isSERPPage('https://example.com/search?q=test'), false);
  assert.strictEqual(enhancer.isSERPPage('https://www.google.com/'), false);
  console.log('  ✓ SERP page detection accurately identifies Google, Bing, DuckDuckGo search pages');

  // 2. HTTP Insecure Link
  const httpRes = enhancer.analyzeLink('http://my-insecure-site.com/login');
  assert.strictEqual(httpRes.verdict, 'SUSPICIOUS');
  assert.strictEqual(httpRes.score, 40);
  assert.ok(httpRes.reason.includes('HTTP'));
  console.log('  ✓ Unencrypted plain HTTP link flagged as SUSPICIOUS');

  // 3. Raw IP Address Host
  const ipRes = enhancer.analyzeLink('http://192.168.1.55/update.exe');
  assert.strictEqual(ipRes.verdict, 'DANGEROUS');
  assert.strictEqual(ipRes.score, 15);
  assert.ok(ipRes.reason.includes('IP address'));
  console.log('  ✓ Raw IP address destination flagged as DANGEROUS');

  // 4. Punycode IDN Homoglyph
  const punyRes = enhancer.analyzeLink('https://xn--pypal-4ve.com/account');
  assert.strictEqual(punyRes.verdict, 'DANGEROUS');
  assert.strictEqual(punyRes.score, 20);
  assert.ok(punyRes.reason.includes('Punycode'));
  console.log('  ✓ Punycode / IDN lookalike destination flagged as DANGEROUS');

  // 5. Embedded Credentials
  const credRes = enhancer.analyzeLink('https://admin:secret@malicious-portal.com');
  assert.strictEqual(credRes.verdict, 'DANGEROUS');
  assert.strictEqual(credRes.score, 10);
  console.log('  ✓ Embedded credentials in search result flagged as DANGEROUS');

  // 6. High-Risk TLD
  const tldRes = enhancer.analyzeLink('https://fast-prizes.top/claim');
  assert.strictEqual(tldRes.verdict, 'SUSPICIOUS');
  assert.strictEqual(tldRes.score, 45);
  assert.ok(tldRes.reason.includes('.top'));
  console.log('  ✓ High-risk top-level domain (.top) flagged as SUSPICIOUS');

  // 7. Combosquatting Brand Impersonation
  const comboRes = enhancer.analyzeLink('https://paypal-security-check.com/signin');
  assert.strictEqual(comboRes.verdict, 'DANGEROUS');
  assert.strictEqual(comboRes.score, 25);
  assert.ok(comboRes.reason.includes('impersonation of paypal'));
  console.log('  ✓ Brand combosquatting (paypal-security-check) flagged as DANGEROUS');

  // 8. Typosquatting Character Substitution
  const typoRes = enhancer.analyzeLink('https://paypa1.com/cgi-bin');
  assert.strictEqual(typoRes.verdict, 'DANGEROUS');
  assert.strictEqual(typoRes.score, 25);
  assert.ok(typoRes.reason.includes('Typosquatting'));
  console.log('  ✓ Typosquatting character substitution (paypa1) flagged as DANGEROUS');

  // 9. Objective Evidence-Based Verification: Clean HTTPS destination with clean FQDN earns high security score
  const safeRes = enhancer.analyzeLink('https://github.com/cypher-21/SafeClick');
  assert.strictEqual(safeRes.verdict, 'SAFE');
  assert.ok(safeRes.score >= 90, 'Clean verified HTTPS site should score >= 90');
  console.log(`  ✓ Verified established domain (github.com) earns SAFE through analysis (${safeRes.score}/100)`);

  // 9b. Dynamic Analysis: Secure government domain (cisa.gov) with clean HTTPS & FQDN earns SAFE (100/100)
  const govRes = enhancer.analyzeLink('https://www.cisa.gov/resources-tools');
  assert.strictEqual(govRes.verdict, 'SAFE');
  assert.strictEqual(govRes.score, 100);
  assert.ok(govRes.reason.includes('HTTPS transport encryption'));
  console.log(`  ✓ Secure government site (cisa.gov) dynamically analyzed and earns SAFE (${govRes.score}/100)`);

  // 9c. Dynamic Analysis: Compromised payload download (.exe) on .gov domain flagged as DANGEROUS
  const govPayloadRes = enhancer.analyzeLink('https://portal.city.gov/updates/driver.exe');
  assert.strictEqual(govPayloadRes.verdict, 'DANGEROUS');
  assert.strictEqual(govPayloadRes.score, 15);
  assert.ok(govPayloadRes.reason.includes('executable'));
  console.log('  ✓ Compromised payload download (.exe) on .gov flagged as DANGEROUS (15/100)');

  // 9d. Dynamic Analysis: Insecure plain HTTP government site flagged as SUSPICIOUS
  const govInsecureRes = enhancer.analyzeLink('http://portal.gov.in/download');
  assert.strictEqual(govInsecureRes.verdict, 'SUSPICIOUS');
  assert.strictEqual(govInsecureRes.score, 40);
  assert.ok(govInsecureRes.reason.includes('HTTP'));
  console.log('  ✓ Unencrypted plain HTTP on government domain flagged as SUSPICIOUS (40/100)');

  // 9e. Dynamic Analysis: Google ecosystem domains analyzed dynamically through evidence
  const deepmindRes = enhancer.analyzeLink('https://deepmind.google/models');
  assert.strictEqual(deepmindRes.verdict, 'SAFE');
  assert.strictEqual(deepmindRes.score, 100);
  const geminiRes = enhancer.analyzeLink('https://gemini.google/latest-news');
  assert.strictEqual(geminiRes.verdict, 'SAFE');
  assert.strictEqual(geminiRes.score, 100);
  const devRes = enhancer.analyzeLink('https://ai.google.dev/gemini-api');
  assert.strictEqual(devRes.verdict, 'SAFE');
  assert.strictEqual(devRes.score, 100);
  console.log('  ✓ Ecosystem domains dynamically analyzed and earn SAFE through evidence (100/100)');

  // 11. Performance benchmark (<0.1 ms latency per link)
  const urls = [
    'https://google.com',
    'https://paypal.com-security.co',
    'http://insecure.net',
    'https://192.168.1.1',
    'https://amazon.com',
    'https://amaz0n.biz'
  ];
  const start = Date.now();
  for (let i = 0; i < 5000; i++) {
    enhancer.analyzeLink(urls[i % urls.length]);
  }
  const duration = Date.now() - start;
  const avgPerLink = duration / 5000;
  assert.ok(avgPerLink < 0.1, `Average analysis latency must be <0.1ms (actual: ${avgPerLink.toFixed(4)}ms)`);
  console.log(`  ✓ Instantaneous classification: ${avgPerLink.toFixed(4)} ms / link (<0.1ms budget met)`);
}

module.exports = run;
if (require.main === module) {
  run().catch(err => {
    console.error(err);
    process.exit(1);
  });
}
