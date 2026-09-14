/**
 * Unit Tests for URLAnalyzer (evidence/url-analyzer.js)
 */
const assert = require('assert');
const { Indicator } = require('../evidence/indicator.js');
global.Indicator = Indicator;

const URLAnalyzer = require('../evidence/url-analyzer.js');

async function run() {
  console.log('--- Running url-analyzer.test.js ---');

  const analyzer = new URLAnalyzer();

  // 1. Clean HTTPS URL
  const cleanIndicators = analyzer.analyze('https://example.com/products/view?id=123');
  assert.ok(cleanIndicators.some(i => i.id === 'url.https'));
  assert.ok(cleanIndicators.some(i => i.id === 'url.clean_structure'));
  assert.ok(!cleanIndicators.some(i => i.polarity === 'negative'));
  console.log('  ✓ Clean HTTPS URL produces positive structure indicators');

  // 2. Unencrypted HTTP
  const httpIndicators = analyzer.analyze('http://example.com/test');
  assert.ok(httpIndicators.some(i => i.id === 'url.no_https' && i.weight === -25));
  console.log('  ✓ Plain HTTP detected with negative security weight');

  // 3. Raw IP Hostname
  const ipIndicators = analyzer.analyze('http://192.168.1.100/admin');
  assert.ok(ipIndicators.some(i => i.id === 'url.ip_host' && i.weight === -30));
  console.log('  ✓ Raw IP address in hostname detected');

  // 4. Non-standard Port
  const portIndicators = analyzer.analyze('https://example.com:8443/login');
  assert.ok(portIndicators.some(i => i.id === 'url.non_standard_port' && i.value === '8443'));
  console.log('  ✓ Non-standard port flagged');

  // 5. Embedded Credentials
  const credIndicators = analyzer.analyze('https://admin:secretpassword@evil.com/login');
  assert.ok(credIndicators.some(i => i.id === 'url.embedded_credentials'));
  console.log('  ✓ Embedded credentials in URL flagged');

  // 6. Punycode & Confusable Homoglyphs
  const punyIndicators = analyzer.analyze('https://xn--pple-43d.com/');
  assert.ok(punyIndicators.some(i => i.id === 'url.punycode'));

  const homoglyphRes = analyzer.detectHomoglyphs('gооgle.com'); // Cyrillic о
  assert.strictEqual(homoglyphRes.isHomoglyph, true);
  assert.strictEqual(homoglyphRes.hasConfusables, true);
  console.log('  ✓ Punycode and Cyrillic/homoglyph spoofing detected');

  // 7. Suspicious High-Abuse TLD
  const tldIndicators = analyzer.analyze('https://suspicious-download.top/file.zip');
  assert.ok(tldIndicators.some(i => i.id === 'url.suspicious_tld' && i.value === '.top'));
  console.log('  ✓ High-abuse TLDs flagged (.top)');

  // 8. Deep Subdomain Nesting & Shannon Entropy
  const deepIndicators = analyzer.analyze('https://a.b.c.d.e.f.example.com/test');
  assert.ok(deepIndicators.some(i => i.id === 'url.high_subdomain_depth'));

  const entropyVal = analyzer.calculateEntropy('x89q2jkz7104bcv9');
  assert.ok(entropyVal >= 3.5, `Entropy should be high, was ${entropyVal}`);
  // 9. Search Portal Query Strings (should NOT be penalized for length)
  const longGoogleUrl = 'https://www.google.com/search?q=codm&sca_esv=2e45838e39a05840&sxsrf=APpeQnvFpLzaYYjtvbMVYi6ls0gjYQbGbA%3A1789369267928&ei=s5unav6eOKenhvcPjqeqwAo&ved=2ahUJ...';
  const googleIndicators = analyzer.analyze(longGoogleUrl);
  assert.strictEqual(googleIndicators.some(i => i.id === 'url.excessive_length'), false, 'Search engine queries must not be penalized for length');
  assert.strictEqual(googleIndicators.some(i => i.id === 'url.clean_structure'), true, 'Search engine queries should be recognized as clean structure');
  console.log('  ✓ Search engine query strings immune to false-positive length penalty');

  console.log('All url-analyzer.test.js tests passed!');
}

if (require.main === module) {
  run().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
  });
}

module.exports = run;
