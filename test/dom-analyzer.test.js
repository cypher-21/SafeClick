/**
 * Unit Tests for DOMAnalyzer (content/dom-analyzer.js)
 */
const assert = require('assert');
const DOMAnalyzer = require('../content/dom-analyzer.js');

// Simple DOM element mock for testing
class MockElement {
  constructor(tag, attrs = {}) {
    this.tagName = tag.toUpperCase();
    this.attrs = attrs;
    this.children = [];
    this.className = attrs.class || '';
    this.name = attrs.name || '';
    this.id = attrs.id || '';
    this.type = attrs.type || '';
  }

  getAttribute(name) {
    return this.attrs[name] || null;
  }

  querySelectorAll(selector) {
    const results = [];
    const check = (el) => {
      if (matchesSelector(el, selector)) results.push(el);
      el.children.forEach(check);
    };
    this.children.forEach(check);
    return results;
  }

  querySelector(selector) {
    const all = this.querySelectorAll(selector);
    return all.length > 0 ? all[0] : null;
  }

  getElementsByClassName(className) {
    const results = [];
    const check = (el) => {
      if (el.className.split(/\s+/).includes(className)) results.push(el);
      el.children.forEach(check);
    };
    this.children.forEach(check);
    return results;
  }

  getBoundingClientRect() {
    return { width: 300, height: 200, left: 10, top: 10 };
  }
}

function matchesSelector(el, selector) {
  if (selector === 'form') return el.tagName === 'FORM';
  if (selector === 'iframe') return el.tagName === 'IFRAME';
  if (selector === 'input[type="password"]') return el.tagName === 'INPUT' && el.type === 'password';
  if (selector === 'input[type="email"]') return el.tagName === 'INPUT' && el.type === 'email';
  if (selector.includes('rel*="icon"')) return el.tagName === 'LINK' && (el.attrs.rel || '').includes('icon');
  if (selector.includes('address') || selector.includes('url-bar')) {
    return (el.className || '').includes('address') || (el.className || '').includes('url-bar');
  }
  if (selector.includes('close') || selector.includes('window-close')) {
    return (el.className || '').includes('close');
  }
  return false;
}

class MockDocument extends MockElement {
  constructor() {
    super('document');
  }
}

async function run() {
  console.log('--- Running dom-analyzer.test.js ---');

  // 1. Cross-origin credential form test
  const doc1 = new MockDocument();
  const form1 = new MockElement('form', { action: 'https://attacker-harvester.com/collect', method: 'POST' });
  const passInput = new MockElement('input', { type: 'password', name: 'user_password' });
  form1.children.push(passInput);
  doc1.children.push(form1);

  const formResult = DOMAnalyzer.analyzeFormActions(doc1, 'https://legit-service.com/login');
  assert.strictEqual(formResult.hasSuspiciousForms, true);
  assert.strictEqual(formResult.risks[0].type, 'CROSS_ORIGIN_CREDENTIAL_FORM');
  console.log('  ✓ Cross-origin credential form action detected');

  // 2. Favicon brand spoofing test
  const doc2 = new MockDocument();
  const linkFavicon = new MockElement('link', { rel: 'shortcut icon', href: 'https://www.google.com/favicon.ico' });
  doc2.children.push(linkFavicon);

  const favResult = DOMAnalyzer.detectFaviconSpoofing(doc2, 'https://phishing-site-123.xyz/login');
  assert.strictEqual(favResult.isSpoofed, true);
  assert.strictEqual(favResult.brand, 'google');
  console.log('  ✓ Favicon brand spoofing on third-party domain detected');

  // 3. Browser-in-Browser spoofing test
  const doc3 = new MockDocument();
  const winFrame = new MockElement('div', { class: 'browser-window modal-browser fake-browser' });
  const addrBar = new MockElement('div', { class: 'address-bar url-bar' });
  const closeBtn = new MockElement('button', { class: 'window-close close' });
  const bibPass = new MockElement('input', { type: 'password' });
  winFrame.children.push(addrBar, closeBtn, bibPass);
  doc3.children.push(winFrame);

  const bibResult = DOMAnalyzer.detectBrowserInBrowser(doc3);
  assert.strictEqual(bibResult.hasBiBPatterns, true);
  assert.strictEqual(bibResult.risks[0].type, 'BROWSER_IN_BROWSER');
  console.log('  ✓ Browser-in-Browser fake window controls detected');

  // 4. toIndicatorSpecs conversion test
  const fullAnalysis = {
    hasSuspiciousForms: true,
    hasHiddenIframes: false,
    hasBrowserInBrowserPatterns: true,
    hasFaviconSpoof: true,
    hasCredentialFields: true
  };

  const specs = DOMAnalyzer.toIndicatorSpecs(fullAnalysis);
  assert.strictEqual(specs.length, 4);
  assert.ok(specs.some(s => s.id === 'dom.cross_origin_form'));
  assert.ok(specs.some(s => s.id === 'dom.browser_in_browser'));
  assert.ok(specs.some(s => s.id === 'dom.favicon_spoof'));
  assert.ok(specs.some(s => s.id === 'dom.password_form'));
  console.log('  ✓ toIndicatorSpecs converts findings to structured evidence units');

  console.log('All dom-analyzer.test.js tests passed!');
}

if (require.main === module) {
  run().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
  });
}

module.exports = run;
