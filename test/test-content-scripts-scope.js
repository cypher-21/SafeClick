/**
 * Content Scripts Scope Simulator
 * 
 * Simulates Chrome content script injection sequence to ensure
 * there are no scope collisions, syntax errors, or unhandled exceptions
 * when content scripts execute in webpage contexts.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..');

function testContentScriptsContext() {
  console.log('--- Testing Chrome Content Scripts injection sequence ---');

  const sandbox = {
    console: console,
    Date: Date,
    Math: Math,
    Set: Set,
    Map: Map,
    Array: Array,
    Object: Object,
    String: String,
    Number: Number,
    Boolean: Boolean,
    RegExp: RegExp,
    Promise: Promise,
    JSON: JSON,
    URL: URL,
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    setInterval: setInterval,
    clearInterval: clearInterval,
    window: {
      location: { href: 'https://example.com/login', hostname: 'example.com', pathname: '/login' },
      addEventListener: () => {}
    },
    document: {
      readyState: 'complete',
      location: { href: 'https://example.com/login', hostname: 'example.com' },
      body: {
        appendChild: () => {},
        classList: { add: () => {}, remove: () => {} }
      },
      head: { appendChild: () => {} },
      createElement: (tag) => ({
        tagName: tag.toUpperCase(),
        style: {},
        classList: { add: () => {}, remove: () => {} },
        setAttribute: () => {},
        getAttribute: () => null,
        appendChild: () => {},
        addEventListener: () => {},
        querySelectorAll: () => [],
        querySelector: () => null
      }),
      querySelectorAll: () => [],
      querySelector: () => null,
      getElementById: () => null,
      addEventListener: () => {}
    },
    chrome: {
      runtime: {
        id: 'mock-ext-id',
        sendMessage: (msg, cb) => cb ? cb({ score: 85, verdict: 'SAFE', details: {} }) : Promise.resolve({ score: 85, verdict: 'SAFE', details: {} }),
        onMessage: { addListener: () => {} }
      },
      storage: {
        local: {
          get: (keys, cb) => cb ? cb({ settings: {} }) : Promise.resolve({ settings: {} })
        }
      }
    }
  };

  sandbox.self = sandbox.window;
  sandbox.globalThis = sandbox.window;

  const context = vm.createContext(sandbox);

  const contentScripts = [
    'content/dom-analyzer.js',
    'content/modal-ui.js',
    'content/credential-monitor.js',
    'content/content-main.js',
    'content/serp-enhancer.js'
  ];

  for (const relPath of contentScripts) {
    const fullPath = path.join(ROOT, relPath);
    const code = fs.readFileSync(fullPath, 'utf8');
    try {
      vm.runInContext(code, context, { filename: relPath });
      console.log(`  ✓ Injected ${relPath}`);
    } catch (err) {
      console.error(`  ❌ FAILED to inject ${relPath}:`);
      throw err;
    }
  }

  console.log('🎉 Content scripts injection sequence simulation passed with 0 errors!');
}

if (require.main === module) {
  testContentScriptsContext();
}

module.exports = testContentScriptsContext;
