/**
 * Service Worker Context Simulator
 * 
 * Simulates Chrome's WorkerGlobalScope execution of importScripts
 * to guarantee that background.js loads in Chrome without any SyntaxErrors,
 * global declaration collisions, or runtime initialization errors.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..');

function testServiceWorkerContext() {
  console.log('--- Testing Chrome WorkerGlobalScope importScripts execution ---');

  // Create a simulated WorkerGlobalScope context
  const sandbox = {
    console: console,
    Date: Date,
    Math: Math,
    Set: Set,
    Map: Map,
    Uint8Array: Uint8Array,
    Array: Array,
    Object: Object,
    String: String,
    Number: Number,
    Boolean: Boolean,
    RegExp: RegExp,
    Promise: Promise,
    JSON: JSON,
    URL: URL,
    encodeURIComponent: encodeURIComponent,
    decodeURIComponent: decodeURIComponent,
    setTimeout: setTimeout,
    clearTimeout: clearTimeout,
    setInterval: setInterval,
    clearInterval: clearInterval,
    chrome: {
      runtime: {
        id: 'mock-ext-id',
        getManifest: () => ({ version: '2.0.0' }),
        onMessage: { addListener: () => {} },
        onInstalled: { addListener: () => {} }
      },
      storage: {
        local: {
          get: (keys, cb) => cb ? cb({}) : Promise.resolve({}),
          set: (obj, cb) => cb ? cb() : Promise.resolve({})
        },
        session: {
          get: (keys, cb) => cb ? cb({}) : Promise.resolve({}),
          set: (obj, cb) => cb ? cb() : Promise.resolve({})
        }
      },
      tabs: {
        onUpdated: { addListener: () => {} },
        onActivated: { addListener: () => {} },
        onRemoved: { addListener: () => {} }
      },
      webRequest: {
        onBeforeRedirect: { addListener: () => {} }
      },
      webNavigation: {
        onBeforeNavigate: { addListener: () => {} },
        onCreatedNavigationTarget: { addListener: () => {} }
      },
      alarms: {
        create: () => {},
        clear: () => Promise.resolve(true),
        onAlarm: { addListener: () => {} }
      },
      action: {
        setIcon: () => {},
        setBadgeText: () => {},
        setBadgeBackgroundColor: () => {}
      }
    }
  };

  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;

  const context = vm.createContext(sandbox);

  // Files imported in background.js in exact sequence:
  const scriptFiles = [
    'config.js',
    'modules/url-utils.js',
    'modules/bloom-filter.js',
    'data/storage.js',
    'data/threat-cache.js',
    'data/feed-manager.js',
    'evidence/indicator.js',
    'evidence/threat-intel-provider.js',
    'evidence/url-analyzer.js',
    'evidence/brand-detector.js',
    'ml/feature-extractor.js',
    'ml/classifier.js',
    'scoring/explainer.js',
    'scoring/verdict-engine.js',
    'ai/ai-provider.js',
    'ai/chrome-ai-provider.js',
    'ai/byok-gemini-provider.js',
    'ai/ai-advisor.js',
    'reputation-db.js',
    'phishtank.js',
    'trust-scorer.js',
    'core/tab-manager.js',
    'core/redirect-tracker.js',
    'core/interstitial-controller.js',
    'core/orchestrator.js'
  ];

  for (const relPath of scriptFiles) {
    const fullPath = path.join(ROOT, relPath);
    const code = fs.readFileSync(fullPath, 'utf8');
    try {
      vm.runInContext(code, context, { filename: relPath });
      console.log(`  ✓ Loaded ${relPath}`);
    } catch (err) {
      console.error(`  ❌ FAILED to load ${relPath} into WorkerGlobalScope:`);
      throw err;
    }
  }

  // Now execute the background.js initialization code inside the same context
  const backgroundCode = fs.readFileSync(path.join(ROOT, 'background.js'), 'utf8');
  // Strip importScripts calls since we already ran them in sequence
  const initCode = backgroundCode.replace(/importScripts\([^)]+\);?/g, '');
  try {
    vm.runInContext(initCode, context, { filename: 'background.js (init)' });
    console.log('  ✓ background.js initialization executed cleanly in simulated WorkerGlobalScope');
  } catch (err) {
    console.error('  ❌ FAILED background.js initialization:');
    throw err;
  }

  console.log('🎉 Service worker scope simulation passed with 0 errors!');
}

if (require.main === module) {
  testServiceWorkerContext();
}

module.exports = testServiceWorkerContext;
