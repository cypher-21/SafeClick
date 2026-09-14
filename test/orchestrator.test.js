/**
 * Tests for Orchestrator (core/orchestrator.js)
 */

const assert = require('assert');

// Mock browser APIs
let messageListener = null;

global.chrome = {
  runtime: {
    getManifest: () => ({ version: '2.0.0' }),
    onMessage: {
      addListener: (fn) => { messageListener = fn; }
    },
    onInstalled: { addListener: () => {} }
  },
  tabs: {
    onUpdated: { addListener: () => {} },
    onActivated: { addListener: () => {} },
    onRemoved: { addListener: () => {} },
    sendMessage: async () => {},
    get: async (id) => ({ id, url: 'https://test-site.org' })
  },
  action: {
    setBadgeText: () => {},
    setBadgeBackgroundColor: () => {}
  },
  storage: {
    local: {
      get: async () => ({}),
      set: async () => {}
    }
  }
};

global.SafeClickStorage = require('../data/storage.js');
global.UrlUtils = require('../modules/url-utils.js');
global.TabManager = require('../core/tab-manager.js');
global.RedirectTracker = require('../core/redirect-tracker.js');
global.InterstitialController = require('../core/interstitial-controller.js');

const Orchestrator = require('../core/orchestrator.js');

async function runOrchestratorTests() {
  console.log('[Test] Running Orchestrator Tests...');

  // Mock scoring engine
  const mockScorer = {
    calculateTrustScore: async (url) => ({
      score: 85,
      verdict: 'SAFE',
      reasons: ['[OK] Test score passed'],
      details: { domain: new URL(url).hostname }
    }),
    analysisStats: { count: 1 }
  };

  Orchestrator.init({
    scorer: mockScorer,
    rep: { loaded: true, isListedExact: () => false },
    phish: { loaded: true, isListedExactUrl: () => false },
    feeds: { getStats: () => ({}) }
  });

  assert(messageListener !== null, 'Message listener should be registered');

  // Test GET_SETTINGS via message
  const dispatch = (msg) => new Promise(resolve => messageListener(msg, {}, resolve));

  const settingsRes = await dispatch({ type: 'GET_SETTINGS' });
  assert(settingsRes && settingsRes.settings, 'Should return settings object');
  assert.strictEqual(settingsRes.settings.protectionEnabled, true, 'protectionEnabled should be true');

  // Test GET_DIAGNOSTICS
  const diagRes = await dispatch({ type: 'GET_DIAGNOSTICS' });
  assert(diagRes && diagRes.success, 'Diagnostics request should succeed');
  assert.strictEqual(diagRes.diagnostics.version, '2.0.0', 'Version should match manifest mock');

  // Test standalone URL analysis
  const standalone = await Orchestrator.analyzeUrlStandalone('https://test-example.com/page');
  assert.strictEqual(standalone.score, 85, 'Standalone analysis score should be 85');
  assert.strictEqual(standalone.verdict, 'SAFE', 'Standalone analysis verdict should be SAFE');

  console.log('  ✓ All Orchestrator tests passed!');
}

module.exports = runOrchestratorTests;
if (require.main === module) {
  runOrchestratorTests().catch(err => {
    console.error('Orchestrator test failure:', err);
    process.exit(1);
  });
}
