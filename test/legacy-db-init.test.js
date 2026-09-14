/**
 * Unit Tests for PhishTankDB and ReputationDB initialization without bundled static files
 */
const assert = require('assert');
const PhishTankDB = require('../phishtank.js');
const ReputationDB = require('../reputation-db.js');
const ThreatCache = require('../data/threat-cache.js');

async function run() {
  console.log('--- Running legacy-db-init.test.js ---');

  // Mock chrome runtime and storage
  global.chrome = {
    runtime: {
      getURL: (path) => `chrome-extension://test/${path}`
    },
    storage: {
      local: {
        get: async () => ({}),
        set: async () => {},
        remove: async () => {}
      }
    }
  };

  const threatCache = new ThreatCache();
  await threatCache.init();
  await threatCache.ingest('live_feed', {
    exactUrls: ['https://phish.example.com/login'],
    hosts: ['bad-domain.com']
  });

  // 1. PhishTankDB init without bundled static file
  const phishDB = new PhishTankDB({ threatCache });
  await phishDB.init();
  assert.strictEqual(phishDB.loaded, true, 'PhishTankDB should load successfully even without static file');
  assert.strictEqual(phishDB.isListedExactUrl('https://phish.example.com/login'), true, 'Should query threatCache');
  assert.strictEqual(phishDB.isListedExactUrl('https://safe.example.com/'), false);
  console.log('  ✓ PhishTankDB initializes cleanly without static bundle and queries dynamic cache');

  // 2. ReputationDB init without bundled static file
  const repDB = new ReputationDB();
  repDB.threatCache = threatCache;
  await repDB.init();
  assert.strictEqual(repDB.loaded, true, 'ReputationDB should load successfully even without static files');
  assert.strictEqual(repDB.isListedExact('bad-domain.com'), true, 'Should find bad-domain via threatCache');
  assert.strictEqual(repDB.isListedExact('clean-domain.com'), false);
  console.log('  ✓ ReputationDB initializes cleanly without static bundles and queries dynamic cache');

  console.log('All legacy-db-init.test.js tests passed!');
}

if (require.main === module) {
  run().catch(err => {
    console.error('Test failed:', err);
    process.exit(1);
  });
}

module.exports = run;
