/**
 * Tests for SafeClickStorage (data/storage.js)
 */

const assert = require('assert');

// Mock chrome.storage
const localData = {};
const sessionData = {};

global.chrome = {
  storage: {
    local: {
      get: async (keys) => {
        const res = {};
        if (keys === null) return { ...localData };
        keys.forEach(k => { if (k in localData) res[k] = localData[k]; });
        return res;
      },
      set: async (items) => {
        Object.assign(localData, items);
      },
      remove: async (keys) => {
        keys.forEach(k => delete localData[k]);
      }
    },
    session: {
      get: async (keys) => {
        const res = {};
        keys.forEach(k => { if (k in sessionData) res[k] = sessionData[k]; });
        return res;
      },
      set: async (items) => {
        Object.assign(sessionData, items);
      },
      remove: async (keys) => {
        keys.forEach(k => delete sessionData[k]);
      }
    }
  }
};

const SafeClickStorage = require('../data/storage.js');

async function runStorageTests() {
  console.log('[Test] Running Storage Tests...');

  // 1. Settings
  const defaultSettings = await SafeClickStorage.getSettings();
  assert.strictEqual(defaultSettings.protectionEnabled, true, 'Default protectionEnabled should be true');

  const updatedSettings = await SafeClickStorage.updateSettings({ protectionEnabled: false });
  assert.strictEqual(updatedSettings.protectionEnabled, false, 'Updated protectionEnabled should be false');
  const readBackSettings = await SafeClickStorage.getSettings();
  assert.strictEqual(readBackSettings.protectionEnabled, false, 'Persisted protectionEnabled should be false');

  // 2. Allowlist
  await SafeClickStorage.addAllowedDomain('example.com');
  let allowed = await SafeClickStorage.getAllowedDomains();
  assert(allowed.includes('example.com'), 'example.com should be in allowed domains');
  assert.strictEqual(await SafeClickStorage.isDomainAllowed('example.com'), true, 'example.com is allowed');
  assert.strictEqual(await SafeClickStorage.isDomainAllowed('sub.example.com'), true, 'sub.example.com is allowed by apex');
  assert.strictEqual(await SafeClickStorage.isDomainAllowed('other.org'), false, 'other.org should not be allowed');

  await SafeClickStorage.removeAllowedDomain('example.com');
  allowed = await SafeClickStorage.getAllowedDomains();
  assert(!allowed.includes('example.com'), 'example.com should be removed');

  // 3. Blocked Sites
  await SafeClickStorage.addBlockedSite('phishing-site.xyz');
  let blocked = await SafeClickStorage.getBlockedSites();
  assert(blocked.includes('phishing-site.xyz'), 'phishing-site.xyz should be in blocked list');
  assert.strictEqual(await SafeClickStorage.isUrlBlocked('https://phishing-site.xyz/login'), true, 'URL with blocked host is blocked');
  assert.strictEqual(await SafeClickStorage.isUrlBlocked('https://legit.com'), false, 'Legit site is not blocked');

  await SafeClickStorage.removeBlockedSite('phishing-site.xyz');
  assert.strictEqual(await SafeClickStorage.isUrlBlocked('https://phishing-site.xyz/login'), false, 'Unblocked site is no longer blocked');

  // 4. Trusted Pairs
  await SafeClickStorage.addTrustedPair('source.com', 'destination.com');
  assert.strictEqual(await SafeClickStorage.isTrustedPair('source.com', 'destination.com'), true, 'Trusted pair source->dest exists');
  assert.strictEqual(await SafeClickStorage.isTrustedPair('source.com', 'unknown.com'), false, 'Non-trusted pair does not exist');

  // 5. Session State
  await SafeClickStorage.saveSessionState(101, ['allowed-tab.com'], { url: 'dest.com' });
  const loadedSession = await SafeClickStorage.loadSessionState(101);
  assert(loadedSession.allowlist.includes('allowed-tab.com'), 'Session allowlist should be preserved');
  assert.strictEqual(loadedSession.pending.url, 'dest.com', 'Session pending destination should be preserved');

  await SafeClickStorage.removeSessionState(101);
  const clearedSession = await SafeClickStorage.loadSessionState(101);
  assert.strictEqual(clearedSession.allowlist.length, 0, 'Session allowlist should be cleared');

  console.log('  ✓ All Storage tests passed!');
}

module.exports = runStorageTests;
if (require.main === module) {
  runStorageTests().catch(err => {
    console.error('Storage test failure:', err);
    process.exit(1);
  });
}
