/**
 * SafeClick 2.0 - Background Service Worker
 * Open Source Browser Security Engine
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Core configuration and utilities
importScripts('config.js');
importScripts('modules/url-utils.js');
importScripts('modules/bloom-filter.js');

// Unified storage & threat feeds
importScripts('data/storage.js');
importScripts('data/threat-cache.js');
importScripts('data/feed-manager.js');

// Evidence & Scoring Engine
importScripts('evidence/indicator.js');
importScripts('evidence/threat-intel-provider.js');
importScripts('evidence/url-analyzer.js');
importScripts('evidence/brand-detector.js');
importScripts('ml/feature-extractor.js');
importScripts('ml/classifier.js');
importScripts('scoring/explainer.js');
importScripts('scoring/verdict-engine.js');

// AI Second Opinion Advisory Engine (Prompt injection immune, structured indicators only)
importScripts('ai/ai-provider.js');
importScripts('ai/chrome-ai-provider.js');
importScripts('ai/byok-gemini-provider.js');
importScripts('ai/ai-advisor.js');

// Security datasets and scoring engines
importScripts('reputation-db.js');
importScripts('phishtank.js');
importScripts('trust-scorer.js');

// Modular architecture components
importScripts('core/tab-manager.js');
importScripts('core/redirect-tracker.js');
importScripts('core/interstitial-controller.js');
importScripts('core/orchestrator.js');

// Suppress unhandled rejection noise from disconnected tabs/frames
try {
  self.addEventListener('unhandledrejection', (event) => {
    try {
      console.warn('[Background] Suppressed unhandledrejection:', event.reason?.message || event.reason);
    } catch (_) {}
    event.preventDefault();
  });
} catch (_) {}

// Initialize dynamic threat cache (Bloom filter fast-path + IndexedDB store)
const threatCache = new ThreatCache({ maxEntries: 30000 });

// Initialize security databases (zero static blacklists; dynamic cache backing)
const phishDB = new PhishTankDB({ threatCache });
const repDB = new ReputationDB();
repDB.threatCache = threatCache;

// Initialize threat intelligence providers registry
const threatIntelRegistry = new ThreatIntelRegistry();
threatIntelRegistry.register(new URLhausProvider());
threatIntelRegistry.register(new OpenPhishProvider());

// Initialize threat feed manager (zero maintainer cost, open feeds)
const feedManager = new FeedManager(repDB, {
  updateIntervalMinutes: 60,
  timeoutMs: 30000,
  maxEntriesPerFeed: 10000
}, threatCache);

// Initialize trust scoring engine
const trustScorer = new TrustScorer({ phishDB, repDB });

// Initialize AI Advisory subsystem (Advisory on SUSPICIOUS verdicts only)
const aiRegistry = new AIRegistry();
const chromeAI = new ChromeAIProvider();
const geminiAI = new BYOKGeminiProvider();
aiRegistry.register(chromeAI);
aiRegistry.register(geminiAI);
const aiAdvisor = new AIAdvisor(aiRegistry);

// Initialize modular listeners and orchestrator
RedirectTracker.initListeners();
InterstitialController.initNavigationListeners(() => Orchestrator.getSettings(), repDB, phishDB);
Orchestrator.init({
  scorer: trustScorer,
  rep: repDB,
  phish: phishDB,
  feeds: feedManager,
  threatCache: threatCache,
  threatIntel: threatIntelRegistry,
  aiAdvisor: aiAdvisor,
  aiRegistry: aiRegistry,
  geminiAI: geminiAI
});

// Non-blocking database initialization
Promise.allSettled([
  threatCache.init().catch(err => {
    console.warn('[SafeClick] ThreatCache init fallback:', err);
    threatCache.loaded = true;
  }),
  phishDB.init().catch(err => {
    console.warn('[SafeClick] PhishTank init fallback:', err);
    phishDB.loaded = true;
  }),
  repDB.init().catch(err => {
    console.warn('[SafeClick] ReputationDB init fallback:', err);
    repDB.loaded = true;
  })
]).then(() => {
  feedManager.init().catch(err => {
    console.warn('[SafeClick] FeedManager init failed:', err);
  });
});