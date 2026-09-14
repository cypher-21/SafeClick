/**
 * SafeClick 2.0 - Master Test Runner
 * Open Source Browser Security Engine
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

async function runAll() {
  console.log('====================================================');
  console.log('SafeClick 2.0 - Running Phase 0 Verification Tests');
  console.log('====================================================\n');

  // 1. Syntax check all JS files
  console.log('[1/5] Checking JS syntax across entire codebase...');
  function checkDir(dir) {
    let count = 0;
    fs.readdirSync(dir).forEach(f => {
      const p = path.join(dir, f);
      if (fs.statSync(p).isDirectory()) {
        if (f !== 'node_modules' && f !== '.git') count += checkDir(p);
      } else if (f.endsWith('.js')) {
        execSync(`node --check "${p}"`);
        count++;
      }
    });
    return count;
  }
  const checked = checkDir(path.resolve(__dirname, '..'));
  console.log(`  ✓ Syntax check passed for all ${checked} JavaScript files!\n`);

  // 2. Storage tests
  console.log('[2/5] Running Storage Engine Tests...');
  const runStorageTests = require('./storage.test.js');
  await runStorageTests();
  console.log();

  // 3. Feed manager tests
  console.log('[3/5] Running Feed Manager Tests...');
  const runFeedTests = require('./feed-manager.test.js');
  await runFeedTests();
  console.log();

  // 4. Redirect tracker tests
  console.log('[4/5] Running Redirect Tracker Tests...');
  const runRedirectTests = require('./redirect-tracker.test.js');
  await runRedirectTests();
  console.log();

  // 5. Orchestrator tests
  console.log('[5/7] Running Orchestrator Tests...');
  const runOrchestratorTests = require('./orchestrator.test.js');
  await runOrchestratorTests();
  console.log();

  // 6. Indicators tests
  console.log('[6/7] Running Indicator & Evidence Registry Tests...');
  const runIndicatorTests = require('./indicators.test.js');
  await runIndicatorTests();
  console.log();

  // 7. Verdict engine tests
  console.log('[7/10] Running Four-State Verdict Engine Tests...');
  const runVerdictTests = require('./verdict-engine.test.js');
  await runVerdictTests();
  console.log();

  // 8. Threat Intel Provider tests
  console.log('[8/10] Running Threat Intel Provider Tests...');
  const runThreatIntelTests = require('./threat-intel.test.js');
  await runThreatIntelTests();
  console.log();

  // 9. Threat Cache tests
  console.log('[9/10] Running Threat Cache & Bloom Filter Tests...');
  const runThreatCacheTests = require('./threat-cache.test.js');
  await runThreatCacheTests();
  console.log();

  // 10. Legacy DB zero-static-file tests
  console.log('[10/13] Running DB Zero-Static-File Clean Init Tests...');
  const runLegacyDbTests = require('./legacy-db-init.test.js');
  await runLegacyDbTests();
  console.log();

  // 11. URL Analyzer tests
  console.log('[11/13] Running Local URL Analyzer Tests...');
  const runUrlAnalyzerTests = require('./url-analyzer.test.js');
  await runUrlAnalyzerTests();
  console.log();

  // 12. Brand Detector tests
  console.log('[12/13] Running Brand Impersonation & Typosquatting Tests...');
  const runBrandDetectorTests = require('./brand-detector.test.js');
  await runBrandDetectorTests();
  console.log();

  // 13. DOM Analyzer tests
  console.log('[13/14] Running DOM Security Analyzer Tests...');
  const runDomAnalyzerTests = require('./dom-analyzer.test.js');
  await runDomAnalyzerTests();
  console.log();

  // 14. ML Evaluation & Benchmark tests
  console.log('[14/15] Running Local Machine Learning Benchmark & Evaluation...');
  const runEvaluationTests = require('./evaluation/evaluation.test.js');
  await runEvaluationTests();
  console.log();

  // 15. AI Advisory & Prompt Injection Defense tests
  console.log('[15/16] Running AI Advisory & Prompt Injection Defense Tests...');
  const runAITests = require('./ai-advisor.test.js');
  await runAITests();
  console.log();

  // 16. SERP Enhancer tests
  console.log('[16/17] Running SERP Enhancer & Search Badge Tests...');
  const runSerpTests = require('./serp-enhancer.test.js');
  await runSerpTests();
  console.log();

  // 17. Memory Footprint Audit
  console.log('[17/19] Running Memory Footprint Audit (<25 MB target)...');
  const runMemoryAudit = require('./memory-audit.test.js');
  await runMemoryAudit();
  console.log();

  // 18. Service Worker WorkerGlobalScope simulation
  console.log('[18/19] Running Service Worker Scope Simulation (importScripts sequential load)...');
  const runServiceWorkerScope = require('./test-service-worker-scope.js');
  await runServiceWorkerScope();
  console.log();

  // 19. Content Scripts Scope simulation
  console.log('[19/19] Running Content Scripts Scope Simulation (DOM injection sequence)...');
  const runContentScriptsScope = require('./test-content-scripts-scope.js');
  await runContentScriptsScope();
  console.log();

  console.log('====================================================');
  console.log('🎉 ALL SAFECLICK 2.0 PHASES (0-9) VERIFIED & PASSED!');
  console.log('====================================================');
}

runAll().catch(err => {
  console.error('\n❌ TEST SUITE FAILED:', err);
  process.exit(1);
});
