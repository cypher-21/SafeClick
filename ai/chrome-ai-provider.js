/**
 * SafeClick 2.0 - Chrome Built-in AI Provider (Gemini Nano)
 * Open Source Browser Security Engine
 * 
 * Interfaces with Chrome's on-device Prompt API (self.ai.languageModel).
 * Zero cost, 100% private, on-device local execution.
 */

(function () {
  'use strict';

  // Handle environments
  const _AIProvider = (typeof AIProvider !== 'undefined') ? AIProvider : (function () {
    try { return require('./ai-provider.js').AIProvider; } catch (_) { return null; }
  })();

  class ChromeAIProvider extends (_AIProvider || class {}) {
  constructor(options = {}) {
    super({
      id: 'chrome-builtin-ai',
      name: 'Chrome Built-in AI (Gemini Nano)',
      isLocal: true,
      enabled: true,
      ...options
    });
  }

  /**
   * Check if Chrome Prompt API / Gemini Nano is supported and ready
   */
  async checkAvailability() {
    try {
      const aiObj = (typeof self !== 'undefined' && self.ai) || (typeof window !== 'undefined' && window.ai);
      if (!aiObj || !aiObj.languageModel) {
        return {
          available: false,
          status: 'no',
          reason: 'Chrome Prompt API (self.ai.languageModel) not supported in this browser version'
        };
      }

      // Check model availability/capabilities (Chrome Prompt API spec)
      let status = 'no';
      if (typeof aiObj.languageModel.capabilities === 'function') {
        const caps = await aiObj.languageModel.capabilities();
        status = caps.available || 'no';
      } else if (typeof aiObj.languageModel.availability === 'function') {
        status = await aiObj.languageModel.availability();
      } else {
        status = 'readily';
      }

      return {
        available: status === 'readily' || status === 'after-download',
        status: status,
        reason: status === 'readily' ? 'Gemini Nano ready on-device' : 'Model download required'
      };
    } catch (err) {
      return {
        available: false,
        status: 'error',
        reason: err.message
      };
    }
  }

  /**
   * Send prompt to Gemini Nano on-device session
   * @param {Object} context - { systemPrompt, userPrompt }
   */
  async analyze(context) {
    const aiObj = (typeof self !== 'undefined' && self.ai) || (typeof window !== 'undefined' && window.ai);
    if (!aiObj || !aiObj.languageModel) {
      throw new Error('Chrome Built-in AI not available');
    }

    let session = null;
    try {
      session = await aiObj.languageModel.create({
        systemPrompt: context.systemPrompt
      });

      const responseText = await session.prompt(context.userPrompt);

      // Clean up markdown fences if model returned ```json ... ```
      const cleaned = responseText
        .replace(/```json\s*/i, '')
        .replace(/```\s*$/, '')
        .trim();

      const parsed = JSON.parse(cleaned);
      return {
        summary: parsed.summary || 'Indicators analyzed.',
        confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.85,
        recommendation: parsed.recommendation || 'Verify website identity before entering data.',
        riskLevel: parsed.riskLevel || 'MEDIUM',
        rawResponse: responseText
      };
    } finally {
      if (session && typeof session.destroy === 'function') {
        session.destroy();
      }
    }
  }

  /**
   * General text generation with on-device Gemini Nano
   * @param {Object} options
   * @param {string} options.prompt
   * @param {string} [options.systemInstruction]
   * @returns {Promise<string>}
   */
  async generateText({ prompt, systemInstruction = '' }) {
    const aiObj = (typeof self !== 'undefined' && self.ai) || (typeof window !== 'undefined' && window.ai);
    if (!aiObj || !aiObj.languageModel) {
      throw new Error('Chrome Built-in AI not available');
    }

    let session = null;
    try {
      const opts = {};
      if (systemInstruction) opts.systemPrompt = systemInstruction;
      session = await aiObj.languageModel.create(opts);
      return await session.prompt(prompt);
    } finally {
      if (session && typeof session.destroy === 'function') {
        session.destroy();
      }
    }
  }
}

  // Environment exports
  if (typeof self !== 'undefined') {
    self.ChromeAIProvider = ChromeAIProvider;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = ChromeAIProvider;
  }
})();
