/**
 * SafeClick 2.0 - AI Provider Abstraction
 * Open Source Browser Security Engine
 * 
 * Abstract interface for pluggable AI engines (Chrome Built-in AI, BYOK Gemini, etc.).
 * AI serves strictly as an advisory second opinion on ambiguous verdicts.
 */

(function () {
  'use strict';

  class AIProvider {
  /**
   * @param {Object} options
   * @param {string} options.id - Provider unique identifier
   * @param {string} options.name - Human-readable name
   * @param {boolean} [options.isLocal] - Whether inference runs on-device
   * @param {boolean} [options.enabled] - Whether provider is enabled
   */
  constructor({ id, name, isLocal = true, enabled = true }) {
    if (!id) throw new Error('AIProvider requires an id');
    this.id = id;
    this.name = name || id;
    this.isLocal = isLocal;
    this.enabled = enabled;
  }

  /**
   * Check if this AI provider is currently available on the device
   * @returns {Promise<{ available: boolean, status: string, reason?: string }>}
   */
  async checkAvailability() {
    return { available: false, status: 'unavailable', reason: 'Base class not implemented' };
  }

  /**
   * Send a sanitized security prompt to the model
   * @param {Object} context - Sanitized structured evidence context
   * @param {string} context.systemPrompt - System instruction defining the role
   * @param {string} context.userPrompt - Structured JSON security indicators
   * @returns {Promise<{ summary: string, confidence: number, recommendation: string, riskLevel: string }>}
   */
  async analyze(context) {
    throw new Error('AIProvider.analyze() must be implemented by concrete subclass');
  }

  getStats() {
    return {
      id: this.id,
      name: this.name,
      isLocal: this.isLocal,
      enabled: this.enabled
    };
  }
}

/**
 * AI Provider Registry
 * Coordinates available AI providers and selects the best active engine.
 */
class AIRegistry {
  constructor() {
    this.providers = new Map();
  }

  register(provider) {
    if (provider && provider.id) {
      this.providers.set(provider.id, provider);
    }
    return this;
  }

  get(id) {
    return this.providers.get(id) || null;
  }

  getProvider(id) {
    return this.get(id);
  }

  getAll() {
    return Array.from(this.providers.values());
  }

  /**
   * Find the highest priority available AI provider (honors explicit user setting if passed)
   * @param {string} [preferredId] - Optional explicit provider ID preferred by user settings
   */
  async getPreferredProvider(preferredId = null) {
    if (preferredId) {
      const targetId = (preferredId === 'chrome-ai') ? 'chrome-builtin-ai' : preferredId;
      const explicit = this.get(targetId);
      if (explicit && explicit.enabled) {
        try {
          const avail = await explicit.checkAvailability();
          if (avail.available) return explicit;
        } catch (_) {}
      }
    }

    // 1. Check local providers first (privacy & zero cost)
    for (const provider of this.providers.values()) {
      if (provider.enabled && provider.isLocal) {
        try {
          const avail = await provider.checkAvailability();
          if (avail.available) return provider;
        } catch (_) {}
      }
    }

    // 2. Check cloud BYOK providers
    for (const provider of this.providers.values()) {
      if (provider.enabled && !provider.isLocal) {
        try {
          const avail = await provider.checkAvailability();
          if (avail.available) return provider;
        } catch (_) {}
      }
    }

    return null;
  }
}

  // Environment exports
  if (typeof self !== 'undefined') {
    self.AIProvider = AIProvider;
    self.AIRegistry = AIRegistry;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AIProvider, AIRegistry };
  }
})();
