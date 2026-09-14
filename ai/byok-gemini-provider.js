/**
 * SafeClick 2.0 - Bring-Your-Own-Key (BYOK) Gemini Provider
 * Open Source Browser Security Engine
 * 
 * Direct client-side connection to Google Gemini API using a user-provided key.
 * Zero maintainer costs, zero middleman backend, key stored exclusively in local storage.
 */

(function () {
  'use strict';

  // Handle environments
  const _AIProvider = (typeof AIProvider !== 'undefined') ? AIProvider : (function () {
    try { return require('./ai-provider.js').AIProvider; } catch (_) { return null; }
  })();

  class BYOKGeminiProvider extends (_AIProvider || class {}) {
  /**
   * @param {Object} options
   * @param {string} [options.apiKey] - Google Gemini API Key
   * @param {string} [options.model] - Model name (default: gemini-1.5-flash)
   */
  constructor(options = {}) {
    const model = options.model || 'gemini-3.8-flash';
    super({
      id: 'byok-gemini',
      name: `Google Gemini (${model})`,
      isLocal: false,
      enabled: !!options.apiKey,
      ...options
    });
    this.apiKey = options.apiKey || '';
    this.model = model;
  }

  setApiKey(key) {
    this.apiKey = String(key || '').trim();
    this.enabled = !!this.apiKey;
  }

  setModel(model) {
    if (!model || typeof model !== 'string') return;
    const clean = model.trim().replace(/^models\//, '');
    if (clean) {
      this.model = clean;
      this.name = `Google Gemini (${clean})`;
    }
  }

  async checkAvailability() {
    if (!this.apiKey) {
      return {
        available: false,
        status: 'no_key',
        reason: 'Gemini API key not configured in SafeClick Settings'
      };
    }
    return {
      available: true,
      status: 'ready',
      reason: `Configured with ${this.model}`
    };
  }

  /**
   * Fetch live list of supported generation models available for this API key
   * @param {string} [testKey]
   * @returns {Promise<Array<{ id: string, displayName: string, description: string }>>}
   */
  async listAvailableModels(testKey = null) {
    const key = testKey || this.apiKey;
    if (!key) throw new Error('API key is required to list models');

    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(key)}`;
    const resp = await fetch(endpoint, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });

    if (!resp.ok) {
      const errBody = await resp.json().catch(() => ({}));
      const msg = (errBody.error && errBody.error.message) || `HTTP ${resp.status} ${resp.statusText}`;
      throw new Error(msg);
    }

    const data = await resp.json();
    const rawModels = Array.isArray(data.models) ? data.models : [];

    // Filter for models that support text/content generation
    const contentModels = rawModels
      .filter(m => Array.isArray(m.supportedGenerationMethods) && m.supportedGenerationMethods.includes('generateContent'))
      .map(m => {
        const id = (m.name || '').replace(/^models\//, '');
        return {
          id: id,
          displayName: m.displayName || id,
          description: m.description || ''
        };
      })
      .filter(m => m.id.includes('gemini'));

    // Priority ordering: 3.8-flash > 3.5-flash > 3.5-flash-lite > 3.1-pro > flash > others
    contentModels.sort((a, b) => {
      const rank = (id) => {
        if (id === 'gemini-3.8-flash') return 0;
        if (id.includes('3.8-flash')) return 1;
        if (id === 'gemini-3.5-flash') return 2;
        if (id.includes('3.5-flash-lite')) return 3;
        if (id.includes('3.5-flash')) return 4;
        if (id === 'gemini-3.1-pro') return 5;
        if (id.includes('3.1-pro')) return 6;
        if (id.includes('flash')) return 7;
        return 10;
      };
      return rank(a.id) - rank(b.id);
    });

    return contentModels.length > 0 ? contentModels : [
      { id: 'gemini-3.8-flash', displayName: 'Gemini 3.8 Flash (Recommended)' },
      { id: 'gemini-3.5-flash', displayName: 'Gemini 3.5 Flash' },
      { id: 'gemini-3.5-flash-lite', displayName: 'Gemini 3.5 Flash Lite' },
      { id: 'gemini-3.1-pro', displayName: 'Gemini 3.1 Pro' }
    ];
  }

  /**
   * Test API key validity with a lightweight ping
   * @param {string} [testKey]
   * @param {string} [testModel]
   */
  async testConnection(testKey = null, testModel = null) {
    const key = testKey || this.apiKey;
    if (!key) throw new Error('API key is required to test connection');

    // 1. Fetch available models for this key (the official, infallible way to validate Gemini keys)
    const availableModels = await this.listAvailableModels(key);
    if (!availableModels || availableModels.length === 0) {
      throw new Error('API key is valid, but no text generation models were found for this project.');
    }

    const availableIds = availableModels.map(m => m.id);
    let target = testModel || this.model || 'gemini-3.8-flash';

    // If target model is not in user's authorized models, pick the best one available
    if (!availableIds.includes(target)) {
      const preferred = availableIds.find(id => id.includes('3.8-flash')) ||
                        availableIds.find(id => id.includes('3.5-flash')) ||
                        availableIds.find(id => id.includes('flash')) ||
                        availableIds[0];
      if (preferred) target = preferred;
    }

    this.setApiKey(key);
    this.setModel(target);

    return {
      success: true,
      model: target,
      totalModels: availableModels.length,
      availableModels
    };
  }

  /**
   * Generate advisory opinion via Gemini API
   * @param {Object} context - { systemPrompt, userPrompt }
   */
  async analyze(context) {
    if (!this.apiKey) {
      throw new Error('Gemini API key is not configured');
    }

    const tryCall = async (modelName, useJsonMime = true) => {
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(modelName)}:generateContent?key=${encodeURIComponent(this.apiKey)}`;
      const payload = {
        systemInstruction: {
          parts: [{ text: context.systemPrompt }]
        },
        contents: [
          {
            role: 'user',
            parts: [{ text: context.userPrompt }]
          }
        ],
        generationConfig: {
          temperature: 0.1,
          maxOutputTokens: 350
        }
      };
      if (useJsonMime) {
        payload.generationConfig.responseMimeType = 'application/json';
      }

      return await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    };

    let currentModel = this.model || 'gemini-3.8-flash';
    let resp = await tryCall(currentModel, true);

    // Fallback if model fails with 404/500
    if (!resp.ok && (resp.status === 404 || resp.status === 500 || resp.status === 400)) {
      // Try without JSON mime
      resp = await tryCall(currentModel, false);
      if (!resp.ok) {
        const fallbacks = ['gemini-2.5-flash', 'gemini-3.5-flash', 'gemini-3.5-flash-lite', 'gemini-1.5-flash'];
        for (const fb of fallbacks) {
          if (fb === currentModel) continue;
          const fbResp = await tryCall(fb, true);
          if (fbResp.ok) {
            resp = fbResp;
            this.setModel(fb);
            break;
          }
        }
      }
    }

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error((err.error && err.error.message) || `Gemini API error: HTTP ${resp.status}`);
    }

    const data = await resp.json();
    const candidate = data.candidates && data.candidates[0];
    const textPart = candidate && candidate.content && candidate.content.parts && candidate.content.parts[0];
    const rawText = (textPart && textPart.text) || '';

    const cleaned = rawText.replace(/```json\s*/i, '').replace(/```\s*$/, '').trim();
    let parsed = {};
    try { parsed = JSON.parse(cleaned); } catch (_) {}

    return {
      summary: parsed.summary || rawText.slice(0, 200) || 'Security analysis completed.',
      confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.85,
      recommendation: parsed.recommendation || 'Exercise caution on this page.',
      riskLevel: parsed.riskLevel || 'MEDIUM',
      rawResponse: rawText
    };
  }

  /**
   * General text and conversational generation
   * @param {Object} options
   * @param {string} options.prompt
   * @param {string} [options.systemInstruction]
   * @param {number} [options.maxTokens]
   * @param {boolean} [options.json]
   * @returns {Promise<string>}
   */
  async generateText({ prompt, systemInstruction = '', maxTokens = 500, json = false }) {
    if (!this.apiKey) {
      throw new Error('Gemini API key is not configured');
    }

    const tryCall = async (modelName, withSysInstruction = true) => {
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(modelName)}:generateContent?key=${encodeURIComponent(this.apiKey)}`;
      const userText = (!withSysInstruction && systemInstruction) ? `${systemInstruction}\n\n${prompt}` : prompt;
      const payload = {
        contents: [{ role: 'user', parts: [{ text: userText }] }],
        generationConfig: {
          temperature: 0.2,
          maxOutputTokens: maxTokens
        }
      };

      if (withSysInstruction && systemInstruction) {
        payload.systemInstruction = { parts: [{ text: systemInstruction }] };
      }
      if (json) {
        payload.generationConfig.responseMimeType = 'application/json';
      }

      return await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    };

    let targetModel = this.model || 'gemini-3.8-flash';
    let resp = await tryCall(targetModel, true);

    if (!resp.ok && (resp.status === 404 || resp.status === 500 || resp.status === 400)) {
      // 1. Try without systemInstruction
      resp = await tryCall(targetModel, false);

      // 2. Try candidate fallback models
      if (!resp.ok) {
        const fallbacks = ['gemini-2.5-flash', 'gemini-3.5-flash', 'gemini-3.5-flash-lite', 'gemini-1.5-flash', 'gemini-2.0-flash'];
        for (const fb of fallbacks) {
          if (fb === targetModel) continue;
          const fbResp = await tryCall(fb, true);
          if (fbResp.ok) {
            resp = fbResp;
            this.setModel(fb);
            break;
          }
        }
      }
    }

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error((err.error && err.error.message) || `Gemini API error: HTTP ${resp.status}`);
    }

    const data = await resp.json();
    const candidate = data.candidates && data.candidates[0];
    const textPart = candidate && candidate.content && candidate.content.parts && candidate.content.parts[0];
    return (textPart && textPart.text) || '';
  }
}

  // Environment exports
  if (typeof self !== 'undefined') {
    self.BYOKGeminiProvider = BYOKGeminiProvider;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = BYOKGeminiProvider;
  }
})();
