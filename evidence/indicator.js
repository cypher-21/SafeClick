/**
 * SafeClick 2.0 - Structured Indicator System & Evidence Registry
 * Open Source Browser Security Engine
 * 
 * Defines typed evidence units and the central registry for
 * explainable, queryable security findings.
 */

class Indicator {
  /**
   * @param {Object} params
   * @param {string} params.id - Unique indicator identifier (e.g., 'url.punycode', 'dom.cross_origin_form')
   * @param {string} params.source - Module that produced the indicator (e.g., 'url-analyzer', 'dom-analyzer')
   * @param {string} params.category - Category ('network', 'lexical', 'structural', 'content', 'reputation', 'redirect')
   * @param {string} params.polarity - 'positive' (safety indicator) | 'negative' (threat indicator) | 'info'
   * @param {number} params.weight - Score delta (positive for positive polarity, negative for negative)
   * @param {string} params.confidence - 'high' | 'medium' | 'low'
   * @param {*} params.value - Raw finding value (boolean, number, string, object)
   * @param {string} params.detail - Human-readable explanation of the finding
   * @param {number} [params.timestamp] - Creation epoch milliseconds
   */
  constructor({ id, source, category = 'structural', polarity = 'info', weight = 0, confidence = 'medium', value = null, detail = '', timestamp = Date.now() }) {
    if (!id || typeof id !== 'string') {
      throw new Error('Indicator requires a valid string id');
    }
    this.id = id;
    this.source = source || 'unknown';
    this.category = category;
    this.polarity = polarity; // 'positive' | 'negative' | 'info'
    this.weight = typeof weight === 'number' ? weight : 0;
    this.confidence = confidence; // 'high' | 'medium' | 'low'
    this.value = value;
    this.detail = detail || '';
    this.timestamp = timestamp;
  }

  toJSON() {
    return {
      id: this.id,
      source: this.source,
      category: this.category,
      polarity: this.polarity,
      weight: this.weight,
      confidence: this.confidence,
      value: this.value,
      detail: this.detail,
      timestamp: this.timestamp
    };
  }
}

class IndicatorRegistry {
  constructor() {
    this.indicators = new Map();
  }

  /**
   * Add a single indicator (replaces if identical id already exists)
   */
  add(indicator) {
    if (!(indicator instanceof Indicator)) {
      indicator = new Indicator(indicator);
    }
    this.indicators.set(indicator.id, indicator);
    return this;
  }

  /**
   * Add multiple indicators
   */
  addAll(list) {
    if (Array.isArray(list)) {
      list.forEach(ind => this.add(ind));
    }
    return this;
  }

  get(id) {
    return this.indicators.get(id) || null;
  }

  has(id) {
    return this.indicators.has(id);
  }

  remove(id) {
    return this.indicators.delete(id);
  }

  clear() {
    this.indicators.clear();
  }

  getAll() {
    return Array.from(this.indicators.values());
  }

  getByCategory(category) {
    return this.getAll().filter(ind => ind.category === category);
  }

  getByPolarity(polarity) {
    return this.getAll().filter(ind => ind.polarity === polarity);
  }

  getNegative() {
    return this.getByPolarity('negative');
  }

  getPositive() {
    return this.getByPolarity('positive');
  }

  getInfo() {
    return this.getByPolarity('info');
  }

  filter(predicate) {
    return this.getAll().filter(predicate);
  }

  get size() {
    return this.indicators.size;
  }

  toJSON() {
    return this.getAll().map(ind => ind.toJSON());
  }

  static fromJSON(jsonArray) {
    const reg = new IndicatorRegistry();
    if (Array.isArray(jsonArray)) {
      jsonArray.forEach(item => reg.add(new Indicator(item)));
    }
    return reg;
  }
}

// Environment exports
if (typeof self !== 'undefined') {
  self.Indicator = Indicator;
  self.IndicatorRegistry = IndicatorRegistry;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { Indicator, IndicatorRegistry };
}
