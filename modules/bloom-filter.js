/**
 * Bloom Filter Module for SafeClick Extension
 * Memory-efficient probabilistic data structure for blocklist lookups.
 * 
 * Trade-off: ~1% false positive rate for 80% memory savings.
 * 100k entries → ~125KB instead of 3MB+ raw strings.
 */

const BloomFilter = (function () {

    /**
     * Create a new Bloom filter
     * @param {number} expectedItems - Expected number of items to store
     * @param {number} falsePositiveRate - Desired false positive rate (0-1)
     */
    function create(expectedItems = 100000, falsePositiveRate = 0.01) {
        // Calculate optimal size and hash count
        // m = -n * ln(p) / (ln(2)^2)
        // k = (m/n) * ln(2)
        const n = expectedItems;
        const p = falsePositiveRate;

        const m = Math.ceil(-n * Math.log(p) / (Math.LN2 * Math.LN2));
        const k = Math.ceil((m / n) * Math.LN2);

        // Round up to nearest byte boundary
        const byteSize = Math.ceil(m / 8);

        return {
            bitArray: new Uint8Array(byteSize),
            size: m,
            hashCount: k,
            itemCount: 0
        };
    }

    /**
     * Simple hash functions using FNV-1a variants
     */
    function hash1(str) {
        let hash = 2166136261; // FNV offset basis
        for (let i = 0; i < str.length; i++) {
            hash ^= str.charCodeAt(i);
            hash = Math.imul(hash, 16777619); // FNV prime
        }
        return hash >>> 0;
    }

    function hash2(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash + str.charCodeAt(i)) | 0;
        }
        return hash >>> 0;
    }

    /**
     * Get array of hash values for a string
     */
    function getHashes(str, hashCount, size) {
        const h1 = hash1(str);
        const h2 = hash2(str);
        const hashes = [];

        // Double hashing: h(i) = h1 + i * h2
        for (let i = 0; i < hashCount; i++) {
            hashes.push((h1 + i * h2) % size);
        }
        return hashes;
    }

    /**
     * Set a bit in the filter
     */
    function setBit(filter, position) {
        const byteIndex = Math.floor(position / 8);
        const bitIndex = position % 8;
        filter.bitArray[byteIndex] |= (1 << bitIndex);
    }

    /**
     * Check if a bit is set
     */
    function getBit(filter, position) {
        const byteIndex = Math.floor(position / 8);
        const bitIndex = position % 8;
        return (filter.bitArray[byteIndex] & (1 << bitIndex)) !== 0;
    }

    /**
     * Add an item to the filter
     * @param {Object} filter - The bloom filter object
     * @param {string} item - Item to add (will be lowercased)
     */
    function add(filter, item) {
        if (!item) return;
        const str = String(item).toLowerCase().trim();
        if (!str) return;

        const hashes = getHashes(str, filter.hashCount, filter.size);
        for (const hash of hashes) {
            setBit(filter, hash);
        }
        filter.itemCount++;
    }

    /**
     * Check if an item might be in the filter
     * @param {Object} filter - The bloom filter object
     * @param {string} item - Item to check
     * @returns {boolean} true if item might exist (could be false positive), false if definitely doesn't exist
     */
    function mightContain(filter, item) {
        if (!item || !filter || !filter.bitArray) return false;
        const str = String(item).toLowerCase().trim();
        if (!str) return false;

        const hashes = getHashes(str, filter.hashCount, filter.size);
        for (const hash of hashes) {
            if (!getBit(filter, hash)) {
                return false; // Definitely not in set
            }
        }
        return true; // Might be in set (could be false positive)
    }

    /**
     * Add multiple items to the filter
     * @param {Object} filter - The bloom filter object
     * @param {Array} items - Array of items to add
     */
    function addAll(filter, items) {
        if (!Array.isArray(items)) return;
        for (const item of items) {
            add(filter, item);
        }
    }

    /**
     * Serialize filter to a compact format for storage
     * @param {Object} filter - The bloom filter object
     * @returns {Object} Serializable object
     */
    function serialize(filter) {
        return {
            data: Array.from(filter.bitArray),
            size: filter.size,
            hashCount: filter.hashCount,
            itemCount: filter.itemCount
        };
    }

    /**
     * Deserialize a filter from storage
     * @param {Object} data - Serialized filter data
     * @returns {Object} Filter object
     */
    function deserialize(data) {
        if (!data || !data.data || !data.size) return null;
        return {
            bitArray: new Uint8Array(data.data),
            size: data.size,
            hashCount: data.hashCount || 7,
            itemCount: data.itemCount || 0
        };
    }

    /**
     * Get filter statistics
     */
    function getStats(filter) {
        if (!filter) return null;

        // Count set bits
        let setBits = 0;
        for (let i = 0; i < filter.bitArray.length; i++) {
            let byte = filter.bitArray[i];
            while (byte) {
                setBits += byte & 1;
                byte >>= 1;
            }
        }

        const fillRatio = setBits / filter.size;
        // Estimated false positive rate: (1 - e^(-k*n/m))^k
        const estimatedFPR = Math.pow(1 - Math.exp(-filter.hashCount * filter.itemCount / filter.size), filter.hashCount);

        return {
            sizeBytes: filter.bitArray.length,
            sizeKB: Math.round(filter.bitArray.length / 1024 * 100) / 100,
            totalBits: filter.size,
            setBits: setBits,
            fillRatio: Math.round(fillRatio * 100) / 100,
            hashCount: filter.hashCount,
            itemCount: filter.itemCount,
            estimatedFalsePositiveRate: Math.round(estimatedFPR * 10000) / 10000
        };
    }

    /**
     * Create a filter from a list of URLs/hosts
     * Normalizes entries before adding
     */
    function createFromList(items, expectedItems = null) {
        const count = expectedItems || items.length || 10000;
        const filter = create(count, 0.01);

        for (const item of items) {
            if (!item) continue;
            let entry = String(item).trim();

            // Normalize: extract host from URL if needed
            try {
                if (entry.startsWith('http://') || entry.startsWith('https://')) {
                    const u = new URL(entry);
                    entry = u.hostname.toLowerCase();
                } else {
                    entry = entry.toLowerCase();
                }
            } catch (_) {
                entry = entry.toLowerCase();
            }

            if (entry) add(filter, entry);
        }

        return filter;
    }

    // Public API
    return {
        create,
        add,
        addAll,
        mightContain,
        serialize,
        deserialize,
        getStats,
        createFromList
    };
})();

// Export for use in service worker and node testing
if (typeof self !== 'undefined') {
    self.BloomFilter = BloomFilter;
}
if (typeof module !== 'undefined' && module.exports) {
    module.exports = BloomFilter;
}
