//! Memory-efficient URL and content-hash deduplication using Bloom filters.
//!
//! This module provides probabilistic and exact deduplication mechanisms
//! optimized for low memory usage during high-speed crawling.

use std::collections::{HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use parking_lot::RwLock;

/// Simple Bloom filter implementation for URL deduplication
pub struct BloomFilter {
    bits: Vec<bool>,
    num_hashes: usize,
    size: usize,
}

impl BloomFilter {
    /// Create a new Bloom filter with estimated capacity
    pub fn new(estimated_elements: usize) -> Self {
        // Optimal size: m = -n * ln(p) / (ln(2)^2) where p = 0.01 (1% false positive rate)
        let size = (estimated_elements as f64 * 9.585).ceil() as usize;
        // Optimal number of hashes: k = m/n * ln(2)
        let num_hashes = ((size as f64 / estimated_elements as f64) * 0.693).ceil() as usize;
        
        Self {
            bits: vec![false; size.max(1024)],
            num_hashes: num_hashes.max(2),
            size: size.max(1024),
        }
    }

    /// Compute multiple hash values for an item
    fn get_hash_indices(&self, data: &[u8]) -> Vec<usize> {
        let mut indices = Vec::with_capacity(self.num_hashes);
        
        // Use double hashing technique: h(i) = h1 + i * h2
        let h1 = self.hash_with_seed(data, 0);
        let h2 = self.hash_with_seed(data, 1);
        
        for i in 0..self.num_hashes {
            let hash = (h1.wrapping_add(i as u64 * h2)) % self.size as u64;
            indices.push(hash as usize);
        }
        
        indices
    }

    /// Hash with a seed value
    fn hash_with_seed(&self, data: &[u8], seed: u64) -> u64 {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        data.hash(&mut hasher);
        hasher.finish()
    }

    /// Add an item to the filter
    pub fn insert(&mut self, data: &[u8]) {
        for idx in self.get_hash_indices(data) {
            self.bits[idx] = true;
        }
    }

    /// Check if an item might be in the filter
    pub fn contains(&self, data: &[u8]) -> bool {
        self.get_hash_indices(data).iter().all(|&idx| self.bits[idx])
    }

    /// Get approximate fill ratio
    pub fn fill_ratio(&self) -> f64 {
        let set_count = self.bits.iter().filter(|&&b| b).count();
        set_count as f64 / self.bits.len() as f64
    }
}

/// Thread-safe Bloom filter wrapper
pub struct ConcurrentBloomFilter {
    inner: RwLock<BloomFilter>,
}

impl ConcurrentBloomFilter {
    pub fn new(estimated_elements: usize) -> Self {
        Self {
            inner: RwLock::new(BloomFilter::new(estimated_elements)),
        }
    }

    pub fn insert(&self, data: &[u8]) {
        self.inner.write().insert(data);
    }

    pub fn contains(&self, data: &[u8]) -> bool {
        self.inner.read().contains(data)
    }

    pub fn fill_ratio(&self) -> f64 {
        self.inner.read().fill_ratio()
    }
}

/// Content hash for response body deduplication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash(u64);

impl ContentHash {
    /// Compute hash from bytes
    pub fn compute(data: &[u8]) -> Self {
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        Self(hasher.finish())
    }

    /// Compute hash from string
    pub fn compute_str(s: &str) -> Self {
        Self::compute(s.as_bytes())
    }

    /// Get raw hash value
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// Deduplication cache combining Bloom filter and exact tracking
pub struct DedupeCache {
    /// Bloom filter for quick negative checks
    url_bloom: ConcurrentBloomFilter,
    /// Exact URL tracking for recently processed URLs
    recent_urls: RwLock<HashSet<String>>,
    /// Content hash tracking
    content_hashes: RwLock<HashSet<ContentHash>>,
    /// Maximum recent URLs to track
    max_recent: usize,
    /// Counter for rotation
    processed_count: RwLock<u64>,
}

impl Clone for DedupeCache {
    fn clone(&self) -> Self {
        Self {
            url_bloom: ConcurrentBloomFilter::new(1_000_000),
            recent_urls: RwLock::new(HashSet::new()),
            content_hashes: RwLock::new(HashSet::new()),
            max_recent: self.max_recent,
            processed_count: RwLock::new(0),
        }
    }
}

impl DedupeCache {
    /// Create a new deduplication cache
    pub fn new(capacity: usize) -> Self {
        Self {
            url_bloom: ConcurrentBloomFilter::new(capacity),
            recent_urls: RwLock::new(HashSet::with_capacity(capacity / 10)),
            content_hashes: RwLock::new(HashSet::with_capacity(capacity / 10)),
            max_recent: capacity / 10,
            processed_count: RwLock::new(0),
        }
    }

    /// Check if URL is a duplicate (may have false positives)
    pub fn is_duplicate_url(&self, url: &str) -> bool {
        // Quick Bloom filter check
        if !self.url_bloom.contains(url.as_bytes()) {
            return false;
        }
        
        // Confirm with exact check
        self.recent_urls.read().contains(url)
    }

    /// Mark URL as processed
    pub fn mark_url_processed(&self, url: &str) {
        self.url_bloom.insert(url.as_bytes());
        
        let mut urls = self.recent_urls.write();
        
        // Rotate if needed
        if urls.len() >= self.max_recent {
            // Clear and rely on Bloom filter
            urls.clear();
        }
        
        urls.insert(url.to_string());
        
        *self.processed_count.write() += 1;
    }

    /// Check if content hash is duplicate
    pub fn is_duplicate_content(&self, hash: ContentHash) -> bool {
        self.content_hashes.read().contains(&hash)
    }

    /// Mark content hash as seen
    pub fn mark_content_seen(&self, hash: ContentHash) -> bool {
        let mut hashes = self.content_hashes.write();
        
        // Rotate if needed
        if hashes.len() >= self.max_recent {
            hashes.clear();
        }
        
        hashes.insert(hash)
    }

    /// Check and mark content in one operation
    pub fn check_and_mark_content(&self, data: &[u8]) -> bool {
        let hash = ContentHash::compute(data);
        let mut hashes = self.content_hashes.write();
        
        if hashes.contains(&hash) {
            return true; // Duplicate
        }
        
        // Rotate if needed
        if hashes.len() >= self.max_recent {
            hashes.clear();
        }
        
        hashes.insert(hash);
        false // Not a duplicate
    }

    /// Get statistics
    pub fn stats(&self) -> DedupeStats {
        DedupeStats {
            urls_tracked: self.recent_urls.read().len(),
            content_hashes: self.content_hashes.read().len(),
            bloom_fill_ratio: self.url_bloom.fill_ratio(),
            processed_count: *self.processed_count.read(),
        }
    }

    /// Clear all caches
    pub fn clear(&self) {
        self.recent_urls.write().clear();
        self.content_hashes.write().clear();
        // Note: Bloom filter cannot be cleared without reconstruction
    }
}

/// Statistics about deduplication
#[derive(Debug, Clone)]
pub struct DedupeStats {
    pub urls_tracked: usize,
    pub content_hashes: usize,
    pub bloom_fill_ratio: f64,
    pub processed_count: u64,
}

/// SimHash for near-duplicate detection
pub struct SimHash {
    hash: u64,
}

impl SimHash {
    /// Compute SimHash of text (simplified implementation)
    pub fn compute(text: &str) -> Self {
        let mut fingerprints: [i32; 64] = [0; 64];
        
        // Tokenize and hash each token
        for token in text.split_whitespace() {
            let token_hash = Self::hash_token(token);
            
            // Update fingerprint
            for i in 0..64 {
                if token_hash & (1 << i) != 0 {
                    fingerprints[i] += 1;
                } else {
                    fingerprints[i] -= 1;
                }
            }
        }
        
        // Build final hash
        let mut hash = 0u64;
        for i in 0..64 {
            if fingerprints[i] > 0 {
                hash |= 1 << i;
            }
        }
        
        Self { hash }
    }

    /// Simple token hash
    fn hash_token(token: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        token.hash(&mut hasher);
        hasher.finish()
    }

    /// Calculate Hamming distance between two hashes
    pub fn hamming_distance(&self, other: &Self) -> u32 {
        (self.hash ^ other.hash).count_ones()
    }

    /// Check if two hashes are similar (within threshold)
    pub fn is_similar(&self, other: &Self, threshold: u32) -> bool {
        self.hamming_distance(other) <= threshold
    }

    /// Get raw hash value
    pub fn value(&self) -> u64 {
        self.hash
    }
}

/// MinHash for Jaccard similarity estimation
pub struct MinHash {
    hashes: Vec<u64>,
}

impl MinHash {
    /// Create MinHash with n permutations
    pub fn new(n: usize) -> Self {
        Self {
            hashes: vec![u64::MAX; n],
        }
    }

    /// Update MinHash with a shingle
    pub fn update(&mut self, shingle: &[u8]) {
        for (i, hash) in self.hashes.iter_mut().enumerate() {
            let h = Self::hash_with_index(shingle, i as u64);
            *hash = (*hash).min(h);
        }
    }

    /// Hash with index as seed
    fn hash_with_index(data: &[u8], index: u64) -> u64 {
        let mut hasher = DefaultHasher::new();
        index.hash(&mut hasher);
        data.hash(&mut hasher);
        hasher.finish()
    }

    /// Estimate Jaccard similarity with another MinHash
    pub fn similarity(&self, other: &MinHash) -> f64 {
        let matches = self.hashes.iter()
            .zip(other.hashes.iter())
            .filter(|(a, b)| a == b)
            .count();
        
        matches as f64 / self.hashes.len() as f64
    }

    /// Get hash vector
    pub fn hashes(&self) -> &[u64] {
        &self.hashes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter() {
        let mut bf = BloomFilter::new(1000);
        
        bf.insert(b"hello");
        bf.insert(b"world");
        
        assert!(bf.contains(b"hello"));
        assert!(bf.contains(b"world"));
        assert!(!bf.contains(b"foo")); // Likely not present
    }

    #[test]
    fn test_content_hash() {
        let h1 = ContentHash::compute_str("hello world");
        let h2 = ContentHash::compute_str("hello world");
        let h3 = ContentHash::compute_str("different");
        
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_dedupe_cache() {
        let cache = DedupeCache::new(1000);
        
        assert!(!cache.is_duplicate_url("http://test.com"));
        cache.mark_url_processed("http://test.com");
        assert!(cache.is_duplicate_url("http://test.com"));
    }

    #[test]
    fn test_simhash_similarity() {
        let s1 = SimHash::compute("the quick brown fox jumps over the lazy dog");
        let s2 = SimHash::compute("the quick brown fox leaps over the lazy dog");
        let s3 = SimHash::compute("completely different text here");
        
        // Similar texts should have small Hamming distance
        assert!(s1.hamming_distance(&s2) < s1.hamming_distance(&s3));
    }

    #[test]
    fn test_minhash_similarity() {
        let mut m1 = MinHash::new(10);
        let mut m2 = MinHash::new(10);
        let mut m3 = MinHash::new(10);
        
        let shingles: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        for s in &shingles {
            m1.update(s);
            m2.update(s);
        }
        
        m3.update(b"x");
        m3.update(b"y");
        
        // Identical updates should have high similarity
        assert!(m1.similarity(&m2) > m1.similarity(&m3));
    }
}
