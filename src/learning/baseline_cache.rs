//! Baseline Cache for Target-Specific Behaviors
//! 
//! Caches target-specific baseline behaviors to accelerate differential analysis 
//! on subsequent scans. Uses bounded LRU cache for memory efficiency.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;

/// Cached baseline entry
#[derive(Debug, Clone)]
pub struct BaselineEntry {
    pub url_hash: u64,
    pub fingerprint: BaselineFingerprint,
    pub created_at: Instant,
    pub last_accessed: Instant,
    pub access_count: u64,
    pub ttl_seconds: u64,
}

impl BaselineEntry {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() > self.ttl_seconds
    }
    
    pub fn touch(&mut self) {
        self.last_accessed = Instant::now();
        self.access_count += 1;
    }
}

/// Baseline fingerprint data
#[derive(Debug, Clone)]
pub struct BaselineFingerprint {
    pub body_hash: u64,
    pub headers_hash: u64,
    pub status_code: u16,
    pub content_length: usize,
    pub timing_baseline_ns: u64,
    pub dynamic_markers: Vec<String>,
}

impl BaselineFingerprint {
    pub fn new(
        body: &Bytes,
        headers: &[(String, String)],
        status_code: u16,
        timing_ns: u64,
    ) -> Self {
        use xxhash_rust::xxh3::xxh3_64;
        
        let body_hash = xxh3_64(body);
        
        let headers_str: String = headers
            .iter()
            .map(|(k, v)| format!("{}:{}", k.to_lowercase(), v))
            .collect::<Vec<_>>()
            .join(";");
        let headers_hash = xxh3_64(headers_str.as_bytes());
        
        Self {
            body_hash,
            headers_hash,
            status_code,
            content_length: body.len(),
            timing_baseline_ns: timing_ns,
            dynamic_markers: Vec::new(),
        }
    }
    
    /// Check if current response matches baseline
    pub fn matches(&self, current_body_hash: u64, current_headers_hash: u64, current_status: u16) -> bool {
        self.body_hash == current_body_hash
            && self.headers_hash == current_headers_hash
            && self.status_code == current_status
    }
    
    /// Calculate similarity score with current response
    pub fn similarity(&self, current_body_hash: u64, current_status: u16) -> f64 {
        let mut score = 1.0;
        
        if self.body_hash != current_body_hash {
            score -= 0.5;
        }
        
        if self.status_code != current_status {
            score -= 0.3;
        }
        
        score.max(0.0)
    }
}

/// Bounded LRU cache for baselines
pub struct BaselineCache {
    entries: HashMap<u64, BaselineEntry>,
    access_queue: VecDeque<u64>,
    max_entries: usize,
    default_ttl_seconds: u64,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl BaselineCache {
    pub fn new(max_entries: usize, ttl_seconds: u64) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries.min(1000)),
            access_queue: VecDeque::with_capacity(max_entries.min(1000)),
            max_entries,
            default_ttl_seconds: ttl_seconds,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }
    
    /// Get or create baseline for URL
    pub fn get_or_create(
        &mut self,
        url_hash: u64,
        body: &Bytes,
        headers: &[(String, String)],
        status_code: u16,
        timing_ns: u64,
    ) -> &BaselineFingerprint {
        // Try to get existing entry
        if let Some(entry) = self.entries.get_mut(&url_hash) {
            if !entry.is_expired() {
                entry.touch();
                self.hits.fetch_add(1, Ordering::Relaxed);
                return &entry.fingerprint;
            } else {
                // Remove expired entry
                self.entries.remove(&url_hash);
            }
        }
        
        self.misses.fetch_add(1, Ordering::Relaxed);
        
        // Create new baseline
        let fingerprint = BaselineFingerprint::new(body, headers, status_code, timing_ns);
        
        // Evict if at capacity
        if self.entries.len() >= self.max_entries {
            self.evict_lru();
        }
        
        let entry = BaselineEntry {
            url_hash,
            fingerprint,
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            access_count: 1,
            ttl_seconds: self.default_ttl_seconds,
        };
        
        self.entries.insert(url_hash, entry);
        self.access_queue.push_back(url_hash);
        
        &self.entries.get(&url_hash).unwrap().fingerprint
    }
    
    /// Get baseline if exists
    pub fn get(&mut self, url_hash: u64) -> Option<&BaselineFingerprint> {
        if let Some(entry) = self.entries.get_mut(&url_hash) {
            if !entry.is_expired() {
                entry.touch();
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(&entry.fingerprint);
            } else {
                self.entries.remove(&url_hash);
            }
        }
        
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }
    
    /// Store a baseline
    pub fn store(
        &mut self,
        url_hash: u64,
        fingerprint: BaselineFingerprint,
    ) {
        // Evict if at capacity
        if self.entries.len() >= self.max_entries {
            self.evict_lru();
        }
        
        let entry = BaselineEntry {
            url_hash,
            fingerprint,
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            access_count: 1,
            ttl_seconds: self.default_ttl_seconds,
        };
        
        self.entries.insert(url_hash, entry);
        self.access_queue.push_back(url_hash);
    }
    
    /// Evict least recently used entry
    fn evict_lru(&mut self) {
        while let Some(url_hash) = self.access_queue.pop_front() {
            if self.entries.remove(&url_hash).is_some() {
                self.evictions.fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }
    
    /// Clean up expired entries
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Instant::now();
        let mut removed = 0;
        
        self.entries.retain(|_, entry| {
            if entry.is_expired() {
                removed += 1;
                false
            } else {
                true
            }
        });
        
        removed
    }
    
    /// Get statistics
    pub fn stats(&self) -> BaselineStats {
        BaselineStats {
            cached_entries: self.entries.len(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }
    
    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
        self.access_queue.clear();
    }
    
    /// Hit rate
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed) as f64;
        let misses = self.misses.load(Ordering::Relaxed) as f64;
        let total = hits + misses;
        
        if total == 0.0 {
            return 0.0;
        }
        
        hits / total
    }
}

impl Default for BaselineCache {
    fn default() -> Self {
        Self::new(1000, 3600) // 1000 entries, 1 hour TTL
    }
}

/// Statistics for baseline cache
#[derive(Debug, Clone)]
pub struct BaselineStats {
    pub cached_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

impl BaselineStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0.0;
        }
        self.hits as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_baseline_cache_creation() {
        let cache = BaselineCache::new(100, 3600);
        let stats = cache.stats();
        assert_eq!(stats.cached_entries, 0);
    }
    
    #[test]
    fn test_store_and_get() {
        let mut cache = BaselineCache::new(100, 3600);
        let body = Bytes::from("Hello World");
        let headers = vec![];
        
        let fp = cache.get_or_create(12345, &body, &headers, 200, 1000).clone();
        
        assert_eq!(fp.status_code, 200);
        assert_eq!(fp.content_length, 11);
        
        // Get again should return same fingerprint
        let fp2 = cache.get(12345);
        assert!(fp2.is_some());
    }
    
    #[test]
    fn test_hit_rate() {
        let mut cache = BaselineCache::new(100, 3600);
        let body = Bytes::from("Test");
        let headers = vec![];
        
        // First access - miss
        cache.get_or_create(1, &body, &headers, 200, 100);
        
        // Second access - hit
        cache.get_or_create(1, &body, &headers, 200, 100);
        
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }
}
