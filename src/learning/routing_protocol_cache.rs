//! Routing and Protocol Cache for Self-Learning Engine
//! Caches successful URL parsing bypasses, SNI mismatches, and proxy collapse vectors.
//! Uses bounded storage and zero-copy byte buffers (Stage 1 memory constraints).

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum cache entries (bounded)
const MAX_CACHE_ENTRIES: usize = 256;

/// Maximum payload size per entry (bounded to 1KB)
const MAX_PAYLOAD_SIZE: usize = 1024;

/// Cache entry TTL default (5 minutes)
const DEFAULT_TTL_SECS: u64 = 300;

#[derive(Debug, Clone)]
pub struct RoutingProtocolCacheEntry {
    pub key: String,
    pub value: String,
    pub target: String,
    pub check_type: String,
    pub success_count: u32,
    pub last_used: Instant,
    pub created_at: Instant,
    pub ttl_secs: u64,
}

impl RoutingProtocolCacheEntry {
    pub fn new(key: &str, value: &str, target: &str, check_type: &str) -> Self {
        let now = Instant::now();
        Self {
            key: key.to_string(),
            value: value.chars().take(MAX_PAYLOAD_SIZE).collect(),
            target: target.to_string(),
            check_type: check_type.to_string(),
            success_count: 1,
            last_used: now,
            created_at: now,
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.last_used.elapsed() > Duration::from_secs(self.ttl_secs)
    }

    pub fn increment_success(&mut self) {
        self.success_count = self.success_count.saturating_add(1);
        self.last_used = Instant::now();
    }
}

/// Bounded cache for routing/protocol bypass patterns
pub struct RoutingProtocolCache {
    entries: HashMap<String, RoutingProtocolCacheEntry>,
    max_entries: usize,
    hit_count: u64,
    miss_count: u64,
}

impl RoutingProtocolCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(std::cmp::min(max_entries, MAX_CACHE_ENTRIES)),
            max_entries: std::cmp::min(max_entries, MAX_CACHE_ENTRIES),
            hit_count: 0,
            miss_count: 0,
        }
    }

    /// Store a bypass pattern in the cache
    pub fn store(&mut self, key: &str, value: &str, target: &str, check_type: &str) {
        // Evict expired entries first
        self.evict_expired();

        // If at capacity, evict LRU entry
        if self.entries.len() >= self.max_entries {
            self.evict_lru();
        }

        let entry = RoutingProtocolCacheEntry::new(key, value, target, check_type);
        self.entries.insert(key.to_string(), entry);
    }

    /// Retrieve a cached bypass pattern
    pub fn get(&mut self, key: &str) -> Option<&RoutingProtocolCacheEntry> {
        if let Some(entry) = self.entries.get_mut(key) {
            if !entry.is_expired() {
                entry.increment_success();
                self.hit_count += 1;
                return Some(entry);
            } else {
                // Remove expired entry
                self.entries.remove(key);
            }
        }
        self.miss_count += 1;
        None
    }

    /// Check if a bypass pattern exists
    pub fn contains(&mut self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Evict expired entries
    pub fn evict_expired(&mut self) {
        let expired_keys: Vec<String> = self.entries.iter()
            .filter(|(_, v)| v.is_expired())
            .map(|(k, _)| k.clone())
            .collect();
        
        for key in expired_keys {
            self.entries.remove(&key);
        }
    }

    /// Evict least recently used entry
    fn evict_lru(&mut self) {
        if let Some(lru_key) = self.entries.iter()
            .min_by_key(|(_, v)| v.last_used)
            .map(|(k, _)| k.clone())
        {
            self.entries.remove(&lru_key);
        }
    }

    /// Get all entries of a specific check type
    pub fn get_by_check_type(&self, check_type: &str) -> Vec<&RoutingProtocolCacheEntry> {
        self.entries.values()
            .filter(|e| e.check_type == check_type && !e.is_expired())
            .collect()
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let total = self.hit_count + self.miss_count;
        let hit_rate = if total > 0 {
            self.hit_count as f64 / total as f64
        } else {
            0.0
        };

        CacheStats {
            total_entries: self.entries.len(),
            max_entries: self.max_entries,
            hit_count: self.hit_count,
            miss_count: self.miss_count,
            hit_rate,
        }
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
        self.hit_count = 0;
        self.miss_count = 0;
    }

    /// Export cache for learning engine (bounded JSON)
    pub fn export_bounded_json(&self) -> String {
        let mut json = String::with_capacity(4096);
        json.push_str("{\n  \"cache_stats\": {\n");
        json.push_str(&format!("    \"entries\": {},\n", self.entries.len()));
        json.push_str(&format!("    \"hits\": {},\n", self.hit_count));
        json.push_str(&format!("    \"misses\": {},\n", self.miss_count));
        json.push_str(&format!("    \"hit_rate\": {:.4}\n", self.stats().hit_rate));
        json.push_str("  },\n  \"bypass_patterns\": [\n");

        let mut first = true;
        for (key, entry) in self.entries.iter().take(32) {
            if !first {
                json.push_str(",\n");
            }
            first = false;
            json.push_str(&format!(
                "    {{\"key\": \"{}\", \"type\": \"{}\", \"successes\": {}}}",
                key, entry.check_type, entry.success_count
            ));
        }

        json.push_str("\n  ]\n}\n");
        json
    }
}

#[derive(Debug)]
pub struct CacheStats {
    pub total_entries: usize,
    pub max_entries: usize,
    pub hit_count: u64,
    pub miss_count: u64,
    pub hit_rate: f64,
}

/// Common bypass pattern keys
pub mod cache_keys {
    pub const URL_BYPASS: &str = "url_bypass";
    pub const SNI_BYPASS: &str = "sni_bypass";
    pub const PROXY_COLLAPSE: &str = "proxy_collapse";
    pub const H2_STREAM_EXHAUST: &str = "h2_stream_exhaustion";
    pub const GRPC_REFLECTION: &str = "grpc_reflection";
    pub const WS_MASK_BYPASS: &str = "ws_mask_bypass";
    pub const SSE_INJECTION: &str = "sse_injection";
    pub const QUIC_BYPASS: &str = "quic_bypass";
    pub const CLOUDFRONT_BYPASS: &str = "cloudfront_bypass";
    pub const FAT_GET_BYPASS: &str = "fat_get_bypass";
    pub const XFORWARD_BYPASS: &str = "xforward_bypass";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_store_and_get() {
        let mut cache = RoutingProtocolCache::new(10);
        
        cache.store("test_key", "test_value", "https://target.com", "sni_routing");
        
        let entry = cache.get("test_key");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().success_count, 1);
    }

    #[test]
    fn test_cache_bounded_capacity() {
        let mut cache = RoutingProtocolCache::new(5);
        
        for i in 0..10 {
            cache.store(&format!("key_{}", i), "value", "target", "check");
        }
        
        assert!(cache.entries.len() <= 5);
    }

    #[test]
    fn test_cache_stats() {
        let mut cache = RoutingProtocolCache::new(10);
        
        cache.store("key1", "val1", "target", "check");
        cache.get("key1");
        cache.get("key1");
        cache.get("nonexistent");
        
        let stats = cache.stats();
        assert_eq!(stats.hit_count, 2);
        assert_eq!(stats.miss_count, 1);
        assert!((stats.hit_rate - 0.666).abs() < 0.01);
    }
}
