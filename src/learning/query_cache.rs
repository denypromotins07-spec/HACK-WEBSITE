//! Query Language Injection Learning Cache
//! Caches successful injection syntax, backend engine fingerprints, and WAF bypasses.
//! Implements bounded memory usage with LRU eviction for 2GB RAM ceiling compliance.

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Entry in the query injection cache
#[derive(Debug, Clone)]
pub struct QueryCacheEntry {
    /// The payload that was successful
    pub payload: Cow<'static, str>,
    /// Target backend/engine fingerprint
    pub fingerprint: Cow<'static, str>,
    /// Confidence score of the injection
    pub confidence: f64,
    /// Number of times this payload succeeded
    pub success_count: u32,
    /// Last successful timestamp
    pub last_success: Instant,
    /// WAF bypass techniques that worked
    pub waf_bypasses: Vec<Cow<'static, str>>,
}

/// Bounded learning cache for query-language injections
pub struct QueryCache {
    /// Cached entries by injection type
    entries: HashMap<Cow<'static, str>, VecDeque<QueryCacheEntry>>,
    /// Maximum number of entries per injection type
    max_entries_per_type: usize,
    /// Maximum total entries across all types
    max_total_entries: usize,
    /// Current total entry count
    total_entries: usize,
    /// Cache creation time for TTL calculations
    created_at: Instant,
    /// Default TTL for cache entries
    default_ttl: Duration,
}

impl QueryCache {
    /// Create a new bounded query cache
    pub fn new(max_entries_per_type: usize, max_total_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries_per_type: max_entries_per_type.min(1024),
            max_total_entries: max_total_entries.min(10000),
            total_entries: 0,
            created_at: Instant::now(),
            default_ttl: Duration::from_secs(3600), // 1 hour default
        }
    }

    /// Record a successful injection
    pub fn record_success(
        &mut self,
        injection_type: &'static str,
        payload: Cow<'static, str>,
        fingerprint: Cow<'static, str>,
        confidence: f64,
    ) {
        // Evict if at capacity
        if self.total_entries >= self.max_total_entries {
            self.evict_oldest();
        }

        let entry = QueryCacheEntry {
            payload,
            fingerprint,
            confidence,
            success_count: 1,
            last_success: Instant::now(),
            waf_bypasses: Vec::new(),
        };

        let queue = self.entries
            .entry(Cow::Borrowed(injection_type))
            .or_insert_with(|| VecDeque::with_capacity(self.max_entries_per_type));

        // Check if payload already exists
        if let Some(existing) = queue.iter_mut().find(|e| e.payload == entry.payload) {
            existing.success_count += 1;
            existing.last_success = entry.last_success;
            existing.confidence = (existing.confidence + confidence) / 2.0;
        } else {
            if queue.len() >= self.max_entries_per_type {
                queue.pop_front();
            }
            queue.push_back(entry);
            self.total_entries += 1;
        }
    }

    /// Record a WAF bypass technique
    pub fn record_waf_bypass(
        &mut self,
        injection_type: &str,
        payload: &str,
        bypass_technique: &'static str,
    ) {
        if let Some(queue) = self.entries.get_mut(Cow::Borrowed(injection_type)) {
            if let Some(entry) = queue.iter_mut().find(|e| e.payload.as_ref() == payload) {
                if !entry.waf_bypasses.contains(&Cow::Borrowed(bypass_technique)) {
                    entry.waf_bypasses.push(Cow::Borrowed(bypass_technique));
                }
            }
        }
    }

    /// Get successful payloads for an injection type
    pub fn get_successful_payloads(&self, injection_type: &str) -> Vec<&QueryCacheEntry> {
        self.entries
            .get(Cow::Borrowed(injection_type))
            .map(|queue| queue.iter().collect())
            .unwrap_or_default()
    }

    /// Get the best fingerprint for an injection type
    pub fn get_fingerprint(&self, injection_type: &str) -> Option<Cow<'static, str>> {
        self.entries
            .get(Cow::Borrowed(injection_type))
            .and_then(|queue| {
                queue
                    .iter()
                    .max_by(|a, b| a.confidence.partial_cmp(&b.confidence).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|e| e.fingerprint.clone())
            })
    }

    /// Get known WAF bypasses for a payload
    pub fn get_waf_bypasses(&self, injection_type: &str, payload: &str) -> Vec<Cow<'static, str>> {
        self.entries
            .get(Cow::Borrowed(injection_type))
            .and_then(|queue| {
                queue
                    .iter()
                    .find(|e| e.payload.as_ref() == payload)
                    .map(|e| e.waf_bypasses.clone())
            })
            .unwrap_or_default()
    }

    /// Check if a payload is known to be successful
    pub fn is_known_successful(&self, injection_type: &str, payload: &str) -> bool {
        self.entries
            .get(Cow::Borrowed(injection_type))
            .map(|queue| queue.iter().any(|e| e.payload.as_ref() == payload && e.success_count > 0))
            .unwrap_or(false)
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let mut total_payloads = 0;
        let mut type_counts = HashMap::new();

        for (injection_type, queue) in &self.entries {
            let count = queue.len();
            total_payloads += count;
            type_counts.insert(injection_type.clone(), count);
        }

        CacheStats {
            total_entries: self.total_entries,
            total_payloads,
            type_counts,
            uptime: self.created_at.elapsed(),
            max_capacity: self.max_total_entries,
        }
    }

    /// Evict oldest entry across all types
    fn evict_oldest(&mut self) {
        let mut oldest_type: Option<Cow<'static, str>> = None;
        let mut oldest_time: Option<Instant> = None;

        for (injection_type, queue) in &self.entries {
            if let Some(front) = queue.front() {
                if oldest_time.is_none() || front.last_success < oldest_time.unwrap() {
                    oldest_time = Some(front.last_success);
                    oldest_type = Some(injection_type.clone());
                }
            }
        }

        if let Some(injection_type) = oldest_type {
            if let Some(queue) = self.entries.get_mut(&injection_type) {
                if queue.pop_front().is_some() {
                    self.total_entries = self.total_entries.saturating_sub(1);
                }
            }
        }
    }

    /// Clear expired entries based on TTL
    pub fn clear_expired(&mut self, ttl: Duration) {
        let now = Instant::now();
        let mut removed = 0;

        for queue in self.entries.values_mut() {
            while let Some(front) = queue.front() {
                if now.duration_since(front.last_success) > ttl {
                    queue.pop_front();
                    removed += 1;
                } else {
                    break;
                }
            }
        }

        self.total_entries = self.total_entries.saturating_sub(removed);
        
        // Remove empty queues
        self.entries.retain(|_, queue| !queue.is_empty());
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
        self.total_entries = 0;
    }
}

/// Cache statistics
#[derive(Debug)]
pub struct CacheStats {
    pub total_entries: usize,
    pub total_payloads: usize,
    pub type_counts: HashMap<Cow<'static, str>, usize>,
    pub uptime: Duration,
    pub max_capacity: usize,
}

impl Default for QueryCache {
    fn default() -> Self {
        Self::new(512, 5000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_success() {
        let mut cache = QueryCache::new(100, 1000);
        
        cache.record_success(
            "xpath_injection",
            Cow::Borrowed("' or '1'='1"),
            Cow::Borrowed("XPath-1.0"),
            0.85,
        );

        assert!(cache.is_known_successful("xpath_injection", "' or '1'='1"));
    }

    #[test]
    fn test_waf_bypass_recording() {
        let mut cache = QueryCache::new(100, 1000);
        
        cache.record_success(
            "ldap_injection",
            Cow::Borrowed(")(uid=*)"),
            Cow::Borrowed("OpenLDAP"),
            0.75,
        );

        cache.record_waf_bypass("ldap_injection", ")(uid=*)", "url_encoding");

        let bypasses = cache.get_waf_bypasses("ldap_injection", ")(uid=*)");
        assert!(bypasses.contains(&Cow::Borrowed("url_encoding")));
    }

    #[test]
    fn test_cache_eviction() {
        let mut cache = QueryCache::new(3, 5);
        
        for i in 0..6 {
            cache.record_success(
                "test_type",
                Cow::Owned(format!("payload{}", i)),
                Cow::Borrowed("fingerprint"),
                0.5,
            );
        }

        let stats = cache.stats();
        assert!(stats.total_entries <= 5);
    }
}
