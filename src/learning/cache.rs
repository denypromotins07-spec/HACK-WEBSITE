//! Embedded local cache for successful crawl paths, response codes, and timings.
//!
//! This module provides a self-learning cache that accelerates repeated scans
//! by remembering endpoint behavior from previous crawls.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

/// Cached endpoint entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Endpoint path
    pub path: String,
    /// Last successful HTTP status
    pub last_status: u16,
    /// Response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Number of times accessed
    pub access_count: u32,
    /// Last access timestamp
    pub last_accessed: u64,
    /// Content type if known
    pub content_type: Option<String>,
    /// Content length if known
    pub content_length: Option<usize>,
    /// Whether endpoint requires auth
    pub requires_auth: bool,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Learning metadata
    pub learned_at: u64,
}

impl CacheEntry {
    pub fn new(path: String, status: u16) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            path,
            last_status: status,
            avg_response_time_ms: 0.0,
            access_count: 1,
            last_accessed: now,
            content_type: None,
            content_length: None,
            requires_auth: false,
            tags: Vec::new(),
            learned_at: now,
        }
    }

    /// Update with new observation
    pub fn observe(&mut self, status: u16, response_time_ms: u64, content_type: Option<&str>, content_length: Option<usize>) {
        // Exponential moving average for response time
        let alpha = 0.3;
        self.avg_response_time_ms = (alpha * response_time_ms as f64) 
            + ((1.0 - alpha) * self.avg_response_time_ms);
        
        self.last_status = status;
        self.access_count += 1;
        self.last_accessed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if let Some(ct) = content_type {
            self.content_type = Some(ct.to_string());
        }
        self.content_length = content_length;
        
        // Detect auth requirement
        if status == 401 || status == 403 {
            self.requires_auth = true;
        }
    }

    /// Get priority score for crawling (higher = more important)
    pub fn priority_score(&self) -> f64 {
        let mut score = 0.0;
        
        // Successful endpoints are higher priority
        if self.last_status >= 200 && self.last_status < 400 {
            score += 10.0;
        }
        
        // Fast endpoints are preferred
        score += 5.0 / (1.0 + self.avg_response_time_ms / 100.0);
        
        // Frequently accessed endpoints
        score += (self.access_count as f64).ln();
        
        // Auth-required endpoints might be interesting
        if self.requires_auth {
            score += 5.0;
        }
        
        score
    }
}

/// Learning cache for crawl data
pub struct CrawlCache {
    /// Cached entries by path
    entries: RwLock<HashMap<String, CacheEntry>>,
    /// Paths by status code
    by_status: RwLock<HashMap<u16, Vec<String>>>,
    /// Paths requiring auth
    auth_required: RwLock<Vec<String>>,
    /// Maximum cache size
    max_size: usize,
    /// Cache creation time
    created_at: Instant,
}

impl CrawlCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(max_size / 10)),
            by_status: RwLock::new(HashMap::new()),
            auth_required: RwLock::new(Vec::new()),
            max_size,
            created_at: Instant::now(),
        }
    }

    /// Record a successful crawl result
    pub fn record(&self, path: &str, status: u16, response_time_ms: u64, content_type: Option<&str>, content_length: Option<usize>) {
        let mut entries = self.entries.write();
        
        // Check cache size limit
        if entries.len() >= self.max_size {
            // Evict oldest/least valuable entries
            self.evict_old_entries(&mut entries);
        }
        
        let entry = entries.entry(path.to_string()).or_insert_with(|| {
            CacheEntry::new(path.to_string(), status)
        });
        
        entry.observe(status, response_time_ms, content_type, content_length);
        
        // Update status index
        if status >= 200 && status < 400 {
            let mut by_status = self.by_status.write();
            by_status.entry(status).or_default().push(path.to_string());
        }
        
        // Update auth index
        if entry.requires_auth {
            let mut auth = self.auth_required.write();
            if !auth.contains(&path.to_string()) {
                auth.push(path.to_string());
            }
        }
    }

    /// Get cached entry for a path
    pub fn get(&self, path: &str) -> Option<CacheEntry> {
        self.entries.read().get(path).cloned()
    }

    /// Check if path exists in cache
    pub fn contains(&self, path: &str) -> bool {
        self.entries.read().contains_key(path)
    }

    /// Get all cached paths
    pub fn all_paths(&self) -> Vec<String> {
        self.entries.read().keys().cloned().collect()
    }

    /// Get paths by status code
    pub fn get_by_status(&self, status: u16) -> Vec<String> {
        self.by_status.read().get(&status).cloned().unwrap_or_default()
    }

    /// Get all auth-required paths
    pub fn auth_required_paths(&self) -> Vec<String> {
        self.auth_required.read().clone()
    }

    /// Get high-priority paths for crawling
    pub fn high_priority_paths(&self, limit: usize) -> Vec<(String, f64)> {
        let entries = self.entries.read();
        let mut scored: Vec<(String, f64)> = entries.iter()
            .map(|(path, entry)| (path.clone(), entry.priority_score()))
            .collect();
        
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(limit);
        scored
    }

    /// Evict old entries when cache is full
    fn evict_old_entries(&self, entries: &mut HashMap<String, CacheEntry>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Sort by last accessed time and remove oldest
        let mut sorted: Vec<_> = entries.iter()
            .map(|(k, v)| (k.clone(), v.last_accessed))
            .collect();
        
        sorted.sort_by_key(|(_, t)| *t);
        
        // Remove oldest 20%
        let to_remove = entries.len() / 5;
        for (key, _) in sorted.into_iter().take(to_remove) {
            entries.remove(&key);
        }
    }

    /// Clear the cache
    pub fn clear(&self) {
        self.entries.write().clear();
        self.by_status.write().clear();
        self.auth_required.write().clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let entries = self.entries.read();
        let total = entries.len();
        
        let auth_count = self.auth_required.read().len();
        let status_counts: HashMap<u16, usize> = self.by_status.read()
            .iter()
            .map(|(s, paths)| (*s, paths.len()))
            .collect();
        
        let avg_response_time = entries.values()
            .map(|e| e.avg_response_time_ms)
            .sum::<f64>() / total.max(1) as f64;
        
        CacheStats {
            total_entries: total,
            auth_required_count: auth_count,
            status_2xx: status_counts.get(&200).copied().unwrap_or(0)
                + status_counts.get(&201).copied().unwrap_or(0)
                + status_counts.get(&204).copied().unwrap_or(0),
            status_3xx: status_counts.get(&301).copied().unwrap_or(0)
                + status_counts.get(&302).copied().unwrap_or(0)
                + status_counts.get(&304).copied().unwrap_or(0),
            status_4xx: status_counts.get(&400).copied().unwrap_or(0)
                + status_counts.get(&401).copied().unwrap_or(0)
                + status_counts.get(&403).copied().unwrap_or(0)
                + status_counts.get(&404).copied().unwrap_or(0),
            status_5xx: status_counts.get(&500).copied().unwrap_or(0)
                + status_counts.get(&502).copied().unwrap_or(0)
                + status_counts.get(&503).copied().unwrap_or(0),
            avg_response_time_ms: avg_response_time,
            cache_age_secs: self.created_at.elapsed().as_secs(),
        }
    }

    /// Export cache for persistence
    pub fn export(&self) -> Vec<CacheEntry> {
        self.entries.read().values().cloned().collect()
    }

    /// Import cache entries
    pub fn import(&self, entries: Vec<CacheEntry>) {
        let mut inner = self.entries.write();
        for entry in entries {
            inner.insert(entry.path.clone(), entry);
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_entries: usize,
    pub auth_required_count: usize,
    pub status_2xx: usize,
    pub status_3xx: usize,
    pub status_4xx: usize,
    pub status_5xx: usize,
    pub avg_response_time_ms: f64,
    pub cache_age_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_record_and_get() {
        let cache = CrawlCache::new(1000);
        
        cache.record("/api/users", 200, 50, Some("application/json"), Some(1024));
        
        let entry = cache.get("/api/users").unwrap();
        assert_eq!(entry.last_status, 200);
        assert_eq!(entry.access_count, 1);
    }

    #[test]
    fn test_cache_update() {
        let cache = CrawlCache::new(1000);
        
        cache.record("/api/test", 200, 100, None, None);
        cache.record("/api/test", 200, 50, None, None);
        
        let entry = cache.get("/api/test").unwrap();
        assert_eq!(entry.access_count, 2);
        assert!(entry.avg_response_time_ms > 50.0 && entry.avg_response_time_ms < 100.0);
    }

    #[test]
    fn test_auth_detection() {
        let cache = CrawlCache::new(1000);
        
        cache.record("/admin", 401, 10, None, None);
        
        let entry = cache.get("/admin").unwrap();
        assert!(entry.requires_auth);
        
        let auth_paths = cache.auth_required_paths();
        assert!(auth_paths.contains(&"/admin".to_string()));
    }

    #[test]
    fn test_priority_scoring() {
        let cache = CrawlCache::new(1000);
        
        cache.record("/fast", 200, 10, None, None);
        cache.record("/slow", 200, 1000, None, None);
        
        let fast = cache.get("/fast").unwrap();
        let slow = cache.get("/slow").unwrap();
        
        assert!(fast.priority_score() > slow.priority_score());
    }
}
