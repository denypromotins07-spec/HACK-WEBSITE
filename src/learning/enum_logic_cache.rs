//! Enumeration Logic Cache Module
//!
//! Caches timing baselines, bypassed rate-limit headers, and successful JNDI callbacks.
//! Implements bounded cache storage for the self-learning engine.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Maximum cache entries (bounded)
const MAX_CACHE_ENTRIES: usize = 256;

/// Maximum entries per category (bounded)
const MAX_TIMING_ENTRIES: usize = 64;
const MAX_BYPASS_ENTRIES: usize = 64;
const MAX_JNDI_ENTRIES: usize = 32;

/// Timing baseline entry
#[derive(Debug, Clone)]
pub struct TimingBaselineEntry {
    pub url: String,
    pub check_type: String,
    pub baseline_ns: u128,
    pub threshold_ns: u128,
    pub sample_count: u32,
    pub last_updated: u64,
}

impl TimingBaselineEntry {
    pub fn new(url: String, check_type: String, baseline_ns: u128, threshold_ns: u128) -> Self {
        Self {
            url,
            check_type,
            baseline_ns,
            threshold_ns,
            sample_count: 1,
            last_updated: 0,
        }
    }

    pub fn update(&mut self, new_baseline: u128) {
        // Exponential moving average
        let alpha = 0.3;
        self.baseline_ns = ((1.0 - alpha) * self.baseline_ns as f64 + alpha * new_baseline as f64) as u128;
        self.sample_count += 1;
        self.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

/// Bypass header entry
#[derive(Debug, Clone)]
pub struct BypassHeaderEntry {
    pub url: String,
    pub header: String,
    pub value: String,
    pub success_count: u32,
    pub last_used: u64,
}

impl BypassHeaderEntry {
    pub fn new(url: String, header: String, value: String) -> Self {
        Self {
            url,
            header,
            value,
            success_count: 1,
            last_used: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// JNDI callback entry
#[derive(Debug, Clone)]
pub struct JndiCallbackEntry {
    pub url: String,
    pub payload: String,
    pub injection_point: String,
    pub callback_received: bool,
    pub timestamp: u64,
}

impl JndiCallbackEntry {
    pub fn new(url: String, payload: String, injection_point: String) -> Self {
        Self {
            url,
            payload,
            injection_point,
            callback_received: false,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn mark_callback(mut self) -> Self {
        self.callback_received = true;
        self
    }
}

/// Bounded enumeration cache
pub struct EnumLogicCache {
    timing_baselines: HashMap<String, Vec<TimingBaselineEntry>>,
    bypass_headers: HashMap<String, Vec<BypassHeaderEntry>>,
    jndi_callbacks: HashMap<String, Vec<JndiCallbackEntry>>,
    timing_count: usize,
    bypass_count: usize,
    jndi_count: usize,
}

impl EnumLogicCache {
    pub fn new() -> Self {
        Self {
            timing_baselines: HashMap::new(),
            bypass_headers: HashMap::new(),
            jndi_callbacks: HashMap::new(),
            timing_count: 0,
            bypass_count: 0,
            jndi_count: 0,
        }
    }

    /// Cache a timing baseline
    pub fn cache_timing_baseline(&mut self, url: String, check_type: String, baseline_ns: u128) {
        if self.timing_count >= MAX_TIMING_ENTRIES {
            // Evict oldest entry
            if let Some((_, entries)) = self.timing_baselines.iter_mut().next() {
                if !entries.is_empty() {
                    entries.remove(0);
                    self.timing_count -= 1;
                }
            }
        }

        let threshold_ns = 10_000_000; // Default 10ms threshold
        let entry = TimingBaselineEntry::new(url.clone(), check_type.clone(), baseline_ns, threshold_ns);

        self.timing_baselines
            .entry(url)
            .or_insert_with(Vec::new)
            .push(entry);
        self.timing_count += 1;
    }

    /// Cache a successful bypass header
    pub fn cache_bypass_header(&mut self, url: String, header: String) {
        if self.bypass_count >= MAX_BYPASS_ENTRIES {
            if let Some((_, entries)) = self.bypass_headers.iter_mut().next() {
                if !entries.is_empty() {
                    entries.remove(0);
                    self.bypass_count -= 1;
                }
            }
        }

        let entry = BypassHeaderEntry::new(url.clone(), header.clone(), "bypass".to_string());

        self.bypass_headers
            .entry(url)
            .or_insert_with(Vec::new)
            .push(entry);
        self.bypass_count += 1;
    }

    /// Cache a JNDI callback
    pub fn cache_jndi_callback(&mut self, url: String, payload: String, injection_point: String) {
        if self.jndi_count >= MAX_JNDI_ENTRIES {
            if let Some((_, entries)) = self.jndi_callbacks.iter_mut().next() {
                if !entries.is_empty() {
                    entries.remove(0);
                    self.jndi_count -= 1;
                }
            }
        }

        let entry = JndiCallbackEntry::new(url.clone(), payload, injection_point);

        self.jndi_callbacks
            .entry(url)
            .or_insert_with(Vec::new)
            .push(entry);
        self.jndi_count += 1;
    }

    /// Get timing baseline for URL
    pub fn get_timing_baseline(&self, url: &str, check_type: &str) -> Option<u128> {
        self.timing_baselines.get(url).and_then(|entries| {
            entries.iter()
                .find(|e| e.check_type == check_type)
                .map(|e| e.baseline_ns)
        })
    }

    /// Get bypass headers for URL
    pub fn get_bypass_headers(&self, url: &str) -> Vec<&BypassHeaderEntry> {
        self.bypass_headers.get(url)
            .map(|entries| entries.iter().collect())
            .unwrap_or_default()
    }

    /// Get JNDI callbacks for URL
    pub fn get_jndi_callbacks(&self, url: &str) -> Vec<&JndiCallbackEntry> {
        self.jndi_callbacks.get(url)
            .map(|entries| entries.iter().collect())
            .unwrap_or_default()
    }

    /// Update timing baseline with new sample
    pub fn update_timing_baseline(&mut self, url: &str, check_type: &str, new_baseline: u128) {
        if let Some(entries) = self.timing_baselines.get_mut(url) {
            if let Some(entry) = entries.iter_mut().find(|e| e.check_type == check_type) {
                entry.update(new_baseline);
            }
        }
    }

    /// Clear all cached data
    pub fn clear(&mut self) {
        self.timing_baselines.clear();
        self.bypass_headers.clear();
        self.jndi_callbacks.clear();
        self.timing_count = 0;
        self.bypass_count = 0;
        self.jndi_count = 0;
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            timing_entries: self.timing_count,
            bypass_entries: self.bypass_count,
            jndi_entries: self.jndi_count,
            total_entries: self.timing_count + self.bypass_count + self.jndi_count,
        }
    }
}

impl Default for EnumLogicCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub timing_entries: usize,
    pub bypass_entries: usize,
    pub jndi_entries: usize,
    pub total_entries: usize,
}

/// Global cache wrapper for async access
pub struct LearningCache {
    inner: Arc<RwLock<EnumLogicCache>>,
}

impl LearningCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(EnumLogicCache::new())),
        }
    }

    pub async fn global() -> Result<Arc<RwLock<EnumLogicCache>>, &'static str> {
        static CACHE: once_cell::sync::Lazy<Arc<RwLock<EnumLogicCache>>> =
            once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(EnumLogicCache::new())));
        Ok(CACHE.clone())
    }

    pub async fn cache_timing_baseline(&self, url: String, check_type: String) {
        let mut cache = self.inner.write().await;
        cache.cache_timing_baseline(url, check_type, 100_000_000);
    }

    pub async fn cache_bypass_header(&self, url: String, header: String) {
        let mut cache = self.inner.write().await;
        cache.cache_bypass_header(url, header);
    }

    pub async fn get_stats(&self) -> CacheStats {
        let cache = self.inner.read().await;
        cache.stats()
    }
}

impl Default for LearningCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_cache() {
        let mut cache = EnumLogicCache::new();
        
        cache.cache_timing_baseline(
            "https://example.com/login".to_string(),
            "user_enum".to_string(),
            100_000_000,
        );

        let baseline = cache.get_timing_baseline("https://example.com/login", "user_enum");
        assert_eq!(baseline, Some(100_000_000));
    }

    #[test]
    fn test_bypass_cache() {
        let mut cache = EnumLogicCache::new();
        
        cache.cache_bypass_header(
            "https://example.com/api".to_string(),
            "X-Forwarded-For".to_string(),
        );

        let bypasses = cache.get_bypass_headers("https://example.com/api");
        assert_eq!(bypasses.len(), 1);
        assert_eq!(bypasses[0].header, "X-Forwarded-For");
    }

    #[test]
    fn test_cache_bounds() {
        let mut cache = EnumLogicCache::new();
        
        // Fill timing cache beyond limit
        for i in 0..MAX_TIMING_ENTRIES + 10 {
            cache.cache_timing_baseline(
                format!("https://example{}.com", i),
                "test".to_string(),
                50_000_000,
            );
        }

        assert!(cache.timing_count <= MAX_TIMING_ENTRIES);
    }

    #[test]
    fn test_cache_stats() {
        let mut cache = EnumLogicCache::new();
        
        cache.cache_timing_baseline("url1".to_string(), "type1".to_string(), 100_000_000);
        cache.cache_bypass_header("url2".to_string(), "header1".to_string());
        
        let stats = cache.stats();
        assert_eq!(stats.timing_entries, 1);
        assert_eq!(stats.bypass_entries, 1);
        assert_eq!(stats.total_entries, 2);
    }
}
