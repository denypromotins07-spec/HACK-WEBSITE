//! XSS Learning Cache Module
//! 
//! Caches successful bypasses, payload contexts, and framework fingerprints for learning.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH, Duration};

/// Maximum cache entries to prevent memory exhaustion (2GB ceiling compliance)
const MAX_CACHE_ENTRIES: usize = 10000;

/// Entry in the XSS learning cache
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The target/endpoint that was tested
    pub target: String,
    /// The bypass technique used
    pub bypass_technique: String,
    /// Number of times this bypass succeeded
    pub success_count: u32,
    /// Last successful timestamp
    pub last_success: u64,
    /// Associated payload context
    pub context: String,
    /// Framework fingerprint if detected
    pub framework: Option<String>,
}

/// XSS learning cache for storing successful bypasses and patterns
pub struct XssCache {
    entries: Arc<Mutex<HashMap<String, CacheEntry>>>,
    bypass_patterns: Arc<Mutex<HashMap<String, Vec<String>>>>,
    framework_signatures: Arc<Mutex<HashMap<String, String>>>,
}

impl XssCache {
    /// Create a new XSS cache
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::with_capacity(1000))),
            bypass_patterns: Arc::new(Mutex::new(HashMap::with_capacity(500))),
            framework_signatures: Arc::new(Mutex::new(HashMap::with_capacity(100))),
        }
    }

    /// Record a successful bypass
    pub fn record_bypass(&self, target: String, bypass_technique: String) {
        let mut entries = self.entries.lock().unwrap();
        
        let key = format!("{}:{}", target, bypass_technique);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if let Some(entry) = entries.get_mut(&key) {
            entry.success_count += 1;
            entry.last_success = now;
        } else {
            // Enforce max entries limit
            if entries.len() >= MAX_CACHE_ENTRIES {
                // Remove oldest entries
                self.prune_old_entries(&mut entries);
            }
            
            entries.insert(key, CacheEntry {
                target,
                bypass_technique,
                success_count: 1,
                last_success: now,
                context: String::new(),
                framework: None,
            });
        }
    }

    /// Record bypass with context information
    pub fn record_bypass_with_context(&self, target: String, bypass_technique: String, context: String) {
        let mut entries = self.entries.lock().unwrap();
        
        let key = format!("{}:{}:{}", target, bypass_technique, context);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if let Some(entry) = entries.get_mut(&key) {
            entry.success_count += 1;
            entry.last_success = now;
            entry.context = context;
        } else {
            if entries.len() >= MAX_CACHE_ENTRIES {
                self.prune_old_entries(&mut entries);
            }
            
            entries.insert(key, CacheEntry {
                target,
                bypass_technique,
                success_count: 1,
                last_success: now,
                context,
                framework: None,
            });
        }
    }

    /// Record framework fingerprint
    pub fn record_framework(&self, url: String, framework: String) {
        let mut signatures = self.framework_signatures.lock().unwrap();
        signatures.insert(url, framework);
    }

    /// Get successful bypasses for a target
    pub fn get_bypasses_for_target(&self, target: &str) -> Vec<CacheEntry> {
        let entries = self.entries.lock().unwrap();
        entries
            .values()
            .filter(|e| e.target == target)
            .cloned()
            .collect()
    }

    /// Get most successful bypass techniques
    pub fn get_top_bypasses(&self, limit: usize) -> Vec<CacheEntry> {
        let entries = self.entries.lock().unwrap();
        let mut all_entries: Vec<CacheEntry> = entries.values().cloned().collect();
        
        // Sort by success count descending
        all_entries.sort_by(|a, b| b.success_count.cmp(&a.success_count));
        
        all_entries.into_iter().take(limit).collect()
    }

    /// Check if a bypass technique has been successful before
    pub fn has_successful_bypass(&self, target: &str, technique: &str) -> bool {
        let entries = self.entries.lock().unwrap();
        let key = format!("{}:{}", target, technique);
        entries.contains_key(&key)
    }

    /// Get framework fingerprint for URL
    pub fn get_framework(&self, url: &str) -> Option<String> {
        let signatures = self.framework_signatures.lock().unwrap();
        signatures.get(url).cloned()
    }

    /// Prune old entries to maintain memory bounds
    fn prune_old_entries(&self, entries: &mut HashMap<String, CacheEntry>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let threshold = now - Duration::from_secs(7 * 24 * 60 * 60).as_secs(); // 7 days
        
        // Remove entries older than threshold or keep only top entries
        let mut to_remove = Vec::new();
        for (key, entry) in entries.iter() {
            if entry.last_success < threshold || entry.success_count == 0 {
                to_remove.push(key.clone());
            }
        }
        
        for key in to_remove {
            entries.remove(&key);
        }
        
        // If still over limit, remove lowest success count entries
        while entries.len() > MAX_CACHE_ENTRIES {
            if let Some(min_key) = entries
                .iter()
                .min_by_key(|(_, e)| e.success_count)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&min_key);
            }
        }
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        let entries = self.entries.lock().unwrap();
        let bypasses = self.bypass_patterns.lock().unwrap();
        let frameworks = self.framework_signatures.lock().unwrap();
        
        let total_successes: u32 = entries.values().map(|e| e.success_count).sum();
        
        CacheStats {
            total_entries: entries.len(),
            total_bypass_patterns: bypasses.len(),
            total_frameworks: frameworks.len(),
            total_successes,
        }
    }

    /// Clear the cache
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
        self.bypass_patterns.lock().unwrap().clear();
        self.framework_signatures.lock().unwrap().clear();
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub total_bypass_patterns: usize,
    pub total_frameworks: usize,
    pub total_successes: u32,
}

impl Default for XssCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_creation() {
        let cache = XssCache::new();
        let stats = cache.get_stats();
        assert_eq!(stats.total_entries, 0);
    }

    #[test]
    fn test_record_bypass() {
        let cache = XssCache::new();
        
        cache.record_bypass("https://example.com".to_string(), "xss_filter_bypass".to_string());
        
        assert!(cache.has_successful_bypass("https://example.com", "xss_filter_bypass"));
        
        let bypasses = cache.get_bypasses_for_target("https://example.com");
        assert_eq!(bypasses.len(), 1);
        assert_eq!(bypasses[0].success_count, 1);
    }

    #[test]
    fn test_multiple_bypasses() {
        let cache = XssCache::new();
        
        cache.record_bypass("https://example.com".to_string(), "bypass1".to_string());
        cache.record_bypass("https://example.com".to_string(), "bypass1".to_string());
        cache.record_bypass("https://example.com".to_string(), "bypass2".to_string());
        
        let bypasses = cache.get_bypasses_for_target("https://example.com");
        assert_eq!(bypasses.len(), 2);
        
        let top = cache.get_top_bypasses(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].success_count, 2);
    }

    #[test]
    fn test_framework_recording() {
        let cache = XssCache::new();
        
        cache.record_framework("https://example.com".to_string(), "React".to_string());
        
        assert_eq!(cache.get_framework("https://example.com"), Some("React".to_string()));
    }
}
