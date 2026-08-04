//! Learning module - self-learning cache and heuristics for accelerated scanning.

pub mod cache;
pub mod heuristics;

pub use cache::{CrawlCache, CacheEntry, CacheStats};
pub use heuristics::{HeuristicsEngine, HeuristicRecord, BehaviorFlags, VulnerabilityHint, HeuristicsStats};

use std::sync::Arc;
use parking_lot::RwLock;

/// Combined learning system for the crawler
pub struct LearningSystem {
    /// Endpoint behavior cache
    pub cache: CrawlCache,
    /// Behavior heuristics engine
    pub heuristics: HeuristicsEngine,
    /// Whether learning is enabled
    enabled: RwLock<bool>,
}

impl LearningSystem {
    /// Create a new learning system
    pub fn new(cache_size: usize) -> Self {
        Self {
            cache: CrawlCache::new(cache_size),
            heuristics: HeuristicsEngine::new(),
            enabled: RwLock::new(true),
        }
    }

    /// Create with shared configuration
    pub fn shared(cache_size: usize) -> Arc<Self> {
        Arc::new(Self::new(cache_size))
    }

    /// Record a crawl observation
    pub fn record(
        &self,
        path: &str,
        status: u16,
        response_time_ms: u64,
        content_type: Option<&str>,
        content_length: Option<usize>,
        method: &str,
        headers: std::collections::HashMap<String, String>,
    ) {
        if !*self.enabled.read() {
            return;
        }

        // Record in cache
        self.cache.record(path, status, response_time_ms, content_type, content_length);

        // Record heuristics
        let ct = content_type.unwrap_or("unknown");
        self.heuristics.observe(path, status, ct, method, headers);
    }

    /// Check if path was previously successful
    pub fn was_successful(&self, path: &str) -> bool {
        self.cache.get(path)
            .map(|e| e.last_status >= 200 && e.last_status < 400)
            .unwrap_or(false)
    }

    /// Get cached response time estimate
    pub fn estimated_response_time(&self, path: &str) -> Option<f64> {
        self.cache.get(path).map(|e| e.avg_response_time_ms)
    }

    /// Check if path requires auth
    pub fn requires_auth(&self, path: &str) -> bool {
        self.cache.get(path)
            .map(|e| e.requires_auth)
            .unwrap_or(false)
    }

    /// Get high-priority paths for crawling
    pub fn get_priority_paths(&self, limit: usize) -> Vec<(String, f64)> {
        self.cache.high_priority_paths(limit)
    }

    /// Get vulnerability hints for a path
    pub fn get_vulnerability_hints(&self, path: &str) -> Vec<VulnerabilityHint> {
        self.heuristics.get(path)
            .map(|r| r.flags.vulnerability_hints())
            .unwrap_or_default()
    }

    /// Get all high-risk endpoints
    pub fn get_high_risk_endpoints(&self) -> Vec<(String, u32)> {
        self.heuristics.high_risk_endpoints()
    }

    /// Enable learning
    pub fn enable(&self) {
        *self.enabled.write() = true;
    }

    /// Disable learning
    pub fn disable(&self) {
        *self.enabled.write() = false;
    }

    /// Check if learning is enabled
    pub fn is_enabled(&self) -> bool {
        *self.enabled.read()
    }

    /// Get combined statistics
    pub fn stats(&self) -> LearningStats {
        let cache_stats = self.cache.stats();
        let heuristic_stats = self.heuristics.stats();

        LearningStats {
            cache_entries: cache_stats.total_entries,
            cache_auth_required: cache_stats.auth_required_count,
            cache_avg_response_time: cache_stats.avg_response_time_ms,
            heuristic_endpoints: heuristic_stats.total_endpoints,
            heuristic_api_count: heuristic_stats.api_count,
            heuristic_high_risk: heuristic_stats.high_risk_count,
            learning_enabled: *self.enabled.read(),
        }
    }

    /// Export learning data for persistence
    pub fn export(&self) -> LearningData {
        LearningData {
            cache_entries: self.cache.export(),
            heuristic_records: self.heuristics.all_records(),
        }
    }

    /// Import learning data
    pub fn import(&self, data: LearningData) {
        self.cache.import(data.cache_entries);
        
        // Note: Heuristics would need an import method
        // For now, we just restore the cache
    }

    /// Clear all learning data
    pub fn clear(&self) {
        self.cache.clear();
    }
}

/// Combined learning statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningStats {
    pub cache_entries: usize,
    pub cache_auth_required: usize,
    pub cache_avg_response_time: f64,
    pub heuristic_endpoints: usize,
    pub heuristic_api_count: usize,
    pub heuristic_high_risk: usize,
    pub learning_enabled: bool,
}

/// Serializable learning data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningData {
    pub cache_entries: Vec<cache::CacheEntry>,
    pub heuristic_records: Vec<heuristics::HeuristicRecord>,
}

// Re-export serde for derive macros
pub use serde::{Serialize, Deserialize};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_learning_system_record() {
        let system = LearningSystem::new(1000);
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        system.record(
            "/api/test",
            200,
            50,
            Some("application/json"),
            Some(1024),
            "GET",
            headers,
        );

        assert!(system.was_successful("/api/test"));
        assert!(system.estimated_response_time("/api/test").is_some());
    }

    #[test]
    fn test_learning_system_enable_disable() {
        let system = LearningSystem::new(1000);
        
        assert!(system.is_enabled());
        
        system.disable();
        assert!(!system.is_enabled());
        
        system.enable();
        assert!(system.is_enabled());
    }

    #[test]
    fn test_learning_stats() {
        let system = LearningSystem::new(1000);
        let stats = system.stats();
        
        assert_eq!(stats.cache_entries, 0);
        assert!(stats.learning_enabled);
    }
}
