//! SQL Injection Learning Cache
//! Cache successful DBMS fingerprints, payloads, and timing thresholds.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Maximum cache entries (bounded memory - well under 2GB)
const MAX_CACHE_ENTRIES: usize = 1000;

/// Maximum payload history per endpoint
const MAX_PAYLOAD_HISTORY: usize = 100;

/// Default cache entry TTL
const DEFAULT_TTL_SECS: u64 = 3600; // 1 hour

/// DBMS fingerprint record
#[derive(Debug, Clone)]
pub struct DbmsFingerprint {
    pub dbms_type: String,
    pub version: Option<String>,
    pub confidence: f64,
    pub detection_method: String,
    pub first_seen: Instant,
    last_verified: Instant,
    success_count: u32,
    failure_count: u32,
}

impl DbmsFingerprint {
    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            return 0.5;
        }
        self.success_count as f64 / total as f64
    }

    /// Check if fingerprint is expired
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.last_verified.elapsed() > ttl
    }
}

/// Cached payload with performance metrics
#[derive(Debug, Clone)]
pub struct CachedPayload {
    pub payload: String,
    pub dbms_target: String,
    pub injection_type: String,
    pub success_rate: f64,
    pub avg_response_time_ms: f64,
    pub waf_bypassed: bool,
    last_used: Instant,
    use_count: u32,
}

/// Timing threshold cache entry
#[derive(Debug, Clone)]
pub struct TimingThreshold {
    pub endpoint: String,
    pub baseline_ms: f64,
    pub threshold_ms: f64,
    pub jitter_ms: f64,
    sample_count: usize,
    last_updated: Instant,
}

/// SQLi learning cache
pub struct SqliCache {
    fingerprints: HashMap<String, DbmsFingerprint>, // key: endpoint hash
    payloads: HashMap<String, VecDeque<CachedPayload>>, // key: endpoint hash
    timing_thresholds: HashMap<String, TimingThreshold>, // key: endpoint hash
    ttl: Duration,
}

impl SqliCache {
    /// Create a new SQLi cache with default TTL
    pub fn new() -> Self {
        Self {
            fingerprints: HashMap::new(),
            payloads: HashMap::new(),
            timing_thresholds: HashMap::new(),
            ttl: Duration::from_secs(DEFAULT_TTL_SECS),
        }
    }

    /// Create cache with custom TTL
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            fingerprints: HashMap::new(),
            payloads: HashMap::new(),
            timing_thresholds: HashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Generate endpoint hash key
    fn endpoint_key(endpoint: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        endpoint.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Record a DBMS fingerprint
    pub fn record_fingerprint(
        &mut self,
        dbms_type: crate::checks::sqli::time_based::DbmsType,
        payload: &str,
        response_time_ms: u64,
    ) {
        let dbms_name = match dbms_type {
            crate::checks::sqli::time_based::DbmsType::MySQL => "MySQL",
            crate::checks::sqli::time_based::DbmsType::PostgreSQL => "PostgreSQL",
            crate::checks::sqli::time_based::DbmsType::MSSQL => "MSSQL",
            crate::checks::sqli::time_based::DbmsType::Oracle => "Oracle",
            crate::checks::sqli::time_based::DbmsType::SQLite => "SQLite",
            crate::checks::sqli::time_based::DbmsType::Unknown => "Unknown",
        };

        // For now, use a generic key - in production would be endpoint-specific
        let key = "global".to_string();

        if let Some(fp) = self.fingerprints.get_mut(&key) {
            if fp.dbms_type == dbms_name {
                fp.success_count += 1;
                fp.last_verified = Instant::now();
            } else {
                fp.failure_count += 1;
            }
        } else {
            if self.fingerprints.len() < MAX_CACHE_ENTRIES {
                self.fingerprints.insert(
                    key,
                    DbmsFingerprint {
                        dbms_type: dbms_name.to_string(),
                        version: None,
                        confidence: 0.7,
                        detection_method: payload.to_string(),
                        first_seen: Instant::now(),
                        last_verified: Instant::now(),
                        success_count: 1,
                        failure_count: 0,
                    },
                );
            }
        }
    }

    /// Get cached fingerprint for an endpoint
    pub fn get_fingerprint(&self, endpoint: &str) -> Option<&DbmsFingerprint> {
        let key = Self::endpoint_key(endpoint);
        self.fingerprints.get(&key).or_else(|| self.fingerprints.get("global"))
    }

    /// Cache a successful payload
    pub fn cache_payload(
        &mut self,
        endpoint: &str,
        payload: &str,
        dbms: &str,
        injection_type: &str,
        response_time_ms: f64,
        waf_bypassed: bool,
    ) {
        let key = Self::endpoint_key(endpoint);

        let payload_entry = CachedPayload {
            payload: payload.to_string(),
            dbms_target: dbms.to_string(),
            injection_type: injection_type.to_string(),
            success_rate: 1.0,
            avg_response_time_ms: response_time_ms,
            waf_bypassed,
            last_used: Instant::now(),
            use_count: 1,
        };

        if let Some(history) = self.payloads.get_mut(&key) {
            // Check if payload already exists
            if let Some(existing) = history.iter_mut().find(|p| p.payload == payload) {
                existing.success_rate = (existing.success_rate * existing.use_count as f64 + 1.0)
                    / (existing.use_count + 1) as f64;
                existing.avg_response_time_ms = (existing.avg_response_time_ms
                    * existing.use_count as f64
                    + response_time_ms)
                    / (existing.use_count + 1) as f64;
                existing.use_count += 1;
                existing.last_used = Instant::now();
            } else {
                if history.len() >= MAX_PAYLOAD_HISTORY {
                    history.pop_front();
                }
                history.push_back(payload_entry);
            }
        } else {
            if self.payloads.len() < MAX_CACHE_ENTRIES {
                let mut history = VecDeque::with_capacity(MAX_PAYLOAD_HISTORY);
                history.push_back(payload_entry);
                self.payloads.insert(key, history);
            }
        }
    }

    /// Get cached payloads for an endpoint
    pub fn get_payloads(&self, endpoint: &str) -> Vec<&CachedPayload> {
        let key = Self::endpoint_key(endpoint);
        self.payloads
            .get(&key)
            .map(|h| h.iter().collect())
            .unwrap_or_default()
    }

    /// Get top performing payloads
    pub fn get_top_payloads(&self, endpoint: &str, limit: usize) -> Vec<&CachedPayload> {
        let mut payloads = self.get_payloads(endpoint);
        payloads.sort_by(|a, b| {
            b.success_rate
                .partial_cmp(&a.success_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        payloads.into_iter().take(limit).collect()
    }

    /// Record timing threshold for an endpoint
    pub fn record_timing_threshold(
        &mut self,
        endpoint: &str,
        baseline_ms: f64,
        threshold_ms: f64,
        jitter_ms: f64,
    ) {
        let key = Self::endpoint_key(endpoint);

        if let Some(threshold) = self.timing_thresholds.get_mut(&key) {
            // Update with running average
            let n = threshold.sample_count as f64;
            threshold.baseline_ms = (threshold.baseline_ms * n + baseline_ms) / (n + 1.0);
            threshold.threshold_ms = (threshold.threshold_ms * n + threshold_ms) / (n + 1.0);
            threshold.jitter_ms = (threshold.jitter_ms * n + jitter_ms) / (n + 1.0);
            threshold.sample_count += 1;
            threshold.last_updated = Instant::now();
        } else {
            if self.timing_thresholds.len() < MAX_CACHE_ENTRIES {
                self.timing_thresholds.insert(
                    key,
                    TimingThreshold {
                        endpoint: endpoint.to_string(),
                        baseline_ms,
                        threshold_ms,
                        jitter_ms,
                        sample_count: 1,
                        last_updated: Instant::now(),
                    },
                );
            }
        }
    }

    /// Get timing threshold for an endpoint
    pub fn get_timing_threshold(&self, endpoint: &str) -> Option<&TimingThreshold> {
        let key = Self::endpoint_key(endpoint);
        self.timing_thresholds.get(&key)
    }

    /// Record payload failure
    pub fn record_payload_failure(&mut self, endpoint: &str, payload: &str) {
        let key = Self::endpoint_key(endpoint);

        if let Some(history) = self.payloads.get_mut(&key) {
            if let Some(existing) = history.iter_mut().find(|p| p.payload == payload) {
                existing.success_rate =
                    (existing.success_rate * existing.use_count as f64) / (existing.use_count + 1)
                        as f64;
                existing.use_count += 1;
            }
        }
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&mut self) {
        self.fingerprints.retain(|_, fp| !fp.is_expired(self.ttl));

        self.timing_thresholds
            .retain(|_, t| t.last_updated.elapsed() < self.ttl);
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        CacheStats {
            fingerprint_count: self.fingerprints.len(),
            payload_cache_count: self.payloads.len(),
            timing_threshold_count: self.timing_thresholds.len(),
            total_cached_payloads: self.payloads.values().map(|v| v.len()).sum(),
        }
    }

    /// Clear all cache data
    pub fn clear(&mut self) {
        self.fingerprints.clear();
        self.payloads.clear();
        self.timing_thresholds.clear();
    }

    /// Set custom TTL
    pub fn set_ttl(&mut self, ttl_secs: u64) {
        self.ttl = Duration::from_secs(ttl_secs);
    }
}

impl Default for SqliCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub fingerprint_count: usize,
    pub payload_cache_count: usize,
    pub timing_threshold_count: usize,
    pub total_cached_payloads: usize,
}

/// Self-learning metrics aggregator
pub struct LearningMetrics {
    total_injections: u64,
    successful_injections: u64,
    dbms_distribution: HashMap<String, u64>,
    injection_type_distribution: HashMap<String, u64>,
}

impl LearningMetrics {
    pub fn new() -> Self {
        Self {
            total_injections: 0,
            successful_injections: 0,
            dbms_distribution: HashMap::new(),
            injection_type_distribution: HashMap::new(),
        }
    }

    /// Record an injection attempt
    pub fn record_injection(&mut self, dbms: &str, injection_type: &str, success: bool) {
        self.total_injections += 1;
        if success {
            self.successful_injections += 1;
        }

        *self.dbms_distribution.entry(dbms.to_string()).or_insert(0) += 1;
        *self.injection_type_distribution.entry(injection_type.to_string()).or_insert(0) += 1;
    }

    /// Get overall success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_injections == 0 {
            return 0.0;
        }
        self.successful_injections as f64 / self.total_injections as f64
    }

    /// Get most common DBMS
    pub fn most_common_dbms(&self) -> Option<&String> {
        self.dbms_distribution
            .iter()
            .max_by_key(|(_, v)| *v)
            .map(|(k, _)| k)
    }

    /// Get metrics summary
    pub fn get_summary(&self) -> MetricsSummary {
        MetricsSummary {
            total_attempts: self.total_injections,
            successful_attempts: self.successful_injections,
            success_rate: self.success_rate(),
            unique_dbms_count: self.dbms_distribution.len(),
            unique_injection_types: self.injection_type_distribution.len(),
        }
    }
}

impl Default for LearningMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of learning metrics
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub total_attempts: u64,
    pub successful_attempts: u64,
    pub success_rate: f64,
    pub unique_dbms_count: usize,
    pub unique_injection_types: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::sqli::time_based::DbmsType;

    #[test]
    fn test_fingerprint_recording() {
        let mut cache = SqliCache::new();

        cache.record_fingerprint(DbmsType::MySQL, "SLEEP(2)", 2500);
        
        let fp = cache.get_fingerprint("http://example.com");
        assert!(fp.is_some());
        assert_eq!(fp.unwrap().dbms_type, "MySQL");
    }

    #[test]
    fn test_payload_caching() {
        let mut cache = SqliCache::new();

        cache.cache_payload(
            "http://example.com",
            "' OR 1=1--",
            "MySQL",
            "boolean",
            100.0,
            false,
        );

        let payloads = cache.get_payloads("http://example.com");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].payload, "' OR 1=1--");
    }

    #[test]
    fn test_timing_thresholds() {
        let mut cache = SqliCache::new();

        cache.record_timing_threshold("http://example.com", 50.0, 2000.0, 500.0);

        let threshold = cache.get_timing_threshold("http://example.com");
        assert!(threshold.is_some());
        assert_eq!(threshold.unwrap().baseline_ms, 50.0);
    }

    #[test]
    fn test_cache_stats() {
        let mut cache = SqliCache::new();

        cache.record_fingerprint(DbmsType::PostgreSQL, "pg_sleep", 1500);
        cache.cache_payload("http://test.com", "test", "PG", "time", 100.0, false);

        let stats = cache.get_stats();
        assert!(stats.fingerprint_count > 0);
        assert!(stats.payload_cache_count > 0);
    }

    #[test]
    fn test_learning_metrics() {
        let mut metrics = LearningMetrics::new();

        metrics.record_injection("MySQL", "boolean", true);
        metrics.record_injection("MySQL", "boolean", true);
        metrics.record_injection("PostgreSQL", "time", false);

        assert_eq!(metrics.success_rate(), 2.0 / 3.0);
        assert_eq!(metrics.most_common_dbms(), Some(&"MySQL".to_string()));
    }
}
