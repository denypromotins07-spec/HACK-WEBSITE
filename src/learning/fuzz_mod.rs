//! Fuzz Module - Wire fuzzing feedback into the global self-learning subsystem
//!
//! Connects payload scoring, caching, and mutation engines to enable
//! continuous learning and improvement across scan sessions.

use crate::learning::payload_score::{PayloadScore, ResponseAnalyzer, ReflectionDetector};
use crate::learning::fuzz_cache::{FuzzCache, CachedPattern};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Learning event types for the fuzz subsystem
#[derive(Debug, Clone)]
pub enum LearningEvent {
    /// Payload was tested with result
    PayloadTested {
        payload_id: String,
        target_id: String,
        score: PayloadScore,
    },
    /// Pattern was cached for reuse
    PatternCached {
        pattern_id: String,
        vuln_class: String,
        success_rate: f64,
    },
    /// Mutation strategy updated
    MutationUpdated {
        mutation_type: String,
        weight_change: f64,
    },
    /// New vulnerability signature learned
    SignatureLearned {
        signature: String,
        confidence: f64,
    },
}

/// Fuzz learning module configuration
#[derive(Debug, Clone)]
pub struct FuzzLearningConfig {
    /// Enable persistent caching
    pub enable_caching: bool,
    /// Cache file path
    pub cache_path: Option<String>,
    /// Minimum score to consider successful
    pub success_threshold: f64,
    /// Maximum patterns to cache
    pub max_cached_patterns: usize,
    /// Enable cross-target learning
    pub cross_target_learning: bool,
    /// Learning rate for weight adjustments
    pub learning_rate: f64,
}

impl Default for FuzzLearningConfig {
    fn default() -> Self {
        Self {
            enable_caching: true,
            cache_path: None,
            success_threshold: 0.5,
            max_cached_patterns: 10000,
            cross_target_learning: true,
            learning_rate: 0.1,
        }
    }
}

/// Main fuzz learning module that coordinates all learning components
pub struct FuzzLearningModule {
    config: FuzzLearningConfig,
    analyzer: ResponseAnalyzer,
    cache: FuzzCache,
    reflection_detector: ReflectionDetector,
    event_log: Vec<LearningEvent>,
}

impl FuzzLearningModule {
    /// Create a new fuzz learning module
    pub fn new(config: FuzzLearningConfig) -> Self {
        let mut cache = FuzzCache::new();
        
        if config.enable_caching {
            if let Some(ref path) = config.cache_path {
                cache = FuzzCache::with_persistence(path)
                    .with_max_size(config.max_cached_patterns);
                
                // Load existing cache
                let _ = cache.load();
            }
        }

        Self {
            config,
            analyzer: ResponseAnalyzer::new(),
            cache,
            reflection_detector: ReflectionDetector::new().with_encoded_check(true),
            event_log: Vec::new(),
        }
    }

    /// Process a test result and update learning state
    pub fn process_test_result(
        &mut self,
        payload_id: &str,
        target_id: &str,
        baseline_length: usize,
        response_length: usize,
        baseline_hash: u64,
        response_hash: u64,
        response_time_ms: u64,
        baseline_time_ms: u64,
        status_code: u16,
        baseline_status: u16,
        response_body: &str,
        payload_content: &str,
    ) -> PayloadScore {
        // Detect reflection
        let (reflected, reflection_count) = self.reflection_detector.detect(payload_content, response_body);

        // Count error patterns in response
        let error_patterns = self.count_error_patterns(response_body);

        // Score the response
        let score = self.analyzer.score_response(
            payload_id,
            target_id,
            response_length,
            response_hash,
            response_time_ms,
            status_code,
            reflected,
            reflection_count,
            error_patterns,
        );

        // Record in analyzer history
        self.analyzer.record_score(score.clone());

        // Check if this is a successful finding
        if score.overall_score >= self.config.success_threshold {
            self.handle_successful_payload(payload_id, target_id, &score);
        }

        // Log the event
        self.event_log.push(LearningEvent::PayloadTested {
            payload_id: payload_id.to_string(),
            target_id: target_id.to_string(),
            score: score.clone(),
        });

        score
    }

    /// Handle a successful payload detection
    fn handle_successful_payload(&mut self, payload_id: &str, target_id: &str, score: &PayloadScore) {
        // Extract pattern from payload ID or content
        let pattern_id = format!("learned-{}", payload_id);
        
        // Create a cached pattern
        let mut pattern = CachedPattern::new(
            payload_id,
            "mutation",
            score.vulnerability_hints.first().cloned().unwrap_or_else(|| "unknown".to_string()),
        );
        pattern.result = payload_id.to_string();
        pattern.record_success(target_id);

        // Cache the pattern
        self.cache.add_pattern(&pattern_id, pattern);

        // Log the caching event
        self.event_log.push(LearningEvent::PatternCached {
            pattern_id,
            vuln_class: score.vulnerability_hints.first().cloned().unwrap_or_default(),
            success_rate: pattern.success_rate(),
        });
    }

    /// Count error patterns in response body
    fn count_error_patterns(&self, body: &str) -> usize {
        let error_indicators = [
            "SQL syntax",
            "ORA-",
            "PostgreSQL",
            "MySQL",
            "sqlite",
            "exception",
            "stack trace",
            "fatal error",
            "warning:",
            "error on line",
            "undefined variable",
            "null pointer",
            "access denied",
            "permission denied",
        ];

        error_indicators.iter()
            .filter(|&&indicator| body.to_lowercase().contains(&indicator.to_lowercase()))
            .count()
    }

    /// Get recommended payloads for a vulnerability class based on cache
    pub fn get_recommended_payloads(&self, vuln_class: &str) -> Vec<&CachedPattern> {
        self.cache.get_best_patterns(1)
            .into_iter()
            .filter(|p| p.vuln_class == vuln_class || self.config.cross_target_learning)
            .collect()
    }

    /// Get retry candidates from cache
    pub fn get_retry_candidates(&self) -> Vec<&CachedPattern> {
        self.cache.get_retry_candidates()
    }

    /// Update baseline for a target
    pub fn update_baseline(
        &mut self,
        target_id: &str,
        response_length: usize,
        content_hash: u64,
        response_time_ms: u64,
        status_code: u16,
    ) {
        self.analyzer.update_baseline(target_id, response_length, content_hash, response_time_ms, status_code);
    }

    /// Set initial baseline for a target
    pub fn set_baseline(
        &mut self,
        target_id: &str,
        response_length: usize,
        content_hash: u64,
        response_time_ms: u64,
        status_code: u16,
    ) {
        self.analyzer.set_baseline(target_id, response_length, content_hash, response_time_ms, status_code);
    }

    /// Get top scoring payloads from history
    pub fn get_top_scores(&self, count: usize) -> Vec<&PayloadScore> {
        self.analyzer.get_top_scores(count)
    }

    /// Save cache to disk
    pub fn save_cache(&self) -> Result<(), std::io::Error> {
        self.cache.save()
    }

    /// Load cache from disk
    pub fn load_cache(&mut self) -> Result<(), std::io::Error> {
        self.cache.load()
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> crate::learning::fuzz_cache::FuzzCacheStats {
        self.cache.stats()
    }

    /// Get average score across all tests
    pub fn average_score(&self) -> f64 {
        self.analyzer.average_score()
    }

    /// Clear learning history (but keep cache)
    pub fn clear_history(&mut self) {
        self.analyzer.clear_history();
        self.event_log.clear();
    }

    /// Reset everything including cache
    pub fn reset(&mut self) {
        self.cache.clear();
        self.clear_history();
    }

    /// Get recent learning events
    pub fn get_recent_events(&self, count: usize) -> &[LearningEvent] {
        let start = self.event_log.len().saturating_sub(count);
        &self.event_log[start..]
    }

    /// Export learning data for external analysis
    pub fn export_learning_data(&self) -> LearningDataExport {
        LearningDataExport {
            top_scores: self.analyzer.get_top_scores(100).iter().map(|s| s.payload_id.clone()).collect(),
            cached_patterns: self.cache.stats().total_patterns,
            avg_success_rate: self.cache.stats().avg_success_rate,
            total_tests: self.event_log.len(),
        }
    }
}

/// Thread-safe shared fuzz learning module
#[derive(Clone)]
pub struct SharedFuzzLearningModule {
    inner: Arc<RwLock<FuzzLearningModule>>,
}

impl SharedFuzzLearningModule {
    pub fn new(module: FuzzLearningModule) -> Self {
        Self {
            inner: Arc::new(RwLock::new(module)),
        }
    }

    pub async fn process_test_result(
        &self,
        payload_id: &str,
        target_id: &str,
        baseline_length: usize,
        response_length: usize,
        baseline_hash: u64,
        response_hash: u64,
        response_time_ms: u64,
        baseline_time_ms: u64,
        status_code: u16,
        baseline_status: u16,
        response_body: String,
        payload_content: String,
    ) -> PayloadScore {
        let mut module = self.inner.write().await;
        module.process_test_result(
            payload_id,
            target_id,
            baseline_length,
            response_length,
            baseline_hash,
            response_hash,
            response_time_ms,
            baseline_time_ms,
            status_code,
            baseline_status,
            &response_body,
            &payload_content,
        )
    }

    pub async fn get_recommended(&self, vuln_class: &str) -> Vec<CachedPattern> {
        let module = self.inner.read().await;
        module.get_recommended_payloads(vuln_class).iter().map(|p| (*p).clone()).collect()
    }

    pub async fn save_cache(&self) -> Result<(), std::io::Error> {
        let module = self.inner.read().await;
        module.save_cache()
    }
}

/// Exported learning data summary
#[derive(Debug)]
pub struct LearningDataExport {
    pub top_scores: Vec<String>,
    pub cached_patterns: usize,
    pub avg_success_rate: f64,
    pub total_tests: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_learning_module_creation() {
        let config = FuzzLearningConfig::default();
        let module = FuzzLearningModule::new(config);
        
        assert_eq!(module.average_score(), 0.0);
    }

    #[test]
    fn test_process_test_result() {
        let config = FuzzLearningConfig::default();
        let mut module = FuzzLearningModule::new(config);
        
        module.set_baseline("target1", 1000, 12345, 100, 200);
        
        let score = module.process_test_result(
            "payload1",
            "target1",
            1000,
            1500,
            12345,
            54321,
            2500,
            100,
            500,
            200,
            "Error: SQL syntax near ' OR",
            "' OR '1'='1",
        );

        assert!(score.overall_score > 0.3);
        assert!(!score.vulnerability_hints.is_empty());
    }

    #[test]
    fn test_error_pattern_detection() {
        let module = FuzzLearningModule::new(FuzzLearningConfig::default());
        
        let body = "Internal Server Error: SQL syntax error near 'SELECT'";
        let count = module.count_error_patterns(body);
        assert!(count >= 1);
    }

    #[test]
    fn test_learning_event_logging() {
        let config = FuzzLearningConfig::default();
        let mut module = FuzzLearningModule::new(config);
        
        module.set_baseline("t", 100, 1, 10, 200);
        module.process_test_result(
            "p1", "t", 100, 150, 1, 2, 100, 10, 200, 200, "body", "payload",
        );
        
        assert!(!module.get_recent_events(1).is_empty());
    }
}
