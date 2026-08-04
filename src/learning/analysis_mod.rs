//! Analysis Feedback Loop Module
//! 
//! Wires the analysis feedback loop into the global self-learning registry 
//! for continuous improvement.

pub mod fp_reduction;
pub mod baseline_cache;

use std::sync::Arc;
use std::time::Instant;

pub use fp_reduction::{BayesianFilter, BayesianResult, BayesianStats};
pub use baseline_cache::{BaselineCache, BaselineFingerprint, BaselineStats};

/// Global learning context for analysis feedback
pub struct AnalysisLearningContext {
    pub bayesian_filter: Arc<parking_lot::RwLock<BayesianFilter>>,
    pub baseline_cache: Arc<parking_lot::RwLock<BaselineCache>>,
    
    /// Total feedback events processed
    feedback_processed: std::sync::atomic::AtomicU64,
    
    /// Positive feedback count
    positive_feedback: std::sync::atomic::AtomicU64,
    
    /// Negative feedback count (false positives)
    negative_feedback: std::sync::atomic::AtomicU64,
}

impl AnalysisLearningContext {
    pub fn new() -> Self {
        Self {
            bayesian_filter: Arc::new(parking_lot::RwLock::new(BayesianFilter::new())),
            baseline_cache: Arc::new(parking_lot::RwLock::new(BaselineCache::default())),
            feedback_processed: std::sync::atomic::AtomicU64::new(0),
            positive_feedback: std::sync::atomic::AtomicU64::new(0),
            negative_feedback: std::sync::atomic::AtomicU64::new(0),
        }
    }
    
    /// Record positive feedback for a detection
    pub fn record_positive(&self, features: &[String]) {
        self.positive_feedback.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.feedback_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        let mut filter = self.bayesian_filter.write();
        filter.record_true_positive(features);
    }
    
    /// Record negative feedback (false positive)
    pub fn record_negative(&self, features: &[String]) {
        self.negative_feedback.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.feedback_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        let mut filter = self.bayesian_filter.write();
        filter.record_false_positive(features);
    }
    
    /// Adjust a score based on learned feedback
    pub fn adjust_score(&self, original_score: f64, features: &[String]) -> f64 {
        let filter = self.bayesian_filter.read();
        filter.adjust_score(original_score, features)
    }
    
    /// Get or create baseline for URL
    pub fn get_or_create_baseline(
        &self,
        url_hash: u64,
        body: &bytes::Bytes,
        headers: &[(String, String)],
        status_code: u16,
        timing_ns: u64,
    ) -> BaselineFingerprint {
        let mut cache = self.baseline_cache.write();
        cache.get_or_create(url_hash, body, headers, status_code, timing_ns).clone()
    }
    
    /// Check if baseline exists
    pub fn has_baseline(&self, url_hash: u64) -> bool {
        let mut cache = self.baseline_cache.write();
        cache.get(url_hash).is_some()
    }
    
    /// Get statistics
    pub fn stats(&self) -> AnalysisLearningStats {
        let filter_stats = self.bayesian_filter.read().stats();
        let cache_stats = self.baseline_cache.read().stats();
        
        AnalysisLearningStats {
            feedback_processed: self.feedback_processed.load(std::sync::atomic::Ordering::Relaxed),
            positive_feedback: self.positive_feedback.load(std::sync::atomic::Ordering::Relaxed),
            negative_feedback: self.negative_feedback.load(std::sync::atomic::Ordering::Relaxed),
            bayesian_feature_count: filter_stats.feature_count,
            cached_baselines: cache_stats.cached_entries,
            cache_hit_rate: cache_stats.hit_rate(),
            false_positive_rate: filter_stats.false_positive_rate(),
        }
    }
    
    /// Reset all learning data
    pub fn reset(&self) {
        self.bayesian_filter.write().reset();
        self.baseline_cache.write().clear();
        self.feedback_processed.store(0, std::sync::atomic::Ordering::Relaxed);
        self.positive_feedback.store(0, std::sync::atomic::Ordering::Relaxed);
        self.negative_feedback.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for AnalysisLearningContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for analysis learning
#[derive(Debug, Clone)]
pub struct AnalysisLearningStats {
    pub feedback_processed: u64,
    pub positive_feedback: u64,
    pub negative_feedback: u64,
    pub bayesian_feature_count: usize,
    pub cached_baselines: usize,
    pub cache_hit_rate: f64,
    pub false_positive_rate: f64,
}

impl AnalysisLearningStats {
    pub fn positive_ratio(&self) -> f64 {
        let total = self.positive_feedback + self.negative_feedback;
        if total == 0 {
            return 0.0;
        }
        self.positive_feedback as f64 / total as f64
    }
}

/// Trait for components that provide feedback
pub trait FeedbackProvider: Send + Sync {
    /// Extract features from analysis result
    fn extract_features(&self) -> Vec<String>;
    
    /// Get confidence score
    fn confidence(&self) -> f64;
}

/// Feedback event for learning
#[derive(Debug, Clone)]
pub struct FeedbackEvent {
    pub request_id: u64,
    pub target_url: String,
    pub vulnerability_type: String,
    pub features: Vec<String>,
    pub is_confirmed: bool,
    pub confidence: f64,
    pub timestamp: Instant,
}

impl FeedbackEvent {
    pub fn new(
        request_id: u64,
        target_url: String,
        vulnerability_type: String,
        features: Vec<String>,
        is_confirmed: bool,
    ) -> Self {
        Self {
            request_id,
            target_url,
            vulnerability_type,
            features,
            is_confirmed,
            confidence: 0.5,
            timestamp: Instant::now(),
        }
    }
    
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_learning_context_creation() {
        let ctx = AnalysisLearningContext::new();
        let stats = ctx.stats();
        assert_eq!(stats.feedback_processed, 0);
    }
    
    #[test]
    fn test_record_feedback() {
        let ctx = AnalysisLearningContext::new();
        
        ctx.record_positive(&["sql_error".to_string()]);
        ctx.record_negative(&["waf_block".to_string()]);
        
        let stats = ctx.stats();
        assert_eq!(stats.feedback_processed, 2);
        assert_eq!(stats.positive_feedback, 1);
        assert_eq!(stats.negative_feedback, 1);
    }
    
    #[test]
    fn test_score_adjustment() {
        let ctx = AnalysisLearningContext::new();
        
        // Train with some false positives
        ctx.record_negative(&["pattern_x".to_string()]);
        ctx.record_negative(&["pattern_x".to_string()]);
        
        let adjusted = ctx.adjust_score(0.9, &["pattern_x".to_string()]);
        
        assert!(adjusted < 0.9);
    }
}
