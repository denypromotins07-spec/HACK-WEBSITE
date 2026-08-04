//! Differential Analysis Engine (Boolean & Time-Based)
//! 
//! Lock-free differential engine comparing true/false payload response byte-variances.
//! Uses atomic operations for thread-safety across 100 concurrent agents.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use bytes::Bytes;

use super::fingerprint::ResponseFingerprint;
use super::normalize::NormalizedBody;

/// Comparison mode for differential analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonMode {
    /// Boolean-based: compare true vs false conditions
    Boolean,
    /// Time-based: compare normal vs delayed responses
    TimeBased,
    /// Error-based: compare error vs success responses
    ErrorBased,
    /// Reflection-based: check if payload is reflected
    Reflection,
}

/// Result of differential comparison
#[derive(Debug, Clone)]
pub struct DifferentialResult {
    pub byte_variance: f64,
    pub length_delta: i64,
    pub status_changed: bool,
    pub headers_changed: bool,
    pub content_type_changed: bool,
    pub similarity_score: f64,
    pub comparison_mode: ComparisonMode,
    pub is_different: bool,
    pub confidence: f64,
}

impl DifferentialResult {
    /// Create a result indicating no baseline was available
    pub fn no_baseline() -> Self {
        Self {
            byte_variance: 0.0,
            length_delta: 0,
            status_changed: false,
            headers_changed: false,
            content_type_changed: false,
            similarity_score: 1.0,
            comparison_mode: ComparisonMode::Boolean,
            is_different: false,
            confidence: 0.0,
        }
    }
    
    /// Determine if the difference indicates a potential vulnerability
    pub fn indicates_vulnerability(&self, threshold: f64) -> bool {
        self.is_different && self.confidence >= threshold
    }
}

/// Lock-free differential engine for high-throughput comparison
pub struct DifferentialEngine {
    comparisons_count: AtomicU64,
    differences_detected: AtomicU64,
    total_bytes_compared: AtomicUsize,
}

impl DifferentialEngine {
    pub fn new() -> Self {
        Self {
            comparisons_count: AtomicU64::new(0),
            differences_detected: AtomicU64::new(0),
            total_bytes_compared: AtomicUsize::new(0),
        }
    }
    
    /// Compare two fingerprints and their associated body data
    pub fn compare(
        &self,
        baseline: &ResponseFingerprint,
        current: &ResponseFingerprint,
        current_body: &Bytes,
    ) -> DifferentialResult {
        self.comparisons_count.fetch_add(1, Ordering::Relaxed);
        
        let status_changed = baseline.status_code != current.status_code;
        let headers_changed = baseline.headers_hash != current.headers_hash;
        let content_type_changed = baseline.content_type_hash != current.content_type_hash;
        
        // Calculate byte variance using streaming approach
        let (byte_variance, length_delta) = self.calculate_byte_variance(
            baseline.stripped_length as i64,
            current_body.len() as i64,
            baseline.body_hash,
            current.body_hash,
        );
        
        self.total_bytes_compared.fetch_add(current_body.len(), Ordering::Relaxed);
        
        // Calculate similarity
        let similarity_score = self.calculate_similarity(
            status_changed,
            headers_changed,
            content_type_changed,
            byte_variance,
        );
        
        // Determine if different
        let is_different = byte_variance > 0.05 
            || status_changed 
            || length_delta.abs() > 10;
        
        // Calculate confidence based on multiple factors
        let confidence = self.calculate_confidence(
            byte_variance,
            status_changed,
            length_delta,
            similarity_score,
        );
        
        if is_different {
            self.differences_detected.fetch_add(1, Ordering::Relaxed);
        }
        
        DifferentialResult {
            byte_variance,
            length_delta,
            status_changed,
            headers_changed,
            content_type_changed,
            similarity_score,
            comparison_mode: ComparisonMode::Boolean,
            is_different,
            confidence,
        }
    }
    
    /// Compare boolean-based payloads (true vs false conditions)
    pub fn compare_boolean(
        &self,
        baseline: &ResponseFingerprint,
        true_response: &ResponseFingerprint,
        false_response: &ResponseFingerprint,
        true_body: &Bytes,
        false_body: &Bytes,
    ) -> DifferentialResult {
        // Compare true response against baseline
        let true_diff = self.compare(baseline, true_response, true_body);
        
        // Compare false response against baseline
        let false_diff = self.compare(baseline, false_response, false_body);
        
        // Compare true vs false directly
        let true_false_variance = self.calculate_direct_variance(true_body, false_body);
        
        // If true and false responses differ significantly, likely boolean-based injection
        let is_boolean_vulnerable = true_false_variance > 0.1;
        
        DifferentialResult {
            byte_variance: true_false_variance,
            length_delta: true_body.len() as i64 - false_body.len() as i64,
            status_changed: true_response.status_code != false_response.status_code,
            headers_changed: true_response.headers_hash != false_response.headers_hash,
            content_type_changed: true_response.content_type_hash != false_response.content_type_hash,
            similarity_score: 1.0 - true_false_variance,
            comparison_mode: ComparisonMode::Boolean,
            is_different: is_boolean_vulnerable,
            confidence: if is_boolean_vulnerable { 0.8 } else { 0.2 },
        }
    }
    
    /// Calculate byte variance between expected and actual
    fn calculate_byte_variance(
        &self,
        baseline_stripped: i64,
        current_length: i64,
        baseline_hash: u64,
        current_hash: u64,
    ) -> (f64, i64) {
        let length_delta = current_length - baseline_stripped;
        
        // Fast path: if hashes match, no variance
        if baseline_hash == current_hash {
            return (0.0, length_delta);
        }
        
        // Estimate variance based on length delta and hash difference
        let length_ratio = if baseline_stripped > 0 {
            (length_delta.abs() as f64 / baseline_stripped as f64).min(1.0)
        } else {
            1.0
        };
        
        // Hash difference contributes to variance estimate
        let hash_diff = (baseline_hash.wrapping_sub(current_hash) as f64).abs();
        let hash_factor = (hash_diff / u64::MAX as f64).min(1.0);
        
        let variance = (length_ratio * 0.7 + hash_factor * 0.3).min(1.0);
        
        (variance, length_delta)
    }
    
    /// Calculate direct variance between two byte arrays
    fn calculate_direct_variance(&self, a: &Bytes, b: &Bytes) -> f64 {
        if a.is_empty() && b.is_empty() {
            return 0.0;
        }
        
        if a.is_empty() || b.is_empty() {
            return 1.0;
        }
        
        let len_a = a.len();
        let len_b = b.len();
        let common_len = len_a.min(len_b);
        
        if common_len == 0 {
            return 1.0;
        }
        
        // Sample-based comparison for performance
        let sample_size = 256;
        let step = (common_len / sample_size).max(1);
        
        let mut differences = 0usize;
        let mut compared = 0usize;
        
        for i in (0..common_len).step_by(step) {
            if a[i] != b[i] {
                differences += 1;
            }
            compared += 1;
        }
        
        if compared == 0 {
            return 0.0;
        }
        
        let sample_variance = differences as f64 / compared as f64;
        
        // Factor in length difference
        let length_factor = if len_a.max(len_b) > 0 {
            (len_a.abs_diff(len_b) as f64) / (len_a.max(len_b) as f64)
        } else {
            0.0
        };
        
        (sample_variance * 0.8 + length_factor * 0.2).min(1.0)
    }
    
    /// Calculate overall similarity score
    fn calculate_similarity(
        &self,
        status_changed: bool,
        headers_changed: bool,
        content_type_changed: bool,
        byte_variance: f64,
    ) -> f64 {
        let mut score = 1.0;
        
        if status_changed {
            score -= 0.3;
        }
        
        if headers_changed {
            score -= 0.2;
        }
        
        if content_type_changed {
            score -= 0.1;
        }
        
        score -= byte_variance * 0.4;
        
        score.max(0.0)
    }
    
    /// Calculate confidence in the differential result
    fn calculate_confidence(
        &self,
        byte_variance: f64,
        status_changed: bool,
        length_delta: i64,
        similarity_score: f64,
    ) -> f64 {
        let mut confidence = 0.0;
        
        // High byte variance increases confidence
        confidence += byte_variance.min(1.0) * 0.4;
        
        // Status code change is strong indicator
        if status_changed {
            confidence += 0.3;
        }
        
        // Significant length change
        if length_delta.abs() > 50 {
            confidence += 0.2;
        } else if length_delta.abs() > 10 {
            confidence += 0.1;
        }
        
        // Low similarity increases confidence
        confidence += (1.0 - similarity_score) * 0.1;
        
        confidence.min(1.0)
    }
    
    /// Get statistics
    pub fn stats(&self) -> DifferentialStats {
        DifferentialStats {
            comparisons_count: self.comparisons_count.load(Ordering::Relaxed),
            differences_detected: self.differences_detected.load(Ordering::Relaxed),
            total_bytes_compared: self.total_bytes_compared.load(Ordering::Relaxed),
        }
    }
    
    /// Reset statistics
    pub fn reset_stats(&self) {
        self.comparisons_count.store(0, Ordering::Relaxed);
        self.differences_detected.store(0, Ordering::Relaxed);
        self.total_bytes_compared.store(0, Ordering::Relaxed);
    }
}

impl Default for DifferentialEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for differential analysis
#[derive(Debug, Clone)]
pub struct DifferentialStats {
    pub comparisons_count: u64,
    pub differences_detected: u64,
    pub total_bytes_compared: usize,
}

impl DifferentialStats {
    pub fn difference_rate(&self) -> f64 {
        if self.comparisons_count == 0 {
            return 0.0;
        }
        self.differences_detected as f64 / self.comparisons_count as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::fingerprint::ResponseFingerprint;
    
    #[test]
    fn test_differential_engine_creation() {
        let engine = DifferentialEngine::new();
        let stats = engine.stats();
        assert_eq!(stats.comparisons_count, 0);
    }
    
    #[test]
    fn test_compare_identical() {
        let engine = DifferentialEngine::new();
        
        let body = Bytes::from("Hello World");
        let headers = vec![];
        
        let fp = ResponseFingerprint::new(&body, &headers, 200, "text/plain", 1000);
        
        let result = engine.compare(&fp, &fp, &body);
        
        assert_eq!(result.byte_variance, 0.0);
        assert!(!result.is_different);
    }
    
    #[test]
    fn test_no_baseline() {
        let result = DifferentialResult::no_baseline();
        assert!(!result.is_different);
        assert_eq!(result.confidence, 0.0);
    }
}
