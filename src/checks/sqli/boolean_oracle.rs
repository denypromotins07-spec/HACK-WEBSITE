//! Boolean Oracle for SQL Injection Detection
//! Build inference oracle to extract confidence scores from binary response shifts.

use std::collections::{HashMap, VecDeque};

/// Maximum history size for bounded memory
const MAX_HISTORY: usize = 200;

/// Confidence score range
const MIN_CONFIDENCE: f64 = 0.0;
const MAX_CONFIDENCE: f64 = 1.0;

/// Binary response classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryResponse {
    True,
    False,
    Error,
    Timeout,
}

/// Inference result with confidence scoring
#[derive(Debug, Clone)]
pub struct InferenceResult {
    pub dbms_type: Option<String>,
    pub confidence: f64,
    pub true_response_pattern: String,
    pub false_response_pattern: String,
    pub test_count: usize,
    pub success_rate: f64,
}

/// Historical test record
#[derive(Debug, Clone)]
struct TestRecord {
    payload: String,
    expected: BinaryResponse,
    actual: BinaryResponse,
    response_hash: u64,
    content_length: usize,
}

/// Boolean inference oracle
pub struct BooleanOracle {
    history: VecDeque<TestRecord>,
    response_patterns: HashMap<u64, BinaryResponse>,
    confidence_scores: HashMap<String, f64>,
    true_pattern_hashes: Vec<u64>,
    false_pattern_hashes: Vec<u64>,
}

impl BooleanOracle {
    /// Create a new boolean oracle with bounded storage
    pub fn new() -> Self {
        Self {
            history: VecDeque::with_capacity(MAX_HISTORY),
            response_patterns: HashMap::new(),
            confidence_scores: HashMap::new(),
            true_pattern_hashes: Vec::with_capacity(50),
            false_pattern_hashes: Vec::with_capacity(50),
        }
    }

    /// Record a test result for pattern learning
    pub fn record_test(
        &mut self,
        payload: &str,
        expected: BinaryResponse,
        actual: BinaryResponse,
        response_hash: u64,
        content_length: usize,
    ) {
        let record = TestRecord {
            payload: payload.to_string(),
            expected,
            actual,
            response_hash,
            content_length,
        };

        // Maintain bounded history
        if self.history.len() >= MAX_HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(record);

        // Update pattern mapping
        self.response_patterns.insert(response_hash, actual);

        // Track pattern hashes by response type
        match actual {
            BinaryResponse::True => {
                if !self.true_pattern_hashes.contains(&response_hash) {
                    if self.true_pattern_hashes.len() < 50 {
                        self.true_pattern_hashes.push(response_hash);
                    }
                }
            }
            BinaryResponse::False => {
                if !self.false_pattern_hashes.contains(&response_hash) {
                    if self.false_pattern_hashes.len() < 50 {
                        self.false_pattern_hashes.push(response_hash);
                    }
                }
            }
            _ => {}
        }

        // Update confidence score for this payload pattern
        self.update_confidence(payload, expected == actual);
    }

    /// Update confidence score for a payload pattern
    fn update_confidence(&mut self, payload: &str, success: bool) {
        let score = self.confidence_scores.entry(payload.to_string()).or_insert(0.5);

        let adjustment = if success { 0.05 } else { -0.03 };
        *score = (*score + adjustment).clamp(MIN_CONFIDENCE, MAX_CONFIDENCE);
    }

    /// Classify a response hash as true or false based on learned patterns
    pub fn classify_response(&self, response_hash: u64) -> Option<BinaryResponse> {
        // Check if we've seen this exact hash before
        if let Some(&response) = self.response_patterns.get(&response_hash) {
            return Some(response);
        }

        // Check similarity to known true patterns
        let true_similarity = self.calculate_pattern_similarity(
            response_hash,
            &self.true_pattern_hashes,
        );

        // Check similarity to known false patterns
        let false_similarity = self.calculate_pattern_similarity(
            response_hash,
            &self.false_pattern_hashes,
        );

        if true_similarity > false_similarity && true_similarity > 0.7 {
            Some(BinaryResponse::True)
        } else if false_similarity > true_similarity && false_similarity > 0.7 {
            Some(BinaryResponse::False)
        } else {
            None
        }
    }

    /// Calculate similarity between a hash and a set of known pattern hashes
    fn calculate_pattern_similarity(&self, hash: u64, known_hashes: &[u64]) -> f64 {
        if known_hashes.is_empty() {
            return 0.0;
        }

        // Simple hash proximity check (in production, would use more sophisticated comparison)
        let matches = known_hashes.iter().filter(|&&h| h == hash).count();
        matches as f64 / known_hashes.len() as f64
    }

    /// Extract confidence score for a specific payload
    pub fn get_confidence(&self, payload: &str) -> f64 {
        *self.confidence_scores.get(payload).unwrap_or(&0.5)
    }

    /// Perform inference on test results to determine SQLi likelihood
    pub fn infer(&self, true_tests: usize, false_tests: usize) -> InferenceResult {
        let total_tests = true_tests + false_tests;

        if total_tests == 0 {
            return InferenceResult {
                dbms_type: None,
                confidence: 0.0,
                true_response_pattern: String::new(),
                false_response_pattern: String::new(),
                test_count: 0,
                success_rate: 0.0,
            };
        }

        // Calculate base confidence from test distribution
        let true_ratio = true_tests as f64 / total_tests as f64;
        let false_ratio = false_tests as f64 / total_tests as f64;

        // Higher confidence when there's a clear distinction
        let distinction = (true_ratio - false_ratio).abs();
        let base_confidence = distinction * 0.8;

        // Adjust based on historical success rates
        let avg_historical_confidence = if self.confidence_scores.is_empty() {
            0.5
        } else {
            self.confidence_scores.values().sum::<f64>() / self.confidence_scores.len() as f64
        };

        let final_confidence = (base_confidence + avg_historical_confidence) / 2.0;

        // Generate pattern descriptions
        let true_pattern = format!(
            "True responses: {} ({:.1}%)",
            true_tests,
            true_ratio * 100.0
        );
        let false_pattern = format!(
            "False responses: {} ({:.1}%)",
            false_tests,
            false_ratio * 100.0
        );

        InferenceResult {
            dbms_type: None, // Would be set based on successful payloads
            confidence: final_confidence.clamp(MIN_CONFIDENCE, MAX_CONFIDENCE),
            true_response_pattern: true_pattern,
            false_response_pattern: false_pattern,
            test_count: total_tests,
            success_rate: avg_historical_confidence,
        }
    }

    /// Get the most confident payload patterns
    pub fn get_top_patterns(&self, limit: usize) -> Vec<(String, f64)> {
        let mut sorted: Vec<_> = self.confidence_scores.iter().collect();
        sorted.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
        sorted
            .into_iter()
            .take(limit)
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    /// Reset oracle state
    pub fn reset(&mut self) {
        self.history.clear();
        self.response_patterns.clear();
        self.confidence_scores.clear();
        self.true_pattern_hashes.clear();
        self.false_pattern_hashes.clear();
    }

    /// Get statistics about oracle state
    pub fn get_stats(&self) -> OracleStats {
        OracleStats {
            history_size: self.history.len(),
            pattern_count: self.response_patterns.len(),
            true_patterns: self.true_pattern_hashes.len(),
            false_patterns: self.false_pattern_hashes.len(),
            confidence_entries: self.confidence_scores.len(),
            avg_confidence: if self.confidence_scores.is_empty() {
                0.0
            } else {
                self.confidence_scores.values().sum::<f64>()
                    / self.confidence_scores.len() as f64
            },
        }
    }
}

impl Default for BooleanOracle {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about oracle state
#[derive(Debug, Clone)]
pub struct OracleStats {
    pub history_size: usize,
    pub pattern_count: usize,
    pub true_patterns: usize,
    pub false_patterns: usize,
    pub confidence_entries: usize,
    pub avg_confidence: f64,
}

/// Response shift detector for binary differential analysis
pub struct ResponseShiftDetector {
    baseline_hash: Option<u64>,
    baseline_length: Option<usize>,
    shift_threshold: f64,
}

impl ResponseShiftDetector {
    pub fn new() -> Self {
        Self {
            baseline_hash: None,
            baseline_length: None,
            shift_threshold: 0.3, // 30% change threshold
        }
    }

    /// Set baseline response characteristics
    pub fn set_baseline(&mut self, hash: u64, length: usize) {
        self.baseline_hash = Some(hash);
        self.baseline_length = Some(length);
    }

    /// Detect if a response represents a significant shift from baseline
    pub fn detect_shift(&self, test_hash: u64, test_length: usize) -> ShiftResult {
        let baseline_hash = self.baseline_hash.unwrap_or(0);
        let baseline_length = self.baseline_length.unwrap_or(0);

        let hash_match = baseline_hash == test_hash;
        
        let length_delta = if baseline_length > 0 {
            ((test_length as i64 - baseline_length as i64).abs() as f64)
                / baseline_length as f64
        } else {
            0.0
        };

        let is_significant_shift = !hash_match || length_delta > self.shift_threshold;

        ShiftResult {
            hash_changed: !hash_match,
            length_delta,
            is_significant: is_significant_shift,
            confidence: if hash_match { 0.9 } else { 0.5 },
        }
    }

    /// Reset detector state
    pub fn reset(&mut self) {
        self.baseline_hash = None;
        self.baseline_length = None;
    }
}

impl Default for ResponseShiftDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of shift detection
#[derive(Debug, Clone)]
pub struct ShiftResult {
    pub hash_changed: bool,
    pub length_delta: f64,
    pub is_significant: bool,
    pub confidence: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oracle_recording() {
        let mut oracle = BooleanOracle::new();

        oracle.record_test("payload1", BinaryResponse::True, BinaryResponse::True, 12345, 1000);
        oracle.record_test("payload2", BinaryResponse::False, BinaryResponse::False, 67890, 500);

        assert_eq!(oracle.get_confidence("payload1"), 0.55);
        assert_eq!(oracle.get_confidence("payload2"), 0.55);
    }

    #[test]
    fn test_inference() {
        let oracle = BooleanOracle::new();
        let result = oracle.infer(8, 2);

        assert!(result.confidence > 0.5);
        assert_eq!(result.test_count, 10);
    }

    #[test]
    fn test_shift_detection() {
        let mut detector = ResponseShiftDetector::new();
        detector.set_baseline(12345, 1000);

        let same = detector.detect_shift(12345, 1000);
        let different = detector.detect_shift(67890, 500);

        assert!(!same.is_significant);
        assert!(different.is_significant);
    }

    #[test]
    fn test_oracle_stats() {
        let mut oracle = BooleanOracle::new();

        for i in 0..10 {
            oracle.record_test(
                &format!("payload{}", i),
                BinaryResponse::True,
                BinaryResponse::True,
                i as u64 * 1000,
                1000,
            );
        }

        let stats = oracle.get_stats();
        assert_eq!(stats.history_size, 10);
        assert_eq!(stats.pattern_count, 10);
    }
}
