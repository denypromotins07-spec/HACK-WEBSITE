//! Payload Scoring - Score payloads by response analysis
//!
//! Scores payloads based on response delta, timing anomalies, status codes,
//! reflection behavior, and error pattern detection.

use std::collections::HashMap;
use std::time::Duration;

/// Comprehensive payload score with multiple metrics
#[derive(Debug, Clone)]
pub struct PayloadScore {
    /// Unique identifier for the scored payload
    pub payload_id: String,
    /// Overall score (0.0 to 1.0)
    pub overall_score: f64,
    /// Response delta magnitude
    pub response_delta: f64,
    /// Timing anomaly score
    pub timing_score: f64,
    /// Status code score
    pub status_score: f64,
    /// Reflection detection score
    pub reflection_score: f64,
    /// Error pattern score
    pub error_score: f64,
    /// Confidence level (0.0 to 1.0)
    pub confidence: f64,
    /// Detected vulnerability class hints
    pub vulnerability_hints: Vec<String>,
}

impl PayloadScore {
    pub fn new(payload_id: impl Into<String>) -> Self {
        Self {
            payload_id: payload.into(),
            overall_score: 0.0,
            response_delta: 0.0,
            timing_score: 0.0,
            status_score: 0.0,
            reflection_score: 0.0,
            error_score: 0.0,
            confidence: 0.0,
            vulnerability_hints: Vec::new(),
        }
    }

    /// Calculate overall score from component scores
    pub fn calculate(&mut self) -> f64 {
        // Weighted scoring
        self.overall_score = 
            self.response_delta * 0.25 +
            self.timing_score * 0.20 +
            self.status_score * 0.20 +
            self.reflection_score * 0.25 +
            self.error_score * 0.10;
        
        // Cap at 1.0
        self.overall_score = self.overall_score.min(1.0);
        
        // Calculate confidence based on number of indicators
        let indicator_count = [
            self.response_delta > 0.1,
            self.timing_score > 0.1,
            self.status_score > 0.3,
            self.reflection_score > 0.1,
            self.error_score > 0.1,
        ].iter().filter(|&&b| b).count() as f64;
        
        self.confidence = (indicator_count / 5.0).min(1.0);
        
        self.overall_score
    }

    /// Create score from HTTP response comparison
    pub fn from_response_comparison(
        payload_id: &str,
        baseline_length: usize,
        response_length: usize,
        baseline_hash: u64,
        response_hash: u64,
        response_time_ms: u64,
        baseline_time_ms: u64,
        status_code: u16,
        baseline_status: u16,
        reflected: bool,
        reflection_count: usize,
        error_patterns_found: usize,
    ) -> Self {
        let mut score = Self::new(payload_id);

        // Response delta (length and content difference)
        let length_delta = if baseline_length == 0 {
            1.0
        } else {
            ((response_length as i64 - baseline_length as i64).abs() as f64 / baseline_length as f64).min(1.0)
        };
        let hash_different = baseline_hash != response_hash;
        score.response_delta = if hash_different { length_delta.max(0.5) } else { length_delta * 0.5 };

        // Timing anomaly
        if baseline_time_ms > 0 && response_time_ms > baseline_time_ms * 2 {
            score.timing_score = 1.0;
        } else if response_time_ms > 1000 {
            score.timing_score = (response_time_ms as f64 / 5000.0).min(1.0);
        } else {
            score.timing_score = 0.0;
        }

        // Status code analysis
        score.status_score = match (status_code, baseline_status) {
            (500..=599, _) => 0.8,  // Server error
            (400..=499, 200) => 0.5,  // New client error
            (200, 400..=499) => 0.3,  // Error became success
            (s, b) if s != b => 0.2,  // Any status change
            _ => 0.0,
        };

        // Reflection detection
        score.reflection_score = if reflected {
            (reflection_count as f64 * 0.2).min(1.0)
        } else {
            0.0
        };

        // Error patterns
        score.error_score = (error_patterns_found as f64 * 0.2).min(1.0);

        // Detect vulnerability hints
        score.detect_vulnerability_hints(status_code, response_time_ms, error_patterns_found, reflected);

        score.calculate();
        score
    }

    /// Detect potential vulnerability type from response patterns
    fn detect_vulnerability_hints(
        &mut self,
        status_code: u16,
        response_time_ms: u64,
        error_patterns: usize,
        reflected: bool,
    ) {
        // SQL injection hints
        if error_patterns > 0 && (status_code >= 500 || reflected) {
            self.vulnerability_hints.push("potential_sqli".to_string());
        }

        // Time-based injection hints
        if response_time_ms > 2000 {
            self.vulnerability_hints.push("potential_time_based".to_string());
        }

        // XSS hints
        if reflected && status_code == 200 {
            self.vulnerability_hints.push("potential_xss".to_string());
        }

        // Error-based hints
        if status_code >= 500 {
            self.vulnerability_hints.push("error_based".to_string());
        }
    }

    /// Check if score indicates a likely vulnerability
    pub fn is_likely_vulnerable(&self, threshold: f64) -> bool {
        self.overall_score >= threshold && self.confidence >= 0.3
    }

    /// Get severity estimate from score
    pub fn estimated_severity(&self) -> &'static str {
        if self.overall_score >= 0.8 {
            "Critical"
        } else if self.overall_score >= 0.6 {
            "High"
        } else if self.overall_score >= 0.4 {
            "Medium"
        } else if self.overall_score >= 0.2 {
            "Low"
        } else {
            "Info"
        }
    }
}

/// Response analyzer for computing payload scores
#[derive(Debug, Default)]
pub struct ResponseAnalyzer {
    /// Baseline responses per target
    baselines: HashMap<String, ResponseBaseline>,
    /// Scoring history
    score_history: Vec<PayloadScore>,
}

#[derive(Debug, Clone)]
pub struct ResponseBaseline {
    pub avg_length: usize,
    pub content_hash: u64,
    pub avg_time_ms: u64,
    pub status_code: u16,
    pub sample_count: usize,
}

impl ResponseAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set baseline for a target
    pub fn set_baseline(
        &mut self,
        target_id: &str,
        response_length: usize,
        content_hash: u64,
        response_time_ms: u64,
        status_code: u16,
    ) {
        self.baselines.insert(
            target_id.to_string(),
            ResponseBaseline {
                avg_length: response_length,
                content_hash,
                avg_time_ms,
                status_code,
                sample_count: 1,
            },
        );
    }

    /// Update baseline with new sample (running average)
    pub fn update_baseline(
        &mut self,
        target_id: &str,
        response_length: usize,
        content_hash: u64,
        response_time_ms: u64,
        status_code: u16,
    ) {
        if let Some(baseline) = self.baselines.get_mut(target_id) {
            let n = baseline.sample_count as f64;
            baseline.avg_length = ((baseline.avg_length as f64 * n + response_length as f64) / (n + 1.0)) as usize;
            baseline.avg_time_ms = ((baseline.avg_time_ms as f64 * n + response_time_ms as f64) / (n + 1.0)) as u64;
            baseline.sample_count += 1;
            
            // Update hash if significantly different
            if baseline.content_hash != content_hash {
                baseline.content_hash = content_hash;
            }
        } else {
            self.set_baseline(target_id, response_length, content_hash, response_time_ms, status_code);
        }
    }

    /// Score a response against baseline
    pub fn score_response(
        &self,
        payload_id: &str,
        target_id: &str,
        response_length: usize,
        response_hash: u64,
        response_time_ms: u64,
        status_code: u16,
        reflected: bool,
        reflection_count: usize,
        error_patterns: usize,
    ) -> PayloadScore {
        let baseline = self.baselines.get(target_id);

        let (baseline_length, baseline_hash, baseline_time, baseline_status) = match baseline {
            Some(b) => (b.avg_length, b.content_hash, b.avg_time_ms, b.status_code),
            None => (response_length, response_hash, response_time_ms, status_code),
        };

        PayloadScore::from_response_comparison(
            payload_id,
            baseline_length,
            response_length,
            baseline_hash,
            response_hash,
            response_time_ms,
            baseline_time,
            status_code,
            baseline_status,
            reflected,
            reflection_count,
            error_patterns,
        )
    }

    /// Record a score in history
    pub fn record_score(&mut self, score: PayloadScore) {
        self.score_history.push(score);
    }

    /// Get top scoring payloads
    pub fn get_top_scores(&self, count: usize) -> Vec<&PayloadScore> {
        let mut scores: Vec<&PayloadScore> = self.score_history.iter().collect();
        scores.sort_by(|a, b| {
            b.overall_score.partial_cmp(&a.overall_score).unwrap_or(std::cmp::Ordering::Equal)
        });
        scores.into_iter().take(count).collect()
    }

    /// Get scores filtered by vulnerability hint
    pub fn get_scores_by_hint(&self, hint: &str) -> Vec<&PayloadScore> {
        self.score_history
            .iter()
            .filter(|s| s.vulnerability_hints.iter().any(|h| h == hint))
            .collect()
    }

    /// Clear scoring history
    pub fn clear_history(&mut self) {
        self.score_history.clear();
    }

    /// Get average score across all tests
    pub fn average_score(&self) -> f64 {
        if self.score_history.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.score_history.iter().map(|s| s.overall_score).sum();
        sum / self.score_history.len() as f64
    }
}

/// Reflection detector for checking payload presence in response
#[derive(Debug, Default)]
pub struct ReflectionDetector {
    /// Case-sensitive matching
    case_sensitive: bool,
    /// Check for HTML-encoded variants
    check_encoded: bool,
}

impl ReflectionDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_case_sensitive(mut self, sensitive: bool) -> Self {
        self.case_sensitive = sensitive;
        self
    }

    pub fn with_encoded_check(mut self, check: bool) -> Self {
        self.check_encoded = check;
        self
    }

    /// Check if payload is reflected in response
    pub fn detect(&self, payload: &str, response_body: &str) -> (bool, usize) {
        let mut reflection_count = 0;
        
        // Direct match
        let found = if self.case_sensitive {
            response_body.contains(payload)
        } else {
            response_body.to_lowercase().contains(&payload.to_lowercase())
        };
        
        if found {
            reflection_count += response_body.matches(if self.case_sensitive { payload } else { &payload.to_lowercase() }).count();
        }

        // Check encoded variants
        if self.check_encoded && !found {
            let encoded_variants = self.generate_encoded_variants(payload);
            for variant in encoded_variants {
                if response_body.contains(&variant) {
                    reflection_count += 1;
                }
            }
        }

        (reflection_count > 0, reflection_count)
    }

    fn generate_encoded_variants(&self, payload: &str) -> Vec<String> {
        vec![
            // HTML entity encoding
            payload.replace('<', "&lt;").replace('>', "&gt;"),
            // URL encoding
            payload.replace(' ', "%20").replace('<', "%3C").replace('>', "%3E"),
            // Unicode escapes
            format!("\\u{:04x}", payload.chars().next().unwrap_or(' ') as u32),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_score_calculation() {
        let mut score = PayloadScore::new("test-payload");
        score.response_delta = 0.8;
        score.timing_score = 0.5;
        score.status_score = 0.3;
        score.reflection_score = 0.6;
        score.error_score = 0.2;

        let overall = score.calculate();
        assert!(overall > 0.4);
        assert!(overall < 1.0);
    }

    #[test]
    fn test_response_analyzer() {
        let mut analyzer = ResponseAnalyzer::new();
        
        analyzer.set_baseline("target1", 1000, 12345, 100, 200);
        
        let score = analyzer.score_response(
            "payload1",
            "target1",
            1500,
            54321,
            2500,
            500,
            true,
            2,
            1,
        );

        assert!(score.overall_score > 0.5);
        assert!(!score.vulnerability_hints.is_empty());
    }

    #[test]
    fn test_reflection_detector() {
        let detector = ReflectionDetector::new();
        
        let (found, count) = detector.detect("test", "This is a test response with test value");
        assert!(found);
        assert_eq!(count, 2);

        let (not_found, _) = detector.detect("xyz123", "No match here");
        assert!(!not_found);
    }

    #[test]
    fn test_vulnerability_detection() {
        let score = PayloadScore::from_response_comparison(
            "sqli-test",
            1000,
            1500,
            11111,
            22222,
            3000,
            100,
            500,
            200,
            true,
            1,
            2,
        );

        assert!(score.vulnerability_hints.contains(&"potential_sqli".to_string()));
        assert!(score.vulnerability_hints.contains(&"potential_time_based".to_string()));
    }
}
