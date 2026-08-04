//! Blind Vulnerability Detection Heuristics
//! 
//! Implements heuristic state machines for detecting blind injection 
//! without direct output reflection.

use std::sync::atomic::{AtomicU64, Ordering};
use bytes::Bytes;

use super::timing::TimingResult;
use super::differential::DifferentialResult;

/// State in the blind detection state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindState {
    Initial,
    TestingBooleanTrue,
    TestingBooleanFalse,
    TestingTimeDelay,
    AnalyzingDifferential,
    ConfirmedVulnerable,
    ConfirmedSafe,
    Uncertain,
}

/// Confidence level for blind detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindConfidence {
    None,
    Low,
    Medium,
    High,
    Certain,
}

impl BlindConfidence {
    pub fn score(&self) -> f64 {
        match self {
            Self::None => 0.0,
            Self::Low => 0.25,
            Self::Medium => 0.5,
            Self::High => 0.75,
            Self::Certain => 1.0,
        }
    }
    
    pub fn from_score(score: f64) -> Self {
        if score >= 0.9 {
            Self::Certain
        } else if score >= 0.7 {
            Self::High
        } else if score >= 0.4 {
            Self::Medium
        } else if score >= 0.1 {
            Self::Low
        } else {
            Self::None
        }
    }
}

/// Result of blind injection detection
#[derive(Debug, Clone)]
pub struct BlindDetectionResult {
    pub state: BlindState,
    pub confidence: BlindConfidence,
    pub is_vulnerable: bool,
    pub vulnerability_type: Option<BlindVulnerabilityType>,
    pub evidence_count: u32,
    pub score: f64,
}

/// Type of blind vulnerability detected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindVulnerabilityType {
    BooleanBasedSqlI,
    TimeBasedSqlI,
    BooleanBasedRce,
    TimeBasedRce,
    BlindSsrf,
    BlindXxe,
}

/// Lock-free blind detector using heuristic state machines
pub struct BlindDetector {
    tests_run: AtomicU64,
    vulnerabilities_found: AtomicU64,
    false_positives_avoided: AtomicU64,
}

impl BlindDetector {
    pub fn new() -> Self {
        Self {
            tests_run: AtomicU64::new(0),
            vulnerabilities_found: AtomicU64::new(0),
            false_positives_avoided: AtomicU64::new(0),
        }
    }
    
    /// Analyze boolean-based blind injection
    pub fn analyze_boolean(
        &self,
        true_result: &DifferentialResult,
        false_result: &DifferentialResult,
    ) -> BlindDetectionResult {
        self.tests_run.fetch_add(1, Ordering::Relaxed);
        
        let mut score = 0.0;
        let mut evidence_count = 0u32;
        
        // Check if true and false responses differ significantly
        if true_result.is_different && !false_result.is_different {
            score += 0.3;
            evidence_count += 1;
        }
        
        // Check confidence difference
        let confidence_diff = true_result.confidence - false_result.confidence;
        if confidence_diff > 0.3 {
            score += 0.2;
            evidence_count += 1;
        }
        
        // Check byte variance difference
        let variance_diff = true_result.byte_variance - false_result.byte_variance;
        if variance_diff > 0.1 {
            score += 0.2;
            evidence_count += 1;
        }
        
        // Check status code behavior
        if true_result.status_changed != false_result.status_changed {
            score += 0.15;
            evidence_count += 1;
        }
        
        // Check length delta difference
        let length_diff = (true_result.length_delta - false_result.length_delta).abs();
        if length_diff > 20 {
            score += 0.15;
            evidence_count += 1;
        }
        
        let confidence = BlindConfidence::from_score(score);
        let is_vulnerable = score >= 0.5;
        
        if is_vulnerable {
            self.vulnerabilities_found.fetch_add(1, Ordering::Relaxed);
        } else if score < 0.2 {
            self.false_positives_avoided.fetch_add(1, Ordering::Relaxed);
        }
        
        BlindDetectionResult {
            state: if is_vulnerable { 
                BlindState::ConfirmedVulnerable 
            } else { 
                BlindState::ConfirmedSafe 
            },
            confidence,
            is_vulnerable,
            vulnerability_type: if is_vulnerable { 
                Some(BlindVulnerabilityType::BooleanBasedSqlI) 
            } else { 
                None 
            },
            evidence_count,
            score,
        }
    }
    
    /// Analyze time-based blind injection
    pub fn analyze_time_based(
        &self,
        baseline_timing: &TimingResult,
        payload_timing: &TimingResult,
        differential: &DifferentialResult,
    ) -> BlindDetectionResult {
        self.tests_run.fetch_add(1, Ordering::Relaxed);
        
        let mut score = 0.0;
        let mut evidence_count = 0u32;
        
        // Check if payload timing is anomalous
        if payload_timing.is_anomalous {
            score += 0.3;
            evidence_count += 1;
        }
        
        // Check timing delta
        let timing_delta = payload_timing.elapsed_ns.saturating_sub(baseline_timing.elapsed_ns);
        if timing_delta >= 100_000_000 { // 100ms
            score += 0.3;
            evidence_count += 1;
        }
        
        // Check if response is otherwise similar (indicating blind vs reflected)
        if !differential.is_different && payload_timing.is_anomalous {
            score += 0.2;
            evidence_count += 1;
        }
        
        // Check z-score significance
        if payload_timing.z_score > 3.0 {
            score += 0.15;
            evidence_count += 1;
        }
        
        // Check percentile
        if payload_timing.percentile > 0.95 {
            score += 0.05;
            evidence_count += 1;
        }
        
        let confidence = BlindConfidence::from_score(score);
        let is_vulnerable = score >= 0.5;
        
        if is_vulnerable {
            self.vulnerabilities_found.fetch_add(1, Ordering::Relaxed);
        }
        
        BlindDetectionResult {
            state: if is_vulnerable { 
                BlindState::ConfirmedVulnerable 
            } else { 
                BlindState::ConfirmedSafe 
            },
            confidence,
            is_vulnerable,
            vulnerability_type: if is_vulnerable { 
                Some(BlindVulnerabilityType::TimeBasedSqlI) 
            } else { 
                None 
            },
            evidence_count,
            score,
        }
    }
    
    /// Analyze combined blind injection patterns
    pub fn analyze_combined(
        &self,
        boolean_result: Option<&BlindDetectionResult>,
        time_result: Option<&BlindDetectionResult>,
        oob_detected: bool,
    ) -> BlindDetectionResult {
        self.tests_run.fetch_add(1, Ordering::Relaxed);
        
        let mut score = 0.0;
        let mut evidence_count = 0u32;
        let mut best_vuln_type: Option<BlindVulnerabilityType> = None;
        
        // Factor in boolean results
        if let Some(bool_res) = boolean_result {
            score += bool_res.score * 0.4;
            evidence_count += bool_res.evidence_count;
            if bool_res.is_vulnerable {
                best_vuln_type = bool_res.vulnerability_type;
            }
        }
        
        // Factor in timing results
        if let Some(time_res) = time_result {
            score += time_res.score * 0.4;
            evidence_count += time_res.evidence_count;
            if time_res.is_vulnerable && best_vuln_type.is_none() {
                best_vuln_type = time_res.vulnerability_type;
            }
        }
        
        // Factor in OOB detection (strong indicator)
        if oob_detected {
            score += 0.3;
            evidence_count += 1;
            best_vuln_type = Some(BlindVulnerabilityType::BlindSsrf);
        }
        
        // Normalize score
        score = score.min(1.0);
        
        let confidence = BlindConfidence::from_score(score);
        let is_vulnerable = score >= 0.5;
        
        if is_vulnerable {
            self.vulnerabilities_found.fetch_add(1, Ordering::Relaxed);
        }
        
        BlindDetectionResult {
            state: if is_vulnerable { 
                BlindState::ConfirmedVulnerable 
            } else if score < 0.2 { 
                BlindState::ConfirmedSafe 
            } else { 
                BlindState::Uncertain 
            },
            confidence,
            is_vulnerable,
            vulnerability_type: best_vuln_type,
            evidence_count,
            score,
        }
    }
    
    /// Get statistics
    pub fn stats(&self) -> BlindStats {
        BlindStats {
            tests_run: self.tests_run.load(Ordering::Relaxed),
            vulnerabilities_found: self.vulnerabilities_found.load(Ordering::Relaxed),
            false_positives_avoided: self.false_positives_avoided.load(Ordering::Relaxed),
        }
    }
    
    /// Reset statistics
    pub fn reset_stats(&self) {
        self.tests_run.store(0, Ordering::Relaxed);
        self.vulnerabilities_found.store(0, Ordering::Relaxed);
        self.false_positives_avoided.store(0, Ordering::Relaxed);
    }
}

impl Default for BlindDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for blind detection
#[derive(Debug, Clone)]
pub struct BlindStats {
    pub tests_run: u64,
    pub vulnerabilities_found: u64,
    pub false_positives_avoided: u64,
}

impl BlindStats {
    pub fn detection_rate(&self) -> f64 {
        if self.tests_run == 0 {
            return 0.0;
        }
        self.vulnerabilities_found as f64 / self.tests_run as f64
    }
    
    pub fn false_positive_prevention_rate(&self) -> f64 {
        let total = self.vulnerabilities_found + self.false_positives_avoided;
        if total == 0 {
            return 0.0;
        }
        self.false_positives_avoided as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_blind_detector_creation() {
        let detector = BlindDetector::new();
        let stats = detector.stats();
        assert_eq!(stats.tests_run, 0);
    }
    
    #[test]
    fn test_confidence_from_score() {
        assert_eq!(BlindConfidence::from_score(0.0), BlindConfidence::None);
        assert_eq!(BlindConfidence::from_score(0.15), BlindConfidence::Low);
        assert_eq!(BlindConfidence::from_score(0.5), BlindConfidence::Medium);
        assert_eq!(BlindConfidence::from_score(0.8), BlindConfidence::High);
        assert_eq!(BlindConfidence::from_score(0.95), BlindConfidence::Certain);
    }
}
