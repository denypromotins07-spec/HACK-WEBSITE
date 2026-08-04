//! False Positive Reduction using Bayesian Filtering
//! 
//! Implements a Bayesian filter to downgrade payload scores that consistently 
//! trigger WAFs or produce false positives.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Bayesian filter for false positive reduction
pub struct BayesianFilter {
    /// Prior probability of vulnerability (default 0.01 - 1%)
    prior_probability: f64,
    
    /// True positive rates per feature
    true_positive_rates: HashMap<String, f64>,
    
    /// False positive rates per feature
    false_positive_rates: HashMap<String, f64>,
    
    /// Feature occurrence counts
    feature_counts: HashMap<String, FeatureStats>,
    
    /// Total samples processed
    total_samples: AtomicU64,
    
    /// False positives identified
    false_positives: AtomicU64,
    
    /// True positives confirmed
    true_positives: AtomicU64,
}

/// Statistics for a feature
#[derive(Debug, Clone)]
struct FeatureStats {
    tp_count: u64,  // True positive occurrences
    fp_count: u64,  // False positive occurrences
    total_count: u64,
}

impl FeatureStats {
    fn new() -> Self {
        Self {
            tp_count: 0,
            fp_count: 0,
            total_count: 0,
        }
    }
    
    fn likelihood_ratio(&self) -> f64 {
        if self.total_count == 0 {
            return 1.0;
        }
        
        let tp_rate = if self.tp_count > 0 {
            self.tp_count as f64 / self.total_count as f64
        } else {
            0.01
        };
        
        let fp_rate = if self.fp_count > 0 {
            self.fp_count as f64 / self.total_count as f64
        } else {
            0.01
        };
        
        (tp_rate / fp_rate).max(0.1).min(10.0)
    }
}

/// Result of Bayesian analysis
#[derive(Debug, Clone)]
pub struct BayesianResult {
    pub posterior_probability: f64,
    pub is_likely_false_positive: bool,
    pub confidence: f64,
    pub contributing_features: Vec<String>,
}

impl BayesianFilter {
    pub fn new() -> Self {
        Self {
            prior_probability: 0.01,
            true_positive_rates: HashMap::new(),
            false_positive_rates: HashMap::new(),
            feature_counts: HashMap::new(),
            total_samples: AtomicU64::new(0),
            false_positives: AtomicU64::new(0),
            true_positives: AtomicU64::new(0),
        }
    }
    
    /// Calculate posterior probability given observed features
    pub fn calculate_posterior(&self, features: &[String]) -> BayesianResult {
        let mut log_odds = self.probability_to_log_odds(self.prior_probability);
        let mut contributing_features = Vec::new();
        
        for feature in features {
            if let Some(stats) = self.feature_counts.get(feature) {
                let lr = stats.likelihood_ratio();
                log_odds += lr.ln();
                
                if lr > 1.5 || lr < 0.67 {
                    contributing_features.push(feature.clone());
                }
            }
        }
        
        let posterior = self.log_odds_to_probability(log_odds);
        
        // Determine if likely false positive
        let is_likely_fp = posterior < 0.3;
        
        // Calculate confidence based on number of features
        let confidence = (features.len() as f64 / 10.0).min(1.0) * (1.0 - (posterior - 0.5).abs() * 2.0);
        
        BayesianResult {
            posterior_probability: posterior,
            is_likely_false_positive: is_likely_fp,
            confidence,
            contributing_features,
        }
    }
    
    /// Record a true positive for learning
    pub fn record_true_positive(&mut self, features: &[String]) {
        self.true_positives.fetch_add(1, Ordering::Relaxed);
        self.total_samples.fetch_add(1, Ordering::Relaxed);
        
        for feature in features {
            let stats = self.feature_counts.entry(feature.clone()).or_insert_with(FeatureStats::new);
            stats.tp_count += 1;
            stats.total_count += 1;
        }
    }
    
    /// Record a false positive for learning
    pub fn record_false_positive(&mut self, features: &[String]) {
        self.false_positives.fetch_add(1, Ordering::Relaxed);
        self.total_samples.fetch_add(1, Ordering::Relaxed);
        
        for feature in features {
            let stats = self.feature_counts.entry(feature.clone()).or_insert_with(FeatureStats::new);
            stats.fp_count += 1;
            stats.total_count += 1;
        }
    }
    
    /// Adjust score based on Bayesian analysis
    pub fn adjust_score(&self, original_score: f64, features: &[String]) -> f64 {
        let result = self.calculate_posterior(features);
        
        // Downweight score if likely false positive
        if result.is_likely_false_positive {
            original_score * result.posterior_probability
        } else {
            original_score * result.posterior_probability.max(0.5)
        }
    }
    
    /// Check if a pattern is associated with WAF detection
    pub fn is_waf_pattern(&self, pattern: &str) -> bool {
        // Common WAF response indicators
        let waf_patterns = [
            "blocked", "forbidden", "access denied", "waf", 
            "security", "firewall", "suspicious", "malicious"
        ];
        
        let pattern_lower = pattern.to_lowercase();
        waf_patterns.iter().any(|wp| pattern_lower.contains(wp))
    }
    
    /// Get statistics
    pub fn stats(&self) -> BayesianStats {
        BayesianStats {
            total_samples: self.total_samples.load(Ordering::Relaxed),
            true_positives: self.true_positives.load(Ordering::Relaxed),
            false_positives: self.false_positives.load(Ordering::Relaxed),
            feature_count: self.feature_counts.len(),
        }
    }
    
    /// Convert probability to log odds
    fn probability_to_log_odds(&self, p: f64) -> f64 {
        let p = p.clamp(0.001, 0.999);
        (p / (1.0 - p)).ln()
    }
    
    /// Convert log odds to probability
    fn log_odds_to_probability(&self, log_odds: f64) -> f64 {
        1.0 / (1.0 + (-log_odds).exp())
    }
    
    /// Reset learned data
    pub fn reset(&mut self) {
        self.feature_counts.clear();
        self.true_positive_rates.clear();
        self.false_positive_rates.clear();
        self.total_samples.store(0, Ordering::Relaxed);
        self.false_positives.store(0, Ordering::Relaxed);
        self.true_positives.store(0, Ordering::Relaxed);
    }
}

impl Default for BayesianFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for Bayesian filter
#[derive(Debug, Clone)]
pub struct BayesianStats {
    pub total_samples: u64,
    pub true_positives: u64,
    pub false_positives: u64,
    pub feature_count: usize,
}

impl BayesianStats {
    pub fn false_positive_rate(&self) -> f64 {
        let total = self.true_positives + self.false_positives;
        if total == 0 {
            return 0.0;
        }
        self.false_positives as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bayesian_filter_creation() {
        let filter = BayesianFilter::new();
        let stats = filter.stats();
        assert_eq!(stats.total_samples, 0);
    }
    
    #[test]
    fn test_posterior_calculation() {
        let mut filter = BayesianFilter::new();
        
        // Train with some data
        filter.record_true_positive(&["sql_error".to_string(), "time_delay".to_string()]);
        filter.record_true_positive(&["sql_error".to_string(), "time_delay".to_string()]);
        filter.record_false_positive(&["waf_block".to_string()]);
        
        let result = filter.calculate_posterior(&["sql_error".to_string(), "time_delay".to_string()]);
        
        assert!(result.posterior_probability > 0.5);
        assert!(!result.is_likely_false_positive);
    }
    
    #[test]
    fn test_score_adjustment() {
        let mut filter = BayesianFilter::new();
        
        // Train with false positive data
        filter.record_false_positive(&["waf_block".to_string()]);
        filter.record_false_positive(&["waf_block".to_string()]);
        
        let adjusted = filter.adjust_score(0.9, &["waf_block".to_string()]);
        
        assert!(adjusted < 0.9);
    }
}
