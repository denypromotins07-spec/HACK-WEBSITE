//! High-Precision Timing Analysis
//! 
//! Implements nanosecond timing analysis for time-based blind SQLi and RCE detection.
//! Uses atomic counters for thread-safe statistics across 100 concurrent agents.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Timing thresholds for anomaly detection
#[derive(Debug, Clone)]
pub struct TimingThresholds {
    /// Minimum delay to consider anomalous (nanoseconds)
    pub min_anomaly_ns: u64,
    /// Standard deviation multiplier for outlier detection
    pub stddev_multiplier: f64,
    /// Minimum samples for statistical significance
    pub min_samples: usize,
    /// Maximum timing window (nanoseconds)
    pub max_window_ns: u64,
}

impl Default for TimingThresholds {
    fn default() -> Self {
        Self {
            min_anomaly_ns: 100_000_000, // 100ms
            stddev_multiplier: 3.0,
            min_samples: 5,
            max_window_ns: 30_000_000_000, // 30 seconds
        }
    }
}

/// Result of timing analysis
#[derive(Debug, Clone)]
pub struct TimingResult {
    pub elapsed_ns: u64,
    pub is_anomalous: bool,
    pub confidence: f64,
    pub z_score: f64,
    pub percentile: f64,
    pub category: TimingCategory,
}

impl TimingResult {
    pub fn normal(elapsed_ns: u64) -> Self {
        Self {
            elapsed_ns,
            is_anomalous: false,
            confidence: 0.0,
            z_score: 0.0,
            percentile: 0.5,
            category: TimingCategory::Normal,
        }
    }
    
    pub fn anomalous(elapsed_ns: u64, confidence: f64, z_score: f64) -> Self {
        Self {
            elapsed_ns,
            is_anomalous: true,
            confidence,
            z_score,
            percentile: Self::z_to_percentile(z_score),
            category: TimingCategory::Delayed,
        }
    }
    
    /// Convert z-score to approximate percentile
    fn z_to_percentile(z: f64) -> f64 {
        // Approximation using error function
        let x = z / 2.0f64.sqrt();
        let erf_approx = 1.0 - (-x * x).exp().powi(2);
        0.5 * (1.0 + erf_approx)
    }
}

/// Category of timing result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingCategory {
    Normal,
    SlightlyDelayed,
    Delayed,
    SignificantlyDelayed,
    Timeout,
}

/// Lock-free timing analyzer
pub struct TimingAnalyzer {
    thresholds: TimingThresholds,
    sample_count: AtomicUsize,
    total_elapsed_ns: AtomicU64,
    min_elapsed_ns: AtomicU64,
    max_elapsed_ns: AtomicU64,
    anomalies_detected: AtomicU64,
}

impl TimingAnalyzer {
    pub fn new(thresholds: TimingThresholds) -> Self {
        Self {
            thresholds,
            sample_count: AtomicUsize::new(0),
            total_elapsed_ns: AtomicU64::new(0),
            min_elapsed_ns: AtomicU64::new(u64::MAX),
            max_elapsed_ns: AtomicU64::new(0),
            anomalies_detected: AtomicU64::new(0),
        }
    }
    
    /// Analyze a single timing measurement
    pub fn analyze(&self, elapsed_ns: u64) -> TimingResult {
        self.sample_count.fetch_add(1, Ordering::Relaxed);
        self.total_elapsed_ns.fetch_add(elapsed_ns, Ordering::Relaxed);
        
        // Update min/max atomically
        self.update_min_max(elapsed_ns);
        
        // Check if exceeds minimum anomaly threshold
        if elapsed_ns >= self.thresholds.min_anomaly_ns {
            self.anomalies_detected.fetch_add(1, Ordering::Relaxed);
            
            let z_score = self.calculate_z_score(elapsed_ns);
            let confidence = Self::z_to_confidence(z_score);
            
            let category = Self::categorize(elapsed_ns, &self.thresholds);
            
            return TimingResult::anomalous(elapsed_ns, confidence, z_score);
        }
        
        // Calculate z-score even for normal timings
        let z_score = self.calculate_z_score(elapsed_ns);
        
        TimingResult {
            elapsed_ns,
            is_anomalous: false,
            confidence: 0.0,
            z_score,
            percentile: TimingResult::z_to_percentile(z_score),
            category: Self::categorize(elapsed_ns, &self.thresholds),
        }
    }
    
    /// Analyze timing difference between two requests (for time-based injection)
    pub fn analyze_difference(&self, baseline_ns: u64, payload_ns: u64) -> TimingResult {
        let delta_ns = payload_ns.saturating_sub(baseline_ns);
        
        // Check if delay is significant
        if delta_ns >= self.thresholds.min_anomaly_ns {
            self.anomalies_detected.fetch_add(1, Ordering::Relaxed);
            
            let z_score = (delta_ns as f64) / (baseline_ns as f64).max(1.0);
            let confidence = (z_score / 5.0).min(1.0);
            
            return TimingResult::anomalous(delta_ns, confidence, z_score);
        }
        
        TimingResult::normal(delta_ns)
    }
    
    /// Update min/max values atomically
    fn update_min_max(&self, elapsed_ns: u64) {
        // Update minimum
        let mut current_min = self.min_elapsed_ns.load(Ordering::Relaxed);
        while elapsed_ns < current_min {
            match self.min_elapsed_ns.compare_exchange_weak(
                current_min,
                elapsed_ns,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_min = x,
            }
        }
        
        // Update maximum
        let mut current_max = self.max_elapsed_ns.load(Ordering::Relaxed);
        while elapsed_ns > current_max {
            match self.max_elapsed_ns.compare_exchange_weak(
                current_max,
                elapsed_ns,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_max = x,
            }
        }
    }
    
    /// Calculate z-score based on current statistics
    fn calculate_z_score(&self, elapsed_ns: u64) -> f64 {
        let count = self.sample_count.load(Ordering::Relaxed);
        if count < 2 {
            return 0.0;
        }
        
        let total = self.total_elapsed_ns.load(Ordering::Relaxed);
        let mean = total as f64 / count as f64;
        
        // Simplified standard deviation estimate
        let min = self.min_elapsed_ns.load(Ordering::Relaxed);
        let max = self.max_elapsed_ns.load(Ordering::Relaxed);
        
        if min == u64::MAX || max == 0 {
            return 0.0;
        }
        
        // Range-based stddev approximation
        let range = (max - min) as f64;
        let stddev_approx = range / 4.0; // Rule of thumb
        
        if stddev_approx < 1.0 {
            return 0.0;
        }
        
        (elapsed_ns as f64 - mean) / stddev_approx
    }
    
    /// Convert z-score to confidence level
    fn z_to_confidence(z_score: f64) -> f64 {
        (z_score.abs() / 5.0).min(1.0)
    }
    
    /// Categorize timing result
    fn categorize(elapsed_ns: u64, thresholds: &TimingThresholds) -> TimingCategory {
        if elapsed_ns >= thresholds.max_window_ns {
            TimingCategory::Timeout
        } else if elapsed_ns >= thresholds.min_anomaly_ns * 5 {
            TimingCategory::SignificantlyDelayed
        } else if elapsed_ns >= thresholds.min_anomaly_ns * 2 {
            TimingCategory::Delayed
        } else if elapsed_ns >= thresholds.min_anomaly_ns {
            TimingCategory::SlightlyDelayed
        } else {
            TimingCategory::Normal
        }
    }
    
    /// Get statistics
    pub fn stats(&self) -> TimingStats {
        let count = self.sample_count.load(Ordering::Relaxed);
        let total = self.total_elapsed_ns.load(Ordering::Relaxed);
        let min = self.min_elapsed_ns.load(Ordering::Relaxed);
        let max = self.max_elapsed_ns.load(Ordering::Relaxed);
        let anomalies = self.anomalies_detected.load(Ordering::Relaxed);
        
        TimingStats {
            sample_count: count,
            total_elapsed_ns: total,
            mean_elapsed_ns: if count > 0 { total / count as u64 } else { 0 },
            min_elapsed_ns: if min == u64::MAX { 0 } else { min },
            max_elapsed_ns: max,
            anomalies_detected: anomalies,
        }
    }
    
    /// Reset statistics
    pub fn reset_stats(&self) {
        self.sample_count.store(0, Ordering::Relaxed);
        self.total_elapsed_ns.store(0, Ordering::Relaxed);
        self.min_elapsed_ns.store(u64::MAX, Ordering::Relaxed);
        self.max_elapsed_ns.store(0, Ordering::Relaxed);
        self.anomalies_detected.store(0, Ordering::Relaxed);
    }
}

/// Statistics for timing analysis
#[derive(Debug, Clone)]
pub struct TimingStats {
    pub sample_count: usize,
    pub total_elapsed_ns: u64,
    pub mean_elapsed_ns: u64,
    pub min_elapsed_ns: u64,
    pub max_elapsed_ns: u64,
    pub anomalies_detected: u64,
}

impl TimingStats {
    pub fn anomaly_rate(&self) -> f64 {
        if self.sample_count == 0 {
            return 0.0;
        }
        self.anomalies_detected as f64 / self.sample_count as f64
    }
    
    pub fn mean_ms(&self) -> f64 {
        self.mean_elapsed_ns as f64 / 1_000_000.0
    }
    
    pub fn min_ms(&self) -> f64 {
        self.min_elapsed_ns as f64 / 1_000_000.0
    }
    
    pub fn max_ms(&self) -> f64 {
        self.max_elapsed_ns as f64 / 1_000_000.0
    }
}

/// High-precision timer wrapper
pub struct PrecisionTimer {
    start: Instant,
}

impl PrecisionTimer {
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }
    
    pub fn elapsed_ns(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64
    }
    
    pub fn elapsed_ms(&self) -> f64 {
        self.start.elapsed().as_secs_f64() * 1000.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_timing_analyzer_creation() {
        let analyzer = TimingAnalyzer::new(TimingThresholds::default());
        let stats = analyzer.stats();
        assert_eq!(stats.sample_count, 0);
    }
    
    #[test]
    fn test_normal_timing() {
        let analyzer = TimingAnalyzer::new(TimingThresholds::default());
        let result = analyzer.analyze(50_000_000); // 50ms
        
        assert!(!result.is_anomalous);
        assert_eq!(result.elapsed_ns, 50_000_000);
    }
    
    #[test]
    fn test_anomalous_timing() {
        let analyzer = TimingAnalyzer::new(TimingThresholds::default());
        let result = analyzer.analyze(200_000_000); // 200ms
        
        assert!(result.is_anomalous);
        assert!(result.confidence > 0.0);
    }
    
    #[test]
    fn test_timing_difference() {
        let analyzer = TimingAnalyzer::new(TimingThresholds::default());
        let result = analyzer.analyze_difference(50_000_000, 250_000_000);
        
        assert!(result.is_anomalous);
        assert_eq!(result.elapsed_ns, 200_000_000);
    }
    
    #[test]
    fn test_precision_timer() {
        let timer = PrecisionTimer::start();
        std::thread::sleep(Duration::from_millis(10));
        let elapsed = timer.elapsed_ms();
        
        assert!(elapsed >= 9.0);
    }
}
