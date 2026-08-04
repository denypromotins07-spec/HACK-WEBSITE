//! Time Analysis Module for SQL Injection Detection
//! Nanosecond-precision response timing analysis with jitter compensation.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Maximum number of samples to retain for bounded memory usage
const MAX_SAMPLES: usize = 100;

/// Statistical analysis of response times
#[derive(Debug, Clone)]
pub struct TimingStats {
    pub mean_ms: f64,
    pub median_ms: f64,
    pub stddev_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub sample_count: usize,
}

/// Jitter compensation configuration
#[derive(Debug, Clone)]
pub struct JitterConfig {
    pub base_threshold_ms: u64,
    pub adaptive_factor: f64,
    pub network_variance_weight: f64,
}

impl Default for JitterConfig {
    fn default() -> Self {
        Self {
            base_threshold_ms: 500,
            adaptive_factor: 0.1,
            network_variance_weight: 0.3,
        }
    }
}

/// High-precision timing analyzer for SQLi detection
pub struct TimeAnalyzer {
    samples: VecDeque<u128>, // Nanoseconds for precision
    baseline_samples: VecDeque<u128>,
    jitter_config: JitterConfig,
    last_baseline: Option<u128>,
}

impl TimeAnalyzer {
    /// Create a new time analyzer with bounded queues
    pub fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(MAX_SAMPLES),
            baseline_samples: VecDeque::with_capacity(MAX_SAMPLES / 2),
            jitter_config: JitterConfig::default(),
            last_baseline: None,
        }
    }

    /// Record a timing sample with zero-copy storage
    pub fn record_sample(&mut self, nanos: u128) {
        if self.samples.len() >= MAX_SAMPLES {
            self.samples.pop_front(); // Maintain bounded size
        }
        self.samples.push_back(nanos);
    }

    /// Record a baseline sample
    pub fn record_baseline(&mut self, nanos: u128) {
        if self.baseline_samples.len() >= MAX_SAMPLES / 2 {
            self.baseline_samples.pop_front();
        }
        self.baseline_samples.push_back(nanos);
        self.last_baseline = Some(nanos);
    }

    /// Calculate statistical metrics from samples
    pub fn calculate_stats(&self) -> Option<TimingStats> {
        let samples: Vec<u128> = self.samples.iter().copied().collect();

        if samples.is_empty() {
            return None;
        }

        let n = samples.len() as f64;
        let sum: u128 = samples.iter().sum();
        let mean = sum as f64 / n;

        // Convert to milliseconds for readability
        let mean_ms = mean / 1_000_000.0;

        // Calculate median
        let mut sorted = samples.clone();
        sorted.sort();
        let median = if sorted.len() % 2 == 0 {
            (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) as f64 / 2.0
        } else {
            sorted[sorted.len() / 2] as f64
        };
        let median_ms = median / 1_000_000.0;

        // Calculate standard deviation
        let variance = samples
            .iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / n;
        let stddev_ms = variance.sqrt() / 1_000_000.0;

        let min_ms = (*samples.iter().min().unwrap()) as f64 / 1_000_000.0;
        let max_ms = (*samples.iter().max().unwrap()) as f64 / 1_000_000.0;

        Some(TimingStats {
            mean_ms,
            median_ms,
            stddev_ms,
            min_ms,
            max_ms,
            sample_count: samples.len(),
        })
    }

    /// Calculate adaptive jitter threshold based on observed variance
    pub fn calculate_jitter_threshold(&self) -> u128 {
        let stats = match self.calculate_stats() {
            Some(s) => s,
            None => return self.jitter_config.base_threshold_ms as u128 * 1_000_000,
        };

        // Adaptive threshold: base + (stddev * factor) + (network variance weight * mean)
        let adaptive = stats.stddev_ms * self.jitter_config.adaptive_factor * 1_000_000.0;
        let network_component =
            stats.mean_ms * self.jitter_config.network_variance_weight * 1_000_000.0;

        (self.jitter_config.base_threshold_ms as f64 * 1_000_000.0 + adaptive + network_component)
            as u128
    }

    /// Detect if a timing differential indicates SQLi
    pub fn detect_anomaly(&self, test_time_nanos: u128, expected_delay_nanos: u128) -> bool {
        let baseline = match self.last_baseline {
            Some(b) => b,
            None => return false,
        };

        let jitter_threshold = self.calculate_jitter_threshold();
        let expected_total = baseline + expected_delay_nanos;

        // Check if actual time exceeds expected with jitter compensation
        test_time_nanos >= expected_total.saturating_sub(jitter_threshold)
    }

    /// Perform differential analysis between two timing sets
    pub fn differential_analysis(
        &self,
        control_times: &[u128],
        test_times: &[u128],
    ) -> DifferentialResult {
        let control_mean = control_times.iter().sum::<u128>() as f64 / control_times.len() as f64;
        let test_mean = test_times.iter().sum::<u128>() as f64 / test_times.len() as f64;

        let delta = test_mean - control_mean;
        let delta_percent = if control_mean > 0.0 {
            (delta / control_mean) * 100.0
        } else {
            0.0
        };

        // Calculate confidence score based on consistency
        let control_variance = control_times
            .iter()
            .map(|&x| {
                let diff = x as f64 - control_mean;
                diff * diff
            })
            .sum::<f64>()
            / control_times.len() as f64;

        let test_variance = test_times
            .iter()
            .map(|&x| {
                let diff = x as f64 - test_mean;
                diff * diff
            })
            .sum::<f64>()
            / test_times.len() as f64;

        // Higher confidence if variances are low and delta is significant
        let combined_variance = (control_variance + test_variance) / 2.0;
        let confidence = if combined_variance > 0.0 {
            (delta.abs() / combined_variance.sqrt()).min(1.0)
        } else {
            0.5
        };

        DifferentialResult {
            control_mean_ms: control_mean / 1_000_000.0,
            test_mean_ms: test_mean / 1_000_000.0,
            delta_ms: delta / 1_000_000.0,
            delta_percent,
            confidence,
        }
    }

    /// Reset analyzer state
    pub fn reset(&mut self) {
        self.samples.clear();
        self.baseline_samples.clear();
        self.last_baseline = None;
    }
}

impl Default for TimeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of differential timing analysis
#[derive(Debug, Clone)]
pub struct DifferentialResult {
    pub control_mean_ms: f64,
    pub test_mean_ms: f64,
    pub delta_ms: f64,
    pub delta_percent: f64,
    pub confidence: f64,
}

/// Precision timer utility for measuring request/response cycles
pub struct PrecisionTimer {
    start: Option<Instant>,
    end: Option<Instant>,
}

impl PrecisionTimer {
    pub fn new() -> Self {
        Self {
            start: None,
            end: None,
        }
    }

    pub fn start(&mut self) {
        self.start = Some(Instant::now());
    }

    pub fn stop(&mut self) {
        self.end = Some(Instant::now());
    }

    pub fn elapsed_nanos(&self) -> Option<u128> {
        match (self.start, self.end) {
            (Some(start), Some(end)) => Some(end.duration_since(start).as_nanos()),
            _ => None,
        }
    }

    pub fn elapsed_ms(&self) -> Option<f64> {
        self.elapsed_nanos().map(|n| n as f64 / 1_000_000.0)
    }
}

impl Default for PrecisionTimer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_stats() {
        let mut analyzer = TimeAnalyzer::new();

        // Record some samples (in nanoseconds)
        for i in 0..10 {
            analyzer.record_sample((1000 + i * 100) * 1_000_000); // 1000-1900ms
        }

        let stats = analyzer.calculate_stats().unwrap();
        assert_eq!(stats.sample_count, 10);
        assert!(stats.mean_ms > 1400.0 && stats.mean_ms < 1500.0);
    }

    #[test]
    fn test_differential_analysis() {
        let analyzer = TimeAnalyzer::new();

        let control = vec![1000 * 1_000_000, 1100 * 1_000_000, 1050 * 1_000_000];
        let test = vec![3000 * 1_000_000, 3100 * 1_000_000, 3050 * 1_000_000];

        let result = analyzer.differential_analysis(&control, &test);
        assert!(result.delta_ms > 1900.0);
        assert!(result.delta_percent > 150.0);
    }

    #[test]
    fn test_precision_timer() {
        let mut timer = PrecisionTimer::new();
        timer.start();
        std::thread::sleep(std::time::Duration::from_millis(10));
        timer.stop();

        assert!(timer.elapsed_nanos().unwrap() >= 10_000_000);
    }
}
