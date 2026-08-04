//! Statistical Variance Models
//! 
//! Detects subtle structural shifts in JSON and HTML responses.
//! Uses bounded statistics to maintain 2GB RAM ceiling.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use bytes::Bytes;

/// Result of variance analysis
#[derive(Debug, Clone)]
pub struct VarianceStats {
    pub mean: f64,
    pub variance: f64,
    pub stddev: f64,
    pub sample_count: usize,
    pub min_value: f64,
    pub max_value: f64,
}

impl VarianceStats {
    pub fn empty() -> Self {
        Self {
            mean: 0.0,
            variance: 0.0,
            stddev: 0.0,
            sample_count: 0,
            min_value: 0.0,
            max_value: 0.0,
        }
    }
    
    /// Calculate coefficient of variation
    pub fn coefficient_of_variation(&self) -> f64 {
        if self.mean == 0.0 {
            return 0.0;
        }
        (self.stddev / self.mean.abs()).min(1.0)
    }
}

/// Type of structural shift detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructuralShift {
    None,
    Minor,
    Moderate,
    Significant,
    Critical,
}

impl StructuralShift {
    pub fn severity(&self) -> f64 {
        match self {
            Self::None => 0.0,
            Self::Minor => 0.25,
            Self::Moderate => 0.5,
            Self::Significant => 0.75,
            Self::Critical => 1.0,
        }
    }
}

/// Variance model for response analysis
pub struct VarianceModel {
    samples: Vec<f64>,
    sum: f64,
    sum_squares: f64,
    count: usize,
    min_val: f64,
    max_val: f64,
    max_samples: usize,
    updates: AtomicU64,
}

impl VarianceModel {
    pub fn new(max_samples: usize) -> Self {
        Self {
            samples: Vec::with_capacity(max_samples.min(1000)),
            sum: 0.0,
            sum_squares: 0.0,
            count: 0,
            min_val: f64::MAX,
            max_val: f64::MIN,
            max_samples: max_samples.min(1000), // Cap at 1000 to limit memory
            updates: AtomicU64::new(0),
        }
    }
    
    /// Add a sample value
    pub fn add_sample(&mut self, value: f64) {
        self.updates.fetch_add(1, Ordering::Relaxed);
        
        self.sum += value;
        self.sum_squares += value * value;
        self.count += 1;
        
        if value < self.min_val {
            self.min_val = value;
        }
        if value > self.max_val {
            self.max_val = value;
        }
        
        // Use reservoir sampling for bounded memory
        if self.samples.len() < self.max_samples {
            self.samples.push(value);
        } else {
            // Replace random sample with decreasing probability
            use std::time::{SystemTime, UNIX_EPOCH};
            let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
            let idx = (seed as usize) % self.count;
            if idx < self.max_samples {
                self.samples[idx] = value;
            }
        }
    }
    
    /// Calculate current statistics
    pub fn stats(&self) -> VarianceStats {
        if self.count == 0 {
            return VarianceStats::empty();
        }
        
        let n = self.count as f64;
        let mean = self.sum / n;
        let variance = if n > 1.0 {
            (self.sum_squares - (self.sum * self.sum / n)) / (n - 1.0)
        } else {
            0.0
        };
        let stddev = variance.sqrt();
        
        VarianceStats {
            mean,
            variance: variance.max(0.0),
            stddev,
            sample_count: self.count,
            min_value: if self.min_val == f64::MAX { 0.0 } else { self.min_val },
            max_value: if self.max_val == f64::MIN { 0.0 } else { self.max_val },
        }
    }
    
    /// Check if a new value is an outlier
    pub fn is_outlier(&self, value: f64, threshold_stddevs: f64) -> bool {
        let stats = self.stats();
        if stats.stddev == 0.0 {
            return false;
        }
        
        let z_score = (value - stats.mean).abs() / stats.stddev;
        z_score > threshold_stddevs
    }
    
    /// Reset the model
    pub fn reset(&mut self) {
        self.samples.clear();
        self.sum = 0.0;
        self.sum_squares = 0.0;
        self.count = 0;
        self.min_val = f64::MAX;
        self.max_val = f64::MIN;
    }
}

impl Default for VarianceModel {
    fn default() -> Self {
        Self::new(500)
    }
}

/// Analyze structural shifts in response content
pub struct StructuralAnalyzer {
    json_depth_model: VarianceModel,
    html_tag_model: VarianceModel,
    content_length_model: VarianceModel,
    shifts_detected: AtomicU64,
}

impl StructuralAnalyzer {
    pub fn new() -> Self {
        Self {
            json_depth_model: VarianceModel::new(200),
            html_tag_model: VarianceModel::new(200),
            content_length_model: VarianceModel::new(200),
            shifts_detected: AtomicU64::new(0),
        }
    }
    
    /// Analyze JSON structure variance
    pub fn analyze_json(&mut self, content: &Bytes) -> StructuralShift {
        let depth = Self::calculate_json_depth(content);
        let prev_stats = self.json_depth_model.stats();
        
        self.json_depth_model.add_sample(depth as f64);
        
        // Check for significant depth change
        if prev_stats.sample_count > 5 {
            let current_stats = self.json_depth_model.stats();
            if prev_stats.mean > 0.0 {
                let change_ratio = (current_stats.mean - prev_stats.mean).abs() / prev_stats.mean;
                return Self::classify_shift(change_ratio);
            }
        }
        
        StructuralShift::None
    }
    
    /// Analyze HTML structure variance
    pub fn analyze_html(&mut self, content: &Bytes) -> StructuralShift {
        let tag_count = Self::count_html_tags(content);
        let prev_stats = self.html_tag_model.stats();
        
        self.html_tag_model.add_sample(tag_count as f64);
        
        if prev_stats.sample_count > 5 {
            let current_stats = self.html_tag_model.stats();
            if prev_stats.mean > 0.0 {
                let change_ratio = (current_stats.mean - prev_stats.mean).abs() / prev_stats.mean;
                let shift = Self::classify_shift(change_ratio);
                
                if shift != StructuralShift::None {
                    self.shifts_detected.fetch_add(1, Ordering::Relaxed);
                }
                
                return shift;
            }
        }
        
        StructuralShift::None
    }
    
    /// Analyze content length variance
    pub fn analyze_length(&mut self, length: usize) -> StructuralShift {
        let prev_stats = self.content_length_model.stats();
        
        self.content_length_model.add_sample(length as f64);
        
        if prev_stats.sample_count > 5 {
            let current_stats = self.content_length_model.stats();
            if prev_stats.mean > 0.0 {
                let change_ratio = (current_stats.mean - prev_stats.mean).abs() / prev_stats.mean;
                let shift = Self::classify_shift(change_ratio);
                
                if shift != StructuralShift::None {
                    self.shifts_detected.fetch_add(1, Ordering::Relaxed);
                }
                
                return shift;
            }
        }
        
        StructuralShift::None
    }
    
    /// Calculate JSON nesting depth
    fn calculate_json_depth(content: &Bytes) -> usize {
        let mut depth = 0;
        let mut max_depth = 0;
        
        for byte in content.iter() {
            match byte {
                b'{' | b'[' => {
                    depth += 1;
                    max_depth = max_depth.max(depth);
                }
                b'}' | b']' => {
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
        
        max_depth
    }
    
    /// Count HTML tags in content
    fn count_html_tags(content: &Bytes) -> usize {
        let content_str = String::from_utf8_lossy(content);
        let mut count = 0;
        
        let mut in_tag = false;
        for char in content_str.chars() {
            if char == '<' {
                in_tag = true;
            } else if char == '>' && in_tag {
                count += 1;
                in_tag = false;
            }
        }
        
        count
    }
    
    /// Classify shift severity based on change ratio
    fn classify_shift(change_ratio: f64) -> StructuralShift {
        if change_ratio < 0.1 {
            StructuralShift::None
        } else if change_ratio < 0.25 {
            StructuralShift::Minor
        } else if change_ratio < 0.5 {
            StructuralShift::Moderate
        } else if change_ratio < 1.0 {
            StructuralShift::Significant
        } else {
            StructuralShift::Critical
        }
    }
    
    /// Get total shifts detected
    pub fn shifts_count(&self) -> u64 {
        self.shifts_detected.load(Ordering::Relaxed)
    }
    
    /// Reset all models
    pub fn reset(&mut self) {
        self.json_depth_model.reset();
        self.html_tag_model.reset();
        self.content_length_model.reset();
    }
}

impl Default for StructuralAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Compare two byte arrays for structural similarity
pub fn structural_similarity(a: &Bytes, b: &Bytes) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    
    let len_a = a.len();
    let len_b = b.len();
    
    // Length similarity
    let len_similarity = 1.0 - (len_a.abs_diff(len_b) as f64) / (len_a.max(len_b) as f64);
    
    // Sample-based content similarity
    let sample_size = 64;
    let step_a = (len_a / sample_size).max(1);
    let step_b = (len_b / sample_size).max(1);
    
    let mut matches = 0;
    let mut compared = 0;
    
    for i in (0..len_a).step_by(step_a) {
        let j = (i * len_b) / len_a;
        if j < len_b && a[i] == b[j] {
            matches += 1;
        }
        compared += 1;
    }
    
    let content_similarity = if compared > 0 {
        matches as f64 / compared as f64
    } else {
        0.0
    };
    
    (len_similarity * 0.3 + content_similarity * 0.7).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_variance_model_creation() {
        let model = VarianceModel::new(100);
        let stats = model.stats();
        assert_eq!(stats.sample_count, 0);
    }
    
    #[test]
    fn test_variance_calculation() {
        let mut model = VarianceModel::new(100);
        
        model.add_sample(10.0);
        model.add_sample(20.0);
        model.add_sample(30.0);
        
        let stats = model.stats();
        assert_eq!(stats.sample_count, 3);
        assert!((stats.mean - 20.0).abs() < 0.01);
    }
    
    #[test]
    fn test_structural_analyzer() {
        let mut analyzer = StructuralAnalyzer::new();
        
        let json_content = Bytes::from(r#"{"key": {"nested": "value"}}"#);
        let shift = analyzer.analyze_json(&json_content);
        
        assert_eq!(shift, StructuralShift::None);
    }
    
    #[test]
    fn test_structural_similarity() {
        let a = Bytes::from("Hello World");
        let b = Bytes::from("Hello World");
        let c = Bytes::from("Goodbye World");
        
        assert_eq!(structural_similarity(&a, &b), 1.0);
        assert!(structural_similarity(&a, &c) < 1.0);
    }
}
