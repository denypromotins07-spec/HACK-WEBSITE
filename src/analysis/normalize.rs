//! Body Normalization Routines
//! 
//! Handles whitespace, encoding, and dynamic DOM elements.
//! Uses streaming approach to maintain 2GB RAM ceiling.

use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};
use bytes::Bytes;

/// Statistics for normalization operations
pub struct NormalizeStats {
    pub bytes_processed: AtomicUsize,
    pub whitespace_normalized: AtomicUsize,
    pub entities_decoded: AtomicUsize,
    pub dom_stripped: AtomicUsize,
}

impl NormalizeStats {
    pub fn new() -> Self {
        Self {
            bytes_processed: AtomicUsize::new(0),
            whitespace_normalized: AtomicUsize::new(0),
            entities_decoded: AtomicUsize::new(0),
            dom_stripped: AtomicUsize::new(0),
        }
    }
    
    pub fn total_operations(&self) -> usize {
        self.whitespace_normalized.load(Ordering::Relaxed)
            + self.entities_decoded.load(Ordering::Relaxed)
            + self.dom_stripped.load(Ordering::Relaxed)
    }
}

/// Normalization configuration
#[derive(Debug, Clone)]
pub struct NormalizeConfig {
    pub normalize_whitespace: bool,
    pub decode_html_entities: bool,
    pub strip_comments: bool,
    pub strip_scripts: bool,
    pub strip_styles: bool,
    pub minify: bool,
    pub max_body_size: usize,
}

impl Default for NormalizeConfig {
    fn default() -> Self {
        Self {
            normalize_whitespace: true,
            decode_html_entities: true,
            strip_comments: true,
            strip_scripts: false,
            strip_styles: false,
            minify: true,
            max_body_size: 10 * 1024 * 1024, // 10MB limit
        }
    }
}

/// Normalized body result
#[derive(Debug, Clone)]
pub struct NormalizedBody {
    pub data: Bytes,
    pub original_size: usize,
    pub normalized_size: usize,
    pub compression_ratio: f64,
}

impl NormalizedBody {
    pub fn new(data: Bytes, original_size: usize) -> Self {
        let normalized_size = data.len();
        let compression_ratio = if original_size > 0 {
            1.0 - (normalized_size as f64 / original_size as f64)
        } else {
            0.0
        };
        
        Self {
            data,
            original_size,
            normalized_size,
            compression_ratio,
        }
    }
}

/// Main normalization engine
pub struct BodyNormalizer {
    config: NormalizeConfig,
    stats: NormalizeStats,
}

impl BodyNormalizer {
    pub fn new(config: NormalizeConfig) -> Self {
        Self {
            config,
            stats: NormalizeStats::new(),
        }
    }
    
    pub fn with_default_config() -> Self {
        Self::new(NormalizeConfig::default())
    }
    
    /// Normalize a response body
    pub fn normalize(&self, body: &Bytes) -> NormalizedBody {
        let original_size = body.len();
        self.stats.bytes_processed.fetch_add(original_size, Ordering::Relaxed);
        
        // Early return if body exceeds max size
        if original_size > self.config.max_body_size {
            return NormalizedBody::new(body.clone(), original_size);
        }
        
        let mut result = String::from_utf8_lossy(body).to_string();
        
        // Apply normalizations in order
        if self.config.decode_html_entities {
            result = self.decode_html_entities(&result);
        }
        
        if self.config.strip_comments {
            result = self.strip_comments(&result);
        }
        
        if self.config.strip_scripts {
            result = self.strip_scripts(&result);
        }
        
        if self.config.strip_styles {
            result = self.strip_styles(&result);
        }
        
        if self.config.normalize_whitespace {
            result = self.normalize_whitespace(&result);
        }
        
        if self.config.minify {
            result = self.minify(&result);
        }
        
        NormalizedBody::new(Bytes::from(result), original_size)
    }
    
    /// Decode HTML entities
    fn decode_html_entities(&self, input: &str) -> String {
        self.stats.entities_decoded.fetch_add(1, Ordering::Relaxed);
        
        html_escape::decode_html_entities(input).to_string()
    }
    
    /// Strip HTML comments
    fn strip_comments(&self, input: &str) -> String {
        if let Ok(re) = regex::Regex::new(r"<!--[\s\S]*?-->") {
            return re.replace_all(input, "").to_string();
        }
        input.to_string()
    }
    
    /// Strip script tags
    fn strip_scripts(&self, input: &str) -> String {
        if let Ok(re) = regex::Regex::new(r"(?is)<script[^>]*>.*?</script>") {
            self.stats.dom_stripped.fetch_add(1, Ordering::Relaxed);
            return re.replace_all(input, "").to_string();
        }
        input.to_string()
    }
    
    /// Strip style tags
    fn strip_styles(&self, input: &str) -> String {
        if let Ok(re) = regex::Regex::new(r"(?is)<style[^>]*>.*?</style>") {
            self.stats.dom_stripped.fetch_add(1, Ordering::Relaxed);
            return re.replace_all(input, "").to_string();
        }
        input.to_string()
    }
    
    /// Normalize whitespace
    fn normalize_whitespace(&self, input: &str) -> String {
        self.stats.whitespace_normalized.fetch_add(1, Ordering::Relaxed);
        
        // Replace multiple whitespace with single space
        if let Ok(re) = regex::Regex::new(r"\s+") {
            return re.replace_all(input, " ").to_string();
        }
        input.to_string()
    }
    
    /// Minify content
    fn minify(&self, input: &str) -> String {
        // Remove leading/trailing whitespace per line
        input
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    }
    
    /// Get statistics
    pub fn stats(&self) -> &NormalizeStats {
        &self.stats
    }
}

/// Streaming body normalizer for large responses
pub struct StreamingNormalizer {
    config: NormalizeConfig,
    buffer: Vec<u8>,
    chunk_size: usize,
}

impl StreamingNormalizer {
    pub fn new(config: NormalizeConfig, chunk_size: usize) -> Self {
        Self {
            config,
            buffer: Vec::with_capacity(chunk_size),
            chunk_size,
        }
    }
    
    /// Process a chunk of data
    pub fn process_chunk(&mut self, chunk: &[u8]) -> Option<NormalizedBody> {
        self.buffer.extend_from_slice(chunk);
        
        if self.buffer.len() >= self.chunk_size {
            let data = Bytes::from(self.buffer.split_off(0));
            let normalizer = BodyNormalizer::new(self.config.clone());
            Some(normalizer.normalize(&data))
        } else {
            None
        }
    }
    
    /// Finalize and return remaining data
    pub fn finalize(mut self) -> Option<NormalizedBody> {
        if self.buffer.is_empty() {
            return None;
        }
        
        let data = Bytes::from(self.buffer);
        let normalizer = BodyNormalizer::new(self.config.clone());
        Some(normalizer.normalize(&data))
    }
}

/// Compare two normalized bodies for similarity
pub fn compare_normalized(a: &NormalizedBody, b: &NormalizedBody) -> f64 {
    if a.data == b.data {
        return 1.0;
    }
    
    // Use byte-level comparison with tolerance
    let len_a = a.data.len();
    let len_b = b.data.len();
    
    if len_a == 0 || len_b == 0 {
        return 0.0;
    }
    
    let common_len = len_a.min(len_b);
    let mut matches = 0usize;
    
    // Sample comparison for performance (check every 64th byte)
    let sample_interval = 64;
    let mut checked = 0usize;
    
    for i in (0..common_len).step_by(sample_interval) {
        if a.data[i] == b.data[i] {
            matches += 1;
        }
        checked += 1;
    }
    
    if checked == 0 {
        return 0.0;
    }
    
    matches as f64 / checked as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_normalize_whitespace() {
        let normalizer = BodyNormalizer::with_default_config();
        let input = Bytes::from("Hello   World\n\nTest");
        let result = normalizer.normalize(&input);
        
        assert!(result.compression_ratio > 0.0);
    }
    
    #[test]
    fn test_strip_comments() {
        let config = NormalizeConfig {
            normalize_whitespace: false,
            decode_html_entities: false,
            strip_comments: true,
            strip_scripts: false,
            strip_styles: false,
            minify: false,
            max_body_size: 1024 * 1024,
        };
        let normalizer = BodyNormalizer::new(config);
        let input = Bytes::from("<html><!-- comment --><body>Test</body></html>");
        let result = normalizer.normalize(&input);
        
        let result_str = String::from_utf8_lossy(&result.data);
        assert!(!result_str.contains("<!--"));
    }
    
    #[test]
    fn test_compare_normalized() {
        let a = NormalizedBody::new(Bytes::from("hello world"), 11);
        let b = NormalizedBody::new(Bytes::from("hello world"), 11);
        let c = NormalizedBody::new(Bytes::from("hello rust"), 10);
        
        assert_eq!(compare_normalized(&a, &b), 1.0);
        assert!(compare_normalized(&a, &c) < 1.0);
    }
}
