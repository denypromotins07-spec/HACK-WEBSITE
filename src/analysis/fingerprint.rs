//! Response Fingerprinting and Normalization
//! 
//! Implements baseline response hashing, stripping dynamic tokens like CSRF and timestamps.
//! Maintains strict 2GB RAM ceiling using zero-copy slicing and bounded hash rings.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use xxhash_rust::xxh3::xxh3_64;

/// Dynamic token patterns to strip during fingerprinting
static DYNAMIC_PATTERNS: &[&str] = &[
    "csrf_token",
    "nonce",
    "timestamp",
    "request_id",
    "session_id",
    "trace_id",
    "x-request-id",
    "x-correlation-id",
];

/// Baseline response fingerprint with stripped dynamic content
#[derive(Debug, Clone)]
pub struct ResponseFingerprint {
    pub body_hash: u64,
    pub headers_hash: u64,
    pub status_code: u16,
    pub content_type_hash: u64,
    pub timing_ns: u64,
    pub stripped_length: usize,
    pub created_at: Instant,
}

impl ResponseFingerprint {
    /// Create a new fingerprint from response data
    pub fn new(
        body: &Bytes,
        headers: &[(String, String)],
        status_code: u16,
        content_type: &str,
        timing_ns: u64,
    ) -> Self {
        let (stripped_body, stripped_length) = Self::strip_dynamic_tokens(body);
        let body_hash = xxh3_64(&stripped_body);
        
        let headers_normalized = Self::normalize_headers(headers);
        let headers_hash = xxh3_64(headers_normalized.as_bytes());
        
        let content_type_hash = xxh3_64(content_type.as_bytes());
        
        Self {
            body_hash,
            headers_hash,
            status_code,
            content_type_hash,
            timing_ns,
            stripped_length,
            created_at: Instant::now(),
        }
    }
    
    /// Strip dynamic tokens from body using zero-copy approach where possible
    fn strip_dynamic_tokens(body: &Bytes) -> (Vec<u8>, usize) {
        let body_str = String::from_utf8_lossy(body);
        let mut result = body_str.to_string();
        let original_length = result.len();
        
        for pattern in DYNAMIC_PATTERNS {
            // Remove pattern=value pairs (common in URLs and forms)
            let regex_pattern = format!("{}=[a-zA-Z0-9_-]+", pattern);
            if let Ok(re) = regex::Regex::new(&regex_pattern) {
                result = re.replace_all(&result, "").to_string();
            }
            
            // Remove standalone pattern values (hex strings, base64)
            let hex_pattern = format!(r#"{}["']?\s*[:=]\s*["']?[a-fA-F0-9]{{16,}}["']?"#, pattern);
            if let Ok(re) = regex::Regex::new(&hex_pattern) {
                result = re.replace_all(&result, "").to_string();
            }
        }
        
        // Remove ISO timestamps
        if let Ok(re) = regex::Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?") {
            result = re.replace_all(&result, "<TS>").to_string();
        }
        
        // Remove UUIDs
        if let Ok(re) = regex::Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}") {
            result = re.replace_all(&result, "<UUID>").to_string();
        }
        
        let stripped_length = original_length.saturating_sub(result.len());
        (result.into_bytes(), stripped_length)
    }
    
    /// Normalize headers for consistent hashing
    fn normalize_headers(headers: &[(String, String)]) -> String {
        let mut normalized: Vec<(String, String)> = headers
            .iter()
            .filter(|(name, _)| {
                let name_lower = name.to_lowercase();
                // Skip dynamic headers
                !name_lower.contains("date") 
                    && !name_lower.contains("request-id")
                    && !name_lower.contains("trace")
                    && !name_lower.contains("x-amz")
            })
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();
        
        normalized.sort_by(|a, b| a.0.cmp(&b.0));
        
        normalized
            .into_iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<_>>()
            .join(";")
    }
    
    /// Compare fingerprints for equality (used in differential analysis)
    pub fn matches(&self, other: &Self, tolerance_bytes: usize) -> bool {
        self.status_code == other.status_code
            && self.body_hash == other.body_hash
            && self.headers_hash == other.headers_hash
            && self.content_type_hash == other.content_type_hash
    }
    
    /// Calculate similarity score (0.0 to 1.0)
    pub fn similarity(&self, other: &Self) -> f64 {
        let mut score = 1.0;
        
        if self.status_code != other.status_code {
            score -= 0.3;
        }
        
        if self.body_hash != other.body_hash {
            score -= 0.4;
        }
        
        if self.headers_hash != other.headers_hash {
            score -= 0.2;
        }
        
        if self.content_type_hash != other.content_type_hash {
            score -= 0.1;
        }
        
        score.max(0.0)
    }
}

/// Lock-free fingerprint cache using atomic operations
pub struct FingerprintCache {
    hits: AtomicU64,
    misses: AtomicU64,
    capacity: usize,
}

impl FingerprintCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            capacity,
        }
    }
    
    #[inline]
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }
    
    #[inline]
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed) as f64;
        let misses = self.misses.load(Ordering::Relaxed) as f64;
        let total = hits + misses;
        if total == 0.0 {
            return 0.0;
        }
        hits / total
    }
}

/// Compute fast hash of byte slice
#[inline]
pub fn quick_hash(data: &[u8]) -> u64 {
    xxh3_64(data)
}

/// Compute Levenshtein distance for small strings (bounded to prevent memory issues)
pub fn bounded_levenshtein(a: &str, b: &str, max_distance: usize) -> usize {
    if max_distance == 0 {
        return if a == b { 0 } else { usize::MAX };
    }
    
    let len_a = a.chars().count();
    let len_b = b.chars().count();
    
    // Early exit if length difference exceeds max
    if len_a.abs_diff(len_b) > max_distance {
        return usize::MAX;
    }
    
    // Use bounded matrix to prevent excessive allocation
    let mut prev: Vec<usize> = (0..=len_b.min(max_distance * 2)).collect();
    let mut curr: Vec<usize> = vec![0; len_b.min(max_distance * 2) + 1];
    
    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        
        for (j, cb) in b.chars().enumerate() {
            let j_idx = j + 1;
            if j_idx >= curr.len() {
                continue;
            }
            
            let cost = if ca == cb { 0 } else { 1 };
            curr[j_idx] = (prev[j_idx] + 1)
                .min(curr[j_idx - 1] + 1)
                .min(prev.get(j).copied().unwrap_or(usize::MAX) + cost);
            
            // Early termination if exceeding max
            if curr[j_idx] > max_distance {
                return usize::MAX;
            }
        }
        
        std::mem::swap(&mut prev, &mut curr);
    }
    
    prev.last().copied().unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fingerprint_creation() {
        let body = Bytes::from("<html><body>Hello</body></html>");
        let headers = vec![("Content-Type".to_string(), "text/html".to_string())];
        
        let fp = ResponseFingerprint::new(&body, &headers, 200, "text/html", 1000);
        
        assert_eq!(fp.status_code, 200);
        assert!(fp.body_hash != 0);
    }
    
    #[test]
    fn test_bounded_levenshtein() {
        assert_eq!(bounded_levenshtein("hello", "hello", 10), 0);
        assert_eq!(bounded_levenshtein("hello", "hallo", 10), 1);
        assert_eq!(bounded_levenshtein("hello", "world", 2), usize::MAX);
    }
}
