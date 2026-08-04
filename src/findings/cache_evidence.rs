//! Cache and CDN Evidence Container Module
//! Builds cache and CDN evidence containers with edge headers and normalized keys.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Info
    }
}

/// Evidence container for cache-related vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEvidence {
    /// The URL that was tested
    pub url: String,
    
    /// Type of vulnerability detected
    pub vulnerability_type: String,
    
    /// The specific extension/header/technique used
    pub extension_used: String,
    
    /// The original path being tested
    pub original_path: String,
    
    /// Edge response headers
    pub edge_headers: HashMap<String, String>,
    
    /// Cache status from response (HIT, MISS, BYPASS, etc.)
    pub cache_status: String,
    
    /// Severity of the finding
    pub severity: Severity,
    
    /// Human-readable description
    pub description: String,
}

impl CacheEvidence {
    /// Create new cache evidence
    pub fn new(
        url: String,
        vulnerability_type: String,
        extension_used: String,
        original_path: String,
        edge_headers: HashMap<String, String>,
        cache_status: String,
        severity: Severity,
        description: String,
    ) -> Self {
        Self {
            url,
            vulnerability_type,
            extension_used,
            original_path,
            edge_headers,
            cache_status,
            severity,
            description,
        }
    }

    /// Extract normalized cache key from evidence
    pub fn normalized_cache_key(&self) -> String {
        // Build a normalized representation of what would be cached
        let mut key_parts = vec![self.original_path.clone()];
        
        // Add relevant headers that might affect caching
        if let Some(vary) = self.edge_headers.get("vary") {
            key_parts.push(format!("vary={}", vary));
        }
        
        if let Some(cookie) = self.edge_headers.get("cookie") {
            // Normalize cookie by removing session-specific values
            let normalized_cookie = cookie
                .split(';')
                .map(|c| c.split('=').next().unwrap_or("").trim())
                .collect::<Vec<_>>()
                .join(",");
            key_parts.push(format!("cookies={}", normalized_cookie));
        }
        
        key_parts.join("|")
    }

    /// Get edge-specific headers only
    pub fn edge_only_headers(&self) -> HashMap<String, String> {
        let edge_header_names = [
            "x-cache",
            "x-cache-hits",
            "x-served-by",
            "via",
            "age",
            "cf-cache-status",
            "cf-ray",
            "cf-request-id",
            "x-amz-cf-id",
            "x-amz-cf-pop",
            "fastly-cache-status",
            "x-varnish",
            "x-akamai-transformed",
            "x-akamai-request-id",
        ];
        
        self.edge_headers
            .iter()
            .filter(|(k, _)| {
                edge_header_names.iter().any(|name| k.to_lowercase().contains(name))
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Determine if this is a cache HIT
    pub fn is_cache_hit(&self) -> bool {
        self.cache_status.contains("HIT")
    }

    /// Get CDN provider from edge headers
    pub fn cdn_provider(&self) -> Option<&'static str> {
        if self.edge_headers.contains_key("cf-ray") 
            || self.edge_headers.contains_key("cf-cache-status")
        {
            return Some("Cloudflare");
        }
        
        if self.edge_headers.contains_key("x-amz-cf-id") 
            || self.edge_headers.contains_key("x-amz-cf-pop")
        {
            return Some("CloudFront");
        }
        
        if self.edge_headers.contains_key("x-served-by") 
            && self.edge_headers.get("x-served-by").unwrap().contains("fastly")
        {
            return Some("Fastly");
        }
        
        if self.edge_headers.contains_key("x-akamai-transformed")
            || self.edge_headers.contains_key("x-akamai-request-id")
        {
            return Some("Akamai");
        }
        
        if self.edge_headers.contains_key("via") || self.edge_headers.contains_key("x-cache") {
            return Some("Unknown CDN");
        }
        
        None
    }
}

/// Aggregated evidence for a single target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEvidenceAggregation {
    /// Target URL/domain
    pub target: String,
    
    /// All evidence collected for this target
    pub evidence_list: Vec<CacheEvidence>,
    
    /// Normalized cache keys observed
    pub observed_cache_keys: Vec<String>,
    
    /// CDN provider detected
    pub cdn_provider: Option<String>,
    
    /// Summary statistics
    pub stats: CacheStats,
}

/// Statistics about cache behavior
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total requests made
    pub total_requests: usize,
    
    /// Number of cache hits
    pub cache_hits: usize,
    
    /// Number of cache misses
    pub cache_misses: usize,
    
    /// Number of bypasses detected
    pub bypasses: usize,
    
    /// Number of vulnerabilities found
    pub vulnerabilities_found: usize,
    
    /// Critical findings count
    pub critical_count: usize,
    
    /// High severity findings count
    pub high_count: usize,
}

impl CacheEvidenceAggregation {
    pub fn new(target: String) -> Self {
        Self {
            target,
            evidence_list: Vec::new(),
            observed_cache_keys: Vec::new(),
            cdn_provider: None,
            stats: CacheStats::default(),
        }
    }

    /// Add evidence to aggregation
    pub fn add_evidence(&mut self, evidence: CacheEvidence) {
        // Track cache stats
        self.stats.total_requests += 1;
        
        if evidence.is_cache_hit() {
            self.stats.cache_hits += 1;
        } else if evidence.cache_status.contains("MISS") {
            self.stats.cache_misses += 1;
        }
        
        if evidence.cache_status.contains("BYPASS") {
            self.stats.bypasses += 1;
        }
        
        // Track severity counts
        match evidence.severity {
            Severity::Critical => self.stats.critical_count += 1,
            Severity::High => self.stats.high_count += 1,
            _ => {}
        }
        
        // Add to evidence list
        self.stats.vulnerabilities_found += 1;
        self.evidence_list.push(evidence);
    }

    /// Compute summary of findings
    pub fn summary(&self) -> String {
        format!(
            "Target: {} | CDN: {:?} | Requests: {} | Hits: {} | Misses: {} | Vulnerabilities: {} (Critical: {}, High: {})",
            self.target,
            self.cdn_provider,
            self.stats.total_requests,
            self.stats.cache_hits,
            self.stats.cache_misses,
            self.stats.vulnerabilities_found,
            self.stats.critical_count,
            self.stats.high_count,
        )
    }
}

/// Correlation data between edge and origin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeOriginCorrelation {
    /// Edge response fingerprint
    pub edge_fingerprint: String,
    
    /// Origin response fingerprint  
    pub origin_fingerprint: String,
    
    /// Whether responses match (indicating potential direct origin access)
    pub responses_match: bool,
    
    /// Headers that differ between edge and origin
    pub differing_headers: Vec<String>,
    
    /// Confidence score (0.0 - 1.0) that this is a true positive
    pub confidence: f64,
}

impl EdgeOriginCorrelation {
    pub fn new(edge_fingerprint: String, origin_fingerprint: String) -> Self {
        let responses_match = edge_fingerprint == origin_fingerprint;
        
        Self {
            edge_fingerprint,
            origin_fingerprint,
            responses_match,
            differing_headers: Vec::new(),
            confidence: if responses_match { 0.9 } else { 0.3 },
        }
    }

    /// Calculate fingerprint from response headers
    pub fn fingerprint_from_headers(headers: &HashMap<String, String>) -> String {
        let mut sorted_headers: Vec<_> = headers.iter().collect();
        sorted_headers.sort_by(|a, b| a.0.cmp(b.0));
        
        sorted_headers
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<_>>()
            .join(";")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_evidence_creation() {
        let mut headers = HashMap::new();
        headers.insert("x-cache".to_string(), "HIT".to_string());
        headers.insert("cf-cache-status".to_string(), "HIT".to_string());
        
        let evidence = CacheEvidence::new(
            "https://example.com/admin.css".to_string(),
            "cache_deception".to_string(),
            ".css".to_string(),
            "/admin".to_string(),
            headers.clone(),
            "HIT".to_string(),
            Severity::High,
            "Test description".to_string(),
        );
        
        assert!(evidence.is_cache_hit());
        assert_eq!(evidence.cdn_provider(), Some("Cloudflare"));
    }

    #[test]
    fn test_normalized_cache_key() {
        let mut headers = HashMap::new();
        headers.insert("vary".to_string(), "Accept-Encoding".to_string());
        
        let evidence = CacheEvidence::new(
            "https://example.com/test".to_string(),
            "test".to_string(),
            "test".to_string(),
            "/test".to_string(),
            headers,
            "MISS".to_string(),
            Severity::Info,
            "Test".to_string(),
        );
        
        let key = evidence.normalized_cache_key();
        assert!(key.contains("/test"));
        assert!(key.contains("vary="));
    }

    #[test]
    fn test_evidence_aggregation() {
        let mut agg = CacheEvidenceAggregation::new("https://example.com".to_string());
        
        let mut headers = HashMap::new();
        headers.insert("cf-cache-status".to_string(), "HIT".to_string());
        
        let evidence = CacheEvidence::new(
            "https://example.com/test".to_string(),
            "test".to_string(),
            "test".to_string(),
            "/test".to_string(),
            headers,
            "HIT".to_string(),
            Severity::Critical,
            "Test".to_string(),
        );
        
        agg.add_evidence(evidence);
        
        assert_eq!(agg.stats.total_requests, 1);
        assert_eq!(agg.stats.cache_hits, 1);
        assert_eq!(agg.stats.critical_count, 1);
    }
}
