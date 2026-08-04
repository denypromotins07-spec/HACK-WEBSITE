//! Cache Learning Module
//! Caches cache-key models, poisoning vectors, and CDN origin fingerprints.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Maximum number of entries to keep in bounded caches (2GB RAM ceiling consideration)
const MAX_CACHE_ENTRIES: usize = 10_000;
const MAX_POISONING_VECTORS: usize = 1_000;
const MAX_ORIGIN_FINGERPRINTS: usize = 5_000;

/// Learned cache key model for a URL pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheKeyModel {
    /// URL pattern this model applies to
    pub url_pattern: String,
    
    /// Headers that affect caching (learned from Vary and testing)
    pub keyed_headers: HashSet<String>,
    
    /// Query parameters that affect caching
    pub keyed_query_params: HashSet<String>,
    
    /// Cookie names that affect caching
    pub keyed_cookies: HashSet<String>,
    
    /// Confidence score based on number of observations
    pub confidence: f64,
    
    /// Last updated timestamp
    pub last_updated: u64,
}

impl CacheKeyModel {
    pub fn new(url_pattern: String) -> Self {
        Self {
            url_pattern,
            keyed_headers: HashSet::new(),
            keyed_query_params: HashSet::new(),
            keyed_cookies: HashSet::new(),
            confidence: 0.0,
            last_updated: 0,
        }
    }

    /// Add a header to the keyed set
    pub fn add_keyed_header(&mut self, header: &str) {
        self.keyed_headers.insert(header.to_lowercase());
        self.confidence = ((self.confidence * 100.0) + 1.0) / 101.0;
    }

    /// Add a query parameter to the keyed set
    pub fn add_keyed_query_param(&mut self, param: &str) {
        self.keyed_query_params.insert(param.to_lowercase());
        self.confidence = ((self.confidence * 100.0) + 1.0) / 101.0;
    }

    /// Check if a header is known to be keyed
    pub fn is_header_keyed(&self, header: &str) -> bool {
        self.keyed_headers.contains(&header.to_lowercase())
    }

    /// Check if a query param is known to be keyed
    pub fn is_query_param_keyed(&self, param: &str) -> bool {
        self.keyed_query_params.contains(&param.to_lowercase())
    }
}

/// A poisoning vector that was observed or tested
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoisoningVector {
    /// The header/parameter used for poisoning
    pub injection_point: String,
    
    /// The value that was injected
    pub injected_value: String,
    
    /// Whether the poisoning was successful
    pub success: bool,
    
    /// The type of content that was poisoned
    pub content_type: String,
    
    /// CDN/provider where this worked
    pub cdn_provider: Option<String>,
    
    /// Number of times this vector has been observed
    pub observation_count: usize,
}

impl PoisoningVector {
    pub fn new(injection_point: String, injected_value: String, success: bool) -> Self {
        Self {
            injection_point,
            injected_value,
            success,
            content_type: String::new(),
            cdn_provider: None,
            observation_count: if success { 1 } else { 0 },
        }
    }

    /// Record another observation of this vector
    pub fn record_observation(&mut self, success: bool) {
        if success {
            self.observation_count += 1;
        }
    }

    /// Get effectiveness score (0.0 - 1.0)
    pub fn effectiveness(&self) -> f64 {
        if self.observation_count == 0 {
            return 0.0;
        }
        // Simple ratio of successful observations
        (self.observation_count as f64).min(1.0)
    }
}

/// Fingerprint of an origin server behind a CDN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginFingerprint {
    /// Domain/IP of the origin
    pub origin_identifier: String,
    
    /// Server header value
    pub server_header: Option<String>,
    
    /// X-Powered-By header value
    pub powered_by: Option<String>,
    
    /// Typical response headers (normalized)
    pub characteristic_headers: HashMap<String, String>,
    
    /// Response body hash (first N bytes)
    pub body_hash: String,
    
    /// Associated CDN provider
    pub cdn_provider: String,
    
    /// Discovery method (dns_history, cert_analysis, direct_access, etc.)
    pub discovery_method: String,
    
    /// Confidence that this is the true origin
    pub confidence: f64,
}

impl OriginFingerprint {
    pub fn new(origin_identifier: String, cdn_provider: String, discovery_method: String) -> Self {
        Self {
            origin_identifier,
            server_header: None,
            powered_by: None,
            characteristic_headers: HashMap::new(),
            body_hash: String::new(),
            cdn_provider,
            discovery_method,
            confidence: 0.5,
        }
    }

    /// Update fingerprint with response data
    pub fn update_from_response(&mut self, headers: &HashMap<String, String>, body: &str) {
        self.server_header = headers.get("server").cloned();
        self.powered_by = headers.get("x-powered-by").cloned();
        
        // Store characteristic headers (excluding dynamic ones)
        let static_headers = ["server", "x-powered-by", "content-type"];
        for header in &static_headers {
            if let Some(value) = headers.get(*header) {
                self.characteristic_headers.insert(header.to_string(), value.clone());
            }
        }
        
        // Create simple hash of body prefix
        self.body_hash = format!("{:x}", md5_hash(body.chars().take(500).collect::<String>().as_bytes()));
        
        self.confidence = ((self.confidence * 100.0) + 10.0) / 101.0;
    }
}

/// Simple MD5-like hash function (placeholder - use proper crypto in production)
fn md5_hash(data: &[u8]) -> String {
    // This is a placeholder - in real code use the md5 crate
    format!("{:032x}", data.iter().fold(0u64, |acc, &b| acc.wrapping_mul(31).wrapping_add(b as u64)))
}

/// Main cache learning store
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CacheLearningStore {
    /// Learned cache key models by URL pattern
    cache_key_models: HashMap<String, CacheKeyModel>,
    
    /// Observed poisoning vectors
    poisoning_vectors: Vec<PoisoningVector>,
    
    /// Discovered origin fingerprints
    origin_fingerprints: HashMap<String, OriginFingerprint>,
    
    /// CDN provider quirks learned across scans
    cdn_quirks: HashMap<String, HashSet<String>>,
}

impl CacheLearningStore {
    pub fn new() -> Self {
        Self {
            cache_key_models: HashMap::with_capacity(MAX_CACHE_ENTRIES),
            poisoning_vectors: Vec::with_capacity(MAX_POISONING_VECTORS),
            origin_fingerprints: HashMap::with_capacity(MAX_ORIGIN_FINGERPRINTS),
            cdn_quirks: HashMap::new(),
        }
    }

    /// Get or create a cache key model for a URL
    pub fn get_or_create_model(&mut self, url_pattern: &str) -> &mut CacheKeyModel {
        if !self.cache_key_models.contains_key(url_pattern) {
            self.cache_key_models.insert(
                url_pattern.to_string(),
                CacheKeyModel::new(url_pattern.to_string()),
            );
        }
        self.cache_key_models.get_mut(url_pattern).unwrap()
    }

    /// Record a successful poisoning vector
    pub fn record_poisoning_vector(
        &mut self,
        injection_point: String,
        injected_value: String,
        success: bool,
        cdn_provider: Option<String>,
    ) {
        // Check if we already have this vector
        let existing = self.poisoning_vectors
            .iter_mut()
            .find(|v| v.injection_point == injection_point && v.injected_value == injected_value);
        
        if let Some(vector) = existing {
            vector.record_observation(success);
        } else {
            // Only add if under limit
            if self.poisoning_vectors.len() < MAX_POISONING_VECTORS {
                let mut vector = PoisoningVector::new(injection_point, injected_value, success);
                vector.cdn_provider = cdn_provider;
                self.poisoning_vectors.push(vector);
            }
        }
    }

    /// Get effective poisoning vectors for a CDN provider
    pub fn get_effective_vectors(&self, cdn_provider: &str) -> Vec<&PoisoningVector> {
        self.poisoning_vectors
            .iter()
            .filter(|v| {
                v.success 
                    && v.effectiveness() > 0.5
                    && v.cdn_provider.as_deref() == Some(cdn_provider)
            })
            .collect()
    }

    /// Store an origin fingerprint
    pub fn store_origin_fingerprint(&mut self, fingerprint: OriginFingerprint) {
        if self.origin_fingerprints.len() < MAX_ORIGIN_FINGERPRINTS {
            self.origin_fingerprints
                .insert(fingerprint.origin_identifier.clone(), fingerprint);
        }
    }

    /// Find potential origins for a domain
    pub fn find_origins_for_domain(&self, domain: &str) -> Vec<&OriginFingerprint> {
        self.origin_fingerprints
            .values()
            .filter(|f| {
                f.origin_identifier.contains(domain)
                    || domain.contains(&f.origin_identifier)
            })
            .collect()
    }

    /// Record a CDN-specific quirk
    pub fn record_cdn_quirk(&mut self, cdn_provider: &str, quirk: &str) {
        self.cdn_quirks
            .entry(cdn_provider.to_string())
            .or_insert_with(HashSet::new)
            .insert(quirk.to_string());
    }

    /// Get known quirks for a CDN provider
    pub fn get_cdn_quirks(&self, cdn_provider: &str) -> Vec<&str> {
        self.cdn_quirks
            .get(cdn_provider)
            .map(|s| s.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Get statistics about the learning store
    pub fn stats(&self) -> LearningStats {
        LearningStats {
            cache_key_models: self.cache_key_models.len(),
            poisoning_vectors: self.poisoning_vectors.len(),
            origin_fingerprints: self.origin_fingerprints.len(),
            cdn_providers_tracked: self.cdn_quirks.len(),
        }
    }

    /// Prune old entries to stay within memory bounds
    pub fn prune(&mut self) {
        // Remove lowest confidence cache key models if over limit
        if self.cache_key_models.len() > MAX_CACHE_ENTRIES {
            let mut sorted: Vec<_> = self.cache_key_models.iter().collect();
            sorted.sort_by(|a, b| a.1.confidence.partial_cmp(&b.1.confidence).unwrap());
            
            let to_remove = sorted.iter().take(sorted.len() - MAX_CACHE_ENTRIES);
            for entry in to_remove {
                self.cache_key_models.remove(entry.0);
            }
        }
    }
}

/// Statistics about the learning store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningStats {
    pub cache_key_models: usize,
    pub poisoning_vectors: usize,
    pub origin_fingerprints: usize,
    pub cdn_providers_tracked: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_model() {
        let mut model = CacheKeyModel::new("/api/*".to_string());
        
        model.add_keyed_header("Accept");
        model.add_keyed_header("Accept-Encoding");
        model.add_keyed_query_param("version");
        
        assert!(model.is_header_keyed("Accept"));
        assert!(model.is_header_keyed("accept")); // Case insensitive
        assert!(!model.is_header_keyed("User-Agent"));
        assert!(model.is_query_param_keyed("version"));
    }

    #[test]
    fn test_poisoning_vector() {
        let mut vector = PoisoningVector::new(
            "X-Forwarded-Host".to_string(),
            "evil.com".to_string(),
            true,
        );
        
        vector.record_observation(true);
        vector.record_observation(true);
        
        assert_eq!(vector.observation_count, 3);
        assert!(vector.effectiveness() > 0.5);
    }

    #[test]
    fn test_learning_store() {
        let mut store = CacheLearningStore::new();
        
        // Test cache key model
        let model = store.get_or_create_model("/test");
        model.add_keyed_header("Accept");
        
        // Test poisoning vector recording
        store.record_poisoning_vector(
            "X-Forwarded-Host".to_string(),
            "evil.com".to_string(),
            true,
            Some("Cloudflare".to_string()),
        );
        
        // Test stats
        let stats = store.stats();
        assert_eq!(stats.cache_key_models, 1);
        assert_eq!(stats.poisoning_vectors, 1);
    }
}
