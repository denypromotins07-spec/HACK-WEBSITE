//! Deserialization Learning Cache
//! Caches successful gadget chains, framework fingerprints, and bypass encodings.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Cache for deserialization vulnerability learning
#[derive(Debug)]
pub struct DeserializationCache {
    /// Cached gadget chains by framework
    gadget_chains: HashMap<String, Vec<CachedGadgetChain>>,
    /// Framework fingerprints
    fingerprints: HashMap<String, FrameworkFingerprint>,
    /// Bypass encodings that worked
    bypass_encodings: Vec<BypassEncoding>,
    /// Cache entry timeout
    entry_timeout: Duration,
    /// Maximum cache size
    max_cache_size: usize,
}

/// A cached gadget chain with metadata
#[derive(Debug, Clone)]
pub struct CachedGadgetChain {
    /// Chain identifier/name
    pub name: String,
    /// Target framework
    pub framework: String,
    /// Serialized payload bytes (bounded)
    pub payload_sample: Vec<u8>,
    /// Success count
    pub success_count: u32,
    /// Last successful timestamp
    pub last_success: Instant,
    /// Required library/version
    pub requirements: Vec<String>,
}

/// Framework fingerprint for identification
#[derive(Debug, Clone)]
pub struct FrameworkFingerprint {
    /// Framework name
    pub name: String,
    /// Detected version
    pub version: Option<String>,
    /// Characteristic headers
    pub headers: Vec<String>,
    /// Characteristic response patterns
    pub patterns: Vec<String>,
    /// Confidence score
    pub confidence: u8,
    /// First seen timestamp
    pub first_seen: Instant,
    /// Last seen timestamp
    pub last_seen: Instant,
}

/// Bypass encoding that successfully evaded detection
#[derive(Debug, Clone)]
pub struct BypassEncoding {
    /// Encoding type (base64, gzip, etc.)
    pub encoding_type: String,
    /// Target framework
    pub framework: String,
    /// Encoded payload sample (bounded)
    pub encoded_sample: Vec<u8>,
    /// Original size
    pub original_size: usize,
    /// Encoded size
    pub encoded_size: usize,
    /// Success count
    pub success_count: u32,
}

impl DeserializationCache {
    /// Create a new cache with default settings
    pub fn new() -> Self {
        Self {
            gadget_chains: HashMap::new(),
            fingerprints: HashMap::new(),
            bypass_encodings: Vec::new(),
            entry_timeout: Duration::from_secs(3600), // 1 hour default
            max_cache_size: 1000,
        }
    }

    /// Cache a successful gadget chain
    pub fn cache_gadget_chain(
        &mut self,
        framework: &str,
        name: &str,
        payload: &[u8],
        requirements: &[&str],
    ) {
        // Enforce payload size limit (2GB ceiling)
        if payload.len() > 2 * 1024 * 1024 * 1024 {
            return;
        }

        let chain = CachedGadgetChain {
            name: name.to_string(),
            framework: framework.to_string(),
            payload_sample: payload.to_vec(),
            success_count: 1,
            last_success: Instant::now(),
            requirements: requirements.iter().map(|s| s.to_string()).collect(),
        };

        let chains = self
            .gadget_chains
            .entry(framework.to_string())
            .or_insert_with(Vec::new);

        // Check if chain already exists
        if let Some(existing) = chains.iter_mut().find(|c| c.name == name) {
            existing.success_count += 1;
            existing.last_success = Instant::now();
        } else {
            // Enforce max cache size
            if chains.len() >= self.max_cache_size {
                // Remove oldest entry
                chains.remove(0);
            }
            chains.push(chain);
        }
    }

    /// Get cached gadget chains for a framework
    pub fn get_gadget_chains(&self, framework: &str) -> Vec<&CachedGadgetChain> {
        self.gadget_chains
            .get(framework)
            .map(|chains| chains.iter().collect())
            .unwrap_or_default()
    }

    /// Record a framework fingerprint
    pub fn record_fingerprint(
        &mut self,
        name: &str,
        version: Option<&str>,
        headers: &[&str],
        patterns: &[&str],
    ) {
        let now = Instant::now();
        
        let fingerprint = FrameworkFingerprint {
            name: name.to_string(),
            version: version.map(String::from),
            headers: headers.iter().map(|s| s.to_string()).collect(),
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
            confidence: 50, // Start with moderate confidence
            first_seen: now,
            last_seen: now,
        };

        self.fingerprints.insert(name.to_string(), fingerprint);
    }

    /// Update fingerprint confidence
    pub fn update_fingerprint_confidence(&mut self, name: &str, delta: i8) {
        if let Some(fp) = self.fingerprints.get_mut(name) {
            fp.last_seen = Instant::now();
            fp.confidence = (fp.confidence as i16 + delta as i16).clamp(0, 100) as u8;
        }
    }

    /// Get framework fingerprint
    pub fn get_fingerprint(&self, name: &str) -> Option<&FrameworkFingerprint> {
        self.fingerprints.get(name)
    }

    /// Cache a successful bypass encoding
    pub fn cache_bypass_encoding(
        &mut self,
        encoding_type: &str,
        framework: &str,
        encoded: &[u8],
        original_size: usize,
    ) {
        // Enforce size limit
        if encoded.len() > 2 * 1024 * 1024 * 1024 {
            return;
        }

        let bypass = BypassEncoding {
            encoding_type: encoding_type.to_string(),
            framework: framework.to_string(),
            encoded_sample: encoded.to_vec(),
            original_size,
            encoded_size: encoded.len(),
            success_count: 1,
        };

        // Check if similar bypass exists
        if let Some(existing) = self
            .bypass_encodings
            .iter_mut()
            .find(|b| b.encoding_type == encoding_type && b.framework == framework)
        {
            existing.success_count += 1;
        } else {
            // Enforce max cache size
            if self.bypass_encodings.len() >= self.max_cache_size {
                self.bypass_encodings.remove(0);
            }
            self.bypass_encodings.push(bypass);
        }
    }

    /// Get all bypass encodings for a framework
    pub fn get_bypass_encodings(&self, framework: &str) -> Vec<&BypassEncoding> {
        self.bypass_encodings
            .iter()
            .filter(|b| b.framework == framework)
            .collect()
    }

    /// Clean up expired cache entries
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();

        // Clean gadget chains
        for chains in self.gadget_chains.values_mut() {
            chains.retain(|c| now.duration_since(c.last_success) < self.entry_timeout);
        }

        // Clean fingerprints
        self.fingerprints.retain(|_, fp| {
            now.duration_since(fp.last_seen) < self.entry_timeout
        });

        // Clean bypass encodings (keep those with recent success)
        self.bypass_encodings.retain(|b| {
            // Simple retention based on success count
            b.success_count > 0
        });
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        let total_chains: usize = self
            .gadget_chains
            .values()
            .map(|v| v.len())
            .sum();

        CacheStats {
            gadget_chain_count: total_chains,
            fingerprint_count: self.fingerprints.len(),
            bypass_encoding_count: self.bypass_encodings.len(),
            frameworks_tracked: self.gadget_chains.len(),
        }
    }

    /// Set cache entry timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.entry_timeout = timeout;
        self
    }

    /// Set maximum cache size
    pub fn with_max_size(mut self, size: usize) -> Self {
        self.max_cache_size = size;
        self
    }
}

impl Default for DeserializationCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of cached gadget chains
    pub gadget_chain_count: usize,
    /// Number of cached fingerprints
    pub fingerprint_count: usize,
    /// Number of cached bypass encodings
    pub bypass_encoding_count: usize,
    /// Number of frameworks tracked
    pub frameworks_tracked: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_creation() {
        let cache = DeserializationCache::new();
        let stats = cache.get_stats();
        assert_eq!(stats.gadget_chain_count, 0);
        assert_eq!(stats.fingerprint_count, 0);
    }

    #[test]
    fn test_cache_gadget_chain() {
        let mut cache = DeserializationCache::new();
        cache.cache_gadget_chain("Java", "CommonsCollections1", &[0x01, 0x02], &["commons-collections:3.2.1"]);

        let chains = cache.get_gadget_chains("Java");
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].name, "CommonsCollections1");
    }

    #[test]
    fn test_fingerprint_recording() {
        let mut cache = DeserializationCache::new();
        cache.record_fingerprint(
            "Spring Boot",
            Some("2.5.0"),
            &["X-Powered-By: Spring"],
            &["whitelabel error"],
        );

        let fp = cache.get_fingerprint("Spring Boot");
        assert!(fp.is_some());
        assert_eq!(fp.unwrap().version, Some("2.5.0".to_string()));
    }

    #[test]
    fn test_bypass_caching() {
        let mut cache = DeserializationCache::new();
        cache.cache_bypass_encoding("base64", "Java", &[0x41, 0x42], 2);

        let bypasses = cache.get_bypass_encodings("Java");
        assert_eq!(bypasses.len(), 1);
        assert_eq!(bypasses[0].encoding_type, "base64");
    }
}
