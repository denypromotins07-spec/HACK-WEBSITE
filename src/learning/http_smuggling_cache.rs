//! HTTP Smuggling Cache for Learning System
//! 
//! Caches successful desync signatures and edge proxy fingerprints for future scans.
//! Enables learning-driven optimization of HTTP protocol checks.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Signature cache entry for HTTP smuggling patterns
#[derive(Debug, Clone)]
pub struct SmugglingSignature {
    /// Unique signature identifier
    pub id: String,
    
    /// The check ID that discovered this signature
    pub check_id: String,
    
    /// Target technology fingerprint (e.g., "nginx-1.18", "apache-2.4")
    pub tech_fingerprint: String,
    
    /// The payload pattern that succeeded
    pub payload_pattern: String,
    
    /// Response pattern that indicated success
    pub response_pattern: String,
    
    /// Success rate (0.0 - 1.0)
    pub success_rate: f64,
    
    /// Number of times this signature was tested
    pub test_count: u32,
    
    /// Number of successful detections
    pub success_count: u32,
    
    /// Last used timestamp
    pub last_used: u64,
    
    /// Whether this signature is noisy (may trigger WAF/IDS)
    pub is_noisy: bool,
}

impl SmugglingSignature {
    pub fn new(check_id: String, tech_fingerprint: String, payload: String, response: String) -> Self {
        Self {
            id: format!("sig_{}", generate_id()),
            check_id,
            tech_fingerprint,
            payload_pattern: payload,
            response_pattern: response,
            success_rate: 1.0,
            test_count: 1,
            success_count: 1,
            last_used: current_timestamp(),
            is_noisy: false,
        }
    }

    /// Update statistics after a test
    pub fn record_test(&mut self, success: bool) {
        self.test_count += 1;
        if success {
            self.success_count += 1;
            self.last_used = current_timestamp();
        }
        self.success_rate = self.success_count as f64 / self.test_count as f64;
    }

    /// Check if signature is still reliable
    pub fn is_reliable(&self, min_rate: f64) -> bool {
        self.success_rate >= min_rate && self.test_count >= 3
    }
}

/// Edge proxy fingerprint data
#[derive(Debug, Clone)]
pub struct ProxyFingerprint {
    /// Proxy identification string
    pub proxy_name: String,
    
    /// Version if detectable
    pub version: Option<String>,
    
    /// Known smuggling techniques that work against this proxy
    pub working_techniques: Vec<String>,
    
    /// Known protections enabled
    pub protections: Vec<String>,
    
    /// Confidence in fingerprint accuracy
    pub confidence: f64,
}

impl ProxyFingerprint {
    pub fn new(proxy_name: String) -> Self {
        Self {
            proxy_name,
            version: None,
            working_techniques: Vec::new(),
            protections: Vec::new(),
            confidence: 0.5,
        }
    }

    pub fn with_version(mut self, version: String) -> Self {
        self.version = Some(version);
        self
    }

    pub fn add_working_technique(&mut self, technique: String) {
        if !self.working_techniques.contains(&technique) {
            self.working_techniques.push(technique);
        }
    }

    pub fn add_protection(&mut self, protection: String) {
        if !self.protections.contains(&protection) {
            self.protections.push(protection);
        }
    }
}

/// Main cache for HTTP smuggling signatures and fingerprints
#[derive(Debug, Clone)]
pub struct HttpSmugglingCache {
    /// Cached signatures by target tech fingerprint
    signatures: Arc<RwLock<HashMap<String, Vec<SmugglingSignature>>>>,
    
    /// Proxy fingerprints by target host
    proxy_fingerprints: Arc<RwLock<HashMap<String, ProxyFingerprint>>>,
    
    /// Disabled noisy modules by target type
    disabled_modules: Arc<RwLock<HashMap<String, Vec<String>>>>,
    
    /// Maximum cache size (bounded for memory efficiency)
    max_signatures: usize,
}

impl HttpSmugglingCache {
    pub fn new(max_signatures: usize) -> Self {
        Self {
            signatures: Arc::new(RwLock::new(HashMap::new())),
            proxy_fingerprints: Arc::new(RwLock::new(HashMap::new())),
            disabled_modules: Arc::new(RwLock::new(HashMap::new())),
            max_signatures,
        }
    }

    /// Add a successful smuggling signature
    pub async fn add_signature(&self, signature: SmugglingSignature) {
        let mut sigs = self.signatures.write().await;
        
        let tech_key = signature.tech_fingerprint.clone();
        let entries = sigs.entry(tech_key).or_insert_with(Vec::new);
        
        // Enforce bounded size
        if entries.len() >= self.max_signatures {
            // Remove oldest/least successful entry
            entries.sort_by(|a, b| {
                b.success_rate.partial_cmp(&a.success_rate)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            entries.pop();
        }
        
        entries.push(signature);
    }

    /// Get signatures for a specific technology
    pub async fn get_signatures(&self, tech_fingerprint: &str) -> Vec<SmugglingSignature> {
        let sigs = self.signatures.read().await;
        
        sigs.get(tech_fingerprint)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Get best signatures for a technology (highest success rate)
    pub async fn get_best_signatures(&self, tech_fingerprint: &str, limit: usize) -> Vec<SmugglingSignature> {
        let mut sigs = self.get_signatures(tech_fingerprint).await;
        
        sigs.sort_by(|a, b| {
            b.success_rate.partial_cmp(&a.success_rate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        
        sigs.into_iter().take(limit).collect()
    }

    /// Store proxy fingerprint
    pub async fn store_fingerprint(&self, host: String, fingerprint: ProxyFingerprint) {
        let mut fps = self.proxy_fingerprints.write().await;
        fps.insert(host, fingerprint);
    }

    /// Get proxy fingerprint for a host
    pub async fn get_fingerprint(&self, host: &str) -> Option<ProxyFingerprint> {
        let fps = self.proxy_fingerprints.read().await;
        fps.get(host).cloned()
    }

    /// Disable a noisy module for a target type
    pub async fn disable_module(&self, target_type: String, module_id: String) {
        let mut disabled = self.disabled_modules.write().await;
        
        let entries = disabled.entry(target_type).or_insert_with(Vec::new);
        if !entries.contains(&module_id) {
            entries.push(module_id);
        }
    }

    /// Check if a module is disabled for a target type
    pub async fn is_module_disabled(&self, target_type: &str, module_id: &str) -> bool {
        let disabled = self.disabled_modules.read().await;
        
        disabled.get(target_type)
            .map(|m| m.contains(&module_id.to_string()))
            .unwrap_or(false)
    }

    /// Get all disabled modules for a target type
    pub async fn get_disabled_modules(&self, target_type: &str) -> Vec<String> {
        let disabled = self.disabled_modules.read().await;
        
        disabled.get(target_type)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Clear old entries (cache maintenance)
    pub async fn cleanup(&self, max_age_ms: u64) {
        let now = current_timestamp();
        let mut sigs = self.signatures.write().await;
        
        for (_, entries) in sigs.iter_mut() {
            entries.retain(|s| now - s.last_used < max_age_ms);
        }
        
        // Remove empty entries
        sigs.retain(|_, v| !v.is_empty());
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let sigs = self.signatures.read().await;
        let fps = self.proxy_fingerprints.read().await;
        let disabled = self.disabled_modules.read().await;
        
        let total_sigs: usize = sigs.values().map(|v| v.len()).sum();
        let total_fps = fps.len();
        let total_disabled: usize = disabled.values().map(|v| v.len()).sum();
        
        CacheStats {
            total_signatures: total_sigs,
            total_fingerprints: total_fps,
            total_disabled_modules: total_disabled,
            tech_categories: sigs.len(),
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_signatures: usize,
    pub total_fingerprints: usize,
    pub total_disabled_modules: usize,
    pub tech_categories: usize,
}

/// Generate unique ID
fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    format!("{:x}", duration.as_nanos() as u64)
}

/// Get current timestamp in milliseconds
fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_signature_creation() {
        let sig = SmugglingSignature::new(
            "HTTP-001".to_string(),
            "nginx-1.18".to_string(),
            "CL.TE payload".to_string(),
            "200 OK smuggled".to_string(),
        );
        
        assert_eq!(sig.check_id, "HTTP-001");
        assert_eq!(sig.success_rate, 1.0);
        assert_eq!(sig.test_count, 1);
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let cache = HttpSmugglingCache::new(100);
        
        let sig = SmugglingSignature::new(
            "HTTP-001".to_string(),
            "nginx-1.18".to_string(),
            "test payload".to_string(),
            "test response".to_string(),
        );
        
        cache.add_signature(sig).await;
        
        let sigs = cache.get_signatures("nginx-1.18").await;
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].check_id, "HTTP-001");
    }

    #[tokio::test]
    async fn test_fingerprint_storage() {
        let cache = HttpSmugglingCache::new(100);
        
        let fp = ProxyFingerprint::new("nginx".to_string())
            .with_version("1.18.0".to_string());
        
        cache.store_fingerprint("example.com".to_string(), fp).await;
        
        let retrieved = cache.get_fingerprint("example.com").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().proxy_name, "nginx");
    }

    #[tokio::test]
    async fn test_module_disable() {
        let cache = HttpSmugglingCache::new(100);
        
        cache.disable_module("nginx".to_string(), "HTTP-NOISY-001".to_string()).await;
        
        assert!(cache.is_module_disabled("nginx", "HTTP-NOISY-001").await);
        assert!(!cache.is_module_disabled("nginx", "HTTP-SAFE-001").await);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = HttpSmugglingCache::new(100);
        
        let stats = cache.stats().await;
        assert_eq!(stats.total_signatures, 0);
        assert_eq!(stats.total_fingerprints, 0);
    }
}
