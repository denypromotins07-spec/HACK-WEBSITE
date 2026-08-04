//! SSRF/LFI Learning Cache Module
//!
//! Caches successful SSRF/LFI payloads, internal IP ranges, and wrapper signatures
//! for the self-learning engine.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use crate::findings::Severity;

/// SSRF/LFI learning cache
pub struct SsrfLfiCache {
    /// Successful SSRF payloads by target type
    ssrf_payloads: Arc<RwLock<HashMap<SsrfTargetType, Vec<CachedPayload>>>>,
    /// Successful LFI payloads by technique
    lfi_payloads: Arc<RwLock<HashMap<LfiTechnique, Vec<CachedPayload>>>>,
    /// Internal IP ranges discovered
    internal_ips: Arc<RwLock<HashSet<String>>>,
    /// Cloud metadata endpoints that worked
    cloud_endpoints: Arc<RwLock<HashMap<String, Vec<CachedEndpoint>>>>,
    /// PHP wrapper signatures
    php_wrappers: Arc<RwLock<HashMap<String, WrapperSignature>>>,
    /// Nginx alias patterns
    nginx_aliases: Arc<RwLock<HashMap<String, AliasPattern>>>,
    /// Traversal bypass techniques
    traversal_bypasses: Arc<RwLock<HashMap<String, BypassPattern>>>,
    /// Service fingerprints
    service_fingerprints: Arc<RwLock<HashMap<String, ServiceFingerprint>>>,
    /// Cache statistics
    stats: Arc<RwLock<CacheStats>>,
}

/// SSRF target type
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum SsrfTargetType {
    Localhost,
    PrivateIP,
    CloudMetadata,
    InternalService,
    DnsRebinding,
    ProtocolHandler,
}

/// LFI technique
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum LfiTechnique {
    BasicTraversal,
    NullByte,
    PhpFilter,
    PhpInput,
    ExpectWrapper,
    DataWrapper,
    PharWrapper,
    ZipWrapper,
    LogPoisoning,
    ProcSelfEnviron,
    NormalizationBypass,
    NginxAlias,
}

/// Cached payload with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPayload {
    pub payload: String,
    pub target: String,
    pub technique: String,
    pub severity: Severity,
    pub confidence: u8,
    pub first_seen: u64,
    last_seen: u64,
    pub success_count: u32,
    pub failure_count: u32,
    pub contexts: Vec<String>,
    pub response_indicators: Vec<String>,
}

/// Cached cloud metadata endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedEndpoint {
    pub provider: String,
    pub path: String,
    pub sensitivity: String,
    pub requires_token: bool,
    pub token_header: Option<String>,
    pub first_seen: u64,
    last_seen: u64,
    pub success_count: u32,
}

/// PHP wrapper signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperSignature {
    pub wrapper_name: String,
    pub filter_chain: Option<String>,
    pub detection_patterns: Vec<String>,
    pub requires_config: bool,
    pub config_options: Vec<String>,
    pub first_seen: u64,
    last_seen: u64,
    pub success_count: u32,
    pub rce_capable: bool,
}

/// Nginx alias pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasPattern {
    pub alias_prefix: String,
    pub target_path: String,
    pub traversal_payload: String,
    pub off_by_slash: bool,
    pub multi_level: bool,
    pub first_seen: u64,
    last_seen: u64,
    pub success_count: u32,
}

/// Traversal bypass pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassPattern {
    pub technique: String,
    pub payload_template: String,
    pub description: String,
    pub target_os: String,
    pub first_seen: u64,
    last_seen: u64,
    pub success_count: u32,
}

/// Service fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFingerprint {
    pub service_name: String,
    pub version: Option<String>,
    pub port: u16,
    pub protocol: String,
    pub banner: String,
    pub detection_patterns: Vec<String>,
    pub first_seen: u64,
    last_seen: u64,
    pub success_count: u32,
}

/// Cache statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_ssrf_payloads: usize,
    pub total_lfi_payloads: usize,
    pub total_internal_ips: usize,
    pub total_cloud_endpoints: usize,
    pub total_wrappers: usize,
    pub total_aliases: usize,
    pub total_bypasses: usize,
    pub total_fingerprints: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub last_updated: u64,
}

impl SsrfLfiCache {
    pub fn new() -> Self {
        Self {
            ssrf_payloads: Arc::new(RwLock::new(HashMap::new())),
            lfi_payloads: Arc::new(RwLock::new(HashMap::new())),
            internal_ips: Arc::new(RwLock::new(HashSet::new())),
            cloud_endpoints: Arc::new(RwLock::new(HashMap::new())),
            php_wrappers: Arc::new(RwLock::new(HashMap::new())),
            nginx_aliases: Arc::new(RwLock::new(HashMap::new())),
            traversal_bypasses: Arc::new(RwLock::new(HashMap::new())),
            service_fingerprints: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }

    /// Record a successful SSRF payload
    pub fn record_ssrf_payload(
        &self,
        target_type: SsrfTargetType,
        payload: &str,
        target: &str,
        technique: &str,
        severity: Severity,
        confidence: u8,
        context: &str,
        response_indicators: Vec<String>,
    ) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut payloads = self.ssrf_payloads.write().unwrap();
        let entry = payloads.entry(target_type).or_default();
        
        // Check if payload already exists
        if let Some(existing) = entry.iter_mut().find(|p| p.payload == payload && p.target == target) {
            existing.last_seen = now;
            existing.success_count += 1;
            existing.confidence = existing.confidence.max(confidence);
            if !existing.contexts.contains(&context.to_string()) {
                existing.contexts.push(context.to_string());
            }
            for indicator in response_indicators {
                if !existing.response_indicators.contains(&indicator) {
                    existing.response_indicators.push(indicator);
                }
            }
        } else {
            entry.push(CachedPayload {
                payload: payload.to_string(),
                target: target.to_string(),
                technique: technique.to_string(),
                severity,
                confidence,
                first_seen: now,
                last_seen: now,
                success_count: 1,
                failure_count: 0,
                contexts: vec![context.to_string()],
                response_indicators,
            });
        }
        
        self.update_stats();
    }

    /// Record a successful LFI payload
    pub fn record_lfi_payload(
        &self,
        technique: LfiTechnique,
        payload: &str,
        target: &str,
        severity: Severity,
        confidence: u8,
        context: &str,
        response_indicators: Vec<String>,
    ) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut payloads = self.lfi_payloads.write().unwrap();
        let entry = payloads.entry(technique).or_default();
        
        if let Some(existing) = entry.iter_mut().find(|p| p.payload == payload && p.target == target) {
            existing.last_seen = now;
            existing.success_count += 1;
            existing.confidence = existing.confidence.max(confidence);
            if !existing.contexts.contains(&context.to_string()) {
                existing.contexts.push(context.to_string());
            }
            for indicator in response_indicators {
                if !existing.response_indicators.contains(&indicator) {
                    existing.response_indicators.push(indicator);
                }
            }
        } else {
            entry.push(CachedPayload {
                payload: payload.to_string(),
                target: target.to_string(),
                technique: format!("{:?}", technique),
                severity,
                confidence,
                first_seen: now,
                last_seen: now,
                success_count: 1,
                failure_count: 0,
                contexts: vec![context.to_string()],
                response_indicators,
            });
        }
        
        self.update_stats();
    }

    /// Record discovered internal IP
    pub fn record_internal_ip(&self, ip: &str) {
        let mut ips = self.internal_ips.write().unwrap();
        ips.insert(ip.to_string());
        self.update_stats();
    }

    /// Record cloud metadata endpoint
    pub fn record_cloud_endpoint(
        &self,
        provider: &str,
        path: &str,
        sensitivity: &str,
        requires_token: bool,
        token_header: Option<String>,
    ) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut endpoints = self.cloud_endpoints.write().unwrap();
        let entry = endpoints.entry(provider.to_string()).or_default();
        
        if let Some(existing) = entry.iter_mut().find(|e| e.path == path) {
            existing.last_seen = now;
            existing.success_count += 1;
        } else {
            entry.push(CachedEndpoint {
                provider: provider.to_string(),
                path: path.to_string(),
                sensitivity: sensitivity.to_string(),
                requires_token,
                token_header,
                first_seen: now,
                last_seen: now,
                success_count: 1,
            });
        }
        
        self.update_stats();
    }

    /// Record PHP wrapper signature
    pub fn record_php_wrapper(
        &self,
        wrapper_name: &str,
        filter_chain: Option<String>,
        detection_patterns: Vec<String>,
        requires_config: bool,
        config_options: Vec<String>,
        rce_capable: bool,
    ) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut wrappers = self.php_wrappers.write().unwrap();
        
        if let Some(existing) = wrappers.get_mut(wrapper_name) {
            existing.last_seen = now;
            existing.success_count += 1;
            for pattern in detection_patterns {
                if !existing.detection_patterns.contains(&pattern) {
                    existing.detection_patterns.push(pattern);
                }
            }
            existing.rce_capable = existing.rce_capable || rce_capable;
        } else {
            wrappers.insert(wrapper_name.to_string(), WrapperSignature {
                wrapper_name: wrapper_name.to_string(),
                filter_chain,
                detection_patterns,
                requires_config,
                config_options,
                first_seen: now,
                last_seen: now,
                success_count: 1,
                rce_capable,
            });
        }
        
        self.update_stats();
    }

    /// Record Nginx alias pattern
    pub fn record_nginx_alias(
        &self,
        alias_prefix: &str,
        target_path: &str,
        traversal_payload: &str,
        off_by_slash: bool,
        multi_level: bool,
    ) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut aliases = self.nginx_aliases.write().unwrap();
        let key = format!("{}:{}", alias_prefix, target_path);
        
        if let Some(existing) = aliases.get_mut(&key) {
            existing.last_seen = now;
            existing.success_count += 1;
        } else {
            aliases.insert(key, AliasPattern {
                alias_prefix: alias_prefix.to_string(),
                target_path: target_path.to_string(),
                traversal_payload: traversal_payload.to_string(),
                off_by_slash,
                multi_level,
                first_seen: now,
                last_seen: now,
                success_count: 1,
            });
        }
        
        self.update_stats();
    }

    /// Record traversal bypass pattern
    pub fn record_traversal_bypass(
        &self,
        technique: &str,
        payload_template: &str,
        description: &str,
        target_os: &str,
    ) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut bypasses = self.traversal_bypasses.write().unwrap();
        
        if let Some(existing) = bypasses.get_mut(technique) {
            existing.last_seen = now;
            existing.success_count += 1;
        } else {
            bypasses.insert(technique.to_string(), BypassPattern {
                technique: technique.to_string(),
                payload_template: payload_template.to_string(),
                description: description.to_string(),
                target_os: target_os.to_string(),
                first_seen: now,
                last_seen: now,
                success_count: 1,
            });
        }
        
        self.update_stats();
    }

    /// Record service fingerprint
    pub fn record_service_fingerprint(
        &self,
        service_name: &str,
        version: Option<String>,
        port: u16,
        protocol: &str,
        banner: &str,
        detection_patterns: Vec<String>,
    ) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut fingerprints = self.service_fingerprints.write().unwrap();
        let key = format!("{}:{}", service_name, port);
        
        if let Some(existing) = fingerprints.get_mut(&key) {
            existing.last_seen = now;
            existing.success_count += 1;
            existing.version = version.or(existing.version.clone());
            for pattern in detection_patterns {
                if !existing.detection_patterns.contains(&pattern) {
                    existing.detection_patterns.push(pattern);
                }
            }
        } else {
            fingerprints.insert(key, ServiceFingerprint {
                service_name: service_name.to_string(),
                version,
                port,
                protocol: protocol.to_string(),
                banner: banner.to_string(),
                detection_patterns,
                first_seen: now,
                last_seen: now,
                success_count: 1,
            });
        }
        
        self.update_stats();
    }

    /// Get successful SSRF payloads for a target type
    pub fn get_ssrf_payloads(&self, target_type: &SsrfTargetType) -> Vec<CachedPayload> {
        let payloads = self.ssrf_payloads.read().unwrap();
        payloads.get(target_type).cloned().unwrap_or_default()
    }

    /// Get successful LFI payloads for a technique
    pub fn get_lfi_payloads(&self, technique: &LfiTechnique) -> Vec<CachedPayload> {
        let payloads = self.lfi_payloads.read().unwrap();
        payloads.get(technique).cloned().unwrap_or_default()
    }

    /// Get all internal IPs
    pub fn get_internal_ips(&self) -> HashSet<String> {
        self.internal_ips.read().unwrap().clone()
    }

    /// Get cloud endpoints for a provider
    pub fn get_cloud_endpoints(&self, provider: &str) -> Vec<CachedEndpoint> {
        let endpoints = self.cloud_endpoints.read().unwrap();
        endpoints.get(provider).cloned().unwrap_or_default()
    }

    /// Get PHP wrapper signatures
    pub fn get_php_wrappers(&self) -> HashMap<String, WrapperSignature> {
        self.php_wrappers.read().unwrap().clone()
    }

    /// Get Nginx alias patterns
    pub fn get_nginx_aliases(&self) -> HashMap<String, AliasPattern> {
        self.nginx_aliases.read().unwrap().clone()
    }

    /// Get traversal bypass patterns
    pub fn get_traversal_bypasses(&self) -> HashMap<String, BypassPattern> {
        self.traversal_bypasses.read().unwrap().clone()
    }

    /// Get service fingerprints
    pub fn get_service_fingerprints(&self) -> HashMap<String, ServiceFingerprint> {
        self.service_fingerprints.read().unwrap().clone()
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        self.stats.read().unwrap().clone()
    }

    /// Update cache statistics
    fn update_stats(&self) {
        let mut stats = self.stats.write().unwrap();
        let ssrf_payloads = self.ssrf_payloads.read().unwrap();
        let lfi_payloads = self.lfi_payloads.read().unwrap();
        let internal_ips = self.internal_ips.read().unwrap();
        let cloud_endpoints = self.cloud_endpoints.read().unwrap();
        let php_wrappers = self.php_wrappers.read().unwrap();
        let nginx_aliases = self.nginx_aliases.read().unwrap();
        let traversal_bypasses = self.traversal_bypasses.read().unwrap();
        let service_fingerprints = self.service_fingerprints.read().unwrap();
        
        stats.total_ssrf_payloads = ssrf_payloads.values().map(|v| v.len()).sum();
        stats.total_lfi_payloads = lfi_payloads.values().map(|v| v.len()).sum();
        stats.total_internal_ips = internal_ips.len();
        stats.total_cloud_endpoints = cloud_endpoints.values().map(|v| v.len()).sum();
        stats.total_wrappers = php_wrappers.len();
        stats.total_aliases = nginx_aliases.len();
        stats.total_bypasses = traversal_bypasses.len();
        stats.total_fingerprints = service_fingerprints.len();
        stats.last_updated = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    }

    /// Increment cache hit
    pub fn increment_hit(&self) {
        let mut stats = self.stats.write().unwrap();
        stats.cache_hits += 1;
    }

    /// Increment cache miss
    pub fn increment_miss(&self) {
        let mut stats = self.stats.write().unwrap();
        stats.cache_misses += 1;
    }

    /// Export cache for persistence
    pub fn export(&self) -> CacheExport {
        CacheExport {
            ssrf_payloads: self.ssrf_payloads.read().unwrap().clone(),
            lfi_payloads: self.lfi_payloads.read().unwrap().clone(),
            internal_ips: self.internal_ips.read().unwrap().clone(),
            cloud_endpoints: self.cloud_endpoints.read().unwrap().clone(),
            php_wrappers: self.php_wrappers.read().unwrap().clone(),
            nginx_aliases: self.nginx_aliases.read().unwrap().clone(),
            traversal_bypasses: self.traversal_bypasses.read().unwrap().clone(),
            service_fingerprints: self.service_fingerprints.read().unwrap().clone(),
            stats: self.stats.read().unwrap().clone(),
        }
    }

    /// Import cache from persistence
    pub fn import(&self, export: CacheExport) {
        *self.ssrf_payloads.write().unwrap() = export.ssrf_payloads;
        *self.lfi_payloads.write().unwrap() = export.lfi_payloads;
        *self.internal_ips.write().unwrap() = export.internal_ips;
        *self.cloud_endpoints.write().unwrap() = export.cloud_endpoints;
        *self.php_wrappers.write().unwrap() = export.php_wrappers;
        *self.nginx_aliases.write().unwrap() = export.nginx_aliases;
        *self.traversal_bypasses.write().unwrap() = export.traversal_bypasses;
        *self.service_fingerprints.write().unwrap() = export.service_fingerprints;
        *self.stats.write().unwrap() = export.stats;
    }

    /// Clear all cache data
    pub fn clear(&self) {
        *self.ssrf_payloads.write().unwrap() = HashMap::new();
        *self.lfi_payloads.write().unwrap() = HashMap::new();
        *self.internal_ips.write().unwrap() = HashSet::new();
        *self.cloud_endpoints.write().unwrap() = HashMap::new();
        *self.php_wrappers.write().unwrap() = HashMap::new();
        *self.nginx_aliases.write().unwrap() = HashMap::new();
        *self.traversal_bypasses.write().unwrap() = HashMap::new();
        *self.service_fingerprints.write().unwrap() = HashMap::new();
        *self.stats.write().unwrap() = CacheStats::default();
    }

    /// Cleanup old entries (older than max_age)
    pub fn cleanup(&self, max_age: Duration) -> usize {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let max_age_secs = max_age.as_secs();
        let mut cleaned = 0;

        // Clean SSRF payloads
        {
            let mut payloads = self.ssrf_payloads.write().unwrap();
            for (_, vec) in payloads.iter_mut() {
                let len_before = vec.len();
                vec.retain(|p| now - p.last_seen < max_age_secs);
                cleaned += len_before - vec.len();
            }
        }

        // Clean LFI payloads
        {
            let mut payloads = self.lfi_payloads.write().unwrap();
            for (_, vec) in payloads.iter_mut() {
                let len_before = vec.len();
                vec.retain(|p| now - p.last_seen < max_age_secs);
                cleaned += len_before - vec.len();
            }
        }

        // Clean cloud endpoints
        {
            let mut endpoints = self.cloud_endpoints.write().unwrap();
            for (_, vec) in endpoints.iter_mut() {
                let len_before = vec.len();
                vec.retain(|e| now - e.last_seen < max_age_secs);
                cleaned += len_before - vec.len();
            }
        }

        // Clean wrappers
        {
            let mut wrappers = self.php_wrappers.write().unwrap();
            let len_before = wrappers.len();
            wrappers.retain(|_, w| now - w.last_seen < max_age_secs);
            cleaned += len_before - wrappers.len();
        }

        // Clean aliases
        {
            let mut aliases = self.nginx_aliases.write().unwrap();
            let len_before = aliases.len();
            aliases.retain(|_, a| now - a.last_seen < max_age_secs);
            cleaned += len_before - aliases.len();
        }

        // Clean bypasses
        {
            let mut bypasses = self.traversal_bypasses.write().unwrap();
            let len_before = bypasses.len();
            bypasses.retain(|_, b| now - b.last_seen < max_age_secs);
            cleaned += len_before - bypasses.len();
        }

        // Clean fingerprints
        {
            let mut fingerprints = self.service_fingerprints.write().unwrap();
            let len_before = fingerprints.len();
            fingerprints.retain(|_, f| now - f.last_seen < max_age_secs);
            cleaned += len_before - fingerprints.len();
        }

        self.update_stats();
        cleaned
    }
}

/// Cache export for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheExport {
    pub ssrf_payloads: HashMap<SsrfTargetType, Vec<CachedPayload>>,
    pub lfi_payloads: HashMap<LfiTechnique, Vec<CachedPayload>>,
    pub internal_ips: HashSet<String>,
    pub cloud_endpoints: HashMap<String, Vec<CachedEndpoint>>,
    pub php_wrappers: HashMap<String, WrapperSignature>,
    pub nginx_aliases: HashMap<String, AliasPattern>,
    pub traversal_bypasses: HashMap<String, BypassPattern>,
    pub service_fingerprints: HashMap<String, ServiceFingerprint>,
    pub stats: CacheStats,
}

impl Default for SsrfLfiCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SsrfLfiCache {
    fn clone(&self) -> Self {
        Self {
            ssrf_payloads: Arc::clone(&self.ssrf_payloads),
            lfi_payloads: Arc::clone(&self.lfi_payloads),
            internal_ips: Arc::clone(&self.internal_ips),
            cloud_endpoints: Arc::clone(&self.cloud_endpoints),
            php_wrappers: Arc::clone(&self.php_wrappers),
            nginx_aliases: Arc::clone(&self.nginx_aliases),
            traversal_bypasses: Arc::clone(&self.traversal_bypasses),
            service_fingerprints: Arc::clone(&self.service_fingerprints),
            stats: Arc::clone(&self.stats),
        }
    }
}

/// Global cache instance
use once_cell::sync::OnceCell;

static GLOBAL_CACHE: OnceCell<Arc<SsrfLfiCache>> = OnceCell::new();

/// Get or create global cache
pub fn get_global_cache() -> Arc<SsrfLfiCache> {
    GLOBAL_CACHE.get_or_init(|| Arc::new(SsrfLfiCache::new())).clone()
}

/// Initialize global cache with existing data
pub fn init_global_cache(cache: SsrfLfiCache) {
    let _ = GLOBAL_CACHE.set(Arc::new(cache));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_ssrf_payload() {
        let cache = SsrfLfiCache::new();
        
        cache.record_ssrf_payload(
            SsrfTargetType::CloudMetadata,
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254",
            "cloud_metadata",
            Severity::Critical,
            90,
            "url_param",
            vec!["ami-id".to_string(), "instance-id".to_string()],
        );
        
        let payloads = cache.get_ssrf_payloads(&SsrfTargetType::CloudMetadata);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].payload, "http://169.254.169.254/latest/meta-data/");
        assert_eq!(payloads[0].success_count, 1);
    }

    #[test]
    fn test_record_lfi_payload() {
        let cache = SsrfLfiCache::new();
        
        cache.record_lfi_payload(
            LfiTechnique::PhpFilter,
            "php://filter/read=convert.base64-encode/resource=/etc/passwd",
            "/etc/passwd",
            Severity::High,
            85,
            "file_param",
            vec!["root:".to_string(), "daemon:".to_string()],
        );
        
        let payloads = cache.get_lfi_payloads(&LfiTechnique::PhpFilter);
        assert_eq!(payloads.len(), 1);
        assert!(payloads[0].payload.contains("php://filter"));
    }

    #[test]
    fn test_record_internal_ip() {
        let cache = SsrfLfiCache::new();
        
        cache.record_internal_ip("10.0.0.1");
        cache.record_internal_ip("192.168.1.1");
        cache.record_internal_ip("169.254.169.254");
        
        let ips = cache.get_internal_ips();
        assert_eq!(ips.len(), 3);
        assert!(ips.contains("10.0.0.1"));
        assert!(ips.contains("192.168.1.1"));
        assert!(ips.contains("169.254.169.254"));
    }

    #[test]
    fn test_record_cloud_endpoint() {
        let cache = SsrfLfiCache::new();
        
        cache.record_cloud_endpoint(
            "aws",
            "/latest/meta-data/iam/security-credentials/",
            "critical",
            false,
            None,
        );
        
        let endpoints = cache.get_cloud_endpoints("aws");
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].path, "/latest/meta-data/iam/security-credentials/");
        assert_eq!(endpoints[0].sensitivity, "critical");
    }

    #[test]
    fn test_record_php_wrapper() {
        let cache = SsrfLfiCache::new();
        
        cache.record_php_wrapper(
            "php://filter",
            Some("convert.base64-encode".to_string()),
            vec!["root:".to_string(), "PD9waHA".to_string()],
            false,
            vec![],
            false,
        );
        
        let wrappers = cache.get_php_wrappers();
        assert_eq!(wrappers.len(), 1);
        assert!(wrappers.contains_key("php://filter"));
        assert_eq!(wrappers["php://filter"].detection_patterns.len(), 2);
    }

    #[test]
    fn test_record_nginx_alias() {
        let cache = SsrfLfiCache::new();
        
        cache.record_nginx_alias(
            "/static/",
            "/var/www/static",
            "/static../etc/passwd",
            true,
            false,
        );
        
        let aliases = cache.get_nginx_aliases();
        assert_eq!(aliases.len(), 1);
        let key = "/static/:/var/www/static";
        assert!(aliases.contains_key(key));
        assert!(aliases[key].off_by_slash);
    }

    #[test]
    fn test_record_traversal_bypass() {
        let cache = SsrfLfiCache::new();
        
        cache.record_traversal_bypass(
            "double_encoding",
            "..%252f..%252f..%252fetc%252fpasswd",
            "Double URL encoded traversal",
            "linux",
        );
        
        let bypasses = cache.get_traversal_bypasses();
        assert_eq!(bypasses.len(), 1);
        assert!(bypasses.contains_key("double_encoding"));
        assert_eq!(bypasses["double_encoding"].target_os, "linux");
    }

    #[test]
    fn test_record_service_fingerprint() {
        let cache = SsrfLfiCache::new();
        
        cache.record_service_fingerprint(
            "Redis",
            Some("6.2.0".to_string()),
            6379,
            "tcp",
            "redis_version:6.2.0",
            vec!["redis_version".to_string(), "connected_clients".to_string()],
        );
        
        let fingerprints = cache.get_service_fingerprints();
        assert_eq!(fingerprints.len(), 1);
        let key = "Redis:6379";
        assert!(fingerprints.contains_key(key));
        assert_eq!(fingerprints[key].version, Some("6.2.0".to_string()));
    }

    #[test]
    fn test_cache_stats() {
        let cache = SsrfLfiCache::new();
        
        cache.record_ssrf_payload(
            SsrfTargetType::Localhost,
            "http://127.0.0.1",
            "127.0.0.1",
            "basic",
            Severity::High,
            80,
            "test",
            vec![],
        );
        
        cache.record_lfi_payload(
            LfiTechnique::BasicTraversal,
            "../../../etc/passwd",
            "/etc/passwd",
            Severity::High,
            85,
            "test",
            vec![],
        );
        
        cache.record_internal_ip("10.0.0.1");
        
        let stats = cache.get_stats();
        assert_eq!(stats.total_ssrf_payloads, 1);
        assert_eq!(stats.total_lfi_payloads, 1);
        assert_eq!(stats.total_internal_ips, 1);
    }

    #[test]
    fn test_export_import() {
        let cache = SsrfLfiCache::new();
        
        cache.record_ssrf_payload(
            SsrfTargetType::CloudMetadata,
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254",
            "cloud_metadata",
            Severity::Critical,
            90,
            "test",
            vec![],
        );
        
        let export = cache.export();
        assert_eq!(export.ssrf_payloads.len(), 1);
        
        let new_cache = SsrfLfiCache::new();
        new_cache.import(export);
        
        let payloads = new_cache.get_ssrf_payloads(&SsrfTargetType::CloudMetadata);
        assert_eq!(payloads.len(), 1);
    }

    #[test]
    fn test_cleanup() {
        let cache = SsrfLfiCache::new();
        
        cache.record_ssrf_payload(
            SsrfTargetType::Localhost,
            "http://127.0.0.1",
            "127.0.0.1",
            "basic",
            Severity::High,
            80,
            "test",
            vec![],
        );
        
        // Manually set last_seen to old timestamp
        {
            let mut payloads = cache.ssrf_payloads.write().unwrap();
            if let Some(vec) = payloads.get_mut(&SsrfTargetType::Localhost) {
                for p in vec.iter_mut() {
                    p.last_seen = 0; // Very old
                }
            }
        }
        
        let cleaned = cache.cleanup(Duration::from_secs(3600)); // 1 hour
        assert_eq!(cleaned, 1);
        
        let payloads = cache.get_ssrf_payloads(&SsrfTargetType::Localhost);
        assert_eq!(payloads.len(), 0);
    }

    #[test]
    fn test_global_cache() {
        let cache1 = get_global_cache();
        let cache2 = get_global_cache();
        
        // Should be the same instance
        assert!(Arc::ptr_eq(&cache1, &cache2));
    }
}