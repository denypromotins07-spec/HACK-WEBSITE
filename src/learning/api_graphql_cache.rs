//! API/GraphQL Learning Cache Module
//! Caches discovered schemas, endpoint lists, and successful XXE payloads.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use parking_lot::RwLock;

#[derive(Debug, Clone)]
pub struct CachedSchema {
    pub endpoint: String,
    pub schema_hash: u64,
    pub types_count: usize,
    pub queries_count: usize,
    pub mutations_count: usize,
    pub cached_at: u64,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct CachedEndpoint {
    pub url: String,
    pub method: String,
    pub status_code: u16,
    pub response_hash: u64,
    pub is_vulnerable: bool,
    pub vulnerability_type: Option<String>,
    pub cached_at: u64,
}

#[derive(Debug, Clone)]
pub struct XxePayloadCache {
    pub payload: String,
    pub success_count: usize,
    pub last_success: u64,
    pub target_patterns: Vec<String>,
}

pub struct ApiGraphqlCache {
    schemas: RwLock<BTreeMap<String, CachedSchema>>,
    endpoints: RwLock<BTreeMap<String, CachedEndpoint>>,
    xxe_payloads: RwLock<HashMap<String, XxePayloadCache>>,
    graphql_injection_patterns: RwLock<HashSet<String>>,
    mass_assignment_fields: RwLock<HashSet<String>>,
    stats: RwLock<CacheStats>,
}

#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    pub schema_hits: u64,
    pub schema_misses: u64,
    pub endpoint_hits: u64,
    pub endpoint_misses: u64,
    pub xxe_payload_hits: u64,
    pub total_entries: usize,
}

impl ApiGraphqlCache {
    pub fn new() -> Self {
        Self {
            schemas: RwLock::new(BTreeMap::new()),
            endpoints: RwLock::new(BTreeMap::new()),
            xxe_payloads: RwLock::new(HashMap::new()),
            graphql_injection_patterns: RwLock::new(HashSet::new()),
            mass_assignment_fields: RwLock::new(HashSet::new()),
            stats: RwLock::new(CacheStats::default()),
        }
    }

    // Schema caching
    pub fn cache_schema(&self, endpoint: &str, schema: CachedSchema) {
        let mut schemas = self.schemas.write();
        schemas.insert(endpoint.to_string(), schema);
        
        let mut stats = self.stats.write();
        stats.total_entries = schemas.len() + self.endpoints.read().len();
    }

    pub fn get_cached_schema(&self, endpoint: &str) -> Option<CachedSchema> {
        let schemas = self.schemas.read();
        if let Some(schema) = schemas.get(endpoint) {
            let mut stats = self.stats.write();
            stats.schema_hits += 1;
            Some(schema.clone())
        } else {
            let mut stats = self.stats.write();
            stats.schema_misses += 1;
            None
        }
    }

    // Endpoint caching
    pub fn cache_endpoint(&self, url: &str, endpoint: CachedEndpoint) {
        let mut endpoints = self.endpoints.write();
        endpoints.insert(url.to_string(), endpoint);
        
        let mut stats = self.stats.write();
        stats.total_entries = self.schemas.read().len() + endpoints.len();
    }

    pub fn get_cached_endpoint(&self, url: &str) -> Option<CachedEndpoint> {
        let endpoints = self.endpoints.read();
        if let Some(endpoint) = endpoints.get(url) {
            let mut stats = self.stats.write();
            stats.endpoint_hits += 1;
            Some(endpoint.clone())
        } else {
            let mut stats = self.stats.write();
            stats.endpoint_misses += 1;
            None
        }
    }

    // XXE payload caching
    pub fn cache_xxe_payload(&self, payload: &str, target_pattern: &str, success: bool) {
        let mut payloads = self.xxe_payloads.write();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let entry = payloads.entry(payload.to_string()).or_insert_with(|| XxePayloadCache {
            payload: payload.to_string(),
            success_count: 0,
            last_success: 0,
            target_patterns: Vec::new(),
        });

        if success {
            entry.success_count += 1;
            entry.last_success = now;
            if !entry.target_patterns.contains(&target_pattern.to_string()) {
                entry.target_patterns.push(target_pattern.to_string());
            }
        }

        let mut stats = self.stats.write();
        stats.xxe_payload_hits += 1;
    }

    pub fn get_successful_xxe_payloads(&self) -> Vec<XxePayloadCache> {
        let payloads = self.xxe_payloads.read();
        payloads.values()
            .filter(|p| p.success_count > 0)
            .cloned()
            .collect()
    }

    // GraphQL injection pattern caching
    pub fn add_injection_pattern(&self, pattern: &str) {
        let mut patterns = self.graphql_injection_patterns.write();
        patterns.insert(pattern.to_string());
    }

    pub fn has_injection_pattern(&self, pattern: &str) -> bool {
        let patterns = self.graphql_injection_patterns.read();
        patterns.contains(pattern)
    }

    // Mass assignment field caching
    pub fn add_mass_assignment_field(&self, field: &str) {
        let mut fields = self.mass_assignment_fields.write();
        fields.insert(field.to_string());
    }

    pub fn get_known_mass_assignment_fields(&self) -> Vec<String> {
        let fields = self.mass_assignment_fields.read();
        fields.iter().cloned().collect()
    }

    // Cleanup old entries
    pub fn cleanup_expired(&self, max_age_seconds: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        {
            let mut schemas = self.schemas.write();
            schemas.retain(|_, v| now - v.cached_at < v.ttl_seconds && now - v.cached_at < max_age_seconds);
        }

        {
            let mut endpoints = self.endpoints.write();
            endpoints.retain(|_, v| now - v.cached_at < max_age_seconds);
        }

        {
            let mut payloads = self.xxe_payloads.write();
            payloads.retain(|_, v| now - v.last_success < max_age_seconds);
        }
    }

    pub fn get_stats(&self) -> CacheStats {
        let stats = self.stats.read();
        stats.clone()
    }

    pub fn clear(&self) {
        self.schemas.write().clear();
        self.endpoints.write().clear();
        self.xxe_payloads.write().clear();
        self.graphql_injection_patterns.write().clear();
        self.mass_assignment_fields.write().clear();
        
        let mut stats = self.stats.write();
        *stats = CacheStats::default();
    }
}

impl Default for ApiGraphqlCache {
    fn default() -> Self {
        Self::new()
    }
}

// Thread-safe shared cache type
pub type SharedApiGraphqlCache = Arc<ApiGraphqlCache>;

pub fn create_shared_cache() -> SharedApiGraphqlCache {
    Arc::new(ApiGraphqlCache::new())
}
