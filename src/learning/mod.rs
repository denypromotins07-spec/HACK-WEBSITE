//! Learning module for self-learning cache integration.
//!
//! This module provides:
//! - Authentication heuristics recording
//! - Session caching for authenticated routes
//! - Integration with the global learning registry

pub mod auth_heuristics;
pub mod session_cache;

pub use auth_heuristics::{
    AuthAttempt, AuthErrorFingerprint, AuthHeuristicsManager, AuthResult, EndpointHeuristics,
    LogoutBehavior, TokenExpiryRecord,
};
pub use session_cache::{
    AuthRequestBuilder, AuthRouteCache, SessionAuthCache, SessionAuthCacheConfig,
};

/// Global learning registry that combines all learning components.
use std::sync::{Arc, RwLock};

/// Combined learning state for the scanner.
#[derive(Default)]
pub struct LearningRegistry {
    /// Authentication heuristics manager.
    pub auth_heuristics: Arc<auth_heuristics::AuthHeuristicsManager>,
    /// Session authentication cache.
    pub session_cache: Arc<session_cache::SessionAuthCache>,
}

impl LearningRegistry {
    /// Create a new learning registry.
    pub fn new() -> Self {
        Self {
            auth_heuristics: Arc::new(auth_heuristics::AuthHeuristicsManager::new()),
            session_cache: Arc::new(session_cache::SessionAuthCache::new()),
        }
    }

    /// Record an authentication attempt across all learning components.
    pub fn record_auth_attempt(&self, attempt: auth_heuristics::AuthAttempt) {
        self.auth_heuristics.record_attempt(attempt);
    }

    /// Cache an authenticated route.
    pub fn cache_authenticated_route(&self, route: &str, method: &str, requires_auth: bool) {
        let _ = self.session_cache.cache_route(route, method, requires_auth);
    }

    /// Get heuristics for an endpoint.
    pub fn get_endpoint_heuristics(&self, url: &str) -> Option<auth_heuristics::EndpointHeuristics> {
        self.auth_heuristics.get_endpoint_heuristics(url)
    }

    /// Build authenticated request headers using cached data.
    pub fn build_auth_headers(&self, route: &str, method: &str) -> std::collections::HashMap<String, String> {
        self.session_cache.build_auth_headers(route, method)
    }

    /// Set a session cookie globally.
    pub fn set_session_cookie(&self, name: &str, value: &str) {
        self.session_cache.set_session_cookie(name, value);
    }

    /// Set an auth header globally.
    pub fn set_auth_header(&self, name: &str, value: &str) {
        self.session_cache.set_auth_header(name, value);
    }

    /// Record token expiry observation.
    pub fn record_token_expiry(&self, token_type: &str, lifetime_secs: u64, refresh_endpoint: Option<&str>) {
        self.auth_heuristics.record_token_expiry(token_type, lifetime_secs, refresh_endpoint);
    }

    /// Get expected token lifetime.
    pub fn get_token_lifetime(&self, token_type: &str) -> Option<u64> {
        self.auth_heuristics.get_token_lifetime(token_type)
    }

    /// Invalidate all cached authentication data.
    pub fn invalidate_all(&self) {
        self.session_cache.invalidate_all();
    }

    /// Clean up stale cache entries.
    pub fn cleanup(&self) -> usize {
        let session_cleaned = self.session_cache.cleanup();
        session_cleaned
    }

    /// Export all learning data for persistence.
    pub fn export(&self) -> std::collections::HashMap<String, serde_json::Value> {
        let mut export = std::collections::HashMap::new();
        
        // Export auth heuristics
        let auth_export = self.auth_heuristics.export();
        for (key, value) in auth_export {
            export.insert(format!("auth_{}", key), value);
        }
        
        // Export session cache stats
        export.insert(
            "session_cache_size".to_string(),
            serde_json::json!(self.session_cache.len()),
        );
        
        export
    }

    /// Clear all learning data.
    pub fn clear(&self) {
        self.auth_heuristics.clear();
        self.session_cache.invalidate_all();
    }
}

impl Clone for LearningRegistry {
    fn clone(&self) -> Self {
        Self {
            auth_heuristics: Arc::clone(&self.auth_heuristics),
            session_cache: Arc::clone(&self.session_cache),
        }
    }
}

/// Builder for creating a learning registry with custom configuration.
pub struct LearningRegistryBuilder {
    auth_heuristics: Option<auth_heuristics::AuthHeuristicsManager>,
    session_cache_config: Option<session_cache::SessionAuthCacheConfig>,
}

impl Default for LearningRegistryBuilder {
    fn default() -> Self {
        Self {
            auth_heuristics: None,
            session_cache_config: None,
        }
    }
}

impl LearningRegistryBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set custom auth heuristics manager.
    pub fn with_auth_heuristics(mut self, manager: auth_heuristics::AuthHeuristicsManager) -> Self {
        self.auth_heuristics = Some(manager);
        self
    }

    /// Set session cache configuration.
    pub fn with_session_cache_config(mut self, config: session_cache::SessionAuthCacheConfig) -> Self {
        self.session_cache_config = Some(config);
        self
    }

    /// Build the learning registry.
    pub fn build(self) -> LearningRegistry {
        LearningRegistry {
            auth_heuristics: Arc::new(self.auth_heuristics.unwrap_or_default()),
            session_cache: Arc::new(
                self.session_cache_config
                    .map(session_cache::SessionAuthCache::with_config)
                    .unwrap_or_default(),
            ),
        }
    }
}