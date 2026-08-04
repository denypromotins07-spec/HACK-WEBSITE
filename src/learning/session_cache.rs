//! Session cache for authenticated routes and required headers.
//!
//! Caches authenticated routes, required headers, and auth state
//! to reduce repeated login overhead during scans.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Cached authentication data for a route.
#[derive(Debug, Clone)]
pub struct AuthRouteCache {
    /// Route path/URL.
    pub route: String,
    /// HTTP method.
    pub method: String,
    /// Whether this route requires authentication.
    pub requires_auth: bool,
    /// Required headers for authenticated access.
    pub required_headers: HashMap<String, String>,
    /// Cookie names required.
    pub required_cookies: Vec<String>,
    /// When this was cached.
    pub cached_at: Instant,
    /// Last accessed time.
    pub last_accessed: Instant,
    /// Access count.
    pub access_count: usize,
    /// Whether the cache entry is valid.
    pub valid: bool,
}

impl AuthRouteCache {
    /// Create a new route cache entry.
    pub fn new(route: &str, method: &str, requires_auth: bool) -> Self {
        let now = Instant::now();
        Self {
            route: route.to_string(),
            method: method.to_string(),
            requires_auth,
            required_headers: HashMap::new(),
            required_cookies: Vec::new(),
            cached_at: now,
            last_accessed: now,
            access_count: 0,
            valid: true,
        }
    }

    /// Add a required header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.required_headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Add a required cookie.
    pub fn with_cookie(mut self, name: &str) -> Self {
        self.required_cookies.push(name.to_string());
        self
    }

    /// Mark as accessed.
    pub fn touch(&mut self) {
        self.last_accessed = Instant::now();
        self.access_count += 1;
    }

    /// Check if this cache entry is stale.
    pub fn is_stale(&self, max_age: Duration) -> bool {
        Instant::now().duration_since(self.cached_at) > max_age
    }

    /// Invalidate this entry.
    pub fn invalidate(&mut self) {
        self.valid = false;
    }
}

/// Session-level cache for authenticated access patterns.
#[derive(Default)]
pub struct SessionAuthCache {
    /// Cached routes.
    routes: Arc<RwLock<HashMap<String, AuthRouteCache>>>,
    /// Global session cookies.
    session_cookies: Arc<RwLock<HashMap<String, String>>>,
    /// Global auth headers.
    auth_headers: Arc<RwLock<HashMap<String, String>>>,
    /// Cache configuration.
    config: SessionAuthCacheConfig,
}

/// Configuration for the session auth cache.
#[derive(Debug, Clone)]
pub struct SessionAuthCacheConfig {
    /// Maximum number of cached routes.
    pub max_routes: usize,
    /// Maximum age of cache entries.
    pub max_entry_age: Duration,
    /// Enable automatic cleanup.
    pub auto_cleanup: bool,
}

impl Default for SessionAuthCacheConfig {
    fn default() -> Self {
        Self {
            max_routes: 500,
            max_entry_age: Duration::from_secs(3600), // 1 hour
            auto_cleanup: true,
        }
    }
}

impl SessionAuthCache {
    /// Create a new session auth cache.
    pub fn new() -> Self {
        Self::with_config(SessionAuthCacheConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: SessionAuthCacheConfig) -> Self {
        Self {
            routes: Arc::new(RwLock::new(HashMap::new())),
            session_cookies: Arc::new(RwLock::new(HashMap::new())),
            auth_headers: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Cache an authenticated route.
    pub fn cache_route(&self, route: &str, method: &str, requires_auth: bool) -> Option<()> {
        // Check capacity
        {
            let routes = self.routes.read().ok()?;
            if routes.len() >= self.config.max_routes && !routes.contains_key(route) {
                // Would exceed capacity - could evict oldest
                drop(routes);
                // For simplicity, don't add new entries when full
                return None;
            }
        }

        let mut routes = self.routes.write().ok()?;
        
        let cache = routes.entry(format!("{}:{}", method, route)).or_insert_with(|| {
            AuthRouteCache::new(route, method, requires_auth)
        });
        
        cache.touch();
        Some(())
    }

    /// Get cached route info.
    pub fn get_route(&self, route: &str, method: &str) -> Option<AuthRouteCache> {
        let routes = self.routes.read().ok()?;
        let key = format!("{}:{}", method, route);
        let cache = routes.get(&key)?;
        
        if !cache.valid || cache.is_stale(self.config.max_entry_age) {
            return None;
        }
        
        Some(cache.clone())
    }

    /// Update required headers for a route.
    pub fn set_route_headers(&self, route: &str, method: &str, headers: HashMap<String, String>) -> bool {
        let mut routes = match self.routes.write() {
            Ok(r) => r,
            Err(_) => return false,
        };
        
        let key = format!("{}:{}", method, route);
        if let Some(cache) = routes.get_mut(&key) {
            cache.required_headers = headers;
            cache.touch();
            true
        } else {
            false
        }
    }

    /// Set a global session cookie.
    pub fn set_session_cookie(&self, name: &str, value: &str) {
        if let Ok(mut cookies) = self.session_cookies.write() {
            cookies.insert(name.to_string(), value.to_string());
        }
    }

    /// Get all session cookies.
    pub fn get_session_cookies(&self) -> HashMap<String, String> {
        self.session_cookies.read().map(|c| c.clone()).unwrap_or_default()
    }

    /// Set a global auth header.
    pub fn set_auth_header(&self, name: &str, value: &str) {
        if let Ok(mut headers) = self.auth_headers.write() {
            headers.insert(name.to_string(), value.to_string());
        }
    }

    /// Get all auth headers.
    pub fn get_auth_headers(&self) -> HashMap<String, String> {
        self.auth_headers.read().map(|h| h.clone()).unwrap_or_default()
    }

    /// Build headers for an authenticated request.
    pub fn build_auth_headers(&self, route: &str, method: &str) -> HashMap<String, String> {
        let mut headers = self.get_auth_headers();
        
        // Add route-specific headers
        if let Some(cache) = self.get_route(route, method) {
            for (name, value) in cache.required_headers {
                headers.insert(name, value);
            }
        }
        
        headers
    }

    /// Invalidate all cached routes.
    pub fn invalidate_all(&self) {
        if let Ok(mut routes) = self.routes.write() {
            for cache in routes.values_mut() {
                cache.invalidate();
            }
        }
    }

    /// Clean up stale entries.
    pub fn cleanup(&self) -> usize {
        let mut routes = match self.routes.write() {
            Ok(r) => r,
            Err(_) => return 0,
        };
        
        let before = routes.len();
        let max_age = self.config.max_entry_age;
        
        routes.retain(|_, cache| cache.valid && !cache.is_stale(max_age));
        
        before - routes.len()
    }

    /// Get the number of cached routes.
    pub fn len(&self) -> usize {
        self.routes.read().map(|r| r.len()).unwrap_or(0)
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SessionAuthCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating authenticated requests with cached credentials.
pub struct AuthRequestBuilder {
    /// Base URL.
    base_url: String,
    /// HTTP method.
    method: String,
    /// Headers to include.
    headers: HashMap<String, String>,
    /// Cookies to include.
    cookies: HashMap<String, String>,
}

impl AuthRequestBuilder {
    /// Create a new builder.
    pub fn new(base_url: &str, method: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            method: method.to_string(),
            headers: HashMap::new(),
            cookies: HashMap::new(),
        }
    }

    /// Apply cached authentication from a session cache.
    pub fn with_cached_auth(mut self, cache: &SessionAuthCache, route: &str) -> Self {
        // Apply global auth headers
        for (name, value) in cache.get_auth_headers() {
            self.headers.insert(name, value);
        }
        
        // Apply route-specific headers
        if let Some(route_cache) = cache.get_route(route, &self.method) {
            for (name, value) in route_cache.required_headers {
                self.headers.insert(name, value);
            }
            
            // Apply required cookies
            let session_cookies = cache.get_session_cookies();
            for cookie_name in route_cache.required_cookies {
                if let Some(cookie_value) = session_cookies.get(&cookie_name) {
                    self.cookies.insert(cookie_name, cookie_value.clone());
                }
            }
        }
        
        self
    }

    /// Add a header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Add a cookie.
    pub fn with_cookie(mut self, name: &str, value: &str) -> Self {
        self.cookies.insert(name.to_string(), value.to_string());
        self
    }

    /// Build the final headers map.
    pub fn build_headers(self) -> HashMap<String, String> {
        self.headers
    }

    /// Build the cookie header value.
    pub fn build_cookie_header(self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; ")
    }
}
