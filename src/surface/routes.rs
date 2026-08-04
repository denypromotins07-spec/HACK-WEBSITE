//! Route graph construction from discovered paths, parameters, and response fingerprints.
//!
//! This module builds a directed graph of discovered routes for attack surface mapping.

use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};

/// HTTP method type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Trace,
    Connect,
}

impl From<&str> for HttpMethod {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "DELETE" => HttpMethod::Delete,
            "PATCH" => HttpMethod::Patch,
            "HEAD" => HttpMethod::Head,
            "OPTIONS" => HttpMethod::Options,
            "TRACE" => HttpMethod::Trace,
            "CONNECT" => HttpMethod::Connect,
            _ => HttpMethod::Get,
        }
    }
}

/// Response fingerprint for route identification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseFingerprint {
    /// HTTP status code
    pub status_code: u16,
    /// Content-Type header
    pub content_type: Option<String>,
    /// Content length
    pub content_length: Option<usize>,
    /// Response hash (for similarity detection)
    pub body_hash: u64,
    /// Key headers
    pub headers: HashMap<String, String>,
    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,
}

impl ResponseFingerprint {
    pub fn new(status_code: u16) -> Self {
        Self {
            status_code,
            content_type: None,
            content_length: None,
            body_hash: 0,
            headers: HashMap::new(),
            response_time_ms: None,
        }
    }

    /// Check if two fingerprints are similar (same route behavior)
    pub fn is_similar(&self, other: &Self) -> bool {
        self.status_code == other.status_code
            && self.body_hash == other.body_hash
            && self.content_type == other.content_type
    }
}

/// Parameter definition for a route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteParameter {
    /// Parameter name
    pub name: String,
    /// Parameter location
    pub location: ParamLocation,
    /// Whether parameter is required
    pub required: bool,
    /// Example values observed
    pub examples: Vec<String>,
    /// Parameter type hint
    pub param_type: Option<String>,
}

/// Location where parameter appears
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParamLocation {
    Query,
    Path,
    Header,
    Body,
    Cookie,
}

/// A discovered route/endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredRoute {
    /// Full path
    pub path: String,
    /// Normalized path pattern (with placeholders)
    pub pattern: String,
    /// HTTP methods that work on this route
    pub methods: HashSet<HttpMethod>,
    /// Response fingerprints per method
    pub fingerprints: HashMap<HttpMethod, ResponseFingerprint>,
    /// Parameters for this route
    pub parameters: Vec<RouteParameter>,
    /// Parent route (if any)
    pub parent: Option<String>,
    /// Child routes
    pub children: Vec<String>,
    /// Depth in route tree
    pub depth: u32,
    /// Times accessed during crawl
    pub access_count: u32,
    /// Whether route requires authentication
    pub requires_auth: Option<bool>,
    /// Tags for categorization
    pub tags: Vec<String>,
}

impl DiscoveredRoute {
    pub fn new(path: String) -> Self {
        let pattern = Self::normalize_path(&path);
        Self {
            path,
            pattern,
            methods: HashSet::new(),
            fingerprints: HashMap::new(),
            parameters: Vec::new(),
            parent: None,
            children: Vec::new(),
            depth: 0,
            access_count: 0,
            requires_auth: None,
            tags: Vec::new(),
        }
    }

    /// Normalize path to pattern (replace IDs with placeholders)
    fn normalize_path(path: &str) -> String {
        let mut result = String::new();
        let mut prev_was_param = false;

        for segment in path.split('/') {
            result.push('/');
            
            if segment.is_empty() {
                continue;
            }

            // Check if segment looks like an ID
            if segment.chars().all(|c| c.is_ascii_digit()) 
                || segment.len() == 36 && segment.contains('-') // UUID
                || segment.len() >= 20 && segment.chars().all(|c| c.is_alphanumeric())
            {
                if !prev_was_param {
                    result.push_str("{id}");
                    prev_was_param = true;
                }
            } else {
                result.push_str(segment);
                prev_was_param = false;
            }
        }

        if result.is_empty() {
            "/".to_string()
        } else {
            result
        }
    }

    /// Add an HTTP method to this route
    pub fn add_method(&mut self, method: HttpMethod) {
        self.methods.insert(method);
    }

    /// Record a response fingerprint
    pub fn record_fingerprint(&mut self, method: HttpMethod, fingerprint: ResponseFingerprint) {
        self.fingerprints.insert(method, fingerprint);
        self.access_count += 1;
    }

    /// Add a parameter
    pub fn add_parameter(&mut self, param: RouteParameter) {
        self.parameters.push(param);
    }

    /// Check if route seems to be an API endpoint
    pub fn is_api(&self) -> bool {
        self.path.contains("/api/")
            || self.path.contains("/v1/")
            || self.path.contains("/v2/")
            || self.path.contains("/graphql")
            || self.path.contains("/rest/")
    }

    /// Check if route seems to require authentication
    pub fn detect_auth_requirement(&mut self) {
        for (_, fp) in &self.fingerprints {
            if fp.status_code == 401 || fp.status_code == 403 {
                self.requires_auth = Some(true);
                return;
            }
        }
        self.requires_auth = Some(false);
    }
}

/// Route graph for organizing discovered endpoints
#[derive(Debug, Default)]
pub struct RouteGraph {
    /// All routes by path
    routes: HashMap<String, DiscoveredRoute>,
    /// Routes by pattern
    patterns: HashMap<String, Vec<String>>,
    /// Root routes
    roots: Vec<String>,
    /// Total requests made
    total_requests: u64,
    /// Unique routes discovered
    unique_routes: usize,
}

impl RouteGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or update a route
    pub fn add_route(&mut self, path: String, method: HttpMethod, fingerprint: ResponseFingerprint) {
        self.total_requests += 1;
        
        let entry = self.routes.entry(path.clone()).or_insert_with(|| {
            let mut route = DiscoveredRoute::new(path.clone());
            route.depth = path.matches('/').count() as u32;
            
            // Set parent
            if let Some(parent) = Self::get_parent_path(&path) {
                route.parent = Some(parent.clone());
            } else {
                self.roots.push(path.clone());
            }
            
            route
        });

        entry.add_method(method);
        entry.record_fingerprint(method, fingerprint);
        entry.detect_auth_requirement();

        // Update pattern index
        let pattern = entry.pattern.clone();
        self.patterns.entry(pattern).or_default().push(path);
        
        self.unique_routes = self.routes.len();
    }

    /// Get parent path
    fn get_parent_path(path: &str) -> Option<String> {
        if path == "/" || path.is_empty() {
            return None;
        }
        
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.len() <= 1 {
            return Some("/".to_string());
        }
        
        Some(format!("/{}", parts[..parts.len() - 1].join("/")))
    }

    /// Get a route by path
    pub fn get_route(&self, path: &str) -> Option<&DiscoveredRoute> {
        self.routes.get(path)
    }

    /// Get all routes
    pub fn all_routes(&self) -> Vec<&DiscoveredRoute> {
        self.routes.values().collect()
    }

    /// Get routes matching a pattern
    pub fn get_pattern_matches(&self, pattern: &str) -> Vec<&DiscoveredRoute> {
        self.patterns.get(pattern)
            .map(|paths| paths.iter().filter_map(|p| self.routes.get(p)).collect())
            .unwrap_or_default()
    }

    /// Get all unique patterns
    pub fn all_patterns(&self) -> Vec<&str> {
        self.patterns.keys().map(|s| s.as_str()).collect()
    }

    /// Get root routes
    pub fn roots(&self) -> Vec<&DiscoveredRoute> {
        self.roots.iter().filter_map(|p| self.routes.get(p)).collect()
    }

    /// Find routes by prefix
    pub fn find_by_prefix(&self, prefix: &str) -> Vec<&DiscoveredRoute> {
        self.routes.values()
            .filter(|r| r.path.starts_with(prefix))
            .collect()
    }

    /// Get API routes only
    pub fn api_routes(&self) -> Vec<&DiscoveredRoute> {
        self.routes.values().filter(|r| r.is_api()).collect()
    }

    /// Get routes requiring auth
    pub fn auth_required_routes(&self) -> Vec<&DiscoveredRoute> {
        self.routes.values()
            .filter(|r| r.requires_auth == Some(true))
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> RouteStats {
        RouteStats {
            total_requests: self.total_requests,
            unique_routes: self.unique_routes,
            unique_patterns: self.patterns.len(),
            root_count: self.roots.len(),
            api_count: self.api_routes().len(),
            auth_required_count: self.auth_required_routes().len(),
        }
    }

    /// Export routes for vulnerability modules
    pub fn export_for_vuln_scanning(&self) -> Vec<VulnScanTarget> {
        self.routes.values()
            .map(|r| VulnScanTarget {
                path: r.path.clone(),
                methods: r.methods.iter().copied().collect(),
                parameters: r.parameters.iter().map(|p| p.name.clone()).collect(),
                requires_auth: r.requires_auth.unwrap_or(false),
                is_api: r.is_api(),
            })
            .collect()
    }
}

/// Target for vulnerability scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnScanTarget {
    pub path: String,
    pub methods: Vec<HttpMethod>,
    pub parameters: Vec<String>,
    pub requires_auth: bool,
    pub is_api: bool,
}

/// Route statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteStats {
    pub total_requests: u64,
    pub unique_routes: usize,
    pub unique_patterns: usize,
    pub root_count: usize,
    pub api_count: usize,
    pub auth_required_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_normalization() {
        assert_eq!(DiscoveredRoute::normalize_path("/users/123"), "/users/{id}");
        assert_eq!(DiscoveredRoute::normalize_path("/api/v1/posts/abc123def456ghi789jkl012mno345"), "/api/v1/posts/{id}");
    }

    #[test]
    fn test_route_graph() {
        let mut graph = RouteGraph::new();
        
        let fp = ResponseFingerprint::new(200);
        graph.add_route("/api/users".to_string(), HttpMethod::Get, fp.clone());
        graph.add_route("/api/users".to_string(), HttpMethod::Post, fp);
        
        assert_eq!(graph.unique_routes, 1);
        assert!(graph.get_route("/api/users").is_some());
    }

    #[test]
    fn test_http_method_conversion() {
        assert_eq!(HttpMethod::from("get"), HttpMethod::Get);
        assert_eq!(HttpMethod::from("POST"), HttpMethod::Post);
    }
}
