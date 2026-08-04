//! Endpoint behavior heuristics - JSON responses, auth walls, redirects, and more.
//!
//! This module records behavioral patterns for intelligent crawling and testing.

use std::collections::HashMap;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

/// Behavior flags for endpoints
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BehaviorFlags {
    /// Returns JSON content
    pub returns_json: bool,
    /// Returns XML content
    pub returns_xml: bool,
    /// Returns HTML content
    pub returns_html: bool,
    /// Requires authentication (401/403)
    pub requires_auth: bool,
    /// Performs redirect (3xx)
    pub performs_redirect: bool,
    /// Accepts POST requests
    pub accepts_post: bool,
    /// Accepts PUT requests
    pub accepts_put: bool,
    /// Accepts DELETE requests
    pub accepts_delete: bool,
    /// Supports CORS
    pub supports_cors: bool,
    /// Has rate limiting
    pub has_rate_limiting: bool,
    /// Returns different content based on auth
    pub auth_dependent: bool,
    /// Is idempotent
    pub is_idempotent: bool,
    /// Has CSRF protection
    pub has_csrf_protection: bool,
}

impl Default for BehaviorFlags {
    fn default() -> Self {
        Self {
            returns_json: false,
            returns_xml: false,
            returns_html: false,
            requires_auth: false,
            performs_redirect: false,
            accepts_post: false,
            accepts_put: false,
            accepts_delete: false,
            supports_cors: false,
            has_rate_limiting: false,
            auth_dependent: false,
            is_idempotent: false,
            has_csrf_protection: false,
        }
    }
}

impl BehaviorFlags {
    /// Calculate a risk score based on behaviors
    pub fn risk_score(&self) -> u32 {
        let mut score = 0u32;
        
        if self.returns_json { score += 1; } // API endpoint
        if self.accepts_post { score += 2; } // State-changing
        if self.accepts_put { score += 2; }
        if self.accepts_delete { score += 3; } // Destructive
        if self.requires_auth { score += 1; } // Protected resource
        if self.auth_dependent { score += 2; } // Access control
        if self.has_csrf_protection { score += 1; } // Security measure detected
        if !self.is_idempotent { score += 1; } // Side effects
        
        score
    }

    /// Get vulnerability hints based on behaviors
    pub fn vulnerability_hints(&self) -> Vec<VulnerabilityHint> {
        let mut hints = Vec::new();
        
        if self.returns_json && (self.accepts_post || self.accepts_put) {
            hints.push(VulnerabilityHint::InjectionRisk);
        }
        
        if self.accepts_delete && !self.requires_auth {
            hints.push(VulnerabilityHint::UnauthorizedDeletion);
        }
        
        if self.performs_redirect {
            hints.push(VulnerabilityHint::OpenRedirect);
        }
        
        if self.supports_cors {
            hints.push(VulnerabilityHint::CorsMisconfiguration);
        }
        
        if self.returns_json && !self.has_csrf_protection && self.accepts_post {
            hints.push(VulnerabilityHint::MissingCsrfProtection);
        }
        
        hints
    }
}

/// Vulnerability hint types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VulnerabilityHint {
    InjectionRisk,
    UnauthorizedDeletion,
    OpenRedirect,
    CorsMisconfiguration,
    MissingCsrfProtection,
    AuthBypassPossible,
    InformationDisclosure,
    RateLimitBypass,
}

/// Heuristic record for an endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicRecord {
    /// Endpoint path
    pub path: String,
    /// Observed behavior flags
    pub flags: BehaviorFlags,
    /// Response codes observed
    pub response_codes: Vec<u16>,
    /// Content types observed
    pub content_types: Vec<String>,
    /// Methods that work
    pub working_methods: Vec<String>,
    /// Request count
    pub request_count: u32,
    /// Last updated timestamp
    pub last_updated: u64,
    /// Confidence score (0-100)
    pub confidence: u8,
}

impl HeuristicRecord {
    pub fn new(path: String) -> Self {
        Self {
            path,
            flags: BehaviorFlags::default(),
            response_codes: Vec::new(),
            content_types: Vec::new(),
            working_methods: Vec::new(),
            request_count: 0,
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            confidence: 0,
        }
    }

    /// Record an observation
    pub fn observe(&mut self, status: u16, content_type: &str, method: &str, headers: &HashMap<String, String>) {
        self.request_count += 1;
        self.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Track response codes
        if !self.response_codes.contains(&status) {
            self.response_codes.push(status);
        }
        
        // Track content types
        if !self.content_types.contains(&content_type.to_string()) {
            self.content_types.push(content_type.to_string());
        }
        
        // Track working methods
        if status < 500 && !self.working_methods.contains(&method.to_string()) {
            self.working_methods.push(method.to_string());
        }
        
        // Update flags based on observation
        self.update_flags(status, content_type, method, headers);
        
        // Update confidence
        self.confidence = ((self.request_count as f64).min(100.0) as u8).min(100);
    }

    fn update_flags(&mut self, status: u16, content_type: &str, method: &str, headers: &HashMap<String, String>) {
        let ct_lower = content_type.to_lowercase();
        
        // Content type detection
        if ct_lower.contains("json") {
            self.flags.returns_json = true;
        }
        if ct_lower.contains("xml") {
            self.flags.returns_xml = true;
        }
        if ct_lower.contains("html") {
            self.flags.returns_html = true;
        }
        
        // Auth detection
        if status == 401 || status == 403 {
            self.flags.requires_auth = true;
        }
        
        // Redirect detection
        if status >= 300 && status < 400 {
            self.flags.performs_redirect = true;
        }
        
        // Method tracking
        match method.to_uppercase().as_str() {
            "POST" => self.flags.accepts_post = true,
            "PUT" => self.flags.accepts_put = true,
            "DELETE" => self.flags.accepts_delete = true,
            _ => {}
        }
        
        // CORS detection
        if headers.contains_key("access-control-allow-origin") {
            self.flags.supports_cors = true;
        }
        
        // Rate limiting detection
        if headers.contains_key("x-ratelimit-limit") 
            || headers.contains_key("x-ratelimit-remaining")
            || headers.contains_key("retry-after")
        {
            self.flags.has_rate_limiting = true;
        }
        
        // CSRF detection
        if headers.contains_key("x-csrf-token") 
            || headers.contains_key("x-xsrf-token")
        {
            self.flags.has_csrf_protection = true;
        }
    }

    /// Check if endpoint is likely an API
    pub fn is_api(&self) -> bool {
        self.flags.returns_json 
            && (self.accepts_post() || self.accepts_put() || self.accepts_delete())
    }

    pub fn accepts_post(&self) -> bool {
        self.flags.accepts_post || self.working_methods.iter().any(|m| m == "POST")
    }

    pub fn accepts_put(&self) -> bool {
        self.flags.accepts_put || self.working_methods.iter().any(|m| m == "PUT")
    }

    pub fn accepts_delete(&self) -> bool {
        self.flags.accepts_delete || self.working_methods.iter().any(|m| m == "DELETE")
    }
}

/// Heuristics engine for learning endpoint behavior
pub struct HeuristicsEngine {
    records: RwLock<HashMap<String, HeuristicRecord>>,
}

impl HeuristicsEngine {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
        }
    }

    /// Record an observation
    pub fn observe(&self, path: &str, status: u16, content_type: &str, method: &str, headers: HashMap<String, String>) {
        let mut records = self.records.write();
        
        let record = records.entry(path.to_string()).or_insert_with(|| {
            HeuristicRecord::new(path.to_string())
        });
        
        record.observe(status, content_type, method, &headers);
    }

    /// Get heuristic record for a path
    pub fn get(&self, path: &str) -> Option<HeuristicRecord> {
        self.records.read().get(path).cloned()
    }

    /// Get all records
    pub fn all_records(&self) -> Vec<HeuristicRecord> {
        self.records.read().values().cloned().collect()
    }

    /// Get high-risk endpoints
    pub fn high_risk_endpoints(&self) -> Vec<(String, u32)> {
        let records = self.records.read();
        let mut scored: Vec<(String, u32)> = records.iter()
            .map(|(path, record)| (path.clone(), record.flags.risk_score()))
            .filter(|(_, score)| *score >= 5)
            .collect();
        
        scored.sort_by(|a, b| b.1.cmp(&a.1));
        scored
    }

    /// Get API endpoints
    pub fn api_endpoints(&self) -> Vec<&HeuristicRecord> {
        self.records.read().values()
            .filter(|r| r.is_api())
            .collect()
    }

    /// Get endpoints requiring auth
    pub fn auth_required_endpoints(&self) -> Vec<&HeuristicRecord> {
        self.records.read().values()
            .filter(|r| r.flags.requires_auth)
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> HeuristicsStats {
        let records = self.records.read();
        let total = records.len();
        
        let api_count = records.values().filter(|r| r.is_api()).count();
        let auth_count = records.values().filter(|r| r.flags.requires_auth).count();
        let json_count = records.values().filter(|r| r.flags.returns_json).count();
        let high_risk = records.values().filter(|r| r.flags.risk_score() >= 5).count();
        
        HeuristicsStats {
            total_endpoints: total,
            api_count,
            auth_required_count: auth_count,
            json_response_count: json_count,
            high_risk_count: high_risk,
        }
    }
}

impl Default for HeuristicsEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Heuristics statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeuristicsStats {
    pub total_endpoints: usize,
    pub api_count: usize,
    pub auth_required_count: usize,
    pub json_response_count: usize,
    pub high_risk_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_behavior_flags_risk_score() {
        let mut flags = BehaviorFlags::default();
        assert_eq!(flags.risk_score(), 0);
        
        flags.accepts_delete = true;
        assert_eq!(flags.risk_score(), 3);
        
        flags.requires_auth = true;
        assert_eq!(flags.risk_score(), 4);
    }

    #[test]
    fn test_heuristics_observation() {
        let engine = HeuristicsEngine::new();
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        
        engine.observe("/api/users", 200, "application/json", "GET", headers.clone());
        engine.observe("/api/users", 201, "application/json", "POST", headers);
        
        let record = engine.get("/api/users").unwrap();
        assert!(record.flags.returns_json);
        assert!(record.flags.accepts_post);
        assert!(record.is_api());
    }

    #[test]
    fn test_vulnerability_hints() {
        let mut flags = BehaviorFlags::default();
        flags.returns_json = true;
        flags.accepts_post = true;
        flags.performs_redirect = true;
        
        let hints = flags.vulnerability_hints();
        assert!(hints.contains(&VulnerabilityHint::InjectionRisk));
        assert!(hints.contains(&VulnerabilityHint::OpenRedirect));
    }
}
