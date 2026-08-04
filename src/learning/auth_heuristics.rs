//! Authentication heuristics recording for self-learning scans.
//!
//! Records login success patterns, logout behavior, token expiry,
//! and authentication error fingerprints to improve repeated scans.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Authentication result types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthResult {
    /// Login successful.
    Success,
    /// Login failed (invalid credentials).
    InvalidCredentials,
    /// Account locked.
    AccountLocked,
    /// MFA required.
    MfaRequired,
    /// Session expired.
    SessionExpired,
    /// Token invalid/revoked.
    TokenInvalid,
    /// Unknown error.
    Unknown,
}

/// Authentication error fingerprint.
#[derive(Debug, Clone)]
pub struct AuthErrorFingerprint {
    /// HTTP status code.
    pub status_code: u16,
    /// Response size range.
    pub response_size_range: (usize, usize),
    /// Key phrases in response.
    pub key_phrases: Vec<String>,
    /// Content type.
    pub content_type: Option<String>,
    /// Redirect location (if any).
    pub redirect_location: Option<String>,
    /// Set-Cookie headers indicating failure.
    pub failure_cookies: Vec<String>,
}

/// Recorded authentication attempt.
#[derive(Debug, Clone)]
pub struct AuthAttempt {
    /// Timestamp of attempt.
    pub timestamp: Instant,
    /// Target URL.
    pub url: String,
    /// Auth method used.
    pub method: String,
    /// Result of attempt.
    pub result: AuthResult,
    /// Time taken for the attempt.
    pub duration: Duration,
    /// Associated fingerprint if failed.
    pub fingerprint: Option<AuthErrorFingerprint>,
}

/// Heuristic data for an endpoint.
#[derive(Debug, Clone, Default)]
pub struct EndpointHeuristics {
    /// Number of successful authentications.
    pub success_count: usize,
    /// Number of failed attempts.
    pub failure_count: usize,
    /// Average response time.
    pub avg_response_time: Duration,
    /// Known error fingerprints.
    pub error_fingerprints: Vec<AuthErrorFingerprint>,
    /// Last successful attempt.
    pub last_success: Option<Instant>,
    /// Patterns that indicate success.
    pub success_indicators: Vec<String>,
    /// Patterns that indicate failure.
    pub failure_indicators: Vec<String>,
    /// Whether this endpoint requires authentication.
    pub requires_auth: Option<bool>,
    /// Token type expected.
    pub expected_token_type: Option<String>,
}

impl EndpointHeuristics {
    /// Record a successful authentication.
    pub fn record_success(&mut self, duration: Duration, indicators: &[String]) {
        self.success_count += 1;
        self.last_success = Some(Instant::now());
        self.update_avg_response_time(duration);
        
        for indicator in indicators {
            if !self.success_indicators.contains(indicator) {
                self.success_indicators.push(indicator.clone());
            }
        }
    }

    /// Record a failed authentication.
    pub fn record_failure(&mut self, duration: Duration, fingerprint: AuthErrorFingerprint, indicators: &[String]) {
        self.failure_count += 1;
        self.update_avg_response_time(duration);
        
        // Add fingerprint if not already present
        if !self.error_fingerprints.iter().any(|fp| fp.status_code == fingerprint.status_code) {
            self.error_fingerprints.push(fingerprint);
        }
        
        for indicator in indicators {
            if !self.failure_indicators.contains(indicator) {
                self.failure_indicators.push(indicator.clone());
            }
        }
    }

    fn update_avg_response_time(&mut self, duration: Duration) {
        let total = self.success_count + self.failure_count;
        if total == 1 {
            self.avg_response_time = duration;
        } else {
            // Running average
            let prev_avg = self.avg_response_time.as_millis() as u64;
            let new_avg = (prev_avg * (total as u64 - 1) + duration.as_millis() as u64) / total as u64;
            self.avg_response_time = Duration::from_millis(new_avg);
        }
    }

    /// Get success rate.
    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            return 0.0;
        }
        self.success_count as f64 / total as f64
    }

    /// Check if endpoint likely requires auth.
    pub fn likely_requires_auth(&self) -> bool {
        self.requires_auth.unwrap_or(self.failure_count > 0 && self.success_count > 0)
    }
}

/// Token expiry tracking.
#[derive(Debug, Clone)]
pub struct TokenExpiryRecord {
    /// Token type/identifier.
    pub token_type: String,
    /// Observed lifetime in seconds.
    pub observed_lifetime_secs: u64,
    /// Refresh endpoint if known.
    pub refresh_endpoint: Option<String>,
    /// Last observed at.
    pub last_observed: Instant,
    /// Observation count.
    pub observation_count: usize,
}

/// Logout behavior patterns.
#[derive(Debug, Clone)]
pub struct LogoutBehavior {
    /// Logout endpoint.
    pub endpoint: String,
    /// HTTP method used.
    pub method: String,
    /// Invalidates session server-side.
    pub server_side_invalidation: bool,
    /// Clears cookies client-side.
    pub clears_cookies: bool,
    /// Redirect after logout.
    pub redirect_after: Option<String>,
    /// Observation count.
    pub observation_count: usize,
}

/// Authentication heuristics manager.
#[derive(Default)]
pub struct AuthHeuristicsManager {
    /// Heuristics per endpoint.
    endpoints: Arc<RwLock<HashMap<String, EndpointHeuristics>>>,
    /// Token expiry records.
    token_expiry: Arc<RwLock<HashMap<String, TokenExpiryRecord>>>,
    /// Logout behaviors.
    logout_behaviors: Arc<RwLock<HashMap<String, LogoutBehavior>>>,
    /// Recent auth attempts.
    recent_attempts: Arc<RwLock<Vec<AuthAttempt>>>,
    /// Maximum recent attempts to keep.
    max_recent_attempts: usize,
}

impl AuthHeuristicsManager {
    /// Create a new heuristics manager.
    pub fn new() -> Self {
        Self {
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            token_expiry: Arc::new(RwLock::new(HashMap::new())),
            logout_behaviors: Arc::new(RwLock::new(HashMap::new())),
            recent_attempts: Arc::new(RwLock::new(Vec::new())),
            max_recent_attempts: 1000,
        }
    }

    /// Record an authentication attempt.
    pub fn record_attempt(&self, attempt: AuthAttempt) {
        // Update endpoint heuristics
        {
            let mut endpoints = self.endpoints.write().unwrap();
            let heuristics = endpoints.entry(attempt.url.clone()).or_default();
            
            match attempt.result {
                AuthResult::Success => {
                    heuristics.record_success(attempt.duration, &[]);
                }
                _ => {
                    if let Some(fp) = attempt.fingerprint.clone() {
                        heuristics.record_failure(attempt.duration, fp, &[]);
                    }
                }
            }
        }
        
        // Store in recent attempts
        {
            let mut attempts = self.recent_attempts.write().unwrap();
            attempts.push(attempt);
            
            // Trim if over limit
            while attempts.len() > self.max_recent_attempts {
                attempts.remove(0);
            }
        }
    }

    /// Get heuristics for an endpoint.
    pub fn get_endpoint_heuristics(&self, url: &str) -> Option<EndpointHeuristics> {
        let endpoints = self.endpoints.read().ok()?;
        endpoints.get(url).cloned()
    }

    /// Record token expiry observation.
    pub fn record_token_expiry(&self, token_type: &str, lifetime_secs: u64, refresh_endpoint: Option<&str>) {
        let mut records = self.token_expiry.write().unwrap();
        
        let record = records.entry(token_type.to_string()).or_insert_with(|| TokenExpiryRecord {
            token_type: token_type.to_string(),
            observed_lifetime_secs: lifetime_secs,
            refresh_endpoint: refresh_endpoint.map(String::from),
            last_observed: Instant::now(),
            observation_count: 1,
        });
        
        // Update with running average
        let total = record.observation_count + 1;
        record.observed_lifetime_secs = 
            (record.observed_lifetime_secs * record.observation_count as u64 + lifetime_secs) / total as u64;
        record.observation_count = total;
        record.last_observed = Instant::now();
        
        if let Some(ep) = refresh_endpoint {
            record.refresh_endpoint = Some(ep.to_string());
        }
    }

    /// Get expected token lifetime.
    pub fn get_token_lifetime(&self, token_type: &str) -> Option<u64> {
        let records = self.token_expiry.read().ok()?;
        records.get(token_type).map(|r| r.observed_lifetime_secs)
    }

    /// Record logout behavior.
    pub fn record_logout(&self, behavior: LogoutBehavior) {
        let mut logouts = self.logout_behaviors.write().unwrap();
        logouts.insert(behavior.endpoint.clone(), behavior);
    }

    /// Get logout behavior for an endpoint.
    pub fn get_logout_behavior(&self, endpoint: &str) -> Option<LogoutBehavior> {
        let logouts = self.logout_behaviors.read().ok()?;
        logouts.get(endpoint).cloned()
    }

    /// Get all recorded endpoints.
    pub fn get_all_endpoints(&self) -> Vec<String> {
        let endpoints = self.endpoints.read().unwrap();
        endpoints.keys().cloned().collect()
    }

    /// Clear all recorded heuristics.
    pub fn clear(&self) {
        self.endpoints.write().unwrap().clear();
        self.token_expiry.write().unwrap().clear();
        self.logout_behaviors.write().unwrap().clear();
        self.recent_attempts.write().unwrap().clear();
    }

    /// Export heuristics for persistence.
    pub fn export(&self) -> HashMap<String, serde_json::Value> {
        let mut export = HashMap::new();
        
        if let Ok(endpoints) = self.endpoints.read() {
            let endpoints_json: Vec<_> = endpoints.iter().map(|(k, v)| {
                serde_json::json!({
                    "endpoint": k,
                    "success_count": v.success_count,
                    "failure_count": v.failure_count,
                    "success_rate": v.success_rate(),
                    "requires_auth": v.likely_requires_auth(),
                })
            }).collect();
            export.insert("endpoints".to_string(), serde_json::json!(endpoints_json));
        }
        
        export
    }
}

impl Default for AuthHeuristicsManager {
    fn default() -> Self {
        Self::new()
    }
}
