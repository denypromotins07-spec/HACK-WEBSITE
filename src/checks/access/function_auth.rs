//! Function-Level Authorization Detection Module
//! Detects Broken Function Level Authorization by accessing admin routes from lower-privilege sessions.

use crate::checks::module::{CheckModule, CheckResult, CheckMetadata, CheckCategory};
use crate::findings::finding::Finding;
use crate::session::session::Session;
use crate::http::client::HttpClient;
use crate::learning::access_cache::AccessCache;
use std::sync::Arc;

/// Admin/sensitive route patterns to test
const ADMIN_PATTERNS: &[&str] = &[
    "/admin",
    "/api/admin",
    "/management",
    "/dashboard",
    "/settings",
    "/config",
    "/system",
    "/users",
    "/roles",
    "/permissions",
    "/audit",
    "/logs",
    "/backup",
    "/export",
    "/import",
    "/delete",
    "/purge",
    "/reset",
    "/shutdown",
    "/restart",
];

/// HTTP methods that may require elevated privileges
const PRIVILEGED_METHODS: &[&str] = &["POST", "PUT", "DELETE", "PATCH"];

/// Function-level authorization detector
pub struct FunctionAuthDetector {
    http_client: Arc<HttpClient>,
    access_cache: Arc<AccessCache>,
    admin_patterns: Vec<String>,
}

impl FunctionAuthDetector {
    pub fn new(http_client: Arc<HttpClient>, access_cache: Arc<AccessCache>) -> Self {
        Self {
            http_client,
            access_cache,
            admin_patterns: ADMIN_PATTERNS.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Test if a low-privilege session can access an admin endpoint
    async fn test_function_access(
        &self,
        session: &Session,
        endpoint: &str,
        method: &str,
    ) -> Option<Finding> {
        let response = match method {
            "GET" => self.http_client.get(endpoint).session(session).send().await,
            "POST" => self.http_client.post(endpoint).session(session).send().await,
            "PUT" => self.http_client.put(endpoint).session(session).send().await,
            "DELETE" => self.http_client.delete(endpoint).session(session).send().await,
            "PATCH" => self.http_client.patch(endpoint).session(session).send().await,
            _ => return None,
        };

        // Check for successful access (should be forbidden for low-privilege users)
        if response.status().is_success() {
            let body = response.body();
            
            // Verify it's not a false positive (some apps return 200 with error in body)
            if !body.contains("unauthorized") 
                && !body.contains("forbidden")
                && !body.contains("access denied")
                && !body.contains("permission")
                && !body.contains("not allowed")
            {
                return Some(Finding::new()
                    .with_title("BFLA: Broken Function Level Authorization")
                    .with_description(format!(
                        "Low-privilege user {} can access {} endpoint via {}",
                        session.id(),
                        endpoint,
                        method
                    ))
                    .with_endpoint(endpoint)
                    .with_method(method.to_string())
                    .with_severity(crate::findings::severity::Severity::High)
                    .with_evidence(format!(
                        "Response status: {}, Body preview: {}",
                        response.status(),
                        &body[..body.len().min(300)]
                    )));
            }
        } else if response.status().as_u16() == 403 || response.status().as_u16() == 401 {
            // Properly protected - cache this pattern
            self.access_cache.cache_protected_function(
                endpoint.to_string(),
                method.to_string(),
            );
        }

        None
    }

    /// Scan for function-level authorization issues
    pub async fn scan(&self, sessions: &[Session], endpoints: &[String]) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        // Identify low-privilege sessions (non-admin)
        let low_priv_sessions: Vec<&Session> = sessions
            .iter()
            .filter(|s| !s.is_admin() && !s.has_role("admin"))
            .collect();

        // If no low-priv sessions found, use all sessions as potential test subjects
        let test_sessions = if low_priv_sessions.is_empty() {
            sessions.iter().collect()
        } else {
            low_priv_sessions
        };

        for session in test_sessions {
            // Test known admin patterns
            for pattern in &self.admin_patterns {
                for endpoint in endpoints {
                    if endpoint.contains(pattern.as_str()) {
                        // Test GET access
                        if let Some(finding) = self.test_function_access(session, endpoint, "GET").await {
                            results.push(CheckResult::Finding(finding));
                        }
                        
                        // Test privileged methods
                        for method in PRIVILEGED_METHODS {
                            if let Some(finding) = self.test_function_access(session, endpoint, method).await {
                                results.push(CheckResult::Finding(finding));
                            }
                        }
                    }
                }
            }

            // Also test any endpoint containing admin-related keywords
            for endpoint in endpoints {
                let endpoint_lower = endpoint.to_lowercase();
                if endpoint_lower.contains("admin")
                    || endpoint_lower.contains("manage")
                    || endpoint_lower.contains("config")
                    || endpoint_lower.contains("system")
                    || endpoint_lower.contains("internal")
                {
                    if let Some(finding) = self.test_function_access(session, endpoint, "GET").await {
                        results.push(CheckResult::Finding(finding));
                    }
                    
                    for method in PRIVILEGED_METHODS {
                        if let Some(finding) = self.test_function_access(session, endpoint, method).await {
                            results.push(CheckResult::Finding(finding));
                        }
                    }
                }
            }
        }

        results
    }

    /// Test specific endpoint with role comparison
    pub async fn test_with_role_comparison(
        &self,
        low_priv_session: &Session,
        high_priv_session: &Session,
        endpoint: &str,
        method: &str,
    ) -> Option<Finding> {
        let low_response = match method {
            "GET" => self.http_client.get(endpoint).session(low_priv_session).send().await,
            "POST" => self.http_client.post(endpoint).session(low_priv_session).send().await,
            _ => return None,
        };

        let high_response = match method {
            "GET" => self.http_client.get(endpoint).session(high_priv_session).send().await,
            "POST" => self.http_client.post(endpoint).session(high_priv_session).send().await,
            _ => return None,
        };

        // If both succeed with similar responses, low-priv has unauthorized access
        if low_response.status().is_success() && high_response.status().is_success() {
            // Check if responses are similar (indicating same level of access)
            if low_response.body().len() > 0 
                && high_response.body().len() > 0
                && low_response.body().contains(&high_response.body()[..high_response.body().len().min(50)])
            {
                return Some(Finding::new()
                    .with_title("BFLA: Role-Based Access Bypass")
                    .with_description(format!(
                        "Low-privilege user accesses {} with same response as admin",
                        endpoint
                    ))
                    .with_endpoint(endpoint)
                    .with_severity(crate::findings::severity::Severity::High));
            }
        }

        None
    }
}

impl CheckModule for FunctionAuthDetector {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            name: "function_auth_detector".to_string(),
            category: CheckCategory::AccessControl,
            description: "Detects Broken Function Level Authorization on admin endpoints".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    async fn execute(&self, context: &crate::orchestrator::graph::ScanContext) -> Vec<CheckResult> {
        let sessions = context.sessions();
        let endpoints = context.endpoints();
        self.scan(sessions, endpoints).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_patterns_loaded() {
        let cache = Arc::new(AccessCache::new());
        let client = Arc::new(HttpClient::default());
        let detector = FunctionAuthDetector::new(client, cache);
        
        assert!(detector.admin_patterns.contains(&"/admin".to_string()));
        assert!(detector.admin_patterns.contains(&"/api/admin".to_string()));
        assert!(detector.admin_patterns.contains(&"/users".to_string()));
        assert!(detector.admin_patterns.len() >= 15);
    }

    #[test]
    fn test_privileged_methods() {
        assert!(PRIVILEGED_METHODS.contains(&"POST"));
        assert!(PRIVILEGED_METHODS.contains(&"DELETE"));
        assert!(!PRIVILEGED_METHODS.contains(&"GET"));
    }
}
