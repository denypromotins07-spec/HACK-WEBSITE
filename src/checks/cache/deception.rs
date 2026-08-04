//! Web Cache Deception Detection Module
//! Detects cache deception by appending static extensions to authenticated pages.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::findings::cache_evidence::CacheEvidence;
use crate::http_client::HttpClient;
use crate::session::SessionStore;

/// Static extensions commonly used to trigger cache deception
const STATIC_EXTENSIONS: &[&str] = &[
    ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".webp",
];

/// Paths that typically require authentication and should not be cached
const AUTHENTICATED_PATHS: &[&str] = &[
    "/account", "/profile", "/settings", "/dashboard", "/admin",
    "/user", "/me", "/orders", "/payments", "/subscriptions",
];

pub struct CacheDeceptionChecker {
    http_client: HttpClient,
    session: SessionStore,
}

impl CacheDeceptionChecker {
    pub fn new(http_client: HttpClient, session: SessionStore) -> Self {
        Self {
            http_client,
            session,
        }
    }

    /// Test a single path for cache deception vulnerability
    async fn test_path_deception(&self, base_url: &str, path: &str, extension: &str) -> Option<CacheEvidence> {
        let deceptive_url = format!("{}{}{}", base_url, path, extension);
        
        // First request - should populate cache
        let response1 = self.http_client.get(&deceptive_url).await.ok()?;
        let body1 = response1.body.clone();
        let headers1 = response1.headers.clone();
        
        // Second request with different session/context
        let response2 = self.http_client.get_anonymous(&deceptive_url).await.ok()?;
        let body2 = response2.body.clone();
        
        // If both responses match and contain sensitive content, cache deception detected
        if body1 == body2 && self.contains_authenticated_content(&body1) {
            return Some(CacheEvidence {
                url: deceptive_url,
                vulnerability_type: "cache_deception".to_string(),
                extension_used: extension.to_string(),
                original_path: path.to_string(),
                edge_headers: headers1,
                cache_status: response1.cache_status.unwrap_or_default(),
                severity: Severity::High,
                description: format!(
                    "Authenticated content at {} is being cached when accessed with .{} extension",
                    path, extension
                ),
            });
        }
        
        None
    }

    /// Check if response body contains indicators of authenticated content
    fn contains_authenticated_content(&self, body: &str) -> bool {
        let indicators = [
            "logout", "sign out", "account settings", "personal information",
            "email:", "username:", "user_id", "session", "csrf",
            "\"name\":", "\"email\":", "\"id\":",
        ];
        
        indicators.iter().any(|ind| body.to_lowercase().contains(ind))
    }

    /// Analyze Cache-Control and related headers for caching hints
    fn analyze_cache_headers(&self, headers: &std::collections::HashMap<String, String>) -> Vec<String> {
        let mut findings = Vec::new();
        
        if let Some(cc) = headers.get("cache-control") {
            if cc.contains("public") || !cc.contains("no-store") {
                findings.push(format!("Cache-Control allows caching: {}", cc));
            }
        }
        
        if headers.contains_key("age") {
            findings.push("Age header present - content served from cache".to_string());
        }
        
        if let Some(via) = headers.get("via") {
            findings.push(format!("Proxy/CDN detected: {}", via));
        }
        
        findings
    }
}

#[async_trait::async_trait]
impl CheckModule for CacheDeceptionChecker {
    fn name(&self) -> &'static str {
        "cache_deception"
    }

    fn description(&self) -> &'static str {
        "Detects web cache deception vulnerabilities by testing static extension suffixes on authenticated paths"
    }

    async fn scan(&self, target: &str) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        for path in AUTHENTICATED_PATHS {
            for ext in STATIC_EXTENSIONS {
                if let Some(evidence) = self.test_path_deception(target, path, ext).await {
                    results.push(CheckResult {
                        check_name: self.name(),
                        severity: evidence.severity,
                        finding: evidence.description,
                        evidence: serde_json::to_value(&evidence).unwrap_or_default(),
                        remediation: "Ensure Cache-Control: private, no-store is set for authenticated endpoints. \
                                      Configure CDN to not cache responses based solely on file extension.".to_string(),
                    });
                }
            }
        }
        
        results
    }

    fn supported_checks(&self) -> Vec<&'static str> {
        vec!["cache_deception", "path_extension_abuse", "authenticated_content_caching"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_extensions_defined() {
        assert!(!STATIC_EXTENSIONS.is_empty());
        assert!(STATIC_EXTENSIONS.contains(&".css"));
        assert!(STATIC_EXTENSIONS.contains(&".js"));
    }

    #[test]
    fn test_authenticated_paths_defined() {
        assert!(!AUTHENTICATED_PATHS.is_empty());
        assert!(AUTHENTICATED_PATHS.contains(&"/account"));
    }
}
