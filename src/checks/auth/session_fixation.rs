//! Session Fixation Detection Module
//!
//! Tracks session identifiers pre- and post-authentication to detect fixation vulnerabilities.
//! Monitors cookie behavior, header pollution vectors, and session regeneration patterns.
//! Uses bounded state tracking without dynamic heap allocations.

use async_trait::async_trait;
use std::sync::Arc;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, CheckCategory,
    Severity, ResourceBudget, ModuleError,
};
use crate::findings::finding::{Finding, Evidence, EvidenceType, EvidenceLocation, RemediationHint, EffortLevel};
use crate::http::client::HttpClient;
use crate::learning::cache::LearningCache;

/// Maximum session IDs to track (bounded array)
const MAX_SESSION_TRACKING: usize = 8;

/// Session state tracker with bounded storage
#[derive(Debug, Clone)]
struct SessionTracker {
    pre_auth_session: Option<String>,
    post_auth_session: Option<String>,
    session_history: [Option<String>; MAX_SESSION_TRACKING],
    history_count: usize,
}

impl SessionTracker {
    fn new() -> Self {
        Self {
            pre_auth_session: None,
            post_auth_session: None,
            session_history: [None; MAX_SESSION_TRACKING],
            history_count: 0,
        }
    }

    fn set_pre_auth(&mut self, session_id: String) {
        self.pre_auth_session = Some(session_id);
    }

    fn set_post_auth(&mut self, session_id: String) {
        self.post_auth_session = Some(session_id);
    }

    fn add_to_history(&mut self, session_id: String) {
        if self.history_count < MAX_SESSION_TRACKING {
            self.session_history[self.history_count] = Some(session_id);
            self.history_count += 1;
        }
    }

    fn is_fixated(&self) -> bool {
        match (&self.pre_auth_session, &self.post_auth_session) {
            (Some(pre), Some(post)) => pre == post,
            _ => false,
        }
    }

    fn get_pre_auth(&self) -> Option<&str> {
        self.pre_auth_session.as_deref()
    }

    fn get_post_auth(&self) -> Option<&str> {
        self.post_auth_session.as_deref()
    }
}

/// Session fixation detector
pub struct SessionFixationDetector {
    metadata: CheckMetadata,
    tracker: SessionTracker,
}

impl SessionFixationDetector {
    pub fn new() -> Self {
        let metadata = CheckMetadata::new(
            "auth/session_fixation",
            "Session Fixation Detection",
            "Tracks session identifiers pre- and post-authentication to detect fixation vulnerabilities",
            Severity::High,
            CheckCategory::SessionManagement,
        )
        .with_god_mode(true)
        .with_tags(vec!["session-fixation", "authentication", "session-management", "owasp"])
        .with_references(vec![
            "https://owasp.org/www-community/attacks/Session_fixation",
            "https://cwe.mitre.org/data/definitions/384.html",
        ])
        .with_budget(ResourceBudget {
            max_cpu_ms: 500,
            max_memory_bytes: 2 * 1024 * 1024,
            max_requests: 50,
            max_duration_ms: 3000,
            max_payload_size: 1024,
        });

        Self {
            metadata,
            tracker: SessionTracker::new(),
        }
    }

    /// Extract session ID from response cookies or headers
    fn extract_session_id(&self, headers: &reqwest::header::HeaderMap, body: &str) -> Option<String> {
        // Check Set-Cookie header
        for cookie in headers.get_all(reqwest::header::SET_COOKIE) {
            let cookie_str = cookie.to_str().ok()?;
            
            // Common session cookie names
            let session_names = ["PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", 
                                  "sessionid", "sid", "sess", "token"];
            
            for name in &session_names {
                if cookie_str.starts_with(name) {
                    if let Some(eq_pos) = cookie_str.find('=') {
                        if let Some(semi_pos) = cookie_str[eq_pos..].find(';') {
                            return Some(cookie_str[eq_pos + 1..eq_pos + semi_pos].to_string());
                        } else {
                            return Some(cookie_str[eq_pos + 1..].split_whitespace().next()?.to_string());
                        }
                    }
                }
            }
        }

        // Check custom session headers
        let session_headers = ["X-Session-ID", "X-Auth-Token", "Authorization"];
        for header in &session_headers {
            if let Some(value) = headers.get(*header) {
                if let Ok(val_str) = value.to_str() {
                    return Some(val_str.to_string());
                }
            }
        }

        // Check body for session tokens (JSON responses)
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(token) = json.get("session_id").and_then(|v| v.as_str()) {
                return Some(token.to_string());
            }
            if let Some(token) = json.get("token").and_then(|v| v.as_str()) {
                return Some(token.to_string());
            }
        }

        None
    }

    /// Test for session fixation vulnerability
    async fn test_fixation(
        &self,
        client: &HttpClient,
        base_url: &str,
        provided_session: &str,
    ) -> Result<bool, ModuleError> {
        let mut tracker = SessionTracker::new();
        
        // Step 1: Get initial session (pre-auth)
        let pre_auth_response = client.get(base_url).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;
        
        if let Some(session_id) = self.extract_session_id(pre_auth_response.headers(), 
                                                           &pre_auth_response.text().await.unwrap_or_default()) {
            tracker.set_pre_auth_session(session_id.clone());
            tracker.add_to_history(session_id);
        }

        // Step 2: Attempt authentication with provided session
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::COOKIE,
            reqwest::header::HeaderValue::from_str(&format!("PHPSESSID={}", provided_session))
                .unwrap(),
        );

        let auth_response = client.post_with_headers(
            &format!("{}/login", base_url.trim_end_matches('/')),
            headers.clone(),
            &[("username", "test"), ("password", "test")],
        ).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        // Step 3: Check if session changed post-auth
        if let Some(post_session) = self.extract_session_id(auth_response.headers(),
                                                             &auth_response.text().await.unwrap_or_default()) {
            tracker.set_post_auth_session(post_session);
        }

        // If session didn't change after auth with attacker-provided ID, it's fixated
        Ok(tracker.is_fixated())
    }

    /// Test session regeneration on privilege escalation
    async fn test_privilege_escalation(
        &self,
        client: &HttpClient,
        base_url: &str,
    ) -> Result<Option<(String, String)>, ModuleError> {
        // Get initial session
        let initial_response = client.get(base_url).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;
        
        let initial_session = self.extract_session_id(initial_response.headers(),
                                                       &initial_response.text().await.unwrap_or_default());

        // Perform privilege-changing action
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(ref sess) = initial_session {
            headers.insert(
                reqwest::header::COOKIE,
                reqwest::header::HeaderValue::from_str(&format!("PHPSESSID={}", sess)).unwrap(),
            );
        }

        let escalate_response = client.post_with_headers(
            &format!("{}/admin/elevate", base_url.trim_end_matches('/')),
            headers,
            &[],
        ).await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let new_session = self.extract_session_id(escalate_response.headers(),
                                                   &escalate_response.text().await.unwrap_or_default());

        match (initial_session, new_session) {
            (Some(initial), Some(new)) if initial == new => {
                Some((initial, new)) // Session not regenerated
            }
            _ => None, // Session was properly regenerated or couldn't track
        }
    }

    /// Build evidence for session fixation finding
    fn build_evidence(&self, url: &str, pre_session: &str, post_session: &str) -> Vec<Evidence> {
        vec![
            Evidence {
                evidence_type: EvidenceType::Configuration {
                    key: "pre_auth_session".to_string(),
                    value: pre_session.to_string(),
                },
                data: "Session ID established before authentication".to_string(),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: None,
                    header: Some("Set-Cookie".to_string()),
                },
                confidence: 90,
            },
            Evidence {
                evidence_type: EvidenceType::Configuration {
                    key: "post_auth_session".to_string(),
                    value: post_session.to_string(),
                },
                data: "Session ID unchanged after authentication (fixation)".to_string(),
                location: EvidenceLocation {
                    path: url.to_string(),
                    line: None,
                    parameter: None,
                    header: Some("Set-Cookie".to_string()),
                },
                confidence: 90,
            },
        ]
    }

    /// Generate remediation hint
    fn remediation(&self) -> RemediationHint {
        RemediationHint {
            summary: "Regenerate session ID on authentication and privilege changes".to_string(),
            steps: vec![
                "Generate a new session ID immediately after successful authentication".to_string(),
                "Invalidate the old session ID server-side".to_string(),
                "Regenerate session ID on any privilege level change".to_string(),
                "Implement session timeout and absolute expiration".to_string(),
                "Use secure and HttpOnly flags on session cookies".to_string(),
                "Consider binding sessions to IP address or User-Agent".to_string(),
            ],
            code_example: Some(r#"// PHP Example
session_start();
if ($authenticated) {
    session_regenerate_id(true); // true deletes old session file
    $_SESSION['user_id'] = $user_id;
}

// Node.js Express Example
req.session.regenerate((err) => {
    if (err) throw err;
    req.session.user = user;
});"#.to_string()),
            references: vec![
                "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html".to_string(),
                "https://cwe.mitre.org/data/definitions/384.html".to_string(),
            ],
            estimated_effort: EffortLevel::Low,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for SessionFixationDetector {
    async fn init(&mut self) -> Result<(), ModuleError> {
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    fn should_run(&self, ctx: &CheckContext) -> bool {
        if self.metadata.requires_god_mode && !ctx.god_mode {
            return false;
        }
        true
    }

    async fn run(&self, ctx: CheckContext) -> Result<CheckResult, ModuleError> {
        let client = HttpClient::new();
        let mut findings = Vec::new();
        let mut executed = false;

        let base_url = ctx.target_url.trim_end_matches('/');

        // Test 1: Attacker-provided session fixation
        let attacker_session = format!("FIXATED_{}", uuid::Uuid::new_v4().simple());
        if let Ok(is_fixated) = self.test_fixation(&client, base_url, &attacker_session).await {
            if is_fixated {
                executed = true;

                let mut finding = Finding::new(
                    self.metadata.id.as_str(),
                    Severity::High,
                    "Session Fixation Vulnerability",
                    format!("Application accepts attacker-provided session ID and does not regenerate it after authentication at {}", base_url),
                    base_url,
                )
                .with_payload(format!("Attacker session: {}", attacker_session))
                .with_confidence(85)
                .with_agent_id(ctx.agent_id)
                .with_tags(vec!["session-fixation", "authentication-bypass"]);

                let evidence = self.build_evidence(base_url, &attacker_session, &attacker_session);
                for ev in evidence {
                    finding = finding.with_evidence(ev);
                }

                finding = finding.with_remediation(self.remediation());
                findings.push(finding);
            }
        }

        // Test 2: Session regeneration on privilege escalation
        if let Ok(Some((initial, new))) = self.test_privilege_escalation(&client, base_url).await {
            executed = true;

            let mut finding = Finding::new(
                self.metadata.id.as_str(),
                Severity::Medium,
                "Session Not Regenerated on Privilege Escalation",
                format!("Session ID remains unchanged after privilege escalation at {}", base_url),
                base_url,
            )
            .with_payload(format!("Session: {} -> {}", initial, new))
            .with_confidence(75)
            .with_agent_id(ctx.agent_id)
            .with_tags(vec!["session-management", "privilege-escalation"]);

            finding = finding.with_remediation(RemediationHint {
                summary: "Regenerate session on privilege changes".to_string(),
                steps: vec![
                    "Call session_regenerate_id() before granting elevated privileges".to_string(),
                    "Implement role-based session validation".to_string(),
                ],
                code_example: None,
                references: vec![],
                estimated_effort: EffortLevel::Low,
            });

            findings.push(finding);
        }

        // Cache findings for learning engine
        if !findings.is_empty() {
            if let Ok(cache) = LearningCache::global().await {
                cache.cache_bypass_header(ctx.target_url.clone(), "session_fixation".to_string()).await;
            }
        }

        Ok(CheckResult {
            findings,
            executed,
            timed_out: false,
            resource_usage: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_tracker() {
        let mut tracker = SessionTracker::new();
        assert!(!tracker.is_fixated());

        tracker.set_pre_auth("abc123".to_string());
        tracker.set_post_auth("abc123".to_string());
        assert!(tracker.is_fixated());

        tracker.set_post_auth("xyz789".to_string());
        assert!(!tracker.is_fixated());
    }

    #[test]
    fn test_bounded_history() {
        let mut tracker = SessionTracker::new();
        
        for i in 0..MAX_SESSION_TRACKING + 5 {
            tracker.add_to_history(format!("session_{}", i));
        }

        assert_eq!(tracker.history_count, MAX_SESSION_TRACKING);
    }
}
