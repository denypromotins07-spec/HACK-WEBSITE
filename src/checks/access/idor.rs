//! IDOR (Insecure Direct Object Reference) Detection Module
//! Detects IDOR vulnerabilities by mutating identifiers across personas and measuring access.

use crate::checks::module::{CheckModule, CheckResult, CheckMetadata, CheckCategory};
use crate::findings::finding::Finding;
use crate::session::session::Session;
use crate::http::client::HttpClient;
use crate::learning::access_cache::AccessCache;
use std::collections::HashMap;
use std::sync::Arc;

/// IDOR detector that mutates object identifiers across user personas
pub struct IdorDetector {
    http_client: Arc<HttpClient>,
    access_cache: Arc<AccessCache>,
    id_patterns: Vec<String>,
    max_concurrent_probes: usize,
}

impl IdorDetector {
    pub fn new(http_client: Arc<HttpClient>, access_cache: Arc<AccessCache>) -> Self {
        Self {
            http_client,
            access_cache,
            id_patterns: vec![
                r"\d+".to_string(),
                r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}".to_string(),
                r"[a-zA-Z0-9_-]{8,}".to_string(),
            ],
            max_concurrent_probes: 10,
        }
    }

    /// Generate mutated IDs for testing
    fn generate_mutated_ids(&self, original_id: &str) -> Vec<String> {
        let mut mutated = Vec::new();
        
        // Sequential increment/decrement
        if let Ok(num) = original_id.parse::<i64>() {
            for offset in [-5, -3, -2, -1, 1, 2, 3, 5] {
                mutated.push((num + offset).to_string());
            }
        }
        
        // UUID variations
        if original_id.len() == 36 && original_id.contains('-') {
            let parts: Vec<&str> = original_id.split('-').collect();
            if parts.len() == 5 {
                if let Ok(first) = u64::from_str_radix(parts[0].replace('-', "").as_str(), 16) {
                    for offset in [1u64, 2u64, 3u64] {
                        let modified = format!("{:08x}-{}", first.wrapping_add(offset), parts[1..].join("-"));
                        mutated.push(modified);
                    }
                }
            }
        }
        
        // Random alphanumeric generation
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for _ in 0..5 {
            let len = rng.gen_range(8..16);
            let random_id: String = (0..len)
                .map(|_| rng.gen_range(b'a'..=b'z'))
                .map(char::from)
                .collect();
            mutated.push(random_id);
        }
        
        mutated
    }

    /// Test access to an object with a different persona
    async fn test_cross_persona_access(
        &self,
        base_session: &Session,
        target_session: &Session,
        endpoint: &str,
        object_id: &str,
    ) -> Option<Finding> {
        let url = endpoint.replace("{id}", object_id);
        
        let base_response = self.http_client
            .get(&url)
            .session(base_session)
            .send()
            .await;
        
        let target_response = self.http_client
            .get(&url)
            .session(target_session)
            .send()
            .await;
        
        // Check if target can access object belonging to base user
        if target_response.status().is_success() 
            && base_response.status().is_success()
            && !target_response.body().contains("access denied")
            && !target_response.body().contains("unauthorized")
        {
            // Verify the response contains data from the other user's object
            if base_response.body() != target_response.body() {
                return Some(Finding::new()
                    .with_title("IDOR: Cross-Persona Object Access")
                    .with_description(format!(
                        "User {} accessed object {} belonging to user {}",
                        target_session.id(),
                        object_id,
                        base_session.id()
                    ))
                    .with_endpoint(endpoint)
                    .with_severity(crate::findings::severity::Severity::High)
                    .with_evidence(format!(
                        "Base response length: {}, Target response length: {}",
                        base_response.body().len(),
                        target_response.body().len()
                    )));
            }
        }
        
        None
    }

    /// Scan for IDOR vulnerabilities
    pub async fn scan(&self, sessions: &[Session], endpoints: &[String]) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        for endpoint in endpoints {
            // Extract potential ID patterns from endpoint
            let re = regex::Regex::new(r"/(\d+|[a-f0-9-]{36})").unwrap();
            if let Some(captures) = re.captures(endpoint) {
                if let Some(original_id) = captures.get(1) {
                    let mutated_ids = self.generate_mutated_ids(original_id.as_str());
                    
                    for (i, session_a) in sessions.iter().enumerate() {
                        for session_b in sessions.iter().skip(i + 1) {
                            for mutated_id in &mutated_ids {
                                if let Some(finding) = self
                                    .test_cross_persona_access(session_a, session_b, endpoint, mutated_id)
                                    .await
                                {
                                    results.push(CheckResult::Finding(finding));
                                    
                                    // Cache successful bypass pattern
                                    self.access_cache.cache_idor_pattern(
                                        endpoint.clone(),
                                        mutated_id.clone(),
                                        session_b.id().clone(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        
        results
    }
}

impl CheckModule for IdorDetector {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            name: "idor_detector".to_string(),
            category: CheckCategory::AccessControl,
            description: "Detects Insecure Direct Object References by mutating identifiers across personas".to_string(),
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
    fn test_id_generation() {
        let cache = Arc::new(AccessCache::new());
        let client = Arc::new(HttpClient::default());
        let detector = IdorDetector::new(client, cache);
        
        let mutated = detector.generate_mutated_ids("100");
        assert!(mutated.contains(&"99".to_string()));
        assert!(mutated.contains(&"101".to_string()));
        assert!(mutated.len() >= 8);
    }
}
