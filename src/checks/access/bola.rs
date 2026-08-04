//! BOLA (Broken Object Level Authorization) Detection Module
//! Detects BOLA vulnerabilities on API endpoints using sequential and random object IDs.

use crate::checks::module::{CheckModule, CheckResult, CheckMetadata, CheckCategory};
use crate::findings::finding::Finding;
use crate::session::session::Session;
use crate::http::client::HttpClient;
use crate::learning::access_cache::AccessCache;
use std::sync::Arc;

/// BOLA detector for API endpoints
pub struct BolaDetector {
    http_client: Arc<HttpClient>,
    access_cache: Arc<AccessCache>,
    max_object_ids: usize,
    bounded_matrix_size: usize,
}

impl BolaDetector {
    pub fn new(http_client: Arc<HttpClient>, access_cache: Arc<AccessCache>) -> Self {
        Self {
            http_client,
            access_cache,
            max_object_ids: 100,
            bounded_matrix_size: 50,
        }
    }

    /// Generate sequential object IDs for testing
    fn generate_sequential_ids(&self, base_id: i64, count: usize) -> Vec<String> {
        (base_id..base_id + count as i64).map(|i| i.to_string()).collect()
    }

    /// Generate random object IDs within a bounded range
    fn generate_random_ids(&self, min: i64, max: i64, count: usize) -> Vec<String> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut ids = Vec::with_capacity(count);
        
        for _ in 0..count {
            let id = rng.gen_range(min..=max);
            ids.push(id.to_string());
        }
        
        ids
    }

    /// Test object level authorization on an endpoint
    async fn test_bola(
        &self,
        session: &Session,
        endpoint: &str,
        method: &str,
        object_ids: &[String],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for object_id in object_ids {
            let url = endpoint.replace("{id}", object_id);
            
            let response = match method.to_uppercase().as_str() {
                "GET" => self.http_client.get(&url).session(session).send().await,
                "POST" => self.http_client.post(&url).session(session).send().await,
                "PUT" => self.http_client.put(&url).session(session).send().await,
                "DELETE" => self.http_client.delete(&url).session(session).send().await,
                _ => continue,
            };

            // Check for successful access without proper authorization
            if response.status().is_success() {
                let body = response.body();
                
                // Look for signs of unauthorized access
                if !body.contains("unauthorized") 
                    && !body.contains("forbidden")
                    && !body.contains("access denied")
                    && !body.is_empty()
                {
                    findings.push(Finding::new()
                        .with_title("BOLA: Broken Object Level Authorization")
                        .with_description(format!(
                            "Endpoint {} allows unauthorized access to object {}",
                            endpoint, object_id
                        ))
                        .with_endpoint(endpoint)
                        .with_method(method.to_string())
                        .with_severity(crate::findings::severity::Severity::High)
                        .with_evidence(format!(
                            "Response status: {}, Body preview: {}",
                            response.status(),
                            &body[..body.len().min(200)]
                        )));
                    
                    // Cache the bypass pattern
                    self.access_cache.cache_bola_pattern(
                        endpoint.to_string(),
                        method.to_string(),
                        object_id.clone(),
                    );
                }
            }
        }
        
        findings
    }

    /// Scan API endpoints for BOLA vulnerabilities
    pub async fn scan_api(&self, sessions: &[Session], api_endpoints: &[(String, String)]) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        // Use bounded matrix to limit memory usage
        let limited_sessions: Vec<&Session> = sessions.iter().take(self.bounded_matrix_size).collect();
        
        for (endpoint, method) in api_endpoints {
            // Skip endpoints without ID placeholders
            if !endpoint.contains("{id}") && !endpoint.contains("/:id") && !regex::Regex::new(r"/\d+").unwrap().is_match(endpoint) {
                continue;
            }
            
            for session in &limited_sessions {
                // Test with sequential IDs
                let sequential_ids = self.generate_sequential_ids(1, self.max_object_ids / 2);
                let seq_findings = self.test_bola(session, endpoint, method, &sequential_ids).await;
                results.extend(seq_findings.into_iter().map(CheckResult::Finding));
                
                // Test with random IDs
                let random_ids = self.generate_random_ids(1, 10000, self.max_object_ids / 2);
                let random_findings = self.test_bola(session, endpoint, method, &random_ids).await;
                results.extend(random_findings.into_iter().map(CheckResult::Finding));
            }
        }
        
        results
    }

    /// Scan GraphQL endpoints for BOLA
    pub async fn scan_graphql(&self, session: &Session, graphql_endpoint: &str, queries: &[&str]) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        for query in queries {
            let payload = serde_json::json!({
                "query": query.replace("{id}", "1"),
            });
            
            let response = self.http_client
                .post(graphql_endpoint)
                .session(session)
                .json(&payload)
                .send()
                .await;
            
            if response.status().is_success() {
                let body = response.body();
                if !body.contains("errors") && !body.contains("unauthorized") {
                    // Try with different IDs
                    for test_id in ["2", "999", "0"] {
                        let modified_query = query.replace("{id}", test_id);
                        let modified_payload = serde_json::json!({
                            "query": modified_query,
                        });
                        
                        let test_response = self.http_client
                            .post(graphql_endpoint)
                            .session(session)
                            .json(&modified_payload)
                            .send()
                            .await;
                        
                        if test_response.status().is_success() 
                            && !test_response.body().contains("errors")
                        {
                            results.push(CheckResult::Finding(
                                Finding::new()
                                    .with_title("BOLA: GraphQL Object Access")
                                    .with_description(format!(
                                        "GraphQL endpoint allows access to arbitrary objects via ID {}",
                                        test_id
                                    ))
                                    .with_endpoint(graphql_endpoint)
                                    .with_severity(crate::findings::severity::Severity::Medium)
                            ));
                        }
                    }
                }
            }
        }
        
        results
    }
}

impl CheckModule for BolaDetector {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            name: "bola_detector".to_string(),
            category: CheckCategory::AccessControl,
            description: "Detects Broken Object Level Authorization on API endpoints".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    async fn execute(&self, context: &crate::orchestrator::graph::ScanContext) -> Vec<CheckResult> {
        let sessions = context.sessions();
        let api_endpoints = context.api_endpoints();
        self.scan_api(sessions, api_endpoints).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequential_id_generation() {
        let cache = Arc::new(AccessCache::new());
        let client = Arc::new(HttpClient::default());
        let detector = BolaDetector::new(client, cache);
        
        let ids = detector.generate_sequential_ids(100, 5);
        assert_eq!(ids.len(), 5);
        assert_eq!(ids[0], "100");
        assert_eq!(ids[4], "104");
    }

    #[test]
    fn test_random_id_generation() {
        let cache = Arc::new(AccessCache::new());
        let client = Arc::new(HttpClient::default());
        let detector = BolaDetector::new(client, cache);
        
        let ids = detector.generate_random_ids(1, 1000, 10);
        assert_eq!(ids.len(), 10);
        // All IDs should be within range
        for id in &ids {
            let num: i64 = id.parse().unwrap();
            assert!(num >= 1 && num <= 1000);
        }
    }
}
