//! Race Condition Detection Module
//! Detects race conditions using synchronized concurrent requests for coupons, limits, and balance operations.

use crate::checks::module::{CheckModule, CheckResult, CheckMetadata, CheckCategory};
use crate::findings::finding::Finding;
use crate::session::session::Session;
use crate::http::client::HttpClient;
use crate::learning::access_cache::AccessCache;
use std::sync::Arc;
use tokio::sync::Barrier;
use std::time::Duration;

/// Operations prone to race conditions
const RACE_PRONE_PATTERNS: &[&str] = &[
    "coupon",
    "redeem",
    "claim",
    "withdraw",
    "transfer",
    "balance",
    "credit",
    "debit",
    "purchase",
    "order",
    "booking",
    "reserve",
    "limit",
    "quota",
    "rate",
    "count",
    "increment",
    "decrement",
];

/// Race condition detector with controlled concurrency
pub struct RaceConditionDetector {
    http_client: Arc<HttpClient>,
    access_cache: Arc<AccessCache>,
    max_concurrent_requests: usize,
    timeout_ms: u64,
}

impl RaceConditionDetector {
    pub fn new(http_client: Arc<HttpClient>, access_cache: Arc<AccessCache>) -> Self {
        Self {
            http_client,
            access_cache,
            max_concurrent_requests: 20, // Bounded concurrency
            timeout_ms: 5000,
        }
    }

    /// Execute concurrent requests with synchronization barrier
    async fn execute_concurrent(
        &self,
        session: &Session,
        endpoint: &str,
        method: &str,
        payload: Option<serde_json::Value>,
        count: usize,
    ) -> Vec<(u16, String)> {
        let mut handles = Vec::new();
        let barrier = Arc::new(Barrier::new(count.min(self.max_concurrent_requests)));
        
        for i in 0..count.min(self.max_concurrent_requests) {
            let http_client = Arc::clone(&self.http_client);
            let session = session.clone();
            let endpoint = endpoint.to_string();
            let method = method.to_string();
            let payload = payload.clone();
            let barrier = Arc::clone(&barrier);
            
            let handle = tokio::spawn(async move {
                // Wait at the barrier for synchronized start
                barrier.wait().await;
                
                let response = match method.as_str() {
                    "POST" => {
                        let mut req = http_client.post(&endpoint).session(&session);
                        if let Some(p) = &payload {
                            req = req.json(p);
                        }
                        req.send().await
                    }
                    "GET" => http_client.get(&endpoint).session(&session).send().await,
                    _ => http_client.post(&endpoint).session(&session).send().await,
                };
                
                (
                    response.status().as_u16(),
                    response.body().to_string(),
                )
            });
            
            handles.push(handle);
        }
        
        // Collect results with timeout
        let mut results = Vec::new();
        for handle in handles {
            match tokio::time::timeout(Duration::from_millis(self.timeout_ms), handle).await {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(_)) => results.push((0, "task_failed".to_string())),
                Err(_) => results.push((0, "timeout".to_string())),
            }
        }
        
        results
    }

    /// Test for race conditions in coupon/redemption operations
    async fn test_coupon_race(&self, session: &Session, coupon_endpoints: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for endpoint in coupon_endpoints {
            // Send multiple concurrent redemption requests
            let payload = serde_json::json!({
                "code": "TESTCOUPON",
                "quantity": 1
            });
            
            let results = self.execute_concurrent(session, endpoint, "POST", Some(payload), 10).await;
            
            // Count successful responses
            let success_count = results.iter().filter(|(status, _)| *status == 200).count();
            
            // If multiple requests succeeded, there's likely a race condition
            if success_count > 1 {
                findings.push(Finding::new()
                    .with_title("Race Condition: Multiple Coupon Redemption")
                    .with_description(format!(
                        "{} concurrent requests succeeded for coupon redemption at {}",
                        success_count,
                        endpoint
                    ))
                    .with_endpoint(endpoint)
                    .with_severity(crate::findings::severity::Severity::High)
                    .with_evidence(format!(
                        "Total requests: 10, Successful: {}, Expected: 1",
                        success_count
                    )));
                
                // Cache the vulnerable pattern
                self.access_cache.cache_race_condition_pattern(
                    endpoint.clone(),
                    "coupon_redeem".to_string(),
                );
            }
        }
        
        findings
    }

    /// Test for race conditions in balance/transfer operations
    async fn test_balance_race(&self, session: &Session, balance_endpoints: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for endpoint in balance_endpoints {
            // Get initial balance
            let initial_response = self.http_client
                .get(endpoint)
                .session(session)
                .send()
                .await;
            
            let initial_balance: f64 = serde_json::from_str(initial_response.body())
                .ok()
                .and_then(|v: serde_json::Value| v["balance"].as_f64())
                .unwrap_or(0.0);
            
            // Send concurrent withdrawal/transfer requests
            let payload = serde_json::json!({
                "amount": 1,
                "target": "test_account"
            });
            
            let withdraw_endpoint = format!("{}/withdraw", endpoint.trim_end_matches('/'));
            let results = self.execute_concurrent(session, &withdraw_endpoint, "POST", Some(payload), 15).await;
            
            let success_count = results.iter().filter(|(status, _)| *status == 200).count();
            
            // Check final balance
            let final_response = self.http_client
                .get(endpoint)
                .session(session)
                .send()
                .await;
            
            let final_balance: f64 = serde_json::from_str(final_response.body())
                .ok()
                .and_then(|v: serde_json::Value| v["balance"].as_f64())
                .unwrap_or(0.0);
            
            // If more withdrawals succeeded than balance allows, race condition exists
            let expected_balance = initial_balance - (success_count as f64);
            if final_balance > expected_balance && success_count > 1 {
                findings.push(Finding::new()
                    .with_title("Race Condition: Balance Manipulation")
                    .with_description(format!(
                        "Concurrent withdrawals allowed negative or incorrect balance at {}",
                        endpoint
                    ))
                    .with_endpoint(&withdraw_endpoint)
                    .with_severity(crate::findings::severity::Severity::Critical)
                    .with_evidence(format!(
                        "Initial: {}, Withdrawals: {}, Expected: {}, Actual: {}",
                        initial_balance, success_count, expected_balance, final_balance
                    )));
            }
        }
        
        findings
    }

    /// Test for race conditions in limit/quota enforcement
    async fn test_limit_race(&self, session: &Session, limit_endpoints: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for endpoint in limit_endpoints {
            // Send burst of requests to exceed rate limit
            let results = self.execute_concurrent(session, endpoint, "POST", None, 20).await;
            
            let success_count = results.iter().filter(|(status, _)| *status == 200 || *status == 201).count();
            let rate_limited = results.iter().filter(|(status, _)| *status == 429).count();
            
            // If many requests succeeded without rate limiting, there may be a race
            if success_count > 15 && rate_limited == 0 {
                findings.push(Finding::new()
                    .with_title("Race Condition: Rate Limit Bypass")
                    .with_description(format!(
                        "Rate limiting can be bypassed via concurrent requests at {}",
                        endpoint
                    ))
                    .with_endpoint(endpoint)
                    .with_severity(crate::findings::severity::Severity::Medium)
                    .with_evidence(format!(
                        "Concurrent requests: 20, Success: {}, Rate limited: {}",
                        success_count, rate_limited
                    )));
            }
        }
        
        findings
    }

    /// Scan for race condition vulnerabilities
    pub async fn scan(&self, sessions: &[Session], endpoints: &[String]) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        for session in sessions {
            // Categorize endpoints by race-prone patterns
            let mut coupon_endpoints = Vec::new();
            let mut balance_endpoints = Vec::new();
            let mut limit_endpoints = Vec::new();
            
            for endpoint in endpoints {
                let lower = endpoint.to_lowercase();
                
                if RACE_PRONE_PATTERNS.iter().any(|p| lower.contains(p)) {
                    if lower.contains("coupon") || lower.contains("redeem") || lower.contains("claim") {
                        coupon_endpoints.push(endpoint.clone());
                    } else if lower.contains("balance") 
                        || lower.contains("transfer") 
                        || lower.contains("withdraw")
                        || lower.contains("credit")
                    {
                        balance_endpoints.push(endpoint.clone());
                    } else if lower.contains("limit") 
                        || lower.contains("rate")
                        || lower.contains("quota")
                    {
                        limit_endpoints.push(endpoint.clone());
                    }
                }
            }
            
            // Test each category
            let coupon_findings = self.test_coupon_race(session, &coupon_endpoints).await;
            results.extend(coupon_findings.into_iter().map(CheckResult::Finding));
            
            let balance_findings = self.test_balance_race(session, &balance_endpoints).await;
            results.extend(balance_findings.into_iter().map(CheckResult::Finding));
            
            let limit_findings = self.test_limit_race(session, &limit_endpoints).await;
            results.extend(limit_findings.into_iter().map(CheckResult::Finding));
        }
        
        results
    }
}

impl CheckModule for RaceConditionDetector {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            name: "race_condition_detector".to_string(),
            category: CheckCategory::AccessControl,
            description: "Detects race conditions using synchronized concurrent requests".to_string(),
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
    fn test_race_patterns_loaded() {
        assert!(RACE_PRONE_PATTERNS.contains(&"coupon"));
        assert!(RACE_PRONE_PATTERNS.contains(&"balance"));
        assert!(RACE_PRONE_PATTERNS.contains(&"transfer"));
        assert!(RACE_PRONE_PATTERNS.contains(&"limit"));
    }

    #[test]
    fn test_bounded_concurrency() {
        let cache = Arc::new(AccessCache::new());
        let client = Arc::new(HttpClient::default());
        let detector = RaceConditionDetector::new(client, cache);
        
        assert!(detector.max_concurrent_requests <= 20);
        assert!(detector.timeout_ms > 0);
    }
}
