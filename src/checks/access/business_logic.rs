//! Business Logic Abuse Detection Module
//! Detects logic reversals using negative quantities, price tampering, and workflow skipping.

use crate::checks::module::{CheckModule, CheckResult, CheckMetadata, CheckCategory};
use crate::findings::finding::Finding;
use crate::session::session::Session;
use crate::http::client::HttpClient;
use crate::learning::access_cache::AccessCache;
use std::sync::Arc;
use serde_json::{json, Value};

/// Business logic abuse detector
pub struct BusinessLogicDetector {
    http_client: Arc<HttpClient>,
    access_cache: Arc<AccessCache>,
}

impl BusinessLogicDetector {
    pub fn new(http_client: Arc<HttpClient>, access_cache: Arc<AccessCache>) -> Self {
        Self {
            http_client,
            access_cache,
        }
    }

    /// Test for negative quantity exploitation
    async fn test_negative_quantity(&self, session: &Session, order_endpoints: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for endpoint in order_endpoints {
            // Test with negative quantities
            let payloads = vec![
                json!({"quantity": -1, "product_id": "test"}),
                json!({"quantity": -100, "item": "test"}),
                json!({"qty": -5, "sku": "test"}),
                json!({"amount": -50, "product": "test"}),
            ];
            
            for payload in payloads {
                let response = self.http_client
                    .post(endpoint)
                    .session(session)
                    .json(&payload)
                    .send()
                    .await;
                
                if response.status().is_success() {
                    let body = response.body();
                    
                    // Check if the order was accepted (potential for refund fraud)
                    if body.contains("success") 
                        || body.contains("order") 
                        || body.contains("created")
                        || body.contains("confirmed")
                    {
                        // Check for credit/refund indicators
                        if body.contains("credit") 
                            || body.contains("refund")
                            || body.contains("balance")
                            || body.contains("total") && body.contains("-")
                        {
                            findings.push(Finding::new()
                                .with_title("Business Logic: Negative Quantity Exploitation")
                                .with_description(format!(
                                    "Negative quantity accepted at {} potentially generating credit",
                                    endpoint
                                ))
                                .with_endpoint(endpoint)
                                .with_severity(crate::findings::severity::Severity::Critical)
                                .with_evidence(format!(
                                    "Payload: {}, Response: {}",
                                    payload,
                                    &body[..body.len().min(200)]
                                )));
                            
                            break;
                        }
                    }
                }
            }
        }
        
        findings
    }

    /// Test for price tampering
    async fn test_price_tampering(&self, session: &Session, purchase_endpoints: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for endpoint in purchase_endpoints {
            // Test with manipulated prices
            let payloads = vec![
                json!({"price": 0.01, "product_id": "test"}),
                json!({"price": 0, "item": "test"}),
                json!({"price": -10, "product": "test"}),
                json!({"unit_price": 0.001, "sku": "test"}),
                json!({"amount": 1, "original_price": 100}),
            ];
            
            for payload in payloads {
                let response = self.http_client
                    .post(endpoint)
                    .session(session)
                    .json(&payload)
                    .send()
                    .await;
                
                if response.status().is_success() {
                    let body = response.body();
                    
                    // Check if server accepted the manipulated price
                    if body.contains("success") || body.contains("order") || body.contains("purchase") {
                        // Verify the price was actually used
                        let body_lower = body.to_lowercase();
                        if body_lower.contains("0.01") 
                            || body_lower.contains("0.00")
                            || body_lower.contains("total\"):\\s*0")
                            || body_lower.contains("paid\"):\\s*0")
                        {
                            findings.push(Finding::new()
                                .with_title("Business Logic: Price Tampering Successful")
                                .with_description(format!(
                                    "Server accepted manipulated price at {}",
                                    endpoint
                                ))
                                .with_endpoint(endpoint)
                                .with_severity(crate::findings::severity::Severity::Critical)
                                .with_evidence(format!(
                                    "Payload: {}, Response indicates low price accepted: {}",
                                    payload,
                                    &body[..body.len().min(200)]
                                )));
                            
                            self.access_cache.cache_business_logic_pattern(
                                endpoint.clone(),
                                "price_tampering".to_string(),
                            );
                            
                            break;
                        }
                    }
                }
            }
        }
        
        findings
    }

    /// Test for workflow step skipping
    async fn test_workflow_skipping(&self, session: &Session, workflow_steps: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        if workflow_steps.len() < 2 {
            return findings;
        }
        
        // Try to access final step without completing intermediate steps
        let final_step = workflow_steps.last().unwrap();
        
        // Attempt direct access to final step
        let response = self.http_client
            .post(final_step)
            .session(session)
            .send()
            .await;
        
        if response.status().is_success() {
            let body = response.body();
            
            if body.contains("complete") 
                || body.contains("success") 
                || body.contains("finalized")
                || body.contains("confirmed")
            {
                findings.push(Finding::new()
                    .with_title("Business Logic: Workflow Step Skipping")
                    .with_description(format!(
                        "Final workflow step {} can be accessed without completing previous steps",
                        final_step
                    ))
                    .with_endpoint(final_step)
                    .with_severity(crate::findings::severity::Severity::High)
                    .with_evidence(format!(
                        "Response: {}",
                        &body[..body.len().min(200)]
                    )));
            }
        }
        
        // Test accessing steps out of order
        for (i, step) in workflow_steps.iter().enumerate() {
            if i > 0 {
                // Try accessing this step without doing previous steps
                let fresh_session = session.clone_fresh();
                
                let response = self.http_client
                    .post(step)
                    .session(&fresh_session)
                    .send()
                    .await;
                
                if response.status().is_success() 
                    && !response.body().contains("error")
                    && !response.body().contains("incomplete")
                    && !response.body().contains("prerequisite")
                {
                    findings.push(Finding::new()
                        .with_title("Business Logic: Out-of-Order Step Access")
                        .with_description(format!(
                            "Workflow step {} can be accessed out of order",
                            step
                        ))
                        .with_endpoint(step)
                        .with_severity(crate::findings::severity::Severity::Medium));
                }
            }
        }
        
        findings
    }

    /// Test for currency manipulation
    async fn test_currency_manipulation(&self, session: &Session, payment_endpoints: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for endpoint in payment_endpoints {
            // Test with different currency codes or manipulations
            let payloads = vec![
                json!({"currency": "USD", "amount": 100, "currency_code": "EUR"}),
                json!({"amount": 100, "currency": "JPY", "target_currency": "USD"}),
                json!({"price": 100, "currency_symbol": "$", "code": ""}),
            ];
            
            for payload in payloads {
                let response = self.http_client
                    .post(endpoint)
                    .session(session)
                    .json(&payload)
                    .send()
                    .await;
                
                if response.status().is_success() {
                    let body = response.body();
                    
                    // Look for signs of currency confusion
                    if body.contains("currency_mismatch") || body.contains("converted") {
                        continue; // Server detected the issue
                    }
                    
                    if body.contains("success") || body.contains("processed") {
                        findings.push(Finding::new()
                            .with_title("Business Logic: Potential Currency Confusion")
                            .with_description(format!(
                                "Payment endpoint {} may have currency handling issues",
                                endpoint
                            ))
                            .with_endpoint(endpoint)
                            .with_severity(crate::findings::severity::Severity::Medium)
                            .with_evidence(format!(
                                "Payload with multiple currency fields: {}, Response: {}",
                                payload,
                                &body[..body.len().min(150)]
                            )));
                        break;
                    }
                }
            }
        }
        
        findings
    }

    /// Scan for business logic vulnerabilities
    pub async fn scan(&self, sessions: &[Session], endpoints: &[String]) -> Vec<CheckResult> {
        let mut results = Vec::new();
        
        for session in sessions {
            // Categorize endpoints
            let order_endpoints: Vec<String> = endpoints
                .iter()
                .filter(|e| {
                    let lower = e.to_lowercase();
                    lower.contains("order") 
                        || lower.contains("cart") 
                        || lower.contains("checkout")
                        || lower.contains("purchase")
                })
                .cloned()
                .collect();
            
            let purchase_endpoints: Vec<String> = endpoints
                .iter()
                .filter(|e| {
                    let lower = e.to_lowercase();
                    lower.contains("buy") 
                        || lower.contains("payment")
                        || lower.contains("transaction")
                })
                .cloned()
                .collect();
            
            let workflow_endpoints: Vec<String> = endpoints
                .iter()
                .filter(|e| {
                    let lower = e.to_lowercase();
                    lower.contains("step") 
                        || lower.contains("stage")
                        || lower.contains("phase")
                        || lower.contains("wizard")
                })
                .cloned()
                .collect();
            
            let payment_endpoints: Vec<String> = endpoints
                .iter()
                .filter(|e| {
                    let lower = e.to_lowercase();
                    lower.contains("payment")
                        || lower.contains("charge")
                        || lower.contains("invoice")
                })
                .cloned()
                .collect();
            
            // Run tests
            let neg_qty_findings = self.test_negative_quantity(session, &order_endpoints).await;
            results.extend(neg_qty_findings.into_iter().map(CheckResult::Finding));
            
            let price_findings = self.test_price_tampering(session, &purchase_endpoints).await;
            results.extend(price_findings.into_iter().map(CheckResult::Finding));
            
            let workflow_findings = self.test_workflow_skipping(session, &workflow_endpoints).await;
            results.extend(workflow_findings.into_iter().map(CheckResult::Finding));
            
            let currency_findings = self.test_currency_manipulation(session, &payment_endpoints).await;
            results.extend(currency_findings.into_iter().map(CheckResult::Finding));
        }
        
        results
    }
}

impl CheckModule for BusinessLogicDetector {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            name: "business_logic_detector".to_string(),
            category: CheckCategory::AccessControl,
            description: "Detects business logic abuse vulnerabilities".to_string(),
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
    fn test_detector_creation() {
        let cache = Arc::new(AccessCache::new());
        let client = Arc::new(HttpClient::default());
        let _detector = BusinessLogicDetector::new(client, cache);
    }
}
