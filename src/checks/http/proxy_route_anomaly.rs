//! Proxy Route Anomaly Detection
//! 
//! Detects reverse proxy routing anomalies using path and header mutation sequences.
//! Identifies misconfigurations that enable route bypass or request smuggling.

use crate::checks::module::{CheckModule, CheckMetadata, CheckResult, CheckContext};
use crate::findings::finding::Finding;
use crate::orchestrator::budget::ResourceBudget;
use async_trait::async_trait;
use std::time::Duration;

/// Proxy Route Anomaly Detection Module
/// 
/// Tests for scenarios where:
/// - Reverse proxy routing rules can be bypassed
/// - Path normalization differs between proxy and backend
/// - Header-based routing is exploitable
pub struct ProxyRouteAnomalyCheck {
    metadata: CheckMetadata,
    path_mutations: Vec<String>,
    header_mutations: Vec<(String, String)>,
}

impl ProxyRouteAnomalyCheck {
    pub fn new() -> Self {
        Self {
            metadata: CheckMetadata {
                id: "HTTP-011".to_string(),
                name: "Proxy Route Anomaly".to_string(),
                severity: crate::findings::severity::Severity::High,
                category: "HTTP Protocol".to_string(),
                timeout: Duration::from_secs(30),
                resource_budget: ResourceBudget {
                    max_requests: 15,
                    max_memory_bytes: 2 * 1024 * 1024,
                    max_cpu_time_ms: 8000,
                },
                description: "Detects reverse proxy routing anomalies and bypass techniques".to_string(),
                remediation_hint: "Normalize paths consistently across proxy layers. Validate routing headers at proxy level.".to_string(),
            },
            // Path mutations that may bypass routing rules
            path_mutations: vec![
                "/admin".to_string(),
                "/admin/".to_string(),
                "/admin//".to_string(),
                "/admin/.".to_string(),
                "/admin/..".to_string(),
                "/admin%2F".to_string(),
                "/admin%2f".to_string(),
                "/admin/./test".to_string(),
                "/admin/../admin".to_string(),
                "//admin".to_string(),
                "/;admin".to_string(),
                "/admin?".to_string(),
                "/admin#fragment".to_string(),
            ],
            // Header mutations for routing bypass
            header_mutations: vec![
                ("X-Forwarded-Prefix".to_string(), "/admin".to_string()),
                ("X-Rewrite-Url".to_string(), "/admin".to_string()),
                ("X-Original-Url".to_string(), "/admin".to_string()),
                ("X-Forwarded-Path".to_string(), "/admin".to_string()),
                ("X-Forwarded-Prefix".to_string(), "/..".to_string()),
                ("X-Forwarded-Host".to_string(), "internal-server".to_string()),
            ],
        }
    }

    /// Generate path mutation probe
    fn generate_path_probe(&self, boundary_id: &str, path: &str) -> String {
        format!(
            "GET {} HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             X-Boundary: {}\r\n\
             \r\n",
            path, boundary_id
        )
    }

    /// Generate header-based routing probe
    fn generate_header_route_probe(&self, boundary_id: &str, header_name: &str, header_value: &str) -> String {
        format!(
            "GET / HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             {}: {}\r\n\
             X-Boundary: {}\r\n\
             \r\n",
            header_name, header_value, boundary_id
        )
    }

    /// Generate combined path + header probe
    fn generate_combined_probe(&self, boundary_id: &str, path: &str, header_name: &str, header_value: &str) -> String {
        format!(
            "GET {} HTTP/1.1\r\n\
             Host: {{target_host}}\r\n\
             {}: {}\r\n\
             X-Boundary: {}\r\n\
             \r\n",
            path, header_name, header_value, boundary_id
        )
    }

    /// Analyze response for routing anomaly indicators
    fn analyze_response(&self, response: &str, boundary_id: &str, probe_type: &str) -> Option<Finding> {
        // Check if we accessed admin/internal content without proper auth
        if (response.contains("admin") || response.contains("internal")) && 
           !probe_type.contains("legitimate") {
            // If response suggests we reached protected area
            if response.contains(&format!("X-Boundary: {}", boundary_id)) ||
               response.contains("200 OK") && response.len() > 100 {
                return Some(Finding::new(
                    self.metadata.id.clone(),
                    self.metadata.severity.clone(),
                    format!("Proxy route bypass confirmed via {}", probe_type),
                    format!("Probe type: {}\nResponse excerpt: {}", probe_type, &response[..response.len().min(500)]),
                    self.metadata.remediation_hint.clone(),
                ));
            }
        }

        // Check for evidence of path confusion
        if response.contains("different-path") || response.contains("unexpected-route") {
            return Some(Finding::new(
                self.metadata.id.clone(),
                crate::findings::severity::Severity::Medium,
                format!("Path confusion detected via {}", probe_type),
                format!("Probe type: {}\nResponse: {}", probe_type, &response[..response.len().min(500)]),
                self.metadata.remediation_hint.clone(),
            ));
        }

        None
    }
}

#[async_trait]
impl CheckModule for ProxyRouteAnomalyCheck {
    fn metadata(&self) -> &CheckMetadata {
        &self.metadata
    }

    async fn init(&mut self, _context: &CheckContext) -> Result<(), String> {
        Ok(())
    }

    async fn run(&self, context: &CheckContext) -> Result<CheckResult, String> {
        let client = context.client();
        let boundary_id = format!("{:08x}", rand::random::<u32>());
        let mut request_count = 0;

        // Test 1: Path mutations
        for path in &self.path_mutations {
            if request_count >= self.metadata.resource_budget.max_requests as usize / 2 {
                break;
            }

            let probe = self.generate_path_probe(&boundary_id, path);
            match client.send_raw(&probe).await {
                Ok(response) => {
                    if let Some(finding) = self.analyze_response(&response, &boundary_id, &format!("path: {}", path)) {
                        return Ok(CheckResult::VulnerabilityFound(finding));
                    }
                    request_count += 1;
                }
                Err(_) => continue,
            }
        }

        // Test 2: Header-based routing mutations
        for (header_name, header_value) in &self.header_mutations {
            if request_count >= self.metadata.resource_budget.max_requests as usize {
                break;
            }

            let probe = self.generate_header_route_probe(&boundary_id, header_name, header_value);
            match client.send_raw(&probe).await {
                Ok(response) => {
                    if let Some(finding) = self.analyze_response(&response, &boundary_id, &format!("header: {}={}", header_name, header_value)) {
                        return Ok(CheckResult::VulnerabilityFound(finding));
                    }
                    request_count += 1;
                }
                Err(_) => continue,
            }
        }

        // Test 3: Combined path + header mutations (limited)
        let test_paths = ["/admin", "//admin", "/admin/."];
        let test_headers = [("X-Forwarded-Prefix", "/"), ("X-Rewrite-Url", "/admin")];

        for path in &test_paths {
            for (h_name, h_value) in &test_headers {
                if request_count >= self.metadata.resource_budget.max_requests as usize {
                    break;
                }

                let probe = self.generate_combined_probe(&boundary_id, path, h_name, h_value);
                match client.send_raw(&probe).await {
                    Ok(response) => {
                        if let Some(finding) = self.analyze_response(&response, &boundary_id, &format!("combined: {} + {}={}", path, h_name, h_value)) {
                            return Ok(CheckResult::VulnerabilityFound(finding));
                        }
                        request_count += 1;
                    }
                    Err(_) => continue,
                }
            }
        }

        Ok(CheckResult::Safe)
    }

    async fn analyze(&self, result: &CheckResult) -> Result<Option<Finding>, String> {
        match result {
            CheckResult::VulnerabilityFound(finding) => Ok(Some(finding.clone())),
            _ => Ok(None),
        }
    }

    fn remediation(&self) -> Option<String> {
        Some(self.metadata.remediation_hint.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_mutations() {
        let check = ProxyRouteAnomalyCheck::new();
        assert!(check.path_mutations.len() >= 10);
        assert!(check.path_mutations.iter().any(|p| p.contains("admin")));
    }

    #[test]
    fn test_header_mutations() {
        let check = ProxyRouteAnomalyCheck::new();
        assert!(check.header_mutations.len() >= 4);
        assert!(check.header_mutations.iter().any(|(h, _)| h.contains("X-Forwarded")));
    }

    #[test]
    fn test_path_probe_generation() {
        let check = ProxyRouteAnomalyCheck::new();
        let probe = check.generate_path_probe("test123", "/admin");
        assert!(probe.contains("GET /admin"));
        assert!(probe.contains("X-Boundary: test123"));
    }

    #[test]
    fn test_metadata() {
        let check = ProxyRouteAnomalyCheck::new();
        assert_eq!(check.metadata().id, "HTTP-011");
        assert_eq!(check.metadata().severity, crate::findings::severity::Severity::High);
    }
}
