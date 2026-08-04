//! gRPC Reflection Detection Module
//! Detects gRPC server reflection and maps service definitions without authorization.

use crate::checks::CheckModule;
use crate::findings::Finding;
use std::collections::{BTreeMap, HashSet};

const REFLECTION_METHODS: &[&str] = &[
    "grpc.reflection.v1alpha.ServerReflection",
    "grpc.reflection.v1.ServerReflection",
];

const KNOWN_SERVICES: &[&str] = &[
    "UserService", "AuthService", "AccountService", "PaymentService",
    "OrderService", "ProductService", "InventoryService", "NotificationService",
    "AdminService", "ConfigService", "HealthService", "MetadataService"
];

pub struct GrpcReflectionCheck {
    enabled: bool,
    timeout_ms: u64,
}

impl GrpcReflectionCheck {
    pub fn new() -> Self {
        Self {
            enabled: true,
            timeout_ms: 5000,
        }
    }

    fn probe_reflection(&self, host: &str, port: u16, client: &reqwest::Client) -> Option<ReflectionResult> {
        // Try to detect gRPC reflection via HTTP/2 or standard HTTP probing
        // Note: Full gRPC reflection requires h2c support, we probe via common patterns
        
        let base_url = format!("https://{}:{}", host, port);
        let alt_base = format!("http://{}:{}", host, port);

        // Probe for gRPC-web endpoints that might expose reflection
        for method in REFLECTION_METHODS {
            for url in [&base_url, &alt_base] {
                let reflection_path = format!("{}/{}", url, method.replace('.', "/"));
                
                if let Some(result) = self.probe_endpoint(&reflection_path, client) {
                    return Some(result);
                }
            }
        }

        // Probe known services
        for service in KNOWN_SERVICES {
            for url in [&base_url, &alt_base] {
                let service_path = format!("{}/{}", url, service);
                
                if let Some(result) = self.probe_endpoint(&service_path, client) {
                    return Some(ReflectionResult {
                        service: service.to_string(),
                        discovered: true,
                        reflection_enabled: false,
                        details: format!("Service {} detected", service),
                    });
                }
            }
        }

        None
    }

    fn probe_endpoint(&self, url: &str, client: &reqwest::Client) -> Option<ReflectionResult> {
        let resp = client
            .get(url)
            .header("Content-Type", "application/grpc")
            .send()
            .ok()?;

        let status = resp.status().as_u16();
        
        // gRPC-specific responses
        let headers = resp.headers();
        let is_grpc = headers.contains_key("grpc-status") || 
                      headers.contains_key("grpc-message") ||
                      resp.headers().get("content-type")
                          .and_then(|v| v.to_str().ok())
                          .map(|ct| ct.contains("grpc"))
                          .unwrap_or(false);

        if is_grpc || status == 200 || status == 405 {
            let body_preview = resp.text().ok()?.chars().take(300).collect::<String>();
            
            return Some(ReflectionResult {
                service: url.to_string(),
                discovered: true,
                reflection_enabled: status == 200,
                details: body_preview,
            });
        }

        None
    }

    fn parse_reflection_response(&self, body: &str) -> Vec<String> {
        let mut services = Vec::new();
        
        // Look for service names in response
        for line in body.lines() {
            if line.contains("service") || line.contains("Service") {
                if let Some(start) = line.find('"') {
                    if let Some(end) = line[start + 1..].find('"') {
                        services.push(line[start + 1..start + 1 + end].to_string());
                    }
                }
            }
        }
        
        services
    }
}

#[derive(Debug)]
struct ReflectionResult {
    service: String,
    discovered: bool,
    reflection_enabled: bool,
    details: String,
}

impl CheckModule for GrpcReflectionCheck {
    fn name(&self) -> &'static str {
        "grpc_reflection"
    }

    fn description(&self) -> &'static str {
        "Detects gRPC server reflection and maps service definitions without authorization"
    }

    fn severity(&self) -> crate::checks::Severity {
        crate::checks::Severity::Medium
    }

    fn run(&self, target: &crate::target::Target, context: &crate::context::ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        if !self.enabled {
            return findings;
        }

        let host = target.host();
        let ports = vec![443, 80, 8080, 8443, 50051]; // Common gRPC ports
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .build()
            .unwrap_or_default();

        let mut discovered_services: BTreeMap<String, ReflectionResult> = BTreeMap::new();

        for port in ports {
            if let Some(result) = self.probe_reflection(host, port, &client) {
                if result.discovered {
                    discovered_services.insert(format!("{}:{}", host, port), result);
                }
            }
        }

        for (address, result) in &discovered_services {
            if result.reflection_enabled {
                let evidence = crate::findings::Evidence::new()
                    .with_detail("address", address.clone())
                    .with_detail("service", result.service.clone())
                    .with_detail("reflection_enabled", "true".to_string())
                    .with_raw_response(result.details.chars().take(500).to_string());

                findings.push(Finding::new(self.name())
                    .with_target(address.clone())
                    .with_severity(crate::checks::Severity::High)
                    .with_title("gRPC Reflection Enabled")
                    .with_description("gRPC server reflection is enabled, allowing enumeration of all services and methods")
                    .with_evidence(evidence)
                    .with_confidence(0.90));
            } else {
                let evidence = crate::findings::Evidence::new()
                    .with_detail("address", address.clone())
                    .with_detail("service", result.service.clone())
                    .with_raw_response(result.details.chars().take(300).to_string());

                findings.push(Finding::new(self.name())
                    .with_target(address.clone())
                    .with_severity(self.severity())
                    .with_title("gRPC Service Detected")
                    .with_description(format!("gRPC service detected at {}", address))
                    .with_evidence(evidence)
                    .with_confidence(0.75));
            }
        }

        findings
    }

    fn clone_box(&self) -> Box<dyn CheckModule> {
        Box::new(self.clone())
    }
}

impl Clone for GrpcReflectionCheck {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            timeout_ms: self.timeout_ms,
        }
    }
}
