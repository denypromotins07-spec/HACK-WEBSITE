//! Daemon Socket and Container API Exposure Module
//! Checks for exposed Docker sockets (/var/run/docker.sock) and unauthenticated Kubelet APIs.

use crate::http::client::HttpClient;
use crate::findings::evidence::Evidence;

/// Maximum number of paths to probe (bounded)
const MAX_SOCKET_PATHS: usize = 100;

/// Docker socket and container API endpoints
const CONTAINER_ENDPOINTS: &[(&str, &str)] = &[
    // Docker socket proxy paths
    ("/var/run/docker.sock", "Docker Socket"),
    ("/run/docker.sock", "Docker Socket"),
    ("/_docker/", "Docker Proxy"),
    
    // Docker Remote API endpoints
    ("/version", "Docker API Version"),
    ("/info", "Docker API Info"),
    ("/containers/json", "Docker Containers"),
    ("/images/json", "Docker Images"),
    ("/v1.24/version", "Docker API v1.24"),
    ("/v1.24/info", "Docker API v1.24"),
    
    // Kubernetes Kubelet API
    ("/pods", "Kubelet Pods"),
    ("/runningpods", "Kubelet Running Pods"),
    ("/stats/summary", "Kubelet Stats"),
    ("/metrics", "Kubelet Metrics"),
    ("/logs/", "Kubelet Logs"),
    ("/run/", "Kubelet Run"),
    ("/exec/", "Kubelet Exec"),
    ("/attach/", "Kubelet Attach"),
    ("/portForward/", "Kubelet Port Forward"),
    
    // Kubernetes API Server
    ("/api/v1/namespaces", "K8s Namespaces"),
    ("/api/v1/pods", "K8s Pods"),
    ("/apis/apps/v1/deployments", "K8s Deployments"),
    ("/healthz", "K8s Health Check"),
    ("/readyz", "K8s Ready Check"),
    
    // Containerd
    ("/run/containerd/containerd.sock", "Containerd Socket"),
    
    // CRI-O
    ("/var/run/crio/crio.sock", "CRI-O Socket"),
];

/// Daemon socket scanner
pub struct DaemonSocketScanner {
    client: HttpClient,
}

impl DaemonSocketScanner {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Scan for exposed Docker/Kubernetes endpoints
    pub async fn scan(&self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        let base = base_url.trim_end_matches('/');
        let mut found_endpoints = Vec::new();
        
        for (path, service) in CONTAINER_ENDPOINTS.iter().take(MAX_SOCKET_PATHS) {
            let url = if path.starts_with("http") {
                path.to_string()
            } else {
                format!("{}{}", base, path)
            };
            
            if let Ok(response) = self.client.get(&url).send().await {
                let status = response.status();
                
                // Check for accessible endpoints
                if status == 200 || status == 400 || status == 404 {
                    // Some APIs return 400/404 but still confirm existence
                    if let Ok(body) = response.text().await {
                        if self.is_valid_container_response(path, &body, status) {
                            found_endpoints.push(((*path).to_string(), (*service).to_string()));
                            
                            let severity = self.determine_severity(service);
                            let info = self.extract_info(path, &body);
                            
                            evidences.push(Evidence::ExposedContainerApi {
                                endpoint: (*path).to_string(),
                                service: (*service).to_string(),
                                url: url.clone(),
                                severity: severity.to_string(),
                                info,
                                confidence: 85,
                                remediation: self.get_remediation(service),
                            });
                        }
                    }
                }
            }
        }
        
        // Summary evidence for critical findings
        let docker_findings: Vec<_> = found_endpoints.iter()
            .filter(|(_, s)| s.contains("Docker"))
            .collect();
        
        let k8s_findings: Vec<_> = found_endpoints.iter()
            .filter(|(_, s)| s.contains("Kubelet") || s.contains("K8s"))
            .collect();
        
        if !docker_findings.is_empty() {
            evidences.push(Evidence::CriticalContainerExposure {
                container_type: "Docker".to_string(),
                endpoints_found: docker_findings.len(),
                base_url: base_url.to_string(),
                confidence: 95,
                remediation: "CRITICAL: Docker API exposed. Immediately restrict access using firewall rules and authentication.".to_string(),
            });
        }
        
        if !k8s_findings.is_empty() {
            evidences.push(Evidence::CriticalContainerExposure {
                container_type: "Kubernetes".to_string(),
                endpoints_found: k8s_findings.len(),
                base_url: base_url.to_string(),
                confidence: 95,
                remediation: "CRITICAL: Kubernetes API exposed. Enable RBAC and restrict Kubelet access.".to_string(),
            });
        }
        
        evidences
    }

    /// Validate container API response
    fn is_valid_container_response(&self, path: &str, body: &str, status: u16) -> bool {
        match path {
            p if p.contains("version") => {
                body.contains("ApiVersion") || body.contains("Version") || body.contains("version")
            },
            p if p.contains("info") => {
                body.contains("Containers") || body.contains("Images") || body.contains("Architecture")
            },
            p if p.contains("containers") => {
                body.contains("Names") || body.contains("Image") || body.contains("State")
            },
            p if p.contains("pods") => {
                body.contains("items") || body.contains("metadata") || body.contains("spec")
            },
            p if p.contains("metrics") => {
                body.contains("# HELP") || body.contains("TYPE") // Prometheus format
            },
            p if p.contains("namespaces") => {
                body.contains("items") || body.contains("Namespace")
            },
            p if p.contains("healthz") || p.contains("readyz") => {
                body.contains("ok") || status == 200
            },
            _ => !body.is_empty(),
        }
    }

    /// Determine severity based on endpoint type
    fn determine_severity(&self, service: &str) -> &'static str {
        if service.contains("Exec") || service.contains("Attach") || service.contains("Run") {
            "Critical"
        } else if service.contains("Socket") || service.contains("Kubelet") {
            "Critical"
        } else if service.contains("Docker") || service.contains("K8s") {
            "High"
        } else if service.contains("Metrics") || service.contains("Stats") {
            "Medium"
        } else {
            "Low"
        }
    }

    /// Extract safe information from responses
    fn extract_info(&self, path: &str, body: &str) -> String {
        if path.contains("version") {
            if let Some(start) = body.find("\"Version\"") {
                if let Some(end) = body[start..].find('"') {
                    if let Some(end2) = body[start + end + 1..].find('"') {
                        return format!("Version: {}", &body[start + end + 2..start + end + 1 + end2]);
                    }
                }
            }
        }
        
        if path.contains("info") {
            if body.contains("Containers") {
                if let Some(start) = body.find("\"Containers\":") {
                    if let Some(comma) = body[start..].find(',') {
                        return format!("Info accessible - {}", &body[start..start + comma]);
                    }
                }
            }
        }
        
        if path.contains("pods") || path.contains("namespaces") {
            if body.contains("\"items\"") {
                return "Pod/Namespace listing accessible".to_string();
            }
        }
        
        "Endpoint accessible".to_string()
    }

    /// Get remediation guidance
    fn get_remediation(&self, service: &str) -> String {
        match *service {
            "Docker Socket" | "Docker Proxy" => {
                "Never expose Docker socket to network. Use TLS and authentication for remote Docker.".to_string()
            },
            "Kubelet Pods" | "Kubelet Running Pods" | "Kubelet Exec" | "Kubelet Attach" => {
                "Enable Kubelet authentication and authorization. Use --anonymous-auth=false.".to_string()
            },
            "K8s Namespaces" | "K8s Pods" | "K8s Deployments" => {
                "Enable RBAC on Kubernetes API server. Use service accounts with minimal privileges.".to_string()
            },
            _ => {
                "Restrict access to container management interfaces. Implement network segmentation.".to_string()
            }
        }
    }

    /// Quick check for any container exposure
    pub async fn has_container_exposure(&self, base_url: &str) -> bool {
        let base = base_url.trim_end_matches('/');
        let quick_paths = ["/version", "/info", "/pods", "/runningpods"];
        
        for path in quick_paths.iter() {
            let url = format!("{}{}", base, path);
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status() == 200 {
                    return true;
                }
            }
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let client = HttpClient::new();
        let _scanner = DaemonSocketScanner::new(client);
    }

    #[test]
    fn test_bounded_paths() {
        assert!(CONTAINER_ENDPOINTS.len() <= MAX_SOCKET_PATHS);
    }
}
