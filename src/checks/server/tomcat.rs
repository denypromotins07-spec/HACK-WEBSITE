//! Tomcat Server Management Module
//! Probes Tomcat Manager (/manager/html) and tests against bounded default credential lists.

use crate::http::client::HttpClient;
use crate::findings::evidence::Evidence;

/// Maximum number of credentials to test (bounded for memory safety)
const MAX_CREDENTIALS: usize = 100;

/// Common Tomcat manager paths
const TOMCAT_MANAGER_PATHS: &[&str] = &[
    "/manager/html",
    "/manager/text",
    "/manager/jmxproxy",
    "/manager/status",
    "/host-manager/html",
];

/// Bounded default credential list for testing
const DEFAULT_CREDENTIALS: &[(&str, &str)] = &[
    ("tomcat", "tomcat"),
    ("admin", "admin"),
    ("root", "root"),
    ("manager", "manager"),
    ("admin", ""),
    ("", "admin"),
    ("tomcat", ""),
    ("role", "tomcat"),
    ("j2ee", "j2ee"),
    ("ovwebusr", "OvW*busr1"),
    ("cxsdk", "kdsxc"),
    ("xampp", "xampp"),
    ("QCC", "QLogic66"),
];

/// Tomcat scanner struct
pub struct TomcatScanner {
    client: HttpClient,
}

impl TomcatScanner {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Check if Tomcat manager is accessible
    pub async fn is_tomcat_manager(&self, base_url: &str) -> bool {
        let base = base_url.trim_end_matches('/');
        
        for path in TOMCAT_MANAGER_PATHS {
            let url = format!("{}{}", base, path);
            if let Ok(response) = self.client.get(&url).send().await {
                let status = response.status();
                // 200 = accessible, 401 = auth required (confirms existence), 403 = forbidden
                if status == 200 || status == 401 || status == 403 {
                    return true;
                }
            }
        }
        
        false
    }

    /// Test default credentials against Tomcat manager (bounded iteration)
    pub async fn test_default_credentials(&self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        let base = base_url.trim_end_matches('/');
        let manager_path = "/manager/html";
        let url = format!("{}{}", base, manager_path);
        
        // Test bounded credential set
        for (username, password) in DEFAULT_CREDENTIALS.iter().take(MAX_CREDENTIALS) {
            if let Ok(response) = self.client
                .get(&url)
                .basic_auth(username.to_string(), Some(password.to_string()))
                .send()
                .await
            {
                if response.status() == 200 {
                    evidences.push(Evidence::DefaultCredentials {
                        service: "Tomcat Manager".to_string(),
                        username: username.to_string(),
                        password: password.to_string(),
                        url: url.clone(),
                        confidence: 100,
                        remediation: "Immediately change default credentials. Use strong, unique passwords.".to_string(),
                    });
                    break; // Found valid credentials, no need to continue
                }
            }
        }
        
        evidences
    }

    /// Check for Tomcat version exposure
    pub async fn enumerate_version(&self, base_url: &str) -> Option<String> {
        let base = base_url.trim_end_matches('/');
        
        // Try to get version from server header or error pages
        let url = base.to_string();
        if let Ok(response) = self.client.get(&url).send().await {
            // Check Server header
            if let Some(server) = response.headers().get("Server") {
                if server.contains("Apache-Coyote") || server.contains("Tomcat") {
                    if let Some(start) = server.find('/') {
                        return Some(server[start + 1..].to_string());
                    }
                }
            }
            
            // Check body for version info
            if let Ok(body) = response.text().await {
                if body.contains("Apache Tomcat") {
                    if let Some(start) = body.find("Apache Tomcat/") {
                        if let Some(end) = body[start..].find(' ') {
                            return Some(body[start + 14..start + end].to_string());
                        }
                    }
                }
            }
        }
        
        None
    }

    /// Full Tomcat scan
    pub async fn scan(&self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        
        if !self.is_tomcat_manager(base_url).await {
            return evidences;
        }

        // Version detection
        if let Some(version) = self.enumerate_version(base_url).await {
            evidences.push(Evidence::ServiceVersion {
                service: "Apache Tomcat".to_string(),
                version: version.clone(),
                url: base_url.to_string(),
                confidence: 85,
                remediation: "Keep Tomcat updated to the latest stable version.".to_string(),
            });
        }

        // Default credential testing
        let cred_evidences = self.test_default_credentials(base_url).await;
        evidences.extend(cred_evidences);

        // Manager accessibility evidence
        evidences.push(Evidence::ExposedManagement {
            service: "Tomcat Manager".to_string(),
            paths: TOMCAT_MANAGER_PATHS.iter().map(|s| s.to_string()).collect(),
            url: base_url.to_string(),
            confidence: 90,
            remediation: "Restrict access to Tomcat Manager using IP whitelisting and strong authentication.".to_string(),
        });

        evidences
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let client = HttpClient::new();
        let _scanner = TomcatScanner::new(client);
    }

    #[test]
    fn test_bounded_credentials() {
        assert!(DEFAULT_CREDENTIALS.len() <= MAX_CREDENTIALS);
    }
}
