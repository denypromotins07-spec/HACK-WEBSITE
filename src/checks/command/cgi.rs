//! CGI Script Vulnerability Detection
//! Probes CGI scripts and legacy bash environments for unsafe execution paths.
//! Detects common CGI misconfigurations that lead to command execution.

use crate::checks::Check;
use crate::findings::Finding;
use crate::http::{Request, Response, Method};
use std::collections::HashMap;

/// Maximum CGI paths to probe (bounded)
const MAX_CGI_PATHS: usize = 30;

/// Common CGI script locations
const CGI_PATHS: &[&str] = &[
    "/cgi-bin/test-cgi",
    "/cgi-bin/printenv",
    "/cgi-bin/php",
    "/cgi-bin/php.cgi",
    "/cgi-bin/php5",
    "/cgi-bin/php-cgi",
    "/cgi-bin/awstats.pl",
    "/cgi-bin/awstats",
    "/cgi-bin/calendar",
    "/cgi-bin/count.cgi",
    "/cgi-bin/formmail",
    "/cgi-bin/formmail.pl",
    "/cgi-bin/handler",
    "/cgi-bin/index.cgi",
    "/cgi-bin/login",
    "/cgi-bin/mail",
    "/cgi-bin/mj_wwwusr",
    "/cgi-bin/nph-test-cgi",
    "/cgi-bin/pass",
    "/cgi-bin/passwd",
    "/cgi-bin/perl",
    "/cgi-bin/perl.cgi",
    "/cgi-bin/python",
    "/cgi-bin/search",
    "/cgi-bin/status",
    "/cgi-bin/test",
    "/cgi-bin/webmail",
];

/// Payloads to test CGI execution
const CGI_PAYLOADS: &[&str] = &[
    "?cmd=id",
    "?&id",
    "?.id",
    "/id",
    "/etc/passwd",
];

pub struct CgiCheck {
    cgi_paths: Vec<String>,
}

impl CgiCheck {
    pub fn new() -> Self {
        let mut paths = Vec::with_capacity(MAX_CGI_PATHS);
        
        for path in CGI_PATHS.iter() {
            paths.push(path.to_string());
            
            // Add variants with different extensions
            if !path.ends_with(".pl") && !path.ends_with(".cgi") {
                paths.push(format!("{}.pl", path));
                paths.push(format!("{}.cgi", path));
            }
        }
        
        Self { cgi_paths: paths }
    }
    
    /// Test a specific CGI path
    fn test_cgi_path(&self, base_url: &str, path: &str) -> Option<Finding> {
        for payload in CGI_PAYLOADS.iter() {
            let test_url = format!("{}{}{}", base_url, path, payload);
            
            let mut req = Request::new(&test_url, Method::GET);
            req.set_header("Accept", "*/*");
            
            match req.send_with_timeout(5000) {
                Ok(response) => {
                    if self.detect_cgi_vulnerability(&response, path) {
                        return Some(Finding::new(
                            "CGI_COMMAND_EXECUTION",
                            &format!("CGI script at '{}' allows command execution", path),
                            &test_url,
                            9,
                        )
                        .with_payload(payload)
                        .with_evidence(self.extract_evidence(&response))
                        .with_remediation(
                            "Remove or disable unnecessary CGI scripts. \
                             Update CGI scripts to validate all input. \
                             Use mod_security or similar WAF rules."
                        ));
                    }
                }
                Err(_) => continue,
            }
        }
        None
    }
    
    /// Detect CGI vulnerability based on response
    fn detect_cgi_vulnerability(&self, response: &Response, path: &str) -> bool {
        let body = response.body_slice();
        
        // Check for command output patterns
        let indicators = [
            b"uid=",
            b"gid=",
            b"groups=",
            b"root:",
            b"user:",
            b"daemon:",
            b"/bin/",
            b"SERVER_",
            b"HTTP_",
            b"GATEWAY_",
        ];
        
        let mut matches = 0;
        for indicator in indicators.iter() {
            if body.contains(indicator) {
                matches += 1;
            }
        }
        
        // If multiple indicators found, likely vulnerable
        if matches >= 2 {
            return true;
        }
        
        // Check for printenv-style output
        if path.contains("printenv") && body.contains(b"=") {
            let lines: Vec<&[u8]> = body.split(|&b| b == b'\n').collect();
            let env_lines = lines.iter()
                .filter(|l| l.contains(&b'='))
                .count();
            
            if env_lines >= 5 {
                return true;
            }
        }
        
        false
    }
    
    /// Extract evidence from response
    fn extract_evidence(&self, response: &Response) -> String {
        let body = response.body_slice();
        
        // Get first few lines as evidence
        let lines: Vec<&[u8]> = body.split(|&b| b == b'\n').take(3).collect();
        
        let mut evidence = String::with_capacity(200);
        for line in lines {
            if line.len() < 100 {
                evidence.push_str(&String::from_utf8_lossy(line));
                evidence.push('\n');
            }
        }
        
        evidence
    }
}

impl Check for CgiCheck {
    fn name(&self) -> &'static str {
        "CgiVulnerability"
    }
    
    fn run(&self, request: &Request) -> Vec<Finding> {
        let mut findings = Vec::new();
        let base_url = request.base_url();
        
        // Test each CGI path
        for path in self.cgi_paths.iter() {
            if let Some(finding) = self.test_cgi_path(&base_url, path) {
                findings.push(finding);
                break; // One finding per scan
            }
        }
        
        findings
    }
    
    fn metadata(&self) -> HashMap<&'static str, &'static str> {
        let mut meta = HashMap::new();
        meta.insert("type", "cgi_vulnerability");
        meta.insert("severity", "high");
        meta.insert("cwe", "CWE-78,CWE-117");
        meta.insert("category", "legacy");
        meta
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cgi_path_bounds() {
        let check = CgiCheck::new();
        assert!(check.cgi_paths.len() <= MAX_CGI_PATHS * 3);
    }
    
    #[test]
    fn test_common_paths_included() {
        let check = CgiCheck::new();
        assert!(check.cgi_paths.iter().any(|p| p.contains("printenv")));
        assert!(check.cgi_paths.iter().any(|p| p.contains("test-cgi")));
    }
}
