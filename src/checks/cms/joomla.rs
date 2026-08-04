//! Joomla CMS Exploitation Module
//! Parses core request parameters for structural flaw signatures and remote object instantiation.

use crate::http::client::HttpClient;
use crate::findings::evidence::Evidence;

/// Maximum number of Joomla paths to probe (bounded)
const MAX_JOOMLA_PATHS: usize = 100;

/// Joomla signature paths
const JOOMLA_SIGNATURE_PATHS: &[&str] = &[
    "/administrator/",
    "/components/",
    "/modules/",
    "/plugins/",
    "/templates/",
    "/media/",
];

/// Known Joomla vulnerability vectors
struct JoomlaVector {
    name: &'static str,
    cve: &'static str,
    path: &'static str,
    params: &'static str,
    match_string: &'static str,
    severity: &'static str,
}

const JOOMLA_VECTORS: &[JoomlaVector] = &[
    // CVE-2015-8562 - Remote Code Execution
    JoomlaVector {
        name: "Joomla RCE CVE-2015-8562",
        cve: "CVE-2015-8562",
        path: "/",
        params: "__debug=a",
        match_string: "JResponseJson",
        severity: "Critical",
    },
    // CVE-2017-8917 - SQL Injection
    JoomlaVector {
        name: "Joomla SQLi CVE-2017-8917",
        cve: "CVE-2017-8917",
        path: "/index.php?option=com_fields&view=fields",
        params: "layout=modal&list[fullordering]=extractvalue(0x0a,concat(0x0a,(select md5(1))))",
        match_string: "",
        severity: "Critical",
    },
    // CVE-2019-3811 - Core RCE
    JoomlaVector {
        name: "Joomla Core RCE CVE-2019-3811",
        cve: "CVE-2019-3811",
        path: "/index.php",
        params: "option=com_users",
        match_string: "",
        severity: "High",
    },
];

/// Joomla scanner struct
pub struct JoomlaScanner {
    client: HttpClient,
}

impl JoomlaScanner {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Check if target is Joomla
    pub async fn is_joomla(&self, base_url: &str) -> bool {
        let base = base_url.trim_end_matches('/');
        
        // Check signature paths
        for path in JOOMLA_SIGNATURE_PATHS {
            let url = format!("{}{}", base, path);
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status() == 200 || response.status() == 403 {
                    return true;
                }
            }
        }
        
        // Check for Joomla-specific headers and content
        let url = base.to_string();
        if let Ok(response) = self.client.get(&url).send().await {
            // Check X-Generator header
            if let Some(generator) = response.headers().get("X-Generator") {
                if generator.contains("Joomla") {
                    return true;
                }
            }
            
            // Check body content
            if let Ok(body) = response.text().await {
                if body.contains("Joomla!") 
                    || body.contains("com_content") 
                    || body.contains("joomla")
                    || body.contains("/media/jui/")
                    || body.contains("/media/system/") {
                    return true;
                }
            }
        }
        
        false
    }

    /// Enumerate Joomla version
    pub async fn enumerate_version(&self, base_url: &str) -> Option<String> {
        let paths = [
            "/administrator/components/com_joomlaupdate/joomlaupdate.xml",
            "/administrator/manifests/files/joomla.xml",
            "/language/en-GB/en-GB.xml",
            "/README.txt",
        ];
        
        let base = base_url.trim_end_matches('/');
        
        for path in paths.iter().take(MAX_JOOMLA_PATHS) {
            let url = format!("{}{}", base, path);
            
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status() == 200 {
                    if let Ok(body) = response.text().await {
                        // Parse version from XML manifest
                        if let Some(start) = body.find("<version>") {
                            if let Some(end) = body[start..].find("</version>") {
                                return Some(body[start + 9..start + end].to_string());
                            }
                        }
                        
                        // Parse from README.txt
                        if body.contains("Joomla!") && body.contains("version") {
                            for line in body.lines() {
                                if line.contains("Joomla!") && line.contains("version") {
                                    if let Some(start) = line.find("version") {
                                        let rest = &line[start + 7..];
                                        if let Some(end) = rest.find(|c: char| !char::is_alphanumeric() && c != '.' && c != ' ') {
                                            return Some(rest[..end].trim().to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        None
    }

    /// Test for known Joomla vulnerabilities (non-destructive)
    pub async fn test_vulnerabilities(&self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        let base = base_url.trim_end_matches('/');
        
        for vector in JOOMLA_VECTORS {
            let url = if vector.params.is_empty() {
                format!("{}{}", base, vector.path)
            } else {
                format!("{}{}?{}", base, vector.path, vector.params)
            };
            
            // Non-destructive probe - check endpoint behavior
            if let Ok(response) = self.client.get(&url).send().await {
                let status = response.status();
                
                // Analyze response for vulnerability indicators
                if status == 200 || status == 500 || status == 403 {
                    if let Ok(body) = response.text().await {
                        // Check for specific vulnerability markers
                        if !vector.match_string.is_empty() && body.contains(vector.match_string) {
                            evidences.push(Evidence::PotentialRce {
                                cms: "Joomla".to_string(),
                                vector: vector.name.to_string(),
                                cve: vector.cve.to_string(),
                                url: url.clone(),
                                severity: vector.severity.to_string(),
                                confidence: 70,
                                remediation: format!(
                                    "Patch Joomla immediately. {} affects unpatched installations.",
                                    vector.cve
                                ),
                            });
                        } else if status == 200 && vector.match_string.is_empty() {
                            // Endpoint accessible - flag for manual review
                            evidences.push(Evidence::SuspiciousEndpoint {
                                cms: "Joomla".to_string(),
                                endpoint: url.clone(),
                                description: format!("Potentially vulnerable endpoint ({})", vector.cve),
                                confidence: 40,
                                remediation: "Verify endpoint security and apply latest patches.".to_string(),
                            });
                        }
                    }
                }
            }
        }
        
        evidences
    }

    /// Full Joomla scan
    pub async fn scan(&self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        
        if !self.is_joomla(base_url).await {
            return evidences;
        }

        // Version detection
        if let Some(version) = self.enumerate_version(base_url).await {
            evidences.push(Evidence::CmsVersion {
                cms: "Joomla".to_string(),
                version: version.clone(),
                url: base_url.to_string(),
                confidence: 90,
                remediation: "Keep Joomla core and extensions updated.".to_string(),
            });
        }

        // Vulnerability testing
        let vuln_evidences = self.test_vulnerabilities(base_url).await;
        evidences.extend(vuln_evidences);

        evidences
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let client = HttpClient::new();
        let _scanner = JoomlaScanner::new(client);
    }
}
