//! Drupal CMS Exploitation Module
//! Detects Drupalgeddon vectors and unauthenticated RCE entry points in legacy cores.

use crate::http::client::HttpClient;
use crate::findings::evidence::Evidence;

/// Maximum number of Drupal paths to probe (bounded)
const MAX_DRUPAL_PATHS: usize = 100;

/// Drupal signature paths
const DRUPAL_SIGNATURE_PATHS: &[&str] = &[
    "/sites/",
    "/core/",
    "/modules/",
    "/themes/",
    "/profiles/",
];

/// Drupalgeddon vulnerability signatures
struct DrupalgeddonVector {
    name: &'static str,
    cve: &'static str,
    path: &'static str,
    method: &'static str,
    payload: &'static str,
    match_string: &'static str,
    severity: &'static str,
}

const DRUPALGEDDON_VECTORS: &[DrupalgeddonVector] = &[
    // Drupalgeddon2 (CVE-2018-7600)
    DrupalgeddonVector {
        name: "Drupalgeddon2",
        cve: "CVE-2018-7600",
        path: "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
        method: "POST",
        payload: "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=print&mail[#type]=markup&mail[#markup]=DRUPALGEDDON_TEST",
        match_string: "DRUPALGEDDON_TEST",
        severity: "Critical",
    },
    // Drupalgeddon3 (CVE-2018-7602)
    DrupalgeddonVector {
        name: "Drupalgeddon3",
        cve: "CVE-2018-7602",
        path: "/admin/config/development/configuration/single/import",
        method: "POST",
        payload: "",
        match_string: "",
        severity: "High",
    },
    // Drupalgeddon4 (CVE-2019-6339)
    DrupalgeddonVector {
        name: "Drupalgeddon4",
        cve: "CVE-2019-6339",
        path: "/node/?_format=hal_json",
        method: "POST",
        payload: "",
        match_string: "",
        severity: "Critical",
    },
];

/// Drupal scanner struct
pub struct DrupalScanner {
    client: HttpClient,
}

impl DrupalScanner {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    /// Check if target is Drupal
    pub async fn is_drupal(&self, base_url: &str) -> bool {
        let base = base_url.trim_end_matches('/');
        
        // Check signature paths
        for path in DRUPAL_SIGNATURE_PATHS {
            let url = format!("{}{}", base, path);
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status() == 200 || response.status() == 403 {
                    return true;
                }
            }
        }
        
        // Check for Drupal-specific headers
        let url = base.to_string();
        if let Ok(response) = self.client.get(&url).send().await {
            if let Some(generator) = response.headers().get("X-Generator") {
                if generator.contains("Drupal") {
                    return true;
                }
            }
            
            if let Ok(body) = response.text().await {
                if body.contains("Drupal.settings") || body.contains("drupalSettings") {
                    return true;
                }
            }
        }
        
        false
    }

    /// Enumerate Drupal version
    pub async fn enumerate_version(&self, base_url: &str) -> Option<String> {
        let paths = [
            "/core/CHANGELOG.txt",
            "/CHANGELOG.txt",
            "/core/lib/Drupal.php",
        ];
        
        let base = base_url.trim_end_matches('/');
        
        for path in paths.iter().take(MAX_DRUPAL_PATHS) {
            let url = format!("{}{}", base, path);
            
            if let Ok(response) = self.client.get(&url).send().await {
                if response.status() == 200 {
                    if let Ok(body) = response.text().await {
                        // Parse version from CHANGELOG.txt
                        if let Some(line) = body.lines().find(|l| l.contains("Drupal ")) {
                            if let Some(start) = line.find("Drupal ") {
                                let version_part = &line[start + 7..];
                                if let Some(end) = version_part.find(' ') {
                                    return Some(version_part[..end].to_string());
                                }
                            }
                        }
                        
                        // Parse from Drupal.php
                        if body.contains("const VERSION") {
                            if let Some(start) = body.find("const VERSION = '") {
                                if let Some(end) = body[start..].find("';") {
                                    return Some(body[start + 17..start + end].to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        
        None
    }

    /// Test for Drupalgeddon vulnerabilities (non-destructive canary test)
    pub async fn test_drupalgeddon(&self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        let base = base_url.trim_end_matches('/');
        
        for vector in DRUPALGEDDON_VECTORS {
            let url = format!("{}{}", base, vector.path);
            
            // Non-destructive test - only check if endpoint exists and is vulnerable
            // without executing actual payloads
            if let Ok(response) = match vector.method {
                "POST" => self.client.post(&url).send().await,
                _ => self.client.get(&url).send().await,
            } {
                // Check for vulnerability indicators
                let status = response.status();
                
                // If we get specific error patterns or the endpoint accepts unusual input
                if status == 200 || status == 500 {
                    if let Ok(body) = response.text().await {
                        // Look for error patterns that indicate potential vulnerability
                        if body.contains("Access denied") || body.contains("Forbidden") {
                            continue; // Protected
                        }
                        
                        // Flag potential vulnerability for manual verification
                        evidences.push(Evidence::PotentialRce {
                            cms: "Drupal".to_string(),
                            vector: vector.name.to_string(),
                            cve: vector.cve.to_string(),
                            url: url.clone(),
                            severity: vector.severity.to_string(),
                            confidence: 60, // Lower confidence - needs manual verification
                            remediation: format!(
                                "Immediately patch Drupal core. {} affects versions prior to security update.",
                                vector.cve
                            ),
                        });
                    }
                }
            }
        }
        
        evidences
    }

    /// Full Drupal scan
    pub async fn scan(&self, base_url: &str) -> Vec<Evidence> {
        let mut evidences = Vec::new();
        
        if !self.is_drupal(base_url).await {
            return evidences;
        }

        // Version detection
        if let Some(version) = self.enumerate_version(base_url).await {
            evidences.push(Evidence::CmsVersion {
                cms: "Drupal".to_string(),
                version: version.clone(),
                url: base_url.to_string(),
                confidence: 90,
                remediation: "Keep Drupal core updated to the latest security release.".to_string(),
            });
        }

        // Drupalgeddon testing
        let dg_evidences = self.test_drupalgeddon(base_url).await;
        evidences.extend(dg_evidences);

        evidences
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let client = HttpClient::new();
        let _scanner = DrupalScanner::new(client);
    }
}
