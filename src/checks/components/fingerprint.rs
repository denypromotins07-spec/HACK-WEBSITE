//! Component and Framework Fingerprinting
//! Detects JS frameworks, libraries, and backend versions via zero-copy header/body regex.

use crate::http::response::HttpResponse;
use crate::findings::evidence::Evidence;
use std::borrow::Cow;

/// Maximum number of fingerprint patterns to store in bounded cache
const MAX_FINGERPRINT_PATTERNS: usize = 500;

/// Zero-copy fingerprint pattern matcher
pub struct FingerprintDetector {
    patterns: Vec<FingerprintPattern>,
}

struct FingerprintPattern {
    name: &'static str,
    regex: &'static str,
    version_group: usize,
    confidence: u8,
}

impl FingerprintDetector {
    pub fn new() -> Self {
        let patterns = vec![
            // JavaScript Frameworks
            FingerprintPattern {
                name: "React",
                regex: r#"react(?:\.min)?\.js(?:\?ver=([0-9.]+))?"#,
                version_group: 1,
                confidence: 90,
            },
            FingerprintPattern {
                name: "Vue.js",
                regex: r#"vue(?:\.min)?\.js(?:\?ver=([0-9.]+))?"#,
                version_group: 1,
                confidence: 90,
            },
            FingerprintPattern {
                name: "Angular",
                regex: r#"angular(?:\.min)?\.js(?:\?ver=([0-9.]+))?"#,
                version_group: 1,
                confidence: 90,
            },
            FingerprintPattern {
                name: "jQuery",
                regex: r#"jquery(?:\.min)?\.js(?:\?ver=([0-9.]+))?"#,
                version_group: 1,
                confidence: 95,
            },
            FingerprintPattern {
                name: "Bootstrap",
                regex: r#"bootstrap(?:\.min)?\.(?:css|js)(?:\?ver=([0-9.]+))?"#,
                version_group: 1,
                confidence: 85,
            },
            // Backend Frameworks
            FingerprintPattern {
                name: "Django",
                regex: r#"csrftoken|django_language|#django-form"#,
                version_group: 0,
                confidence: 80,
            },
            FingerprintPattern {
                name: "Ruby on Rails",
                regex: r#"_rails_|authenticity_token|application/ruby"#,
                version_group: 0,
                confidence: 85,
            },
            FingerprintPattern {
                name: "Laravel",
                name: "Laravel",
                regex: r#"XSRF-TOKEN|laravel_session"#,
                version_group: 0,
                confidence: 85,
            },
            FingerprintPattern {
                name: "Express.js",
                regex: r#"X-Powered-By:\s*Express"#,
                version_group: 0,
                confidence: 90,
            },
            FingerprintPattern {
                name: "ASP.NET",
                regex: r#"X-AspNet-Version|__VIEWSTATE|#aspx"#,
                version_group: 0,
                confidence: 90,
            },
            FingerprintPattern {
                name: "Spring Boot",
                regex: r#"Whitelabel Error Page|x-application-context"#,
                version_group: 0,
                confidence: 85,
            },
        ];
        
        // Bounded pattern storage
        let mut bounded_patterns = Vec::with_capacity(MAX_FINGERPRINT_PATTERNS.min(patterns.len()));
        bounded_patterns.extend(patterns.into_iter().take(MAX_FINGERPRINT_PATTERNS));
        
        Self {
            patterns: bounded_patterns,
        }
    }

    /// Scan HTTP response for framework fingerprints using zero-copy operations
    pub fn scan<'a>(&self, response: &'a HttpResponse) -> Vec<Cow<'a, str>> {
        let mut findings = Vec::new();
        let body_slice = response.body_as_slice();
        let headers_slice = response.headers_as_slice();
        
        for pattern in &self.patterns {
            if let Ok(re) = regex::Regex::new(pattern.regex) {
                // Check headers first (faster)
                if let Some(caps) = re.captures_iter(std::str::from_utf8_lossy(headers_slice).as_ref()).next() {
                    let version = caps.get(pattern.version_group)
                        .map(|m| m.as_str())
                        .unwrap_or("unknown");
                    findings.push(Cow::Owned(format!("{} ({})", pattern.name, version)));
                    continue;
                }
                
                // Check body
                if let Some(caps) = re.captures_iter(std::str::from_utf8_lossy(body_slice).as_ref()).next() {
                    let version = caps.get(pattern.version_group)
                        .map(|m| m.as_str())
                        .unwrap_or("unknown");
                    findings.push(Cow::Owned(format!("{} ({})", pattern.name, version)));
                }
            }
        }
        
        findings
    }

    /// Generate evidence from fingerprint scan
    pub fn generate_evidence(&self, response: &HttpResponse, url: &str) -> Option<Evidence> {
        let findings = self.scan(response);
        if findings.is_empty() {
            return None;
        }

        Some(Evidence::ComponentFingerprint {
            url: url.to_string(),
            components: findings.iter().map(|c| c.to_string()).collect(),
            confidence: 85,
            remediation: "Consider hiding framework signatures in production. Keep all components updated.".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_detection() {
        let detector = FingerprintDetector::new();
        assert!(!detector.patterns.is_empty());
    }
}
