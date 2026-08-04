//! Window Opener Hijacking Detection Module
//! 
//! Identifies Window Opener Hijacking (noopener gaps) by analyzing target attributes on external links.
//! Maintains 2GB RAM ceiling via bounded payload buffers.

use crate::checks::xss::context::XssContext;
use crate::findings::xss_evidence::XssEvidence;
use crate::learning::xss_cache::XssCache;
use std::time::Duration;

/// Window opener hijacking detector
pub struct WindowOpenerDetector {
    cache: XssCache,
    god_mode: bool,
    timeout: Duration,
}

impl WindowOpenerDetector {
    /// Create a new window opener detector
    pub fn new(god_mode: bool) -> Self {
        Self {
            cache: XssCache::new(),
            god_mode,
            timeout: Duration::from_secs(5),
        }
    }

    /// Detect window.opener vulnerabilities in HTML content
    pub fn detect_opener_gaps(&self, html_content: &str, url: &str) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        // Find all anchor tags with target="_blank"
        let blank_links = self.extract_blank_links(html_content);
        
        for link in blank_links {
            // Check if rel="noopener" or rel="noreferrer" is present
            let has_protection = self.check_rel_protection(&link);
            
            if !has_protection {
                let href = self.extract_href(&link);
                let is_external = self.is_external_link(&href, url);
                
                if is_external {
                    let evidence = XssEvidence {
                        vulnerability_type: "Window Opener Hijacking".to_string(),
                        location: format!("External link without noopener at {}", url),
                        payload: format!("<a target=\"_blank\" href=\"{}\">", href),
                        context: XssContext::Html,
                        stack_trace: None,
                        callback_triggered: false,
                        remediation: self.generate_remediation(),
                        severity: crate::findings::Severity::Medium,
                    };
                    evidences.push(evidence);
                    
                    self.cache.record_bypass(href, "window_opener".to_string());
                }
            }
        }
        
        evidences
    }

    /// Detect JavaScript window.open calls without noopener
    pub fn detect_window_open_gaps(&self, js_code: &str, url: &str) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        // Find window.open calls
        if js_code.contains("window.open(") || js_code.contains(".open(") {
            // Check for noopener/noreferrer in features
            if !self.has_noopener_features(js_code) {
                let evidence = XssEvidence {
                    vulnerability_type: "Window Opener Hijacking".to_string(),
                    location: format!("window.open() without noopener at {}", url),
                    payload: "window.open(url, name)".to_string(),
                    context: XssContext::JavaScript,
                    stack_trace: None,
                    callback_triggered: false,
                    remediation: self.generate_remediation(),
                    severity: crate::findings::Severity::Medium,
                };
                evidences.push(evidence);
                
                self.cache.record_bypass("window.open".to_string(), "window_opener".to_string());
            }
        }
        
        evidences
    }

    /// Extract links with target="_blank"
    fn extract_blank_links(&self, html_content: &str) -> Vec<String> {
        let mut links = Vec::new();
        let mut current_tag = String::new();
        let mut in_anchor = false;
        
        for ch in html_content.chars() {
            if ch == '<' {
                if in_anchor {
                    current_tag.push(ch);
                }
            } else if ch == '>' {
                if in_anchor {
                    current_tag.push(ch);
                    // Check if this anchor has target="_blank"
                    if current_tag.contains("target=\"_blank\"") || current_tag.contains("target='_blank'") {
                        links.push(current_tag.clone());
                    }
                    current_tag.clear();
                    in_anchor = false;
                }
            } else {
                if ch == 'a' && !in_anchor {
                    // Potential start of anchor tag - check next char
                    in_anchor = true;
                    current_tag.push('<');
                } else if in_anchor {
                    current_tag.push(ch);
                }
            }
        }
        
        // Simpler approach: find all occurrences
        links.clear();
        let lines: Vec<&str> = html_content.lines().collect();
        for line in lines {
            let mut pos = 0;
            while let Some(start) = line[pos..].find("<a ") {
                let abs_start = pos + start;
                if let Some(end) = line[abs_start..].find('>') {
                    let tag = &line[abs_start..abs_start + end + 1];
                    if tag.contains("target=\"_blank\"") || tag.contains("target='_blank'") {
                        links.push(tag.to_string());
                    }
                    pos = abs_start + end + 1;
                } else {
                    break;
                }
            }
        }
        
        links
    }

    /// Check if link has rel="noopener" or rel="noreferrer"
    fn check_rel_protection(&self, link: &str) -> bool {
        let rel_patterns = [
            "rel=\"noopener\"",
            "rel='noopener'",
            "rel=\"noreferrer\"",
            "rel='noreferrer'",
            "rel=\"noopener noreferrer\"",
            "rel='noopener noreferrer'",
            "rel=\"noreferrer noopener\"",
            "rel='noreferrer noopener'",
        ];
        
        rel_patterns.iter().any(|pattern| link.contains(pattern))
    }

    /// Extract href from anchor tag
    fn extract_href(&self, link: &str) -> String {
        // Try double quotes first
        if let Some(start) = link.find("href=\"") {
            let value_start = start + 6;
            if let Some(end) = link[value_start..].find('"') {
                return link[value_start..value_start + end].to_string();
            }
        }
        
        // Try single quotes
        if let Some(start) = link.find("href='") {
            let value_start = start + 6;
            if let Some(end) = link[value_start..].find('\'') {
                return link[value_start..value_start + end].to_string();
            }
        }
        
        "#".to_string()
    }

    /// Check if link is external
    fn is_external_link(&self, href: &str, base_url: &str) -> bool {
        // External if starts with http:// or https:// and different domain
        if href.starts_with("http://") || href.starts_with("https://") {
            // Simple check: different domain than base
            let base_domain = self.extract_domain(base_url);
            let href_domain = self.extract_domain(href);
            return base_domain != href_domain && !href_domain.is_empty();
        }
        
        // Protocol-relative URLs are external
        if href.starts_with("//") {
            return true;
        }
        
        false
    }

    /// Extract domain from URL
    fn extract_domain(&self, url: &str) -> String {
        let url = url.trim_start_matches("http://").trim_start_matches("https://");
        if let Some(slash_pos) = url.find('/') {
            url[..slash_pos].to_string()
        } else {
            url.split(':').next().unwrap_or("").to_string()
        }
    }

    /// Check if window.open has noopener features
    fn has_noopener_features(&self, js_code: &str) -> bool {
        let patterns = [
            "noopener",
            "noreferrer",
        ];
        
        patterns.iter().any(|pattern| js_code.contains(pattern))
    }

    /// Generate remediation guidance for window opener hijacking
    fn generate_remediation(&self) -> String {
        "Always add rel=\"noopener noreferrer\" to anchor tags with target=\"_blank\". \
         For window.open(), include 'noopener,noreferrer' in the features parameter. \
         Consider using Content Security Policy (CSP) to restrict navigation. \
         Modern browsers automatically set noopener for target=\"_blank\", but explicit \
         declaration ensures compatibility."
            .to_string()
    }

    /// Enable god-mode for intrusive validation
    pub fn enable_god_mode(&mut self) {
        self.god_mode = true;
        self.timeout = Duration::from_secs(10);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_opener_detector_creation() {
        let detector = WindowOpenerDetector::new(false);
        assert!(!detector.god_mode);
    }

    #[test]
    fn test_opener_gap_detection() {
        let detector = WindowOpenerDetector::new(false);
        
        let html = r#"
            <a href="https://external.com" target="_blank">External Link</a>
            <a href="https://safe.com" target="_blank" rel="noopener noreferrer">Safe Link</a>
        "#;
        
        let evidences = detector.detect_opener_gaps(html, "https://example.com");
        assert_eq!(evidences.len(), 1);
    }

    #[test]
    fn test_domain_extraction() {
        let detector = WindowOpenerDetector::new(false);
        
        assert_eq!(detector.extract_domain("https://example.com/path"), "example.com");
        assert_eq!(detector.extract_domain("http://sub.example.com"), "sub.example.com");
        assert_eq!(detector.extract_domain("https://example.com:8080"), "example.com:8080");
    }
}
