//! Mutation XSS (MXSS) Detection Module
//! 
//! Detects Mutation XSS (MXSS) by crafting payloads that transform after browser DOM parsing.
//! Maintains 2GB RAM ceiling via bounded payload buffers.

use crate::checks::xss::context::XssContext;
use crate::findings::xss_evidence::XssEvidence;
use crate::learning::xss_cache::XssCache;
use std::time::Duration;

/// MXSS payloads that mutate during DOM parsing
const MXSS_PAYLOADS: &[&str] = &[
    // SVG mutation payloads
    "<svg><style><img src=x onerror=alert(1)>",
    // MathML mutation
    "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    // Nested tag mutation
    "<!--><script>alert(1)</script>-->",
    // CDATA mutation
    "<![CDATA[><script>alert(1)</script>]]>",
    // Namespace mutation
    "<svg><![CDATA[><g xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=javascript:alert(1)><rect/>",
];

/// MXSS detector
pub struct MxssDetector {
    cache: XssCache,
    god_mode: bool,
    timeout: Duration,
}

impl MxssDetector {
    /// Create a new MXSS detector
    pub fn new(god_mode: bool) -> Self {
        Self {
            cache: XssCache::new(),
            god_mode,
            timeout: Duration::from_secs(5),
        }
    }

    /// Detect potential MXSS vulnerabilities in HTML handling code
    pub fn detect_mxss_patterns(&self, html_content: &str, url: &str) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        // Check for dangerous element combinations that can cause mutations
        if self.detect_svg_mutation_risk(html_content) {
            let evidence = XssEvidence {
                vulnerability_type: "Mutation XSS".to_string(),
                location: format!("SVG mutation risk at {}", url),
                payload: "<svg> with nested unsafe content".to_string(),
                context: XssContext::Html,
                stack_trace: None,
                callback_triggered: false,
                remediation: self.generate_remediation(),
                severity: crate::findings::Severity::High,
            };
            evidences.push(evidence);
            
            self.cache.record_bypass(url.to_string(), "mxss_svg".to_string());
        }
        
        if self.detect_mathml_mutation_risk(html_content) {
            let evidence = XssEvidence {
                vulnerability_type: "Mutation XSS".to_string(),
                location: format!("MathML mutation risk at {}", url),
                payload: "<math> with nested unsafe content".to_string(),
                context: XssContext::Html,
                stack_trace: None,
                callback_triggered: false,
                remediation: self.generate_remediation(),
                severity: crate::findings::Severity::High,
            };
            evidences.push(evidence);
            
            self.cache.record_bypass(url.to_string(), "mxss_mathml".to_string());
        }
        
        if self.detect_comment_mutation_risk(html_content) {
            let evidence = XssEvidence {
                vulnerability_type: "Mutation XSS".to_string(),
                location: format!("Comment-based mutation risk at {}", url),
                payload: "<!--> comment bypass pattern".to_string(),
                context: XssContext::Html,
                stack_trace: None,
                callback_triggered: false,
                remediation: self.generate_remediation(),
                severity: crate::findings::Severity::High,
            };
            evidences.push(evidence);
            
            self.cache.record_bypass(url.to_string(), "mxss_comment".to_string());
        }
        
        evidences
    }

    /// Detect SVG-based mutation risks
    fn detect_svg_mutation_risk(&self, html_content: &str) -> bool {
        // Look for SVG elements with potentially mutable content
        if !html_content.contains("<svg") {
            return false;
        }
        
        // Check for dangerous patterns inside SVG
        let dangerous_svg_patterns = [
            "<svg><style>",
            "<svg><foreignobject>",
            "<svg><desc>",
            "<svg><title>",
            "<svg><![CDATA[",
        ];
        
        dangerous_svg_patterns.iter().any(|pattern| html_content.contains(pattern))
    }

    /// Detect MathML-based mutation risks
    fn detect_mathml_mutation_risk(&self, html_content: &str) -> bool {
        if !html_content.contains("<math") {
            return false;
        }
        
        // Check for mtext table trick pattern
        let mathml_patterns = [
            "<math><mtext><table>",
            "<math><mtext><mglyph>",
            "<math><annotation>",
        ];
        
        mathml_patterns.iter().any(|pattern| html_content.contains(pattern))
    }

    /// Detect comment-based mutation risks
    fn detect_comment_mutation_risk(&self, html_content: &str) -> bool {
        // Look for unusual comment patterns that browsers might parse differently
        let comment_patterns = [
            "<!-->",
            "<!-->",
            "<!--<![CDATA[",
            "<!---->",
        ];
        
        comment_patterns.iter().any(|pattern| html_content.contains(pattern))
    }

    /// Get test payloads for MXSS testing
    pub fn get_test_payloads(&self) -> Vec<String> {
        MXSS_PAYLOADS.iter().map(|s| s.to_string()).collect()
    }

    /// Simulate browser mutation (simplified)
    pub fn simulate_mutation(&self, payload: &str) -> String {
        // This is a simplified simulation - real mutation requires browser engine
        // In production, this would use a headless browser
        
        let mutated = payload
            .replace("<!-->", "")
            .replace("<!---->", "")
            .to_string();
        
        mutated
    }

    /// Generate remediation guidance for MXSS
    fn generate_remediation(&self) -> String {
        "Avoid using innerHTML or document.write with user-controlled input containing \
         SVG, MathML, or unusual comment structures. Use textContent for inserting \
         untrusted data. Implement strict Content Security Policy (CSP). Use a robust \
         HTML sanitizer like DOMPurify that handles browser-specific mutation behaviors. \
         Test payloads across multiple browsers as mutation behavior varies."
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
    fn test_mxss_detector_creation() {
        let detector = MxssDetector::new(false);
        assert!(!detector.god_mode);
    }

    #[test]
    fn test_payload_generation() {
        let detector = MxssDetector::new(false);
        let payloads = detector.get_test_payloads();
        
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("svg")));
    }

    #[test]
    fn test_svg_mutation_detection() {
        let detector = MxssDetector::new(false);
        
        let html = r#"<svg><style><img src=x onerror=alert(1)>"#;
        let evidences = detector.detect_mxss_patterns(html, "https://example.com");
        
        assert!(!evidences.is_empty());
    }

    #[test]
    fn test_mutation_simulation() {
        let detector = MxssDetector::new(false);
        
        let original = "<!-->test";
        let mutated = detector.simulate_mutation(original);
        
        assert_eq!(mutated, "test");
    }
}
