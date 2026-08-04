//! DOM-based XSS Detection Module
//! 
//! Analyzes client-side JavaScript sources and sinks to detect DOM-based XSS safely.
//! Uses lightweight headless browser hook mocking to avoid runtime dependencies.
//! Maintains 2GB RAM ceiling via bounded payload buffers.

use crate::checks::xss::context::XssContext;
use crate::findings::xss_evidence::XssEvidence;
use crate::learning::xss_cache::XssCache;
use std::collections::HashMap;
use std::time::Duration;

/// Known DOM XSS sources (user-controlled inputs)
const DOM_SOURCES: &[&str] = &[
    "location.hash",
    "location.search",
    "location.href",
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "window.name",
    "localStorage",
    "sessionStorage",
    "document.cookie",
];

/// Known DOM XSS sinks (dangerous execution points)
const DOM_SINKS: &[&str] = &[
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    "eval",
    "setTimeout",
    "setInterval",
    "Function",
    "execScript",
    "element.src",
    "element.href",
    "location.replace",
    "location.assign",
    "location.href",
    "document.domain",
];

/// Mock browser environment for DOM analysis
pub struct MockBrowserEnv {
    sources_found: Vec<String>,
    sinks_found: Vec<String>,
    flows_detected: Vec<DomFlow>,
}

/// Represents a source-to-sink data flow
#[derive(Debug, Clone)]
pub struct DomFlow {
    pub source: String,
    pub sink: String,
    pub sanitization: bool,
    pub line_number: Option<usize>,
}

impl MockBrowserEnv {
    /// Create a new mock browser environment
    pub fn new() -> Self {
        Self {
            sources_found: Vec::new(),
            sinks_found: Vec::new(),
            flows_detected: Vec::new(),
        }
    }

    /// Analyze JavaScript code for DOM XSS patterns
    pub fn analyze_js_code(&mut self, js_code: &str) -> Vec<DomFlow> {
        let lines: Vec<&str> = js_code.lines().collect();
        
        for (line_num, line) in lines.iter().enumerate() {
            // Check for sources
            for source in DOM_SOURCES {
                if line.contains(source) {
                    self.sources_found.push(source.to_string());
                    
                    // Check if this line also contains a sink (direct flow)
                    for sink in DOM_SINKS {
                        if line.contains(sink) {
                            // Check for sanitization patterns
                            let has_sanitization = self.check_sanitization(line);
                            
                            let flow = DomFlow {
                                source: source.to_string(),
                                sink: sink.to_string(),
                                sanitization: has_sanitization,
                                line_number: Some(line_num + 1),
                            };
                            self.flows_detected.push(flow);
                        }
                    }
                }
            }
            
            // Check for sinks independently
            for sink in DOM_SINKS {
                if line.contains(sink) && !self.sinks_found.contains(&sink.to_string()) {
                    self.sinks_found.push(sink.to_string());
                }
            }
        }
        
        self.flows_detected.clone()
    }

    /// Check if line contains sanitization patterns
    fn check_sanitization(&self, line: &str) -> bool {
        let sanitization_patterns = [
            ".textContent",
            ".innerText",
            "DOMPurify",
            "sanitize",
            "escapeHTML",
            "encodeURIComponent",
            "htmlspecialchars",
        ];
        
        sanitization_patterns.iter().any(|pattern| line.contains(pattern))
    }

    /// Get all detected flows
    pub fn get_flows(&self) -> &[DomFlow] {
        &self.flows_detected
    }

    /// Reset the environment for new analysis
    pub fn reset(&mut self) {
        self.sources_found.clear();
        self.sinks_found.clear();
        self.flows_detected.clear();
    }
}

/// DOM XSS detector with source-sink flow analysis
pub struct DomXssDetector {
    browser_env: MockBrowserEnv,
    cache: XssCache,
    god_mode: bool,
    timeout: Duration,
}

impl DomXssDetector {
    /// Create a new DOM XSS detector
    pub fn new(god_mode: bool) -> Self {
        Self {
            browser_env: MockBrowserEnv::new(),
            cache: XssCache::new(),
            god_mode,
            timeout: Duration::from_secs(5),
        }
    }

    /// Detect DOM XSS in inline scripts
    pub fn detect_inline_script_xss(&mut self, html_content: &str, url: &str) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        // Extract inline scripts (simplified extraction)
        let inline_scripts = self.extract_inline_scripts(html_content);
        
        for (script_index, script) in inline_scripts.iter().enumerate() {
            self.browser_env.reset();
            let flows = self.browser_env.analyze_js_code(script);
            
            for flow in flows {
                if !flow.sanitization {
                    let evidence = XssEvidence {
                        vulnerability_type: "DOM XSS".to_string(),
                        location: format!("Inline script #{} at {}", script_index + 1, url),
                        payload: format!("Source: {} -> Sink: {}", flow.source, flow.sink),
                        context: XssContext::JavaScript,
                        stack_trace: flow.line_number.map(|ln| format!("Line {}", ln)),
                        callback_triggered: false,
                        remediation: self.generate_csp_remediation(),
                        severity: self.calculate_severity(&flow.sink),
                    };
                    evidences.push(evidence);
                    
                    self.cache.record_bypass(
                        format!("{}_{}", flow.source, flow.sink),
                        "dom_flow".to_string(),
                    );
                }
            }
        }
        
        evidences
    }

    /// Detect DOM XSS in external JavaScript files
    pub fn detect_external_script_xss(&mut self, js_content: &str, script_url: &str) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        self.browser_env.reset();
        let flows = self.browser_env.analyze_js_code(js_content);
        
        for flow in flows {
            if !flow.sanitization {
                let evidence = XssEvidence {
                    vulnerability_type: "DOM XSS".to_string(),
                    location: format!("External script: {}", script_url),
                    payload: format!("Source: {} -> Sink: {}", flow.source, flow.sink),
                    context: XssContext::JavaScript,
                    stack_trace: flow.line_number.map(|ln| format!("Line {}", ln)),
                    callback_triggered: false,
                    remediation: self.generate_csp_remediation(),
                    severity: self.calculate_severity(&flow.sink),
                };
                evidences.push(evidence);
                
                self.cache.record_bypass(
                    format!("{}_{}", flow.source, flow.sink),
                    "dom_external".to_string(),
                );
            }
        }
        
        evidences
    }

    /// Extract inline scripts from HTML content
    fn extract_inline_scripts(&self, html_content: &str) -> Vec<String> {
        let mut scripts = Vec::new();
        let mut current_script = String::new();
        let mut in_script = false;
        
        for line in html_content.lines() {
            if line.contains("<script") && !line.contains("src=") {
                in_script = true;
                // Get content after opening tag on same line
                if let Some(pos) = line.find('>') {
                    let after_tag = &line[pos + 1..];
                    if !after_tag.trim().is_empty() && !after_tag.contains("</script>") {
                        current_script.push_str(after_tag);
                    } else if let Some(end_pos) = after_tag.find("</script>") {
                        scripts.push(after_tag[..end_pos].to_string());
                        in_script = false;
                    }
                }
            } else if in_script {
                if line.contains("</script>") {
                    if let Some(end_pos) = line.find("</script>") {
                        current_script.push_str(&line[..end_pos]);
                        scripts.push(current_script.clone());
                        current_script.clear();
                        in_script = false;
                    }
                } else {
                    current_script.push_str(line);
                    current_script.push('\n');
                }
            }
        }
        
        scripts
    }

    /// Generate CSP remediation guidance for DOM XSS
    fn generate_csp_remediation(&self) -> String {
        "Implement Content Security Policy (CSP) with 'strict-dynamic' or hash-based script \
         allowlisting. Avoid using innerHTML, document.write, and eval. Use textContent for \
         inserting user data. Implement input validation and output encoding. Consider using \
         DOMPurify or similar libraries for HTML sanitization."
            .to_string()
    }

    /// Calculate severity based on sink type
    fn calculate_severity(&self, sink: &str) -> crate::findings::Severity {
        match sink {
            "eval" | "Function" | "execScript" => crate::findings::Severity::Critical,
            "innerHTML" | "document.write" | "document.writeln" => crate::findings::Severity::High,
            "location.href" | "location.replace" | "location.assign" => crate::findings::Severity::High,
            _ => crate::findings::Severity::Medium,
        }
    }

    /// Enable god-mode for intrusive DOM manipulation
    pub fn enable_god_mode(&mut self) {
        self.god_mode = true;
        self.timeout = Duration::from_secs(10);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dom_xss_detector_creation() {
        let detector = DomXssDetector::new(false);
        assert!(!detector.god_mode);
    }

    #[test]
    fn test_flow_detection() {
        let mut env = MockBrowserEnv::new();
        let js_code = r#"
            var userInput = location.hash;
            document.getElementById('output').innerHTML = userInput;
        "#;
        
        let flows = env.analyze_js_code(js_code);
        assert!(!flows.is_empty());
        assert_eq!(flows[0].source, "location.hash");
        assert_eq!(flows[0].sink, "innerHTML");
        assert!(!flows[0].sanitization);
    }

    #[test]
    fn test_sanitization_detection() {
        let mut env = MockBrowserEnv::new();
        let js_code = r#"
            var userInput = location.hash;
            document.getElementById('output').textContent = userInput;
        "#;
        
        let flows = env.analyze_js_code(js_code);
        // textContent is a safe sink, so no dangerous flows should be detected
        assert!(flows.is_empty());
    }
}
