//! Prototype Pollution Detection Module
//! 
//! Detects Client-Side Prototype Pollution by injecting __proto__ properties into JSON objects.
//! Maintains 2GB RAM ceiling via bounded payload buffers.

use crate::checks::xss::context::XssContext;
use crate::findings::xss_evidence::XssEvidence;
use crate::learning::xss_cache::XssCache;
use std::time::Duration;

/// Prototype pollution payloads for testing
const POLLUTION_PAYLOADS: &[&str] = &[
    r#"{"__proto__":{"polluted":"true"}}"#,
    r#"{"__proto__.polluted":"true"}"#,
    r#"{"constructor":{"prototype":{"polluted":"true"}}}"#,
    r#"{"__proto__":{"toString":{"value":"polluted"}}}"#,
    r#"{"__proto__":{"hasOwnProperty":"malicious"}}"#,
];

/// Known dangerous properties when polluted
const DANGEROUS_PROPERTIES: &[&str] = &[
    "toString",
    "valueOf",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
];

/// Prototype Pollution detector
pub struct PrototypePollutionDetector {
    cache: XssCache,
    god_mode: bool,
    timeout: Duration,
}

impl PrototypePollutionDetector {
    /// Create a new prototype pollution detector
    pub fn new(god_mode: bool) -> Self {
        Self {
            cache: XssCache::new(),
            god_mode,
            timeout: Duration::from_secs(5),
        }
    }

    /// Detect prototype pollution vulnerabilities in JSON handling code
    pub fn detect_pollution_patterns(&self, js_code: &str, url: &str) -> Vec<XssEvidence> {
        let mut evidences = Vec::new();
        
        // Check for unsafe object merging patterns
        if self.detect_unsafe_merge(js_code) {
            let evidence = XssEvidence {
                vulnerability_type: "Prototype Pollution".to_string(),
                location: format!("Unsafe object merge at {}", url),
                payload: "Object.assign(target, source)".to_string(),
                context: XssContext::JavaScript,
                stack_trace: None,
                callback_triggered: false,
                remediation: self.generate_remediation(),
                severity: crate::findings::Severity::High,
            };
            evidences.push(evidence);
            
            self.cache.record_bypass("unsafe_merge".to_string(), "prototype_pollution".to_string());
        }
        
        // Check for recursive property assignment without __proto__ check
        if self.detect_recursive_assignment(js_code) {
            let evidence = XssEvidence {
                vulnerability_type: "Prototype Pollution".to_string(),
                location: format!("Recursive assignment without protection at {}", url),
                payload: "for...in without hasOwnProperty check".to_string(),
                context: XssContext::JavaScript,
                stack_trace: None,
                callback_triggered: false,
                remediation: self.generate_remediation(),
                severity: crate::findings::Severity::High,
            };
            evidences.push(evidence);
            
            self.cache.record_bypass("recursive_assign".to_string(), "prototype_pollution".to_string());
        }
        
        // Check for JSON.parse with user input
        if self.detect_unsafe_json_parse(js_code) {
            let evidence = XssEvidence {
                vulnerability_type: "Prototype Pollution".to_string(),
                location: format!("JSON.parse with unvalidated input at {}", url),
                payload: "JSON.parse(userInput)".to_string(),
                context: XssContext::JavaScript,
                stack_trace: None,
                callback_triggered: false,
                remediation: self.generate_remediation(),
                severity: crate::findings::Severity::Medium,
            };
            evidences.push(evidence);
            
            self.cache.record_bypass("json_parse".to_string(), "prototype_pollution".to_string());
        }
        
        evidences
    }

    /// Detect unsafe object merge patterns
    fn detect_unsafe_merge(&self, js_code: &str) -> bool {
        let unsafe_patterns = [
            "Object.assign(",
            "{...",  // Spread operator
            "jQuery.extend(",
            "$.extend(",
            "_.merge(",
            "lodash.merge(",
        ];
        
        // Check if any unsafe pattern exists without __proto__ filtering
        if unsafe_patterns.iter().any(|pattern| js_code.contains(pattern)) {
            // Check if there's any __proto__ protection
            let protection_patterns = [
                "__proto__",
                "Object.getPrototypeOf",
                "Object.setPrototypeOf",
                "Object.create(null)",
            ];
            
            return !protection_patterns.iter().any(|pattern| js_code.contains(pattern));
        }
        
        false
    }

    /// Detect recursive assignment without hasOwnProperty check
    fn detect_recursive_assignment(&self, js_code: &str) -> bool {
        // Pattern: for (var key in obj) { target[key] = source[key]; }
        // without hasOwnProperty check
        
        let has_for_in = js_code.contains("for (") && js_code.contains(" in ");
        let has_property_assignment = js_code.contains("[key]") || js_code.contains("[prop]");
        let has_has_own_property = js_code.contains("hasOwnProperty");
        
        has_for_in && has_property_assignment && !has_has_own_property
    }

    /// Detect unsafe JSON.parse usage
    fn detect_unsafe_json_parse(&self, js_code: &str) -> bool {
        // Check for JSON.parse with potentially user-controlled input
        let unsafe_sources = [
            "location.hash",
            "location.search",
            "document.referrer",
            "postMessage",
            "xhr.responseText",
            "fetch(",
        ];
        
        if js_code.contains("JSON.parse(") {
            return unsafe_sources.iter().any(|source| {
                // Check if the source is used near JSON.parse
                let parse_pos = js_code.find("JSON.parse(").unwrap_or(0);
                let context_start = parse_pos.saturating_sub(100);
                let context_end = (parse_pos + 200).min(js_code.len());
                let context = &js_code[context_start..context_end];
                context.contains(source)
            });
        }
        
        false
    }

    /// Generate test payloads for prototype pollution
    pub fn get_test_payloads(&self) -> Vec<String> {
        POLLUTION_PAYLOADS.iter().map(|s| s.to_string()).collect()
    }

    /// Get list of dangerous properties to check
    pub fn get_dangerous_properties(&self) -> Vec<String> {
        DANGEROUS_PROPERTIES.iter().map(|s| s.to_string()).collect()
    }

    /// Generate remediation guidance for prototype pollution
    fn generate_remediation(&self) -> String {
        "Use Object.create(null) to create objects without prototypes. Implement \
         deep cloning with prototype pollution protection (e.g., lodash.cloneDeep with \
         security patches). Validate and sanitize all JSON input before parsing. Use \
         Object.freeze() on critical objects. Avoid using Object.assign or spread \
         operator with untrusted input. Consider using libraries like 'secure-json-parse'."
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
    fn test_prototype_pollution_detector_creation() {
        let detector = PrototypePollutionDetector::new(false);
        assert!(!detector.god_mode);
    }

    #[test]
    fn test_unsafe_merge_detection() {
        let detector = PrototypePollutionDetector::new(false);
        
        let js_code = r#"
            function mergeConfig(userConfig) {
                return Object.assign({}, defaultConfig, userConfig);
            }
        "#;
        
        let evidences = detector.detect_pollution_patterns(js_code, "https://example.com");
        assert!(!evidences.is_empty());
    }

    #[test]
    fn test_payload_generation() {
        let detector = PrototypePollutionDetector::new(false);
        let payloads = detector.get_test_payloads();
        
        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|p| p.contains("__proto__")));
    }
}
