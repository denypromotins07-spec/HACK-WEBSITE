//! NoSQL Syntax Injection Detection
//! Detects syntax-based MongoDB and CouchDB injection using quote, brace, and comment probes.
//! Maintains bounded memory usage with zero-copy payload templates.

use crate::checks::CheckResult;
use crate::findings::Evidence;
use std::borrow::Cow;

/// Safe syntax probes for NoSQL injection detection
pub struct SyntaxProbes {
    /// Bounded queue of probe results
    results: Vec<Cow<'static, str>>,
    max_probes: usize,
}

impl SyntaxProbes {
    pub fn new(max_probes: usize) -> Self {
        Self {
            results: Vec::with_capacity(max_probes.min(1024)),
            max_probes: max_probes.min(1024),
        }
    }

    /// Generate quote-based syntax probes
    pub fn quote_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "'", "\"", "\\\"", "\\'", 
            "' || '", "\" || \"",
            "' + '", "\" + \"",
        ].into_iter()
    }

    /// Generate brace-based probes for JSON/NoSQL structure manipulation
    pub fn brace_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "{}", "{\"a\":1}", "{\"$ne\":null}",
            "[]", "[1]", "{\"$in\":[1]}",
            "{{}}", "{}}", "{{}",
        ].into_iter()
    }

    /// Generate comment-based probes for NoSQL comment injection
    pub fn comment_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "//", "/*", "*/", "#",
            "' //", "\" //",
            "' /*", "\" /*",
        ].into_iter()
    }

    /// Analyze response for syntax injection indicators
    pub fn analyze_response(&mut self, original: &str, mutated: &str, param: &str) -> Option<CheckResult> {
        if self.results.len() >= self.max_probes {
            return None;
        }

        // Detect structural changes indicating successful injection
        let structural_delta = self.detect_structural_change(original, mutated);
        
        if structural_delta > 0.3 {
            let evidence = Evidence::new()
                .with_parameter(param.to_string())
                .with_evidence_type("nosql_syntax")
                .with_original(Cow::Borrowed(original))
                .with_mutated(Cow::Borrowed(mutated))
                .with_confidence(0.7);

            self.results.push(Cow::Owned(format!("Syntax delta: {}", structural_delta)));
            
            return Some(CheckResult {
                vulnerability: "NoSQL Syntax Injection".to_string(),
                severity: "High".to_string(),
                evidence,
                remediation: "Use parameterized queries and input validation. Avoid direct string concatenation in NoSQL queries.".to_string(),
            });
        }
        None
    }

    /// Detect structural changes in response indicating injection success
    fn detect_structural_change(&self, original: &str, mutated: &str) -> f64 {
        // Simple structural change detection based on length and token differences
        let orig_len = original.len() as f64;
        let mut_len = mutated.len() as f64;
        
        if orig_len == 0.0 {
            return if mut_len > 0.0 { 1.0 } else { 0.0 };
        }

        let len_ratio = (orig_len - mut_len).abs() / orig_len;
        
        // Check for JSON structure indicators
        let orig_braces = original.matches('{').count() + original.matches('}').count();
        let mut_braces = mutated.matches('{').count() + mutated.matches('}').count();
        
        let brace_delta = if orig_braces == 0 {
            if mut_braces > 0 { 0.5 } else { 0.0 }
        } else {
            (orig_braces as i32 - mut_braces as i32).abs() as f64 / orig_braces as f64
        };

        (len_ratio * 0.4 + brace_delta * 0.6).min(1.0)
    }

    /// Clear results for memory management
    pub fn clear(&mut self) {
        self.results.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quote_probes() {
        let probes = SyntaxProbes::new(100);
        let quote_count: usize = probes.quote_probes().count();
        assert_eq!(quote_count, 10);
    }

    #[test]
    fn test_brace_probes() {
        let probes = SyntaxProbes::new(100);
        let brace_count: usize = probes.brace_probes().count();
        assert_eq!(brace_count, 9);
    }
}
