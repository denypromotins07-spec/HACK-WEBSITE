//! Hibernate HQL Injection Detection
//! Detects Hibernate HQL injection using safe clause manipulation and error differentials.
//! Implements bounded memory usage with zero-copy evidence storage.

use crate::checks::CheckResult;
use crate::findings::Evidence;
use std::borrow::Cow;

/// Safe HQL injection probes for Hibernate ORM detection
pub struct HqlProbes {
    /// Bounded results queue
    results: Vec<Cow<'static, str>>,
    max_results: usize,
}

impl HqlProbes {
    pub fn new(max_results: usize) -> Self {
        Self {
            results: Vec::with_capacity(max_results.min(512)),
            max_results: max_results.min(512),
        }
    }

    /// Generate HQL comment-based probes
    pub fn comment_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "'--",
            "\"--",
            "/*",
            "*/",
            "'/*comment*/'",
            "\"/*comment*/\"",
        ].into_iter()
    }

    /// Generate HQL clause manipulation probes
    pub fn clause_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' AND '1'='2",
            "\" AND \"1\"=\"2",
        ].into_iter()
    }

    /// Generate HQL function-based probes (safe variants)
    pub fn function_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "' || 'test",
            "\" || \"test",
            "' + 'test",
            "CONCAT('a','b')",
            "SUBSTRING('test',1,1)",
            "LENGTH('test')",
        ].into_iter()
    }

    /// Generate HQL type conversion probes for error-based detection
    pub fn type_conversion_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "' + 1 + '",
            "\" + 1 + \"",
            "CAST('1' AS INT)",
            "CONVERT(INT, '1')",
        ].into_iter()
    }

    /// Analyze response for HQL injection indicators
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

        let confidence = self.calculate_hql_injection_confidence(original, mutated, probe);

        if confidence > 0.5 {
            let evidence = Evidence::new()
                .with_parameter(param.to_string())
                .with_evidence_type("orm_hql")
                .with_payload(Cow::Borrowed(probe))
                .with_original(Cow::Borrowed(original))
                .with_mutated(Cow::Borrowed(mutated))
                .with_confidence(confidence);

            self.results.push(Cow::Owned(format!("HQL probe: {}", probe)));

            return Some(CheckResult {
                vulnerability: "Hibernate HQL Injection".to_string(),
                severity: "Critical".to_string(),
                evidence,
                remediation: "Use parameterized HQL queries with named parameters. Avoid string concatenation in query construction. Implement input validation.".to_string(),
            });
        }
        None
    }

    /// Calculate confidence score for HQL injection
    fn calculate_hql_injection_confidence(&self, original: &str, mutated: &str, probe: &str) -> f64 {
        let mut confidence = 0.0;

        // Check for HQL-specific error patterns
        let hql_errors = [
            "org.hibernate",
            "QueryException",
            "HibernateException",
            "unexpected token",
            "invalid comparison",
            "could not resolve property",
        ];

        for error in hql_errors.iter() {
            if mutated.contains(error) && !original.contains(error) {
                confidence += 0.2;
            }
        }

        // Check for boolean differential behavior
        if probe.contains("OR") && mutated.len() != original.len() {
            confidence += 0.3;
        }

        if probe.contains("AND") && mutated.len() < original.len() {
            confidence += 0.2;
        }

        // Check for syntax error indicators
        let syntax_indicators = ["syntax error", "mismatched input", "extraneous input"];
        for indicator in syntax_indicators.iter() {
            if mutated.to_lowercase().contains(indicator) {
                confidence += 0.15;
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
    fn test_comment_probes() {
        let probes = HqlProbes::new(100);
        let count: usize = probes.comment_probes().count();
        assert_eq!(count, 6);
    }

    #[test]
    fn test_confidence_with_error() {
        let probes = HqlProbes::new(100);
        let original = "{\"status\":\"ok\"}";
        let mutated = "{\"error\":\"org.hibernate.QueryException: unexpected token\"}";
        
        let confidence = probes.calculate_hql_injection_confidence(original, mutated, "' OR '1'='1");
        assert!(confidence > 0.2);
    }
}
