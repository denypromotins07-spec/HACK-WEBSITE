//! NoSQL Operator Injection Detection
//! Detects operator-based injection using $gt, $ne, $regex, and $where safe comparisons.
//! Implements bounded memory usage with zero-copy evidence storage.

use crate::checks::CheckResult;
use crate::findings::Evidence;
use std::borrow::Cow;

/// MongoDB and CouchDB operator injection probes
pub struct OperatorProbes {
    /// Bounded results queue
    results: Vec<Cow<'static, str>>,
    max_results: usize,
}

impl OperatorProbes {
    pub fn new(max_results: usize) -> Self {
        Self {
            results: Vec::with_capacity(max_results.min(512)),
            max_results: max_results.min(512),
        }
    }

    /// Generate MongoDB comparison operator probes
    pub fn comparison_operators(&self) -> impl Iterator<Item = &'static str> {
        [
            "{\"$gt\":0}",
            "{\"$gte\":0}",
            "{\"$lt\":999999}",
            "{\"$lte\":999999}",
            "{\"$ne\":\"admin\"}",
            "{\"$eq\":\"test\"}",
        ].into_iter()
    }

    /// Generate MongoDB logical operator probes
    pub fn logical_operators(&self) -> impl Iterator<Item = &'static str> {
        [
            "{\"$or\":[{\"a\":1},{\"b\":1}]}",
            "{\"$and\":[{\"a\":1},{\"b\":1}]}",
            "{\"$nor\":[{\"a\":1}]}",
            "{\"$not\":{\"a\":1}}",
        ].into_iter()
    }

    /// Generate MongoDB array operator probes
    pub fn array_operators(&self) -> impl Iterator<Item = &'static str> {
        [
            "{\"$in\":[\"admin\",\"root\"]}",
            "{\"$nin\":[\"guest\"]}",
            "{\"$all\":[1,2,3]}",
            "{\"$size\":0}",
        ].into_iter()
    }

    /// Generate MongoDB regex and JavaScript probes (safe variants)
    pub fn regex_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "{\"$regex\":\"^a\"}",
            "{\"$regex\":\".*\"}",
            "{\"$regex\":\".*\",\"$options\":\"i\"}",
            "{\"$where\":\"this.a==this.b\"}",
        ].into_iter()
    }

    /// Generate element operator probes
    pub fn element_operators(&self) -> impl Iterator<Item = &'static str> {
        [
            "{\"$exists:true}",
            "{\"$exists:false}",
            "{\"$type\":\"string\"}",
            "{\"$type\":2}",
        ].into_iter()
    }

    /// Analyze response for operator injection success
    pub fn analyze_response(
        &mut self,
        original_response: &str,
        mutated_response: &str,
        param: &str,
        operator: &str,
    ) -> Option<CheckResult> {
        if self.results.len() >= self.max_results {
            return None;
        }

        // Detect behavioral changes indicating successful operator injection
        let confidence = self.calculate_injection_confidence(original_response, mutated_response);

        if confidence > 0.6 {
            let evidence = Evidence::new()
                .with_parameter(param.to_string())
                .with_evidence_type("nosql_operator")
                .with_payload(Cow::Borrowed(operator))
                .with_original(Cow::Borrowed(original_response))
                .with_mutated(Cow::Borrowed(mutated_response))
                .with_confidence(confidence);

            self.results.push(Cow::Owned(format!("Operator: {}", operator)));

            return Some(CheckResult {
                vulnerability: "NoSQL Operator Injection".to_string(),
                severity: "Critical".to_string(),
                evidence,
                remediation: "Use schema validation, parameterized queries, and avoid direct operator injection in user input. Implement strict type checking.".to_string(),
            });
        }
        None
    }

    /// Calculate confidence score based on response differential analysis
    fn calculate_injection_confidence(&self, original: &str, mutated: &str) -> f64 {
        // Check for significant response changes
        let orig_len = original.len() as f64;
        let mut_len = mutated.len() as f64;

        if orig_len == 0.0 && mut_len > 0.0 {
            return 0.8;
        }

        let len_delta = (orig_len - mut_len).abs() / orig_len.max(1.0);

        // Check for common NoSQL error patterns that indicate injection attempt was processed
        let error_indicators = [
            "MongoError",
            "BSONError",
            "CastError",
            "operator",
            "$where",
            "$regex",
        ];

        let error_score: f64 = error_indicators
            .iter()
            .filter(|&&ind| mutated.contains(ind))
            .count() as f64
            * 0.15;

        // Check for authentication bypass indicators
        let bypass_indicators = [
            "\"loggedIn\":true",
            "\"authenticated\":true",
            "\"success\":true",
            "\"role\":\"admin\"",
        ];

        let bypass_score: f64 = bypass_indicators
            .iter()
            .filter(|&&ind| mutated.contains(ind) && !original.contains(ind))
            .count() as f64
            * 0.2;

        (len_delta * 0.3 + error_score + bypass_score).min(1.0)
    }

    /// Clear stored results for memory management
    pub fn clear(&mut self) {
        self.results.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comparison_operators() {
        let probes = OperatorProbes::new(100);
        let count: usize = probes.comparison_operators().count();
        assert_eq!(count, 6);
    }

    #[test]
    fn test_confidence_calculation() {
        let probes = OperatorProbes::new(100);
        let original = "{\"user\":\"guest\",\"role\":\"user\"}";
        let mutated = "{\"user\":\"admin\",\"role\":\"admin\",\"loggedIn\":true}";
        
        let confidence = probes.calculate_injection_confidence(original, mutated);
        assert!(confidence > 0.2);
    }
}
