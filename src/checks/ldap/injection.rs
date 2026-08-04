//! LDAP Injection Detection
//! Detects LDAP filter injection with safe wildcard, parenthesis, and attribute probes.
//! Implements bounded memory usage with zero-copy evidence storage.

use crate::checks::CheckResult;
use crate::findings::Evidence;
use std::borrow::Cow;

/// LDAP injection detection probes
pub struct LdapProbes {
    results: Vec<Cow<'static, str>>,
    max_results: usize,
}

impl LdapProbes {
    pub fn new(max_results: usize) -> Self {
        Self {
            results: Vec::with_capacity(max_results.min(512)),
            max_results: max_results.min(512),
        }
    }

    /// Generate parenthesis-based LDAP injection probes
    pub fn parenthesis_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            ")(",
            ")(uid=*)",
            ")(cn=*)",
            ")(|(uid=*))",
            ")(objectClass=*)",
        ].into_iter()
    }

    /// Generate wildcard-based LDAP injection probes
    pub fn wildcard_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "*",
            "*)(uid=*",
            "*)(cn=admin*",
            "*)(|(uid=*))",
            "admin*",
            "*admin*",
        ].into_iter()
    }

    /// Generate attribute manipulation probes
    pub fn attribute_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "uid=*)(&",
            "cn=*)(&",
            "mail=*)(&",
            "objectClass=*)(&",
            "userPassword=*)(&",
        ].into_iter()
    }

    /// Generate null byte injection probes
    pub fn null_byte_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "admin\u{0000}",
            "user\u{0000}*)(uid=*)",
            "test\u{0000})(cn=*)",
        ].into_iter()
    }

    /// Generate LDAP filter bypass probes
    pub fn bypass_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "admin)(|(uid=*))",
            "*)(uid=*)(|(uid=*))",
            "anonymous)(|(objectClass=*))",
            "guest)(|(cn=*))",
        ].into_iter()
    }

    /// Analyze response for LDAP injection indicators
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

        let confidence = self.calculate_ldap_confidence(original, mutated, probe);

        if confidence > 0.5 {
            let evidence = Evidence::new()
                .with_parameter(param.to_string())
                .with_evidence_type("ldap_injection")
                .with_payload(Cow::Borrowed(probe))
                .with_original(Cow::Borrowed(original))
                .with_mutated(Cow::Borrowed(mutated))
                .with_confidence(confidence);

            self.results.push(Cow::Owned(format!("LDAP probe: {}", probe)));

            return Some(CheckResult {
                vulnerability: "LDAP Injection".to_string(),
                severity: "High".to_string(),
                evidence,
                remediation: "Use parameterized LDAP queries. Implement strict input validation and sanitization. Escape special LDAP characters in user input.".to_string(),
            });
        }
        None
    }

    /// Calculate LDAP injection confidence score
    fn calculate_ldap_confidence(&self, original: &str, mutated: &str, probe: &str) -> f64 {
        let mut confidence = 0.0;

        // Check for LDAP-specific error patterns
        let ldap_errors = [
            "Bad search filter",
            "Invalid filter syntax",
            "javax.naming.InvalidNameException",
            "System.DirectoryServices",
            "DirectoryOperationException",
            "Filter is invalid",
        ];

        for error in ldap_errors.iter() {
            if mutated.contains(error) && !original.contains(error) {
                confidence += 0.3;
            }
        }

        // Check for filter manipulation success indicators
        if probe.contains(")(") || probe.contains(")(|") {
            let len_delta = if original.is_empty() {
                0.0
            } else {
                (mutated.len() as i32 - original.len() as i32).abs() as f64 / original.len() as f64
            };
            
            if len_delta > 0.5 {
                confidence += 0.4;
            }
        }

        // Check for wildcard expansion indicators
        if probe.contains("*") {
            let result_count_original = original.matches("\"id\":").count();
            let result_count_mutated = mutated.matches("\"id\":").count();
            
            if result_count_mutated > result_count_original {
                confidence += 0.3;
            }
        }

        // Check for LDAP attribute exposure
        let ldap_attributes = [
            "uid=", "cn=", "mail=", "objectClass=", "dn=", "userPassword=",
            "givenName=", "sn=", "memberOf=",
        ];
        
        for attr in ldap_attributes.iter() {
            if mutated.contains(attr) && !original.contains(attr) {
                confidence += 0.2;
            }
        }

        // Check for authentication bypass indicators
        let bypass_indicators = ["authenticated", "loggedIn", "success", "valid"];
        for indicator in bypass_indicators.iter() {
            if mutated.to_lowercase().contains(indicator) && !original.to_lowercase().contains(indicator) {
                confidence += 0.25;
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
    fn test_parenthesis_probes() {
        let probes = LdapProbes::new(100);
        let count: usize = probes.parenthesis_probes().count();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_wildcard_probes() {
        let probes = LdapProbes::new(100);
        let count: usize = probes.wildcard_probes().count();
        assert_eq!(count, 6);
    }

    #[test]
    fn test_confidence_with_error() {
        let probes = LdapProbes::new(100);
        let original = "{\"result\":\"not found\"}";
        let mutated = "{\"error\":\"Bad search filter: Invalid filter syntax\"}";
        
        let confidence = probes.calculate_ldap_confidence(original, mutated, ")(uid=*)");
        assert!(confidence > 0.25);
    }
}
