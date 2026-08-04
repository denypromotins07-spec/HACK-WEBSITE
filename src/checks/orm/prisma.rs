//! Prisma and GraphQL-adjacent ORM Injection Detection
//! Detects query manipulation via structured parameter tests.
//! Implements bounded memory usage with zero-copy evidence storage.

use crate::checks::CheckResult;
use crate::findings::Evidence;
use std::borrow::Cow;

/// Prisma/GraphQL ORM injection probes
pub struct PrismaProbes {
    results: Vec<Cow<'static, str>>,
    max_results: usize,
}

impl PrismaProbes {
    pub fn new(max_results: usize) -> Self {
        Self {
            results: Vec::with_capacity(max_results.min(512)),
            max_results: max_results.min(512),
        }
    }

    /// Generate Prisma filter manipulation probes
    pub fn filter_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "{\"where\":{\"id\":{\"not\":null}}}",
            "{\"where\":{\"AND\":[{\"id\":{\"gt\":0}}]}}",
            "{\"where\":{\"OR\":[{\"id\":1},{\"id\":2}]}}",
            "{\"where\":{\"NOT\":{\"id\":0}}}",
        ].into_iter()
    }

    /// Generate GraphQL-style query probes
    pub fn graphql_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "{user{id name}}",
            "{users(where:{id_gt:0}){id}}",
            "query{user(id:\"1' OR '1'='1\"){name}}",
            "{__schema{types{name}}}",
        ].into_iter()
    }

    /// Generate nested query probes for deep object traversal
    pub fn nested_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "{\"include\":{\"posts\":true}}",
            "{\"select\":{\"password\":true}}",
            "{\"include\":{\"_count\":true}}",
            "{\"where\":{\"author\":{\"is\":{\"banned\":false}}}}",
        ].into_iter()
    }

    /// Generate order/sort manipulation probes
    pub fn sort_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "{\"orderBy\":{\"id\":\"desc\"}}",
            "{\"orderBy\":[{\"createdAt\":\"desc\"},{\"id\":\"asc\"}]}",
            "{\"orderBy\":{\"_count\":{\"posts\":\"desc\"}}}",
        ].into_iter()
    }

    /// Generate raw query injection probes (dangerous patterns)
    pub fn raw_query_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "{\"raw\":\"SELECT * FROM users\"}",
            "{\"$queryRaw\":\"DELETE FROM users\"}",
            "{\"executeRaw\":\"DROP TABLE\"}",
        ].into_iter()
    }

    /// Analyze response for Prisma/ORM injection indicators
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

        let confidence = self.calculate_injection_confidence(original, mutated, probe);

        if confidence > 0.5 {
            let evidence = Evidence::new()
                .with_parameter(param.to_string())
                .with_evidence_type("orm_prisma")
                .with_payload(Cow::Borrowed(probe))
                .with_original(Cow::Borrowed(original))
                .with_mutated(Cow::Borrowed(mutated))
                .with_confidence(confidence);

            self.results.push(Cow::Owned(format!("Prisma probe: {}", probe)));

            return Some(CheckResult {
                vulnerability: "Prisma ORM Injection".to_string(),
                severity: "High".to_string(),
                evidence,
                remediation: "Use Prisma's type-safe query builder. Avoid raw queries with user input. Implement strict input validation and schema constraints.".to_string(),
            });
        }
        None
    }

    /// Calculate confidence score for ORM injection
    fn calculate_injection_confidence(&self, original: &str, mutated: &str, probe: &str) -> f64 {
        let mut confidence = 0.0;

        // Check for Prisma-specific errors
        let prisma_errors = [
            "PrismaClientValidationError",
            "PrismaClientKnownRequestError",
            "Invalid `prisma.` invocation",
            "Argument `where`",
            "Field does not exist",
        ];

        for error in prisma_errors.iter() {
            if mutated.contains(error) && !original.contains(error) {
                confidence += 0.25;
            }
        }

        // Check for GraphQL errors
        let graphql_errors = [
            "Cannot query field",
            "Variable \"$",
            "Expected value of type",
            "GraphQLError",
        ];

        for error in graphql_errors.iter() {
            if mutated.contains(error) && !original.contains(error) {
                confidence += 0.2;
            }
        }

        // Check for data exposure indicators
        let exposure_indicators = ["\"password\"", "\"secret\"", "\"token\"", "\"key\""];
        for indicator in exposure_indicators.iter() {
            if mutated.contains(indicator) && !original.contains(indicator) {
                confidence += 0.3;
            }
        }

        // Structural change detection
        let orig_fields = original.matches('"').count();
        let mut_fields = mutated.matches('"').count();
        
        if (orig_fields as i32 - mut_fields as i32).abs() > 4 {
            confidence += 0.15;
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
    fn test_filter_probes() {
        let probes = PrismaProbes::new(100);
        let count: usize = probes.filter_probes().count();
        assert_eq!(count, 4);
    }

    #[test]
    fn test_confidence_with_prisma_error() {
        let probes = PrismaProbes::new(100);
        let original = "{\"data\":[]}";
        let mutated = "{\"error\":\"PrismaClientValidationError: Invalid argument\"}";
        
        let confidence = probes.calculate_injection_confidence(original, mutated, "{\"where\":{}}");
        assert!(confidence > 0.2);
    }
}
