//! Boolean-Based Blind SQL Injection Detection Module
//! Detects true/false differentials using structural hashing and token stripping.

use crate::checks::module::{CheckModule, CheckResult, Severity};
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::learning::sqli_cache::SqliCache;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Boolean test result comparison
#[derive(Debug, Clone)]
pub struct BooleanComparison {
    pub true_hash: u64,
    pub false_hash: u64,
    pub original_hash: u64,
    pub true_content_length: usize,
    pub false_content_length: usize,
    pub original_content_length: usize,
    pub structural_similarity: f64,
}

/// Token-stripped content for comparison
#[derive(Debug, Clone)]
pub struct StrippedContent {
    pub hash: u64,
    pub token_count: usize,
    pub significant_tokens: Vec<String>,
}

/// Boolean-based SQLi detector
pub struct BooleanDetector {
    cache: SqliCache,
    http_client: HttpClient,
    tolerance_threshold: f64,
}

impl BooleanDetector {
    /// Create a new boolean-based detector
    pub fn new(cache: SqliCache, http_client: HttpClient) -> Self {
        Self {
            cache,
            http_client,
            tolerance_threshold: 0.85, // 85% similarity threshold
        }
    }

    /// Calculate structural hash of response content
    fn calculate_structural_hash(&self, content: &str) -> u64 {
        let mut hasher = DefaultHasher::new();

        // Strip whitespace and normalize
        let normalized = content
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();

        normalized.hash(&mut hasher);
        hasher.finish()
    }

    /// Strip HTML tokens for content comparison
    fn strip_tokens(&self, content: &str) -> StrippedContent {
        let mut hasher = DefaultHasher::new();
        let mut significant_tokens = Vec::new();

        // Simple tokenization - split on common delimiters
        let tokens: Vec<&str> = content
            .split(|c: char| c.is_whitespace() || c == '<' || c == '>' || c == '=' || c == '"')
            .filter(|t| !t.is_empty() && t.len() > 2)
            .collect();

        for token in &tokens {
            token.hash(&mut hasher);
            if token.len() > 3 {
                significant_tokens.push(token.to_string());
            }
        }

        StrippedContent {
            hash: hasher.finish(),
            token_count: tokens.len(),
            significant_tokens,
        }
    }

    /// Calculate structural similarity between two contents
    fn calculate_similarity(&self, content1: &str, content2: &str) -> f64 {
        let stripped1 = self.strip_tokens(content1);
        let stripped2 = self.strip_tokens(content2);

        if stripped1.token_count == 0 || stripped2.token_count == 0 {
            return 0.0;
        }

        // Compare significant tokens
        let common_tokens: usize = stripped1
            .significant_tokens
            .iter()
            .filter(|t| stripped2.significant_tokens.contains(t))
            .count();

        let total_tokens = stripped1.token_count.max(stripped2.token_count);
        common_tokens as f64 / total_tokens as f64
    }

    /// Execute request and get response content
    async fn get_response_content(&self, request: &HttpRequest) -> Result<String, String> {
        match self.http_client.execute(request).await {
            Ok(response) => Ok(response.body().to_string()),
            Err(e) => Err(format!("Request failed: {}", e)),
        }
    }

    /// Generate boolean test payloads
    fn generate_boolean_payloads(&self, param: &str) -> Vec<(String, bool)> {
        vec![
            // True conditions
            (format!("{}' AND 1=1-- ", param), true),
            (format!("{}' OR 1=1-- ", param), true),
            (format!("{}' AND 'a'='a", param), true),
            (format!("{}' OR 'a'='a", param), true),
            
            // False conditions
            (format!("{}' AND 1=2-- ", param), false),
            (format!("{}' OR 1=2-- ", param), false),
            (format!("{}' AND 'a'='b", param), false),
            (format!("{}' OR 'a'='b", param), false),
        ]
    }

    /// Perform boolean-based SQLi detection
    pub async fn detect(
        &mut self,
        request: &HttpRequest,
        param: &str,
    ) -> Option<CheckResult> {
        // Get baseline response
        let baseline_content = match self.get_response_content(request).await {
            Ok(c) => c,
            Err(_) => return None,
        };

        let baseline_hash = self.calculate_structural_hash(&baseline_content);
        let baseline_stripped = self.strip_tokens(&baseline_content);

        let payloads = self.generate_boolean_payloads(param);
        let mut true_results = Vec::new();
        let mut false_results = Vec::new();

        for (payload, is_true_condition) in payloads {
            let mut test_request = request.clone();

            // Inject payload
            if let Some(body) = test_request.body_mut() {
                body.replace(&format!("{}=", param), &format!("{}={}", param, payload));
            } else if let Some(query) = test_request.query_mut() {
                query.replace(&format!("{}=", param), &format!("{}={}", param, payload));
            }

            let content = match self.get_response_content(&test_request).await {
                Ok(c) => c,
                Err(_) => continue,
            };

            let hash = self.calculate_structural_hash(&content);
            let content_len = content.len();

            if is_true_condition {
                true_results.push((hash, content_len, content));
            } else {
                false_results.push((hash, content_len, content));
            }
        }

        // Analyze results for boolean differential
        if let Some(detection) = self.analyze_boolean_differential(
            baseline_hash,
            baseline_stripped,
            &true_results,
            &false_results,
            param,
        ) {
            return Some(detection);
        }

        None
    }

    /// Analyze boolean differential patterns
    fn analyze_boolean_differential(
        &self,
        baseline_hash: u64,
        baseline_stripped: StrippedContent,
        true_results: &[(u64, usize, String)],
        false_results: &[(u64, usize, String)],
        param: &str,
    ) -> Option<CheckResult> {
        if true_results.is_empty() || false_results.is_empty() {
            return None;
        }

        // Check if true conditions produce similar responses
        let true_hashes: Vec<u64> = true_results.iter().map(|(h, _, _)| *h).collect();
        let false_hashes: Vec<u64> = false_results.iter().map(|(h, _, _)| *h).collect();

        // Count consistent true responses
        let true_consistent = true_hashes
            .iter()
            .filter(|&&h| h == true_hashes[0])
            .count();

        // Count consistent false responses
        let false_consistent = false_hashes
            .iter()
            .filter(|&&h| h == false_hashes[0])
            .count();

        // Check if true and false produce different responses
        let true_false_different = true_hashes[0] != false_hashes[0];

        // Check similarity between baseline and true condition
        if let Some(true_content) = true_results.first().map(|(_, _, c)| c) {
            let similarity = self.calculate_similarity(
                &true_content,
                &true_results.get(0).map(|(_, _, c)| c.as_str()).unwrap_or(""),
            );

            if true_consistent >= true_results.len() / 2
                && false_consistent >= false_results.len() / 2
                && true_false_different
            {
                // Potential boolean-based SQLi detected
                return Some(CheckResult {
                    module: "boolean_based_sqli".to_string(),
                    severity: Severity::High,
                    confidence: 0.8,
                    description: format!(
                        "Boolean-based blind SQLi detected. True conditions: {} consistent, False conditions: {} consistent",
                        true_consistent, false_consistent
                    ),
                    evidence: format!(
                        "True hash: {:?}, False hash: {:?}",
                        true_hashes.first(),
                        false_hashes.first()
                    ),
                    parameter: Some(param.to_string()),
                    remediation: "Use parameterized queries and input validation".to_string(),
                });
            }
        }

        None
    }
}

impl CheckModule for BooleanDetector {
    fn name(&self) -> &'static str {
        "boolean_based_sqli"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn run(&mut self, request: &HttpRequest) -> Vec<CheckResult> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_structural_hash() {
        let cache = SqliCache::new();
        let client = HttpClient::default();
        let detector = BooleanDetector::new(cache, client);

        let content1 = "<html><body>Hello World</body></html>";
        let content2 = "<html><body>Hello World</body></html>";
        let content3 = "<html><body>Different Content</body></html>";

        let hash1 = detector.calculate_structural_hash(content1);
        let hash2 = detector.calculate_structural_hash(content2);
        let hash3 = detector.calculate_structural_hash(content3);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_token_stripping() {
        let cache = SqliCache::new();
        let client = HttpClient::default();
        let detector = BooleanDetector::new(cache, client);

        let content = "<div class='test'>Hello World</div>";
        let stripped = detector.strip_tokens(content);

        assert!(stripped.token_count > 0);
        assert!(stripped.significant_tokens.contains(&"Hello".to_string()));
    }

    #[test]
    fn test_similarity_calculation() {
        let cache = SqliCache::new();
        let client = HttpClient::default();
        let detector = BooleanDetector::new(cache, client);

        let content1 = "Hello World Test";
        let content2 = "Hello World Test";
        let content3 = "Completely Different";

        let sim_same = detector.calculate_similarity(content1, content2);
        let sim_diff = detector.calculate_similarity(content1, content3);

        assert!(sim_same > sim_diff);
    }
}
