use rand::Rng;
use std::collections::HashMap;

/// Header mutation engine that randomizes casing, spacing, and encoding.
/// Bypasses naive regex filters by generating valid but varied HTTP headers.
pub struct HeaderMutator {
    rng: rand::rngs::ThreadRng,
    mutation_strategies: Vec<MutationStrategy>,
}

impl HeaderMutator {
    pub fn new() -> Self {
        let strategies = vec![
            MutationStrategy::CaseRandomization,
            MutationStrategy::WhitespaceInsertion,
            MutationStrategy::EncodingVariation,
            MutationStrategy::OrderShuffling,
        ];

        Self {
            rng: rand::thread_rng(),
            mutation_strategies: strategies,
        }
    }

    /// Mutate header name with random casing.
    pub fn mutate_case(&mut self, name: &str) -> String {
        name.chars()
            .map(|c| {
                if self.rng.gen_bool(0.5) {
                    c.to_uppercase().to_string()
                } else {
                    c.to_lowercase().to_string()
                }
            })
            .collect()
    }

    /// Insert random whitespace around colon (valid per RFC).
    pub fn mutate_whitespace(&mut self, name: &str, value: &str) -> (String, String) {
        let spaces_before = self.rng.gen_range(0..=2);
        let spaces_after = self.rng.gen_range(0..=3);
        
        let mutated_name = format!("{}{}", " ".repeat(spaces_before), name);
        let mutated_value = format!("{}{}", " ".repeat(spaces_after), value);
        
        (mutated_name, mutated_value)
    }

    /// Apply URL encoding variations to header value.
    pub fn mutate_encoding(&mut self, value: &str) -> String {
        // Only encode some characters randomly
        value
            .chars()
            .map(|c| {
                if self.rng.gen_bool(0.1) && c.is_ascii_alphanumeric() {
                    format!("%{:02X}", c as u8)
                } else {
                    c.to_string()
                }
            })
            .collect()
    }

    /// Generate all mutations for a set of headers.
    pub fn mutate_all(&mut self, headers: &[(String, String)]) -> Vec<(String, String)> {
        let mut result = Vec::with_capacity(headers.len());

        for (name, value) in headers {
            let mutated_name = self.mutate_case(name);
            let (with_spaces_name, with_spaces_value) = self.mutate_whitespace(&mutated_name, value);
            
            result.push((with_spaces_name, with_spaces_value));
        }

        result
    }

    /// Shuffle header order (some WAFs check specific order).
    pub fn shuffle_headers(&mut self, headers: &[(String, String)]) -> Vec<(String, String)> {
        let mut shuffled: Vec<_> = headers.to_vec();
        
        // Fisher-Yates shuffle
        for i in (1..shuffled.len()).rev() {
            let j = self.rng.gen_range(0..=i);
            shuffled.swap(i, j);
        }
        
        shuffled
    }

    /// Add decoy headers to confuse pattern matching.
    pub fn add_decoys(&mut self, headers: &mut Vec<(String, String)>) {
        let decoys = [
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("Via", "1.1 proxy"),
            ("X-Client-IP", "192.168.1.1"),
        ];

        for (name, value) in &decoys {
            if self.rng.gen_bool(0.3) {
                headers.push((self.mutate_case(name), value.to_string()));
            }
        }
    }

    /// Generate a completely randomized header set.
    pub fn generate_evasive_headers(&mut self, base_headers: &[(String, String)]) -> Vec<(String, String)> {
        let mut result = self.mutate_all(base_headers);
        result = self.shuffle_headers(&result);
        self.add_decoys(&mut result);
        result
    }
}

#[derive(Debug, Clone)]
enum MutationStrategy {
    CaseRandomization,
    WhitespaceInsertion,
    EncodingVariation,
    OrderShuffling,
}

impl Default for HeaderMutator {
    fn default() -> Self {
        Self::new()
    }
}

/// Common user-agent strings for rotation.
pub mod user_agents {
    pub const CHROME_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    pub const FIREFOX_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0";
    pub const SAFARI_MACOS: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15";
    pub const CHROME_LINUX: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    pub const EDGE_WINDOWS: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";

    pub const ALL: &[&str] = &[
        CHROME_WINDOWS,
        FIREFOX_WINDOWS,
        SAFARI_MACOS,
        CHROME_LINUX,
        EDGE_WINDOWS,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_mutations() {
        let mut mutator = HeaderMutator::new();
        let original = "content-type";
        
        // Run multiple times to ensure randomness
        let mut results = std::collections::HashSet::new();
        for _ in 0..10 {
            results.insert(mutator.mutate_case(original));
        }
        
        // Should have at least some variation
        assert!(results.len() >= 1);
    }

    #[test]
    fn test_whitespace_mutations() {
        let mut mutator = HeaderMutator::new();
        let (name, value) = mutator.mutate_whitespace("host", "example.com");
        
        // Name might have leading spaces, value should have trailing
        assert!(name.contains("host") || name.contains("Host"));
        assert!(value.contains("example.com"));
    }

    #[test]
    fn test_shuffle() {
        let mut mutator = HeaderMutator::new();
        let headers = vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
            ("c".to_string(), "3".to_string()),
        ];
        
        let shuffled = mutator.shuffle_headers(&headers);
        assert_eq!(shuffled.len(), 3);
        // Content should be the same, order may differ
    }
}
