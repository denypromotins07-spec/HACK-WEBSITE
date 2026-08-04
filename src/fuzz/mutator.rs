//! Fuzz Mutator - Mutation operators for payload evolution
//!
//! Implements mutation operators including insertion, deletion, case flipping,
//! encoding swaps, and boundary value generation for genetic algorithm-based
//! payload evolution.

use crate::payload::{GeneratedPayload, PayloadClass, Severity, SafetyLevel};
use rand::Rng;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global mutation counter for deterministic seeding
static MUTATION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Types of mutations available
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationType {
    /// Insert random character(s)
    Insert,
    /// Delete character(s)
    Delete,
    /// Substitute character(s)
    Substitute,
    /// Flip case of letters
    CaseFlip,
    /// Swap adjacent characters
    Swap,
    /// Duplicate character(s)
    Duplicate,
    /// Truncate string
    Truncate,
    /// Extend with padding
    Extend,
    /// Apply URL encoding
    EncodeUrl,
    /// Apply HTML encoding
    EncodeHtml,
    /// Apply Unicode normalization
    UnicodeNormalize,
    /// Add SQL comment syntax
    SqlComment,
    /// Add null byte
    NullByte,
    /// Add whitespace variants
    WhitespaceVariant,
    /// Boundary value injection
    BoundaryValue,
}

/// Configuration for the mutator
#[derive(Debug, Clone)]
pub struct MutatorConfig {
    /// Probability of each mutation type (0.0 to 1.0)
    pub mutation_rates: Vec<(MutationType, f64)>,
    /// Maximum number of mutations per payload
    pub max_mutations: usize,
    /// Minimum mutation count
    pub min_mutations: usize,
    /// Use deterministic seeding for reproducibility
    pub deterministic: bool,
    /// Seed for deterministic mode
    pub seed: u64,
}

impl Default for MutatorConfig {
    fn default() -> Self {
        Self {
            mutation_rates: vec![
                (MutationType::Insert, 0.15),
                (MutationType::Delete, 0.1),
                (MutationType::Substitute, 0.2),
                (MutationType::CaseFlip, 0.1),
                (MutationType::Swap, 0.05),
                (MutationType::Duplicate, 0.1),
                (MutationType::Truncate, 0.05),
                (MutationType::Extend, 0.05),
                (MutationType::EncodeUrl, 0.05),
                (MutationType::EncodeHtml, 0.03),
                (MutationType::NullByte, 0.02),
                (MutationType::WhitespaceVariant, 0.05),
                (MutationType::BoundaryValue, 0.05),
            ],
            max_mutations: 5,
            min_mutations: 1,
            deterministic: false,
            seed: 0,
        }
    }
}

/// Payload mutator for genetic algorithm evolution
#[derive(Debug)]
pub struct PayloadMutator {
    config: MutatorConfig,
    rng_seed: u64,
}

impl PayloadMutator {
    pub fn new(config: MutatorConfig) -> Self {
        let seed = if config.deterministic {
            config.seed
        } else {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
        };
        
        Self {
            config,
            rng_seed: seed,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(MutatorConfig::default())
    }

    /// Enable deterministic mode with specific seed
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.rng_seed = seed;
        self.config.deterministic = true;
        self
    }

    /// Apply mutations to a payload
    pub fn mutate(&self, payload: &GeneratedPayload) -> Vec<GeneratedPayload> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.get_next_seed());
        let num_mutations = rng.gen_range(self.config.min_mutations..=self.config.max_mutations);
        
        let mut mutated = Vec::with_capacity(num_mutations);
        
        for i in 0..num_mutations {
            let mutation_type = self.select_mutation_type(&mut rng);
            if let Some(mutated_payload) = self.apply_mutation(payload, mutation_type) {
                mutated.push(mutated_payload);
            }
        }
        
        mutated
    }

    /// Apply a single specific mutation
    pub fn apply_single_mutation(
        &self,
        payload: &GeneratedPayload,
        mutation_type: MutationType,
    ) -> Option<GeneratedPayload> {
        self.apply_mutation(payload, mutation_type)
    }

    /// Generate boundary value payloads
    pub fn generate_boundary_values(&self, context: &str) -> Vec<GeneratedPayload> {
        let mut payloads = Vec::new();
        
        match context {
            "sql" => {
                payloads.extend(self.sql_boundary_values());
            }
            "xss" => {
                payloads.extend(self.xss_boundary_values());
            }
            "command" => {
                payloads.extend(self.command_boundary_values());
            }
            "path" => {
                payloads.extend(self.path_boundary_values());
            }
            _ => {}
        }
        
        payloads
    }

    fn sql_boundary_values(&self) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new("bound-sql-001", "' OR '1'='1", PayloadClass::SqlInjection, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-sql-002", "' OR '1'='1' --", PayloadClass::SqlInjection, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-sql-003", "1; DROP TABLE users--", PayloadClass::SqlInjection, Severity::Critical, SafetyLevel::Dangerous),
            GeneratedPayload::new("bound-sql-004", "1 UNION SELECT NULL--", PayloadClass::SqlInjection, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-sql-005", "1' AND 1=1--", PayloadClass::SqlInjection, Severity::Medium, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-sql-006", "1' AND 1=2--", PayloadClass::SqlInjection, Severity::Medium, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-sql-007", "admin'--", PayloadClass::SqlInjection, Severity::Medium, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-sql-008", "1 OR 1=1", PayloadClass::SqlInjection, Severity::High, SafetyLevel::Unsafe),
        ]
    }

    fn xss_boundary_values(&self) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new("bound-xss-001", "<script>alert(1)</script>", PayloadClass::Xss, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-xss-002", "<img src=x onerror=alert(1)>", PayloadClass::Xss, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-xss-003", "\"><script>alert(1)</script>", PayloadClass::Xss, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-xss-004", "javascript:alert(1)", PayloadClass::Xss, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-xss-005", "<svg onload=alert(1)>", PayloadClass::Xss, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-xss-006", "<body onpageshow=alert(1)>", PayloadClass::Xss, Severity::Medium, SafetyLevel::Unsafe),
        ]
    }

    fn command_boundary_values(&self) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new("bound-cmd-001", "; ls", PayloadClass::CommandInjection, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-cmd-002", "| cat /etc/passwd", PayloadClass::CommandInjection, Severity::Critical, SafetyLevel::Dangerous),
            GeneratedPayload::new("bound-cmd-003", "`whoami`", PayloadClass::CommandInjection, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-cmd-004", "$(id)", PayloadClass::CommandInjection, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-cmd-005", "&& echo pwned", PayloadClass::CommandInjection, Severity::Medium, SafetyLevel::Unsafe),
        ]
    }

    fn path_boundary_values(&self) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new("bound-path-001", "../../../etc/passwd", PayloadClass::PathTraversal, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-path-002", "..\\..\\..\\windows\\system32\\config\\sam", PayloadClass::PathTraversal, Severity::Critical, SafetyLevel::Dangerous),
            GeneratedPayload::new("bound-path-003", "....//....//etc/passwd", PayloadClass::PathTraversal, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-path-004", "%2e%2e%2f%2e%2e%2fetc/passwd", PayloadClass::PathTraversal, Severity::High, SafetyLevel::Unsafe),
            GeneratedPayload::new("bound-path-005", "/etc/shadow\0.txt", PayloadClass::PathTraversal, Severity::High, SafetyLevel::Unsafe),
        ]
    }

    fn select_mutation_type<R: Rng>(&self, rng: &mut R) -> MutationType {
        let total: f64 = self.config.mutation_rates.iter().map(|(_, r)| r).sum();
        let mut roll = rng.gen::<f64>() * total;
        
        for &(mutation_type, rate) in &self.config.mutation_rates {
            if roll < rate {
                return mutation_type;
            }
            roll -= rate;
        }
        
        MutationType::Substitute
    }

    fn apply_mutation(&self, payload: &GeneratedPayload, mutation_type: MutationType) -> Option<GeneratedPayload> {
        let raw = &payload.raw;
        
        if raw.is_empty() {
            return None;
        }
        
        let mutated_str = match mutation_type {
            MutationType::Insert => self.mutate_insert(raw),
            MutationType::Delete => self.mutate_delete(raw),
            MutationType::Substitute => self.mutate_substitute(raw),
            MutationType::CaseFlip => self.mutate_case_flip(raw),
            MutationType::Swap => self.mutate_swap(raw),
            MutationType::Duplicate => self.mutate_duplicate(raw),
            MutationType::Truncate => self.mutate_truncate(raw),
            MutationType::Extend => self.mutate_extend(raw),
            MutationType::EncodeUrl => self.mutate_url_encode(raw),
            MutationType::EncodeHtml => self.mutate_html_encode(raw),
            MutationType::UnicodeNormalize => raw.to_string(),
            MutationType::SqlComment => self.mutate_sql_comment(raw),
            MutationType::NullByte => self.mutate_null_byte(raw),
            MutationType::WhitespaceVariant => self.mutate_whitespace(raw),
            MutationType::BoundaryValue => return None,
        };
        
        if mutated_str == *raw {
            return None;
        }
        
        Some(GeneratedPayload::new(
            format!("{}-mut-{}", payload.id, MUTATION_COUNTER.fetch_add(1, Ordering::SeqCst)),
            mutated_str,
            payload.class.clone(),
            payload.severity,
            payload.safety,
        ))
    }

    fn mutate_insert(&self, s: &str) -> String {
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.get_next_seed());
        let chars: Vec<char> = vec!['\'', '"', ';', '--', '#', '<', '>', '\\', '/', '%'];
        let pos = rng.gen_range(0..=s.len());
        let ch = chars[rng.gen_range(0..chars.len())];
        
        let mut result = s.to_string();
        result.insert(pos, ch);
        result
    }

    fn mutate_delete(&self, s: &str) -> String {
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.get_next_seed());
        if s.len() <= 1 {
            return s.to_string();
        }
        let pos = rng.gen_range(0..s.len());
        let mut result: String = s.chars().enumerate().filter(|(i, _)| *i != pos).collect();
        result
    }

    fn mutate_substitute(&self, s: &str) -> String {
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.get_next_seed());
        if s.is_empty() {
            return s.to_string();
        }
        let pos = rng.gen_range(0..s.len());
        let subs: Vec<char> = vec!['\'', '"', '\\', ' ', '\t', '\n', '0', '1'];
        let sub = subs[rng.gen_range(0..subs.len())];
        
        let mut chars: Vec<char> = s.chars().collect();
        chars[pos] = sub;
        chars.into_iter().collect()
    }

    fn mutate_case_flip(&self, s: &str) -> String {
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.get_next_seed());
        s.chars().map(|c| {
            if rng.gen_bool(0.3) {
                if c.is_lowercase() {
                    c.to_uppercase().next().unwrap_or(c)
                } else if c.is_uppercase() {
                    c.to_lowercase().next().unwrap_or(c)
                } else {
                    c
                }
            } else {
                c
            }
        }).collect()
    }

    fn mutate_swap(&self, s: &str) -> String {
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.get_next_seed());
        let mut chars: Vec<char> = s.chars().collect();
        if chars.len() < 2 {
            return s.to_string();
        }
        let pos = rng.gen_range(0..chars.len() - 1);
        chars.swap(pos, pos + 1);
        chars.into_iter().collect()
    }

    fn mutate_duplicate(&self, s: &str) -> String {
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.get_next_seed());
        if s.is_empty() {
            return s.to_string();
        }
        let pos = rng.gen_range(0..s.len());
        let mut result = s.to_string();
        if let Some(ch) = s.chars().nth(pos) {
            result.insert(pos, ch);
        }
        result
    }

    fn mutate_truncate(&self, s: &str) -> String {
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.get_next_seed());
        let len = s.len();
        if len <= 1 {
            return s.to_string();
        }
        let truncate_at = rng.gen_range(1..len);
        s[..truncate_at].to_string()
    }

    fn mutate_extend(&self, s: &str) -> String {
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.get_next_seed());
        let paddings = vec![" ", "\t", "--", "#", "/*", "*/", ";;"];
        let padding = paddings[rng.gen_range(0..paddings.len())];
        format!("{}{}", s, padding)
    }

    fn mutate_url_encode(&self, s: &str) -> String {
        s.chars().flat_map(|c| {
            if c.is_ascii_alphanumeric() {
                vec![c]
            } else {
                format!("%{:02X}", c as u8).chars().collect()
            }
        }).collect()
    }

    fn mutate_html_encode(&self, s: &str) -> String {
        s.replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
    }

    fn mutate_sql_comment(&self, s: &str) -> String {
        let comments = vec!["--", "#", "/*", "*/"];
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.get_next_seed());
        let comment = comments[rng.gen_range(0..comments.len())];
        format!("{}{}", s, comment)
    }

    fn mutate_null_byte(&self, s: &str) -> String {
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.get_next_seed());
        let pos = rng.gen_range(0..=s.len());
        let mut result = s.to_string();
        result.insert_str(pos, "\0");
        result
    }

    fn mutate_whitespace(&self, s: &str) -> String {
        s.replace(' ', &["\t", "\n", "\r", "%20", "+"][rand::rngs::StdRng::seed_from_u64(self.get_next_seed()).gen_range(0..5)])
    }

    fn get_next_seed(&self) -> u64 {
        if self.config.deterministic {
            MUTATION_COUNTER.fetch_add(1, Ordering::SeqCst) ^ self.rng_seed
        } else {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutator_creation() {
        let mutator = PayloadMutator::with_defaults();
        assert!(mutator.config.max_mutations > 0);
    }

    #[test]
    fn test_deterministic_mode() {
        let mutator = PayloadMutator::with_defaults().with_seed(12345);
        assert!(mutator.config.deterministic);
        assert_eq!(mutator.rng_seed, 12345);
    }

    #[test]
    fn test_mutate_payload() {
        let mutator = PayloadMutator::with_defaults().with_seed(42);
        let payload = GeneratedPayload::new(
            "test",
            "' OR 1=1",
            PayloadClass::SqlInjection,
            Severity::High,
            SafetyLevel::Unsafe,
        );
        
        let mutated = mutator.mutate(&payload);
        assert!(!mutated.is_empty());
        
        for m in &mutated {
            assert_ne!(m.raw, payload.raw);
        }
    }

    #[test]
    fn test_boundary_values() {
        let mutator = PayloadMutator::with_defaults();
        
        let sql_bounds = mutator.generate_boundary_values("sql");
        assert!(!sql_bounds.is_empty());
        
        let xss_bounds = mutator.generate_boundary_values("xss");
        assert!(!xss_bounds.is_empty());
    }
}
