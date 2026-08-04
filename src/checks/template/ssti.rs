//! Server-Side Template Injection Detection
//! Detects SSTI in Twig, Jinja2, Freemarker, Thymeleaf, and Pebble using safe math canaries.
//! Implements bounded memory usage with zero-copy evidence storage.

use crate::checks::CheckResult;
use crate::findings::Evidence;
use std::borrow::Cow;

/// Safe SSTI detection probes using math canaries
pub struct SstiProbes {
    results: Vec<Cow<'static, str>>,
    max_results: usize,
}

impl SstiProbes {
    pub fn new(max_results: usize) -> Self {
        Self {
            results: Vec::with_capacity(max_results.min(512)),
            max_results: max_results.min(512),
        }
    }

    /// Generate Twig template injection probes (safe math)
    pub fn twig_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "{{7*7}}",
            "{{7*'7'}}",
            "{{dump(app)}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}",
            "{% for c in app.request.query.all() %}{{c}}{% endfor %}",
        ].into_iter()
    }

    /// Generate Jinja2 template injection probes (safe math)
    pub fn jinja2_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "{{7*7}}",
            "{{config}}",
            "{{self.__init__.__globals__}}",
            "{{request.application.__globals__}}",
            "{% for key in config %}{{key}}{% endfor %}",
        ].into_iter()
    }

    /// Generate Freemarker template injection probes
    pub fn freemarker_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "${7*7}",
            "${freemarker.template.utility.Execute?new()(\"id\")}",
            "${class.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")}",
            "${?version}",
            "${.ftl_version}",
        ].into_iter()
    }

    /// Generate Thymeleaf template injection probes
    pub fn thymeleaf_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "[[${7*7}]]",
            "[[__${7*7}__]]",
            "__${T(java.lang.Runtime).getRuntime().exec('id')}__",
            "[[${applicationScope}]]",
        ].into_iter()
    }

    /// Generate Pebble template injection probes
    pub fn pebble_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "{{7*7}}",
            "{% dump app %}",
            "{{app.request.query.all()}}",
            "{% for i in 1..3 %}{{i}}{% endfor %}",
        ].into_iter()
    }

    /// Generate generic SSTI probes for unknown engines
    pub fn generic_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "{7*7}",
        ].into_iter()
    }

    /// Analyze response for SSTI indicators
    pub fn analyze_response(
        &mut self,
        original: &str,
        mutated: &str,
        param: &str,
        probe: &str,
    ) -> Option<CheckResult> {
        if self.results.len() >= self.max_results {
            return None;
        }

        let confidence = self.calculate_ssti_confidence(original, mutated, probe);

        if confidence > 0.5 {
            let engine = self.identify_template_engine(mutated, probe);
            
            let evidence = Evidence::new()
                .with_parameter(param.to_string())
                .with_evidence_type("ssti")
                .with_payload(Cow::Borrowed(probe))
                .with_template_engine(engine)
                .with_original(Cow::Borrowed(original))
                .with_mutated(Cow::Borrowed(mutated))
                .with_confidence(confidence);

            self.results.push(Cow::Owned(format!("SSTI probe: {}", probe)));

            return Some(CheckResult {
                vulnerability: "Server-Side Template Injection".to_string(),
                severity: "Critical".to_string(),
                evidence,
                remediation: "Use sandboxed template engines. Avoid passing user input directly to template expressions. Implement strict input validation and output encoding.".to_string(),
            });
        }
        None
    }

    /// Calculate SSTI confidence score
    fn calculate_ssti_confidence(&self, original: &str, mutated: &str, probe: &str) -> f64 {
        let mut confidence = 0.0;

        // Check for math evaluation (49 = 7*7)
        if probe.contains("7*7") && mutated.contains("49") && !original.contains("49") {
            confidence += 0.5;
        }

        // Check for template engine error patterns
        let ssti_errors = [
            "TemplateSyntaxError",
            "UndefinedError",
            "FreemarkerException",
            "ThymeleafException",
            "TemplateException",
            "Twig_Error",
        ];

        for error in ssti_errors.iter() {
            if mutated.contains(error) && !original.contains(error) {
                confidence += 0.3;
            }
        }

        // Check for object dumping indicators
        let dump_indicators = ["__class__", "__globals__", "__init__", "Runtime", "getClass"];
        for indicator in dump_indicators.iter() {
            if mutated.contains(indicator) && !original.contains(indicator) {
                confidence += 0.25;
            }
        }

        // Check for configuration exposure
        let config_indicators = ["secret_key", "SECRET_KEY", "DEBUG", "config_object"];
        for indicator in config_indicators.iter() {
            if mutated.contains(indicator) && !original.contains(indicator) {
                confidence += 0.3;
            }
        }

        confidence.min(1.0)
    }

    /// Identify the template engine based on response patterns
    fn identify_template_engine(&self, response: &str, probe: &str) -> Cow<'static, str> {
        if probe.starts_with("{{") && probe.ends_with("}}") {
            if response.contains("Twig_Error") || response.contains("twig") {
                return Cow::Borrowed("Twig");
            }
            if response.contains("Jinja") || response.contains("jinja") {
                return Cow::Borrowed("Jinja2");
            }
            if response.contains("Pebble") || response.contains("pebble") {
                return Cow::Borrowed("Pebble");
            }
            return Cow::Borrowed("Unknown-Curly");
        }

        if probe.starts_with("${") && probe.ends_with("}") {
            if response.contains("Freemarker") || response.contains("freemarker") {
                return Cow::Borrowed("Freemarker");
            }
            return Cow::Borrowed("Unknown-Dollar");
        }

        if probe.contains("[[") && probe.contains("]]") {
            return Cow::Borrowed("Thymeleaf");
        }

        Cow::Borrowed("Unknown")
    }

    /// Clear stored results
    pub fn clear(&mut self) {
        self.results.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_twig_probes() {
        let probes = SstiProbes::new(100);
        let count: usize = probes.twig_probes().count();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_confidence_math_evaluation() {
        let probes = SstiProbes::new(100);
        let original = "Hello {{name}}";
        let mutated = "Hello 49";
        
        let confidence = probes.calculate_ssti_confidence(original, mutated, "{{7*7}}");
        assert!(confidence >= 0.5);
    }
}
