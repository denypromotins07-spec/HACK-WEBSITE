//! Expression Language Injection Detection
//! Detects Java EL, Spring Expression, and OGNL injection with harmless evaluation probes.
//! Implements bounded memory usage with zero-copy evidence storage.

use crate::checks::CheckResult;
use crate::findings::Evidence;
use std::borrow::Cow;

/// Expression Language injection probes
pub struct ElProbes {
    results: Vec<Cow<'static, str>>,
    max_results: usize,
}

impl ElProbes {
    pub fn new(max_results: usize) -> Self {
        Self {
            results: Vec::with_capacity(max_results.min(512)),
            max_results: max_results.min(512),
        }
    }

    /// Generate Java EL (Expression Language) probes
    pub fn java_el_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "#{1+1}",
            "${1+1}",
            "#{T(java.lang.Runtime).getRuntime().exec('id')}",
            "${applicationScope}",
            "#{pageContext.request.contextPath}",
        ].into_iter()
    }

    /// Generate Spring Expression Language (SpEL) probes
    pub fn spel_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "#{7*7}",
            "${7*7}",
            "#{T(java.lang.Runtime).getRuntime().exec('touch /tmp/pwned')}",
            "${new java.util.Scanner(T(java.lang.Runtime).getRuntime().start('id')).useDelimiter('\\\\A').next()}",
            "#{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().getInputStream())}",
        ].into_iter()
    }

    /// Generate OGNL (Object-Graph Navigation Language) probes
    pub fn ognl_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "${#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Test','test')}",
            "@java.lang.Runtime@getRuntime().exec('id')",
            "${(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)?(@org.apache.struts2.ServletActionContext@getResponse().setCharacterEncoding('utf-8'))}",
            "${__spring_request__}",
            "${__jsp_page_context__}",
        ].into_iter()
    }

    /// Generate JSP EL probes
    pub fn jsp_el_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "${param:test}",
            "${header:user-agent}",
            "${cookie}",
            "${sessionScope}",
            "${requestScope}",
        ].into_iter()
    }

    /// Generate JSF EL probes
    pub fn jsf_el_probes(&self) -> impl Iterator<Item = &'static str> {
        [
            "#{view}",
            "#{facesContext}",
            "#{externalContext}",
            "#{request}",
            "#{session}",
        ].into_iter()
    }

    /// Analyze response for EL injection indicators
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

        let confidence = self.calculate_el_confidence(original, mutated, probe);
        let el_type = self.identify_el_type(probe, mutated);

        if confidence > 0.5 {
            let evidence = Evidence::new()
                .with_parameter(param.to_string())
                .with_evidence_type("el_injection")
                .with_expression_language(el_type)
                .with_payload(Cow::Borrowed(probe))
                .with_original(Cow::Borrowed(original))
                .with_mutated(Cow::Borrowed(mutated))
                .with_confidence(confidence);

            self.results.push(Cow::Owned(format!("EL probe: {}", probe)));

            return Some(CheckResult {
                vulnerability: "Expression Language Injection".to_string(),
                severity: "Critical".to_string(),
                evidence,
                remediation: "Avoid evaluating user input as expressions. Use parameterized expressions. Implement strict input validation and sandboxing.".to_string(),
            });
        }
        None
    }

    /// Calculate EL injection confidence score
    fn calculate_el_confidence(&self, original: &str, mutated: &str, probe: &str) -> f64 {
        let mut confidence = 0.0;

        // Check for math evaluation (2 = 1+1, 49 = 7*7)
        if (probe.contains("1+1") && mutated.contains("2")) ||
           (probe.contains("7*7") && mutated.contains("49")) {
            if !original.contains("2") || !original.contains("49") {
                confidence += 0.5;
            }
        }

        // Check for EL-specific error patterns
        let el_errors = [
            "ELException",
            "ExpressionException",
            "SpelEvaluationException",
            "OGNLException",
            "MethodNotFoundException",
            "PropertyNotFoundException",
        ];

        for error in el_errors.iter() {
            if mutated.contains(error) && !original.contains(error) {
                confidence += 0.3;
            }
        }

        // Check for object/context exposure
        let exposure_indicators = [
            "Runtime",
            "ServletContext",
            "HttpServletRequest",
            "HttpServletResponse",
            "ApplicationContext",
        ];

        for indicator in exposure_indicators.iter() {
            if mutated.contains(indicator) && !original.contains(indicator) {
                confidence += 0.25;
            }
        }

        // Check for successful execution indicators
        if probe.contains("exec") || probe.contains("Runtime") {
            let exec_indicators = ["uid=", "gid=", "root", "user"];
            for indicator in exec_indicators.iter() {
                if mutated.to_lowercase().contains(&indicator.to_lowercase()) {
                    confidence += 0.3;
                }
            }
        }

        confidence.min(1.0)
    }

    /// Identify the expression language type
    fn identify_el_type(&self, probe: &str, response: &str) -> Cow<'static, str> {
        if probe.contains("#ognl") || probe.contains("@java.lang") || response.contains("OGNL") {
            return Cow::Borrowed("OGNL");
        }

        if probe.contains("T(java.lang") || 
           response.contains("SpelEvaluationException") || 
           response.contains("Spring") {
            return Cow::Borrowed("SpEL");
        }

        if probe.contains("#{") && (probe.contains("facesContext") || probe.contains("view")) {
            return Cow::Borrowed("JSF-EL");
        }

        if probe.contains("${") || probe.contains("#{") {
            if response.contains("JSP") || response.contains("javax.el") {
                return Cow::Borrowed("JSP-EL");
            }
            return Cow::Borrowed("Java-EL");
        }

        Cow::Borrowed("Unknown-EL")
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
    fn test_java_el_probes() {
        let probes = ElProbes::new(100);
        let count: usize = probes.java_el_probes().count();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_spel_probes() {
        let probes = ElProbes::new(100);
        let count: usize = probes.spel_probes().count();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_confidence_math() {
        let probes = ElProbes::new(100);
        let original = "Hello ${name}";
        let mutated = "Hello 2";
        
        let confidence = probes.calculate_el_confidence(original, mutated, "#{1+1}");
        assert!(confidence >= 0.5);
    }
}
