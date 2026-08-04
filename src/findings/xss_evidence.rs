//! XSS Evidence Module
//! 
//! Creates XSS evidence containers with context and remediation guidance.

use crate::checks::xss::context::XssContext;

/// Severity levels for findings
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// XSS evidence container
#[derive(Debug, Clone)]
pub struct XssEvidence {
    /// Type of vulnerability detected
    pub vulnerability_type: String,
    /// Location where vulnerability was found
    pub location: String,
    /// Payload used for detection
    pub payload: String,
    /// Context of the vulnerability (HTML, JS, Attribute, URL)
    pub context: XssContext,
    /// Optional stack trace or line number
    pub stack_trace: Option<String>,
    /// Whether an OOB callback was triggered
    pub callback_triggered: bool,
    /// Remediation guidance
    pub remediation: String,
    /// Severity level
    pub severity: Severity,
}

impl XssEvidence {
    /// Create a new XSS evidence instance
    pub fn new(
        vulnerability_type: String,
        location: String,
        payload: String,
        context: XssContext,
        severity: Severity,
        remediation: String,
    ) -> Self {
        Self {
            vulnerability_type,
            location,
            payload,
            context,
            stack_trace: None,
            callback_triggered: false,
            remediation,
            severity,
        }
    }

    /// Set stack trace information
    pub fn with_stack_trace(mut self, stack_trace: String) -> Self {
        self.stack_trace = Some(stack_trace);
        self
    }

    /// Mark as callback triggered
    pub fn with_callback_triggered(mut self) -> Self {
        self.callback_triggered = true;
        self
    }

    /// Get a summary of the evidence
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} at {} - Severity: {:?}",
            self.vulnerability_type, self.payload, self.location, self.severity
        )
    }

    /// Check if this is a critical finding
    pub fn is_critical(&self) -> bool {
        self.severity == Severity::Critical
    }

    /// Get CSP-specific remediation if applicable
    pub fn csp_remediation(&self) -> Option<String> {
        if self.vulnerability_type.contains("CSP") || 
           self.vulnerability_type.contains("XSS") {
            Some(format!(
                "Additional CSP guidance: {}",
                self.remediation
            ))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_creation() {
        let evidence = XssEvidence::new(
            "Reflected XSS".to_string(),
            "https://example.com/search".to_string(),
            "<script>alert(1)</script>".to_string(),
            XssContext::JavaScript,
            Severity::High,
            "Implement CSP".to_string(),
        );
        
        assert_eq!(evidence.vulnerability_type, "Reflected XSS");
        assert_eq!(evidence.severity, Severity::High);
        assert!(!evidence.callback_triggered);
    }

    #[test]
    fn test_evidence_with_modifiers() {
        let evidence = XssEvidence::new(
            "Blind XSS".to_string(),
            "https://admin.example.com".to_string(),
            "<img onerror=fetch()>".to_string(),
            XssContext::EventHandler,
            Severity::Critical,
            "Implement input validation".to_string(),
        )
        .with_stack_trace("Line 42".to_string())
        .with_callback_triggered();
        
        assert!(evidence.stack_trace.is_some());
        assert!(evidence.callback_triggered);
        assert!(evidence.is_critical());
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }
}
