//! Safe Detection Payloads - Harmless canary strings and validation markers
//!
//! Implements non-destructive payloads for vulnerability detection including
//! canary strings, mathematical checks, and time-delay markers. All payloads
//! in this module are guaranteed safe for production use.

use crate::payload::{GeneratedPayload, PayloadClass, Severity, SafetyLevel};
use std::time::{SystemTime, UNIX_EPOCH};

/// Types of canary strings for reflection detection
#[derive(Debug, Clone, Copy)]
pub enum CanaryType {
    /// Simple alphanumeric canary
    Alphanumeric,
    /// UUID-style canary
    Uuid,
    /// XML-style canary
    Xml,
    /// HTML-style canary
    Html,
    /// JavaScript-style canary
    Javascript,
    /// Random bytes (hex encoded)
    RandomHex,
}

impl CanaryType {
    pub fn generate(&self) -> String {
        match self {
            CanaryType::Alphanumeric => self.gen_alphanumeric(),
            CanaryType::Uuid => self.gen_uuid(),
            CanaryType::Xml => self.gen_xml(),
            CanaryType::Html => self.gen_html(),
            CanaryType::Javascript => self.gen_javascript(),
            CanaryType::RandomHex => self.gen_random_hex(),
        }
    }

    fn gen_alphanumeric(&self) -> String {
        format!("CANARY{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())
    }

    fn gen_uuid(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let mut hasher = DefaultHasher::new();
        now.hash(&mut hasher);
        let hash = hasher.finish();
        
        format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            hash & 0xFFFFFFFF,
            (hash >> 32) & 0xFFFF,
            (hash >> 48) & 0xFFFF,
            (hash >> 64) & 0xFFFF,
            hash.wrapping_mul(0x123456789ABCDEF0)
        )
    }

    fn gen_xml(&self) -> String {
        format!("<canary>{}</canary>", self.gen_alphanumeric())
    }

    fn gen_html(&self) -> String {
        format!("<div id=\"canary-{0}\">{0}</div>", self.gen_alphanumeric())
    }

    fn gen_javascript(&self) -> String {
        format!("var canary_{0} = \"{0}\";", self.gen_alphanumeric())
    }

    fn gen_random_hex(&self) -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
        format!("{:016x}", now)
    }
}

/// Mathematical check payloads for expression evaluation testing
#[derive(Debug, Clone)]
pub struct MathCheck {
    pub expression: String,
    pub expected_result: String,
    pub description: String,
}

impl MathCheck {
    /// SQL math checks
    pub fn sql_checks() -> Vec<Self> {
        vec![
            Self {
                expression: "SELECT 1+1".into(),
                expected_result: "2".into(),
                description: "Basic SQL addition".into(),
            },
            Self {
                expression: "SELECT CONCAT('a', 'b')".into(),
                expected_result: "ab".into(),
                description: "SQL string concatenation".into(),
            },
            Self {
                expression: "SELECT LENGTH('test')".into(),
                expected_result: "4".into(),
                description: "SQL string length".into(),
            },
            Self {
                expression: "SELECT SUBSTRING('hello', 1, 2)".into(),
                expected_result: "he".into(),
                description: "SQL substring".into(),
            },
        ]
    }

    /// JavaScript math checks
    pub fn js_checks() -> Vec<Self> {
        vec![
            Self {
                expression: "1+1".into(),
                expected_result: "2".into(),
                description: "JS addition".into(),
            },
            Self {
                expression: "'a'+'b'".into(),
                expected_result: "ab".into(),
                description: "JS string concat".into(),
            },
            Self {
                expression: "Math.sqrt(16)".into(),
                expected_result: "4".into(),
                description: "JS math function".into(),
            },
        ]
    }

    /// Template expression checks
    pub fn template_checks() -> Vec<Self> {
        vec![
            Self {
                expression: "${{1+1}}".into(),
                expected_result: "2".into(),
                description: "Spring EL addition".into(),
            },
            Self {
                expression: "{{1+1}}".into(),
                expected_result: "2".into(),
                description: "Jinja2 addition".into(),
            },
            Self {
                expression: "<%= 1+1 %>".into(),
                expected_result: "2".into(),
                description: "ERB addition".into(),
            },
        ]
    }

    pub fn to_payload(&self, class: PayloadClass) -> GeneratedPayload {
        GeneratedPayload::new(
            format!("math-{}", self.description.replace(' ', "-").to_lowercase()),
            &self.expression,
            class,
            Severity::Medium,
            SafetyLevel::Safe,
        )
    }
}

/// Time-delay markers for blind detection
#[derive(Debug, Clone)]
pub struct TimeMarker {
    pub payload: String,
    pub delay_ms: u64,
    pub context: &'static str,
}

impl TimeMarker {
    /// SQL time-based payloads (safe delays)
    pub fn sql_delays() -> Vec<Self> {
        vec![
            Self {
                payload: "'; WAITFOR DELAY '0:0:1' --".into(),
                delay_ms: 1000,
                context: "mssql",
            },
            Self {
                payload: "'; SELECT SLEEP(1) --".into(),
                delay_ms: 1000,
                context: "mysql",
            },
            Self {
                payload: "'; SELECT pg_sleep(1) --".into(),
                delay_ms: 1000,
                context: "postgres",
            },
        ]
    }

    /// Command injection time delays (safe ping commands)
    pub fn command_delays() -> Vec<Self> {
        vec![
            Self {
                payload: "; sleep 1".into(),
                delay_ms: 1000,
                context: "unix",
            },
            Self {
                payload: " && sleep 1".into(),
                delay_ms: 1000,
                context: "unix",
            },
            Self {
                payload: "| timeout /t 1".into(),
                delay_ms: 1000,
                context: "windows",
            },
        ]
    }

    /// LDAP time-based patterns
    pub fn ldap_delays() -> Vec<Self> {
        vec![
            Self {
                payload: "*)(uid=*)(&(uid=*".into(),
                delay_ms: 0,
                context: "ldap-injection",
            },
        ]
    }

    pub fn to_payload(&self, class: PayloadClass) -> GeneratedPayload {
        GeneratedPayload::new(
            format!("time-{}-{}ms", self.context, self.delay_ms),
            &self.payload,
            class,
            Severity::Medium,
            SafetyLevel::Safe,
        )
    }
}

/// Safe payload generator for initial reconnaissance
#[derive(Debug, Default)]
pub struct SafePayloadGenerator {
    counter: u64,
}

impl SafePayloadGenerator {
    pub fn new() -> Self {
        Self { counter: 0 }
    }

    /// Generate a single safe canary payload
    pub fn generate_canary(&mut self, canary_type: CanaryType) -> GeneratedPayload {
        self.counter += 1;
        let value = canary_type.generate();
        
        GeneratedPayload::new(
            format!("canary-{}-{}", canary_type.as_str(), self.counter),
            &value,
            PayloadClass::InfoDisclosure,
            Severity::Info,
            SafetyLevel::Safe,
        )
    }

    /// Generate a batch of mixed safe payloads
    pub fn generate_batch(&self, count: usize) -> Vec<GeneratedPayload> {
        let mut payloads = Vec::with_capacity(count);
        
        // Distribute across different safe payload types
        let canaries = count / 3;
        let math = count / 3;
        let times = count - canaries - math;

        // Add canary payloads
        for (i, canary_type) in [
            CanaryType::Alphanumeric,
            CanaryType::Uuid,
            CanaryType::Html,
            CanaryType::Javascript,
        ].iter().cycle().take(canaries).enumerate() {
            payloads.push(GeneratedPayload::new(
                format!("canary-{}", i),
                canary_type.generate(),
                PayloadClass::InfoDisclosure,
                Severity::Info,
                SafetyLevel::Safe,
            ));
        }

        // Add math check payloads
        for check in MathCheck::sql_checks().into_iter().take(math) {
            payloads.push(check.to_payload(PayloadClass::SqlInjection));
        }

        // Add time marker payloads
        for marker in TimeMarker::sql_delays().into_iter().take(times) {
            payloads.push(marker.to_payload(PayloadClass::SqlInjection));
        }

        payloads.truncate(count);
        payloads
    }

    /// Generate XSS-safe reflection test payloads
    pub fn generate_xss_safe(&self) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new(
                "xss-safe-001",
                "<script>console.log('XSS-TEST')</script>",
                PayloadClass::Xss,
                Severity::Low,
                SafetyLevel::Safe,
            ),
            GeneratedPayload::new(
                "xss-safe-002",
                "<img src=x onerror=console.log('XSS-TEST')>",
                PayloadClass::Xss,
                Severity::Low,
                SafetyLevel::Safe,
            ),
            GeneratedPayload::new(
                "xss-safe-003",
                "\"><script>alert('XSS-TEST')</script>",
                PayloadClass::Xss,
                Severity::Low,
                SafetyLevel::Safe,
            ),
        ]
    }

    /// Generate SSRF-safe internal IP checks
    pub fn generate_ssrf_safe(&self) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new(
                "ssrf-safe-001",
                "http://127.0.0.1",
                PayloadClass::Ssrf,
                Severity::Low,
                SafetyLevel::Safe,
            ),
            GeneratedPayload::new(
                "ssrf-safe-002",
                "http://localhost",
                PayloadClass::Ssrf,
                Severity::Low,
                SafetyLevel::Safe,
            ),
            GeneratedPayload::new(
                "ssrf-safe-003",
                "http://0.0.0.0",
                PayloadClass::Ssrf,
                Severity::Low,
                SafetyLevel::Safe,
            ),
        ]
    }

    /// Generate path traversal safe checks
    pub fn generate_traversal_safe(&self) -> Vec<GeneratedPayload> {
        vec![
            GeneratedPayload::new(
                "traversal-safe-001",
                "../../../etc/passwd",
                PayloadClass::PathTraversal,
                Severity::Low,
                SafetyLevel::Safe,
            ),
            GeneratedPayload::new(
                "traversal-safe-002",
                "..\\..\\..\\windows\\system32\\config\\sam",
                PayloadClass::PathTraversal,
                Severity::Low,
                SafetyLevel::Safe,
            ),
        ]
    }
}

impl CanaryType {
    fn as_str(&self) -> &'static str {
        match self {
            CanaryType::Alphanumeric => "alnum",
            CanaryType::Uuid => "uuid",
            CanaryType::Xml => "xml",
            CanaryType::Html => "html",
            CanaryType::Javascript => "js",
            CanaryType::RandomHex => "hex",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_generation() {
        let mut gen = SafePayloadGenerator::new();
        
        let canary = gen.generate_canary(CanaryType::Alphanumeric);
        assert!(canary.raw.starts_with("CANARY"));
        assert_eq!(canary.safety, SafetyLevel::Safe);

        let uuid_canary = gen.generate_canary(CanaryType::Uuid);
        assert!(uuid_canary.raw.contains('-'));
    }

    #[test]
    fn test_math_checks() {
        let sql_checks = MathCheck::sql_checks();
        assert!(!sql_checks.is_empty());
        
        for check in &sql_checks {
            assert!(!check.expression.is_empty());
            assert!(!check.expected_result.is_empty());
        }
    }

    #[test]
    fn test_time_markers() {
        let delays = TimeMarker::sql_delays();
        assert!(!delays.is_empty());
        
        for marker in &delays {
            assert!(marker.delay_ms > 0);
        }
    }

    #[test]
    fn test_batch_generation() {
        let gen = SafePayloadGenerator::new();
        let batch = gen.generate_batch(10);
        
        assert_eq!(batch.len(), 10);
        for payload in &batch {
            assert_eq!(payload.safety, SafetyLevel::Safe);
        }
    }
}
