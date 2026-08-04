//! Access Control Evidence Module
//! Builds access-control evidence with persona diffs, object IDs, and request/response pairs.

use crate::findings::finding::Finding;
use crate::findings::severity::Severity;
use std::collections::HashMap;

/// Evidence for access control vulnerabilities
#[derive(Debug, Clone)]
pub struct AccessEvidence {
    /// Vulnerability type
    pub vuln_type: String,
    /// Original user/session ID
    pub original_user: String,
    /// Attacking user/session ID  
    pub attacker_user: String,
    /// Object ID that was accessed
    pub object_id: Option<String>,
    /// Endpoint where vulnerability occurred
    pub endpoint: String,
    /// HTTP method used
    pub method: String,
    /// Original request
    pub request_data: HashMap<String, String>,
    /// Original response
    pub original_response: ResponseData,
    /// Modified/tampered response
    pub modified_response: ResponseData,
    /// Persona comparison data
    pub persona_diff: PersonaDiff,
    /// Confidence score (0-100)
    pub confidence: u8,
}

/// Response data snapshot
#[derive(Debug, Clone)]
pub struct ResponseData {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body_preview: String,
    pub body_hash: String,
    pub response_time_ms: u64,
}

/// Comparison between user personas
#[derive(Debug, Clone)]
pub struct PersonaDiff {
    /// Original user role
    pub original_role: String,
    /// Attacker user role
    pub attacker_role: String,
    /// Permission differences found
    pub permission_diffs: Vec<String>,
    /// Data accessible to original but not attacker (should be empty if bypass works)
    pub exclusive_data_original: Vec<String>,
    /// Data accessible to attacker (indicates bypass)
    pub accessible_to_attacker: Vec<String>,
}

impl AccessEvidence {
    pub fn new(vuln_type: &str, original_user: &str, attacker_user: &str, endpoint: &str) -> Self {
        Self {
            vuln_type: vuln_type.to_string(),
            original_user: original_user.to_string(),
            attacker_user: attacker_user.to_string(),
            object_id: None,
            endpoint: endpoint.to_string(),
            method: "GET".to_string(),
            request_data: HashMap::new(),
            original_response: ResponseData::default(),
            modified_response: ResponseData::default(),
            persona_diff: PersonaDiff::default(),
            confidence: 50,
        }
    }

    pub fn with_object_id(mut self, object_id: String) -> Self {
        self.object_id = Some(object_id);
        self
    }

    pub fn with_method(mut self, method: String) -> Self {
        self.method = method;
        self
    }

    pub fn with_request_data(mut self, key: &str, value: &str) -> Self {
        self.request_data.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_original_response(mut self, response: ResponseData) -> Self {
        self.original_response = response;
        self
    }

    pub fn with_modified_response(mut self, response: ResponseData) -> Self {
        self.modified_response = response;
        self
    }

    pub fn with_persona_diff(mut self, diff: PersonaDiff) -> Self {
        self.persona_diff = diff;
        self
    }

    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(100);
        self
    }

    /// Convert evidence into a Finding
    pub fn into_finding(self) -> Finding {
        let severity = match self.vuln_type.as_str() {
            t if t.contains("IDOR") || t.contains("BOLA") => Severity::High,
            t if t.contains("Mass Assignment") => Severity::Critical,
            t if t.contains("BFLA") || t.contains("Function Level") => Severity::High,
            t if t.contains("MFA") => Severity::Critical,
            t if t.contains("Race") => Severity::High,
            t if t.contains("JWT") => Severity::Critical,
            t if t.contains("Business Logic") => Severity::High,
            _ => Severity::Medium,
        };

        let mut description = format!(
            "{} detected: User '{}' ({}) accessed resources of user '{}' ({})",
            self.vuln_type,
            self.attacker_user,
            self.persona_diff.attacker_role,
            self.original_user,
            self.persona_diff.original_role,
        );

        if let Some(ref object_id) = self.object_id {
            description.push_str(&format!(" via object ID: {}", object_id));
        }

        Finding::new()
            .with_title(&self.vuln_type)
            .with_description(&description)
            .with_endpoint(&self.endpoint)
            .with_method(self.method)
            .with_severity(severity)
            .with_evidence(&format!(
                "Confidence: {}%\nRequest: {:?}\nOriginal Response: {}\nModified Response: {}",
                self.confidence,
                self.request_data,
                self.original_response.body_preview,
                self.modified_response.body_preview,
            ))
    }
}

impl Default for ResponseData {
    fn default() -> Self {
        Self {
            status_code: 0,
            headers: HashMap::new(),
            body_preview: String::new(),
            body_hash: String::new(),
            response_time_ms: 0,
        }
    }
}

impl Default for PersonaDiff {
    fn default() -> Self {
        Self {
            original_role: "unknown".to_string(),
            attacker_role: "unknown".to_string(),
            permission_diffs: Vec::new(),
            exclusive_data_original: Vec::new(),
            accessible_to_attacker: Vec::new(),
        }
    }
}

/// Builder for creating access evidence from HTTP responses
pub struct AccessEvidenceBuilder {
    evidence: AccessEvidence,
}

impl AccessEvidenceBuilder {
    pub fn new(vuln_type: &str, original_user: &str, attacker_user: &str, endpoint: &str) -> Self {
        Self {
            evidence: AccessEvidence::new(vuln_type, original_user, attacker_user, endpoint),
        }
    }

    pub fn add_response_comparison(
        mut self,
        original_status: u16,
        original_body: &str,
        modified_status: u16,
        modified_body: &str,
    ) -> Self {
        self.evidence.original_response.status_code = original_status;
        self.evidence.original_response.body_preview = 
            original_body[..original_body.len().min(200)].to_string();
        
        self.evidence.modified_response.status_code = modified_status;
        self.evidence.modified_response.body_preview = 
            modified_body[..modified_body.len().min(200)].to_string();

        // Calculate simple hash for comparison
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        original_body.hash(&mut hasher);
        self.evidence.original_response.body_hash = hasher.finish().to_string();
        
        let mut hasher = DefaultHasher::new();
        modified_body.hash(&mut hasher);
        self.evidence.modified_response.body_hash = hasher.finish().to_string();

        self
    }

    pub fn add_persona_info(mut self, original_role: &str, attacker_role: &str) -> Self {
        self.evidence.persona_diff.original_role = original_role.to_string();
        self.evidence.persona_diff.attacker_role = attacker_role.to_string();
        self
    }

    pub fn build(self) -> AccessEvidence {
        self.evidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_creation() {
        let evidence = AccessEvidence::new("IDOR", "user1", "user2", "/api/users/123");
        
        assert_eq!(evidence.vuln_type, "IDOR");
        assert_eq!(evidence.original_user, "user1");
        assert_eq!(evidence.attacker_user, "user2");
        assert_eq!(evidence.endpoint, "/api/users/123");
    }

    #[test]
    fn test_evidence_builder() {
        let evidence = AccessEvidenceBuilder::new("BOLA", "admin", "user", "/api/posts/1")
            .add_response_comparison(200, "{\"data\": \"admin post\"}", 200, "{\"data\": \"admin post\"}")
            .add_persona_info("admin", "regular_user")
            .build();

        assert_eq!(evidence.original_response.status_code, 200);
        assert_eq!(evidence.persona_diff.original_role, "admin");
        assert_eq!(evidence.persona_diff.attacker_role, "regular_user");
    }

    #[test]
    fn test_finding_conversion() {
        let evidence = AccessEvidence::new("IDOR", "user1", "user2", "/api/data/1")
            .with_object_id("1".to_string())
            .with_confidence(90);

        let finding = evidence.into_finding();
        
        assert!(finding.title().contains("IDOR"));
        assert_eq!(finding.severity(), &Severity::High);
    }
}
