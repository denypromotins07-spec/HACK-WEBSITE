//! API/GraphQL Evidence Container Module
//! Builds evidence containers for API/GraphQL findings with schema diffs and request logs.

use std::collections::BTreeMap;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiGraphqlEvidence {
    pub endpoint: String,
    pub method: Option<String>,
    pub request_headers: BTreeMap<String, String>,
    pub request_body: Option<String>,
    pub response_status: u16,
    pub response_headers: BTreeMap<String, String>,
    pub response_body: Option<String>,
    pub schema_diff: Option<SchemaDiff>,
    pub timing_ms: u64,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDiff {
    pub before: Option<String>,
    pub after: Option<String>,
    pub added_fields: Vec<String>,
    pub removed_fields: Vec<String>,
    pub modified_fields: Vec<FieldChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    pub field_name: String,
    pub change_type: String, // "type_change", "nullability", "default_value"
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlOperationLog {
    pub operation_type: String, // "query", "mutation", "subscription"
    pub operation_name: Option<String>,
    pub query_string: String,
    pub variables: Option<String>,
    pub result_summary: OperationResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationResult {
    Success { data_size: usize },
    Error { message: String, code: Option<String> },
    Partial { data_size: usize, errors: Vec<String> },
}

impl ApiGraphqlEvidence {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            method: None,
            request_headers: BTreeMap::new(),
            request_body: None,
            response_status: 0,
            response_headers: BTreeMap::new(),
            response_body: None,
            schema_diff: None,
            timing_ms: 0,
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_method(mut self, method: &str) -> Self {
        self.method = Some(method.to_string());
        self
    }

    pub fn with_request_header(mut self, key: &str, value: &str) -> Self {
        self.request_headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_request_body(mut self, body: &str) -> Self {
        self.request_body = Some(body.to_string());
        self
    }

    pub fn with_response_status(mut self, status: u16) -> Self {
        self.response_status = status;
        self
    }

    pub fn with_response_header(mut self, key: &str, value: &str) -> Self {
        self.response_headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_response_body(mut self, body: &str) -> Self {
        self.response_body = Some(body.to_string());
        self
    }

    pub fn with_schema_diff(mut self, diff: SchemaDiff) -> Self {
        self.schema_diff = Some(diff);
        self
    }

    pub fn with_timing(mut self, ms: u64) -> Self {
        self.timing_ms = ms;
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    pub fn to_redacted(&self) -> Self {
        let mut redacted = self.clone();
        
        // Redact sensitive fields in request/response bodies
        if let Some(ref mut body) = redacted.request_body {
            redact_sensitive_data(body);
        }
        if let Some(ref mut body) = redacted.response_body {
            redact_sensitive_data(body);
        }

        // Redact auth headers
        redacted.request_headers.retain(|k, _| {
            !k.to_lowercase().contains("auth") && 
            !k.to_lowercase().contains("token") &&
            !k.to_lowercase().contains("cookie") &&
            !k.to_lowercase().contains("api-key")
        });

        redacted
    }
}

fn redact_sensitive_data(data: &mut String) {
    let patterns = [
        ("password", "***REDACTED***"),
        ("secret", "***REDACTED***"),
        ("token", "***REDACTED***"),
        ("api_key", "***REDACTED***"),
        ("apikey", "***REDACTED***"),
        ("authorization", "***REDACTED***"),
    ];

    for (pattern, replacement) in patterns.iter() {
        if data.to_lowercase().contains(pattern) {
            *data = data.replace(pattern, replacement);
        }
    }
}

impl From<ApiGraphqlEvidence> for crate::findings::Evidence {
    fn from(evidence: ApiGraphqlEvidence) -> Self {
        let mut finding_evidence = crate::findings::Evidence::new()
            .with_detail("endpoint", evidence.endpoint)
            .with_detail("response_status", evidence.response_status.to_string())
            .with_detail("timing_ms", evidence.timing_ms.to_string());

        if let Some(method) = evidence.method {
            finding_evidence = finding_evidence.with_detail("method", method);
        }

        if let Some(schema_diff) = evidence.schema_diff {
            finding_evidence = finding_evidence.with_detail(
                "schema_changes",
                format!("added: {}, removed: {}, modified: {}",
                    schema_diff.added_fields.len(),
                    schema_diff.removed_fields.len(),
                    schema_diff.modified_fields.len()
                )
            );
        }

        if let Some(body) = evidence.response_body {
            finding_evidence = finding_evidence.with_raw_response(body.chars().take(1000).to_string());
        }

        finding_evidence
    }
}
