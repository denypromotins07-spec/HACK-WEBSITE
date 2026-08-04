//! GraphQL Introspection Detection Module
//! Detects __schema and __type introspection endpoints to map the full type system.

use crate::checks::CheckModule;
use crate::http::RequestBuilder;
use crate::findings::Finding;
use std::collections::BTreeMap;
use std::sync::Arc;

const INTROSPECTION_QUERY: &str = r#"
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          type {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
          defaultValue
        }
        type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
            }
          }
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        description
        type {
          kind
          name
          ofType {
            kind
            name
          }
        }
        defaultValue
      }
      interfaces {
        kind
        name
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        kind
        name
      }
    }
    directives {
      name
      description
      locations
      args {
        name
        description
        type {
          kind
          name
          ofType {
            kind
            name
          }
        }
        defaultValue
      }
    }
  }
}
"#;

pub struct IntrospectionCheck {
    enabled: bool,
    timeout_ms: u64,
}

impl IntrospectionCheck {
    pub fn new() -> Self {
        Self {
            enabled: true,
            timeout_ms: 5000,
        }
    }

    fn probe_introspection(&self, base_url: &str, client: &reqwest::Client) -> Option<BTreeMap<String, serde_json::Value>> {
        let payload = serde_json::json!({
            "query": INTROSPECTION_QUERY
        });

        let resp = client
            .post(base_url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .ok()?;

        if resp.status().is_success() {
            let body: serde_json::Value = resp.json().ok()?;
            if let Some(data) = body.get("data").and_then(|d| d.get("__schema")) {
                return self.parse_schema(data);
            }
        }
        None
    }

    fn parse_schema(&self, schema: &serde_json::Value) -> Option<BTreeMap<String, serde_json::Value>> {
        let mut type_map = BTreeMap::new();
        if let Some(types) = schema.get("types").and_then(|t| t.as_array()) {
            for t in types {
                if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
                    if !name.starts_with("__") || name == "__Schema" || name == "__Type" {
                        type_map.insert(name.to_string(), t.clone());
                    }
                }
            }
        }
        Some(type_map)
    }
}

impl CheckModule for IntrospectionCheck {
    fn name(&self) -> &'static str {
        "graphql_introspection"
    }

    fn description(&self) -> &'static str {
        "Detects GraphQL introspection endpoints (__schema, __type) and maps the full type system"
    }

    fn severity(&self) -> crate::checks::Severity {
        crate::checks::Severity::Medium
    }

    fn run(&self, target: &crate::target::Target, context: &crate::context::ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        if !self.enabled {
            return findings;
        }

        let graphql_endpoints = context.graphql_endpoints();
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .build()
            .unwrap_or_default();

        for endpoint in graphql_endpoints {
            if let Some(schema_map) = self.probe_introspection(&endpoint, &client) {
                let evidence = crate::findings::Evidence::new()
                    .with_detail("endpoint", endpoint.clone())
                    .with_detail("types_discovered", schema_map.len().to_string())
                    .with_raw_response(format!("{:?}", schema_map.keys().collect::<Vec<_>>()));

                findings.push(Finding::new(self.name())
                    .with_target(endpoint)
                    .with_severity(self.severity())
                    .with_title("GraphQL Introspection Enabled")
                    .with_description("The GraphQL endpoint exposes introspection queries allowing full schema enumeration")
                    .with_evidence(evidence)
                    .with_confidence(0.95));
            }
        }

        findings
    }

    fn clone_box(&self) -> Box<dyn CheckModule> {
        Box::new(self.clone())
    }
}

impl Clone for IntrospectionCheck {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            timeout_ms: self.timeout_ms,
        }
    }
}
