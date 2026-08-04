//! API/GraphQL Module Registration
//! Registers API/GraphQL modules with orchestrator, exports metadata, and wires learning caches.

use crate::checks::CheckModule;
use std::sync::Arc;

// GraphQL modules
mod introspection;
mod suggestion;
mod schema_map;
mod query_injection;
mod batching;
mod depth_dos;
mod mass_assignment;

// API modules
mod endpoint_enum;

// gRPC modules
mod reflection;

// XXE modules
mod basic as xxe_basic;
mod blind as xxe_blind;

// JSON modules
mod bomb as json_bomb;

pub use introspection::IntrospectionCheck;
pub use suggestion::SuggestionCheck;
pub use schema_map::SchemaMap;
pub use query_injection::QueryInjectionCheck;
pub use batching::BatchingCheck;
pub use depth_dos::DepthDosCheck;
pub use mass_assignment::GraphqlMassAssignmentCheck;
pub use endpoint_enum::EndpointEnumCheck;
pub use reflection::GrpcReflectionCheck;
pub use xxe_basic::XXEBasicCheck;
pub use xxe_blind::XXEBlindCheck;
pub use json_bomb::JsonBombCheck;

/// Metadata for the API/GraphQL check module group
pub const MODULE_METADATA: &[(&str, &str, &str)] = &[
    ("graphql_introspection", "GraphQL", "Detects exposed introspection endpoints"),
    ("graphql_suggestion", "GraphQL", "Exploits field suggestions for schema reconstruction"),
    ("graphql_query_injection", "GraphQL", "Detects query injection vulnerabilities"),
    ("graphql_batching", "GraphQL", "Detects rate-limit bypass via batching"),
    ("graphql_depth_dos", "GraphQL", "Detects depth/complexity DoS vulnerabilities"),
    ("graphql_mass_assignment", "GraphQL", "Detects mass assignment in mutations"),
    ("api_endpoint_enum", "API", "Enumerates hidden API endpoints"),
    ("grpc_reflection", "gRPC", "Detects gRPC reflection exposure"),
    ("xxe_basic", "XXE", "Detects basic XXE injection"),
    ("xxe_blind", "XXE", "Detects blind XXE via OOB/time-based methods"),
    ("json_bomb", "JSON", "Detects JSON bomb/DoS vulnerabilities"),
];

/// Creates all API/GraphQL check modules
pub fn create_all_checks() -> Vec<Box<dyn CheckModule>> {
    vec![
        Box::new(IntrospectionCheck::new()),
        Box::new(SuggestionCheck::new()),
        Box::new(QueryInjectionCheck::new()),
        Box::new(BatchingCheck::new()),
        Box::new(DepthDosCheck::new()),
        Box::new(GraphqlMassAssignmentCheck::new()),
        Box::new(EndpointEnumCheck::new()),
        Box::new(GrpcReflectionCheck::new()),
        Box::new(XXEBasicCheck::new()),
        Box::new(XXEBlindCheck::new()),
        Box::new(JsonBombCheck::new()),
    ]
}

/// Creates checks filtered by category
pub fn create_checks_by_category(category: &str) -> Vec<Box<dyn CheckModule>> {
    match category {
        "graphql" => vec![
            Box::new(IntrospectionCheck::new()),
            Box::new(SuggestionCheck::new()),
            Box::new(QueryInjectionCheck::new()),
            Box::new(BatchingCheck::new()),
            Box::new(DepthDosCheck::new()),
            Box::new(GraphqlMassAssignmentCheck::new()),
        ],
        "api" => vec![
            Box::new(EndpointEnumCheck::new()),
        ],
        "grpc" => vec![
            Box::new(GrpcReflectionCheck::new()),
        ],
        "xxe" => vec![
            Box::new(XXEBasicCheck::new()),
            Box::new(XXEBlindCheck::new()),
        ],
        "json" => vec![
            Box::new(JsonBombCheck::new()),
        ],
        _ => vec![],
    }
}

/// Gets metadata for a specific check
pub fn get_check_metadata(check_name: &str) -> Option<(&'static str, &'static str)> {
    for &(name, category, desc) in MODULE_METADATA {
        if name == check_name {
            return Some((category, desc));
        }
    }
    None
}

/// Gets all module names
pub fn get_all_module_names() -> Vec<&'static str> {
    MODULE_METADATA.iter().map(|&(name, _, _)| name).collect()
}

/// Gets modules by severity threshold
pub fn create_checks_above_severity(min_severity: crate::checks::Severity) -> Vec<Box<dyn CheckModule>> {
    let all = create_all_checks();
    all.into_iter()
        .filter(|check| {
            let sev = check.severity();
            sev >= min_severity
        })
        .collect()
}

/// Configuration for API/GraphQL scanning
#[derive(Debug, Clone)]
pub struct ApiGraphqlConfig {
    pub enable_graphql: bool,
    pub enable_api_enum: bool,
    pub enable_grpc: bool,
    pub enable_xxe: bool,
    pub enable_json_bomb: bool,
    pub max_introspection_depth: usize,
    pub max_batch_size: usize,
    pub xxe_timeout_ms: u64,
    pub json_bomb_max_depth: usize,
}

impl Default for ApiGraphqlConfig {
    fn default() -> Self {
        Self {
            enable_graphql: true,
            enable_api_enum: true,
            enable_grpc: true,
            enable_xxe: true,
            enable_json_bomb: true,
            max_introspection_depth: 10,
            max_batch_size: 50,
            xxe_timeout_ms: 8000,
            json_bomb_max_depth: 500,
        }
    }
}

impl ApiGraphqlConfig {
    pub fn with_disabled_xxe(mut self) -> Self {
        self.enable_xxe = false;
        self
    }

    pub fn with_disabled_graphql(mut self) -> Self {
        self.enable_graphql = false;
        self
    }

    pub fn to_checks(&self) -> Vec<Box<dyn CheckModule>> {
        let mut checks = Vec::new();

        if self.enable_graphql {
            checks.push(Box::new(IntrospectionCheck::new()));
            checks.push(Box::new(SuggestionCheck::new()));
            checks.push(Box::new(QueryInjectionCheck::new()));
            checks.push(Box::new(BatchingCheck::new()));
            checks.push(Box::new(DepthDosCheck::new()));
            checks.push(Box::new(GraphqlMassAssignmentCheck::new()));
        }

        if self.enable_api_enum {
            checks.push(Box::new(EndpointEnumCheck::new()));
        }

        if self.enable_grpc {
            checks.push(Box::new(GrpcReflectionCheck::new()));
        }

        if self.enable_xxe {
            checks.push(Box::new(XXEBasicCheck::new()));
            checks.push(Box::new(XXEBlindCheck::new()));
        }

        if self.enable_json_bomb {
            checks.push(Box::new(JsonBombCheck::new()));
        }

        checks
    }
}
