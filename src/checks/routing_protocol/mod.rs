//! Routing and Protocol Module Registry
//! Registers routing and protocol modules with the orchestrator and exports metadata.
//! Uses bounded storage and zero-copy byte buffers (Stage 1 memory constraints).

use crate::checks::Check;
use crate::learning::Cache;
use crate::findings::Finding;

// Import all routing and protocol check modules
use super::routing::hop_by_hop::HopByHopCheck;
use super::routing::x_forwarded::XForwardedCheck;
use super::routing::fat_get::FatGetCheck;
use super::routing::url_parsing::UrlParsingCheck;
use super::routing::proxy_collapse::ProxyCollapseCheck;
use super::routing::cloudfront_sig::CloudFrontSigCheck;
use super::protocol::grpc_web::GrpcWebCheck;
use super::protocol::http2_mux::Http2MuxCheck;
use super::protocol::sni_routing::SniRoutingCheck;
use super::protocol::websocket_mask::WebsocketMaskCheck;
use super::protocol::sse_injection::SseInjectionCheck;
use super::protocol::http3_quic::Http3QuicCheck;

/// Maximum number of registered checks (bounded)
const MAX_REGISTERED_CHECKS: usize = 32;

/// Module metadata for orchestrator registration
#[derive(Debug, Clone)]
pub struct ModuleMetadata {
    pub name: &'static str,
    pub description: &'static str,
    pub category: CheckCategory,
    pub severity_default: &'static str,
    pub enabled_by_default: bool,
    pub god_mode_required: bool,
    pub timeout_ms_default: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CheckCategory {
    HopByHop,
    ProxyManipulation,
    UrlParsing,
    ProtocolEngineering,
    WebSocket,
    Streaming,
    QuicHttp3,
}

impl CheckCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            CheckCategory::HopByHop => "hop_by_hop",
            CheckCategory::ProxyManipulation => "proxy_manipulation",
            CheckCategory::UrlParsing => "url_parsing",
            CheckCategory::ProtocolEngineering => "protocol_engineering",
            CheckCategory::WebSocket => "websocket",
            CheckCategory::Streaming => "streaming",
            CheckCategory::QuicHttp3 => "quic_http3",
        }
    }
}

/// Registry for routing and protocol checks
pub struct RoutingProtocolRegistry {
    modules: Vec<ModuleMetadata>,
    checks: Vec<Box<dyn Check + Send + Sync>>,
    max_checks: usize,
}

impl RoutingProtocolRegistry {
    pub fn new() -> Self {
        Self {
            modules: Vec::with_capacity(MAX_REGISTERED_CHECKS),
            checks: Vec::with_capacity(MAX_REGISTERED_CHECKS),
            max_checks: MAX_REGISTERED_CHECKS,
        }
    }

    /// Register all routing and protocol checks
    pub fn register_all(&mut self, timeout_ms: u64, god_mode: bool) {
        // Chapter 1: Hop-by-Hop & Header Manipulation
        self.register(HopByHopCheck::new(timeout_ms, god_mode), ModuleMetadata {
            name: "hop_by_hop",
            description: "Detect hop-by-hop header stripping to drop proxy security attributes",
            category: CheckCategory::HopByHop,
            severity_default: "CRITICAL",
            enabled_by_default: true,
            god_mode_required: false,
            timeout_ms_default: 5000,
        });

        self.register(XForwardedCheck::new(timeout_ms, god_mode), ModuleMetadata {
            name: "x_forwarded",
            description: "Detect internal proxy tracking abuse via X-Forwarded-Host manipulation",
            category: CheckCategory::ProxyManipulation,
            severity_default: "HIGH",
            enabled_by_default: true,
            god_mode_required: false,
            timeout_ms_default: 5000,
        });

        self.register(FatGetCheck::new(timeout_ms, god_mode), ModuleMetadata {
            name: "fat_get",
            description: "Detect Fat GET request processing with JSON bodies in HTTP GET",
            category: CheckCategory::UrlParsing,
            severity_default: "MEDIUM",
            enabled_by_default: true,
            god_mode_required: false,
            timeout_ms_default: 5000,
        });

        // Chapter 2: Proxy Collapse & URL Parsing
        self.register(UrlParsingCheck::new(timeout_ms, god_mode), ModuleMetadata {
            name: "url_parsing",
            description: "Detect URL parsing discrepancies between Nginx, Apache, and other servers",
            category: CheckCategory::UrlParsing,
            severity_default: "HIGH",
            enabled_by_default: true,
            god_mode_required: false,
            timeout_ms_default: 5000,
        });

        self.register(ProxyCollapseCheck::new(timeout_ms, god_mode), ModuleMetadata {
            name: "proxy_collapse",
            description: "Detect reverse proxy collapse via HTTP Upgrade headers",
            category: CheckCategory::ProxyManipulation,
            severity_default: "CRITICAL",
            enabled_by_default: true,
            god_mode_required: true,
            timeout_ms_default: 5000,
        });

        self.register(CloudFrontSigCheck::new(timeout_ms, god_mode), ModuleMetadata {
            name: "cloudfront_sig",
            description: "Identify CloudFront/CDN signature validation gaps",
            category: CheckCategory::ProxyManipulation,
            severity_default: "CRITICAL",
            enabled_by_default: true,
            god_mode_required: false,
            timeout_ms_default: 5000,
        });

        // Chapter 3: Advanced Protocol Engineering
        self.register(GrpcWebCheck::new(timeout_ms, god_mode), ModuleMetadata {
            name: "grpc_web",
            description: "Profile gRPC-Web reflection and parse binary proto-frames",
            category: CheckCategory::ProtocolEngineering,
            severity_default: "HIGH",
            enabled_by_default: true,
            god_mode_required: false,
            timeout_ms_default: 5000,
        });

        self.register(Http2MuxCheck::new(timeout_ms, god_mode), ModuleMetadata {
            name: "http2_mux",
            description: "Detect HTTP/2 stream multiplexing exhaustion and priority frame abuse",
            category: CheckCategory::ProtocolEngineering,
            severity_default: "MEDIUM",
            enabled_by_default: true,
            god_mode_required: false,
            timeout_ms_default: 5000,
        });

        self.register(SniRoutingCheck::new(timeout_ms, god_mode), ModuleMetadata {
            name: "sni_routing",
            description: "Detect SNI routing abuse with mismatched TLS handshakes",
            category: CheckCategory::ProtocolEngineering,
            severity_default: "HIGH",
            enabled_by_default: true,
            god_mode_required: false,
            timeout_ms_default: 5000,
        });

        // Chapter 4: WebSockets, SSE, and QUIC
        self.register(WebsocketMaskCheck::new(timeout_ms, god_mode), ModuleMetadata {
            name: "websocket_mask",
            description: "Detect WebSocket frame masking flaws",
            category: CheckCategory::WebSocket,
            severity_default: "CRITICAL",
            enabled_by_default: true,
            god_mode_required: false,
            timeout_ms_default: 5000,
        });

        self.register(SseInjectionCheck::new(timeout_ms, god_mode), ModuleMetadata {
            name: "sse_injection",
            description: "Detect Server-Sent Events header injection and resource exhaustion",
            category: CheckCategory::Streaming,
            severity_default: "HIGH",
            enabled_by_default: true,
            god_mode_required: false,
            timeout_ms_default: 5000,
        });

        self.register(Http3QuicCheck::new(timeout_ms, god_mode), ModuleMetadata {
            name: "http3_quic",
            description: "Detect HTTP/3 QUIC connection migration and stream hijacking",
            category: CheckCategory::QuicHttp3,
            severity_default: "HIGH",
            enabled_by_default: true,
            god_mode_required: false,
            timeout_ms_default: 5000,
        });
    }

    /// Register a single check
    pub fn register<C: Check + Send + Sync + 'static>(&mut self, check: C, metadata: ModuleMetadata) {
        if self.checks.len() < self.max_checks {
            self.checks.push(Box::new(check));
            self.modules.push(metadata);
        }
    }

    /// Run all registered checks on a target
    pub fn run_all(&self, target: &str, cache: &mut dyn Cache) -> Vec<Finding> {
        let mut all_findings = Vec::new();

        for check in &self.checks {
            let findings = check.run(target, cache);
            all_findings.extend(findings);
        }

        all_findings
    }

    /// Get module metadata by name
    pub fn get_metadata(&self, name: &str) -> Option<&ModuleMetadata> {
        self.modules.iter().find(|m| m.name == name)
    }

    /// Export registry metadata as bounded JSON
    pub fn export_metadata_json(&self) -> String {
        let mut json = String::with_capacity(4096);
        json.push_str("{\n  \"registry\": \"routing_protocol\",\n");
        json.push_str(&format!("  \"total_modules\": {},\n", self.modules.len()));
        json.push_str("  \"modules\": [\n");

        let mut first = true;
        for module in &self.modules {
            if !first {
                json.push_str(",\n");
            }
            first = false;
            json.push_str(&format!(
                "    {{\"name\": \"{}\", \"category\": \"{}\", \"severity\": \"{}\", \"enabled\": {}}}",
                module.name,
                module.category.as_str(),
                module.severity_default,
                module.enabled_by_default
            ));
        }

        json.push_str("\n  ]\n}\n");
        json
    }

    /// Get count of registered modules
    pub fn count(&self) -> usize {
        self.modules.len()
    }

    /// Get checks by category
    pub fn get_by_category(&self, category: &CheckCategory) -> Vec<&(dyn Check + Send + Sync)> {
        self.modules.iter()
            .filter(|m| &m.category == category)
            .enumerate()
            .filter_map(|(i, _)| self.checks.get(i).map(|b| b.as_ref()))
            .collect()
    }
}

impl Default for RoutingProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = RoutingProtocolRegistry::new();
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn test_register_all_modules() {
        let mut registry = RoutingProtocolRegistry::new();
        registry.register_all(5000, true);
        
        // Should have 12 modules registered
        assert_eq!(registry.count(), 12);
    }

    #[test]
    fn test_get_metadata() {
        let mut registry = RoutingProtocolRegistry::new();
        registry.register_all(5000, false);
        
        let metadata = registry.get_metadata("sni_routing");
        assert!(metadata.is_some());
        assert_eq!(metadata.unwrap().category, CheckCategory::ProtocolEngineering);
    }
}
