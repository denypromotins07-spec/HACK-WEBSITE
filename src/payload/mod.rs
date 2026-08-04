//! Payload Module - Export interfaces and connect registry to scanner core
//!
//! This module provides the public API for payload generation, classification,
//! and management. It integrates with Stage 2 dispatch and Stage 4 auth contexts
//! without blocking async workers.

pub mod class;
pub mod registry;
pub mod safe;
pub mod oob;
pub mod encoder;

pub use class::{PayloadClass, Severity, SafetyLevel, VulnerabilityTag, ClassificationBuilder};
pub use registry::{PayloadRegistry, PayloadMeta, PayloadId, GLOBAL_PAYLOAD_REGISTRY};
pub use safe::{SafePayloadGenerator, CanaryType, MathCheck, TimeMarker};
pub use oob::{OobPayloadBuilder, OobCallbackType, DnsCallback, HttpCallback, WebhookCallback};
pub use encoder::{PayloadEncoder, EncodingType, EncoderError};

use std::sync::Arc;
use tokio::sync::mpsc;

/// A generated payload ready for injection
#[derive(Debug, Clone)]
pub struct GeneratedPayload {
    pub id: PayloadId,
    pub raw: String,
    pub encoded: Option<String>,
    pub class: PayloadClass,
    pub severity: Severity,
    pub safety: SafetyLevel,
    pub context: InjectionContext,
    pub tags: Vec<VulnerabilityTag>,
}

impl GeneratedPayload {
    pub fn new(
        id: impl Into<String>,
        raw: impl Into<String>,
        class: PayloadClass,
        severity: Severity,
        safety: SafetyLevel,
    ) -> Self {
        Self {
            id: id.into(),
            raw: raw.into(),
            encoded: None,
            class,
            severity,
            safety,
            context: InjectionContext::Unknown,
            tags: Vec::new(),
        }
    }

    pub fn with_encoding(mut self, encoded: String) -> Self {
        self.encoded = Some(encoded);
        self
    }

    pub fn with_context(mut self, context: InjectionContext) -> Self {
        self.context = context;
        self
    }

    pub fn with_tags(mut self, tags: Vec<VulnerabilityTag>) -> Self {
        self.tags = tags;
        self
    }

    /// Get the effective payload (encoded if available, otherwise raw)
    pub fn effective(&self) -> &str {
        self.encoded.as_deref().unwrap_or(&self.raw)
    }
}

/// Injection context for proper payload placement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InjectionContext {
    Unknown,
    UrlQuery,
    UrlPath,
    Header,
    Cookie,
    BodyForm,
    BodyJson,
    BodyXml,
    BodyMultipart,
    HtmlBody,
    HtmlAttribute,
    Javascript,
    SqlQuery,
    LdapQuery,
    XpathQuery,
    ShellCommand,
    FilePath,
}

impl InjectionContext {
    pub fn is_safe_for(&self, safety: SafetyLevel) -> bool {
        match (self, safety) {
            // Always safe contexts
            (_, SafetyLevel::Safe) => true,
            // Low risk allowed in most contexts
            (_, SafetyLevel::LowRisk) => true,
            // Dangerous payloads restricted from certain contexts
            (InjectionContext::FilePath, SafetyLevel::Dangerous) => false,
            (InjectionContext::ShellCommand, SafetyLevel::Dangerous) => false,
            _ => true,
        }
    }
}

/// Configuration for payload generation
#[derive(Debug, Clone)]
pub struct PayloadConfig {
    /// Maximum number of payloads per scan target
    pub max_payloads: usize,
    /// Only generate safe payloads
    pub safe_only: bool,
    /// Require god-mode for dangerous payloads
    pub require_god_mode: bool,
    /// Enabled vulnerability classes
    pub enabled_classes: Vec<PayloadClass>,
    /// Target injection contexts
    pub target_contexts: Vec<InjectionContext>,
    /// Memory limit for payload arena (bytes)
    pub arena_limit: usize,
}

impl Default for PayloadConfig {
    fn default() -> Self {
        Self {
            max_payloads: 1000,
            safe_only: true,
            require_god_mode: true,
            enabled_classes: vec![
                PayloadClass::SqlInjection,
                PayloadClass::Xss,
                PayloadClass::Ssrf,
                PayloadClass::PathTraversal,
                PayloadClass::CommandInjection,
            ],
            target_contexts: vec![
                InjectionContext::UrlQuery,
                InjectionContext::Header,
                InjectionContext::BodyForm,
                InjectionContext::BodyJson,
            ],
            arena_limit: 64 * 1024 * 1024, // 64MB default arena
        }
    }
}

/// Payload generator service for the scanner swarm
pub struct PayloadService {
    registry: Arc<PayloadRegistry>,
    config: PayloadConfig,
    safe_generator: SafePayloadGenerator,
    oob_builder: OobPayloadBuilder,
}

impl PayloadService {
    /// Create a new payload service with the given configuration
    pub fn new(config: PayloadConfig) -> Self {
        Self {
            registry: Arc::new(PayloadRegistry::new()),
            config,
            safe_generator: SafePayloadGenerator::new(),
            oob_builder: OobPayloadBuilder::new(),
        }
    }

    /// Create with global registry
    pub fn with_global_registry(config: PayloadConfig) -> Self {
        Self {
            registry: GLOBAL_PAYLOAD_REGISTRY.clone(),
            config,
            safe_generator: SafePayloadGenerator::new(),
            oob_builder: OobPayloadBuilder::new(),
        }
    }

    /// Generate safe detection payloads for initial scanning
    pub fn generate_safe_batch(&self, count: usize) -> Vec<GeneratedPayload> {
        self.safe_generator.generate_batch(count)
    }

    /// Generate OOB callback payloads for blind detection
    pub fn generate_oob_payloads(
        &self,
        callback_url: &str,
        callback_type: OobCallbackType,
    ) -> Vec<GeneratedPayload> {
        self.oob_builder.build_for_callback(callback_url, callback_type)
    }

    /// Check if a payload class is enabled
    pub fn is_class_enabled(&self, class: &PayloadClass) -> bool {
        self.config.enabled_classes.is_empty() || self.config.enabled_classes.contains(class)
    }

    /// Check if an injection context is targeted
    pub fn is_context_targeted(&self, context: &InjectionContext) -> bool {
        self.config.target_contexts.is_empty() || self.config.target_contexts.contains(context)
    }

    /// Validate safety level against configuration
    pub fn validate_safety(&self, safety: SafetyLevel) -> bool {
        if self.config.safe_only {
            return safety == SafetyLevel::Safe;
        }
        
        if safety == SafetyLevel::Dangerous {
            return !self.config.require_god_mode;
        }
        
        true
    }

    /// Get the registry reference
    pub fn registry(&self) -> &PayloadRegistry {
        &self.registry
    }

    /// Get configuration reference
    pub fn config(&self) -> &PayloadConfig {
        &self.config
    }
}

/// Async channel-based payload stream for non-blocking worker integration
pub struct PayloadStream {
    receiver: mpsc::Receiver<GeneratedPayload>,
}

impl PayloadStream {
    pub fn new(receiver: mpsc::Receiver<GeneratedPayload>) -> Self {
        Self { receiver }
    }

    pub async fn next(&mut self) -> Option<GeneratedPayload> {
        self.receiver.recv().await
    }
}

impl futures_core::stream::Stream for PayloadStream {
    type Item = GeneratedPayload;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.receiver).poll_recv(cx)
    }
}

/// Builder for creating payload streams
pub struct PayloadStreamBuilder {
    buffer_size: usize,
}

impl PayloadStreamBuilder {
    pub fn new() -> Self {
        Self { buffer_size: 100 }
    }

    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }

    pub fn build(self) -> (mpsc::Sender<GeneratedPayload>, PayloadStream) {
        let (tx, rx) = mpsc::channel(self.buffer_size);
        (tx, PayloadStream::new(rx))
    }
}

impl Default for PayloadStreamBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generated_payload() {
        let payload = GeneratedPayload::new(
            "test-001",
            "' OR '1'='1",
            PayloadClass::SqlInjection,
            Severity::High,
            SafetyLevel::Unsafe,
        );

        assert_eq!(payload.id, "test-001");
        assert_eq!(payload.effective(), "' OR '1'='1");
        assert_eq!(payload.class, PayloadClass::SqlInjection);
    }

    #[test]
    fn test_payload_config_defaults() {
        let config = PayloadConfig::default();
        assert!(config.safe_only);
        assert!(config.require_god_mode);
        assert!(!config.enabled_classes.is_empty());
    }

    #[test]
    fn test_payload_service() {
        let config = PayloadConfig::default();
        let service = PayloadService::new(config);

        let payloads = service.generate_safe_batch(5);
        assert_eq!(payloads.len(), 5);
        
        for payload in &payloads {
            assert_eq!(payload.safety, SafetyLevel::Safe);
        }
    }

    #[test]
    fn test_injection_context_safety() {
        assert!(InjectionContext::UrlQuery.is_safe_for(SafetyLevel::Safe));
        assert!(!InjectionContext::ShellCommand.is_safe_for(SafetyLevel::Dangerous));
    }
}
