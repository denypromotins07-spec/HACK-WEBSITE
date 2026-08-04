//! SSRF/LFI Evidence Containers
//!
//! Creates evidence containers for SSRF/LFI with response bodies, headers, and OOB logs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::findings::{Evidence, EvidenceType, EvidenceLocation, Finding};

/// SSRF-specific evidence container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrfEvidence {
    /// Base evidence
    pub base: Evidence,
    /// SSRF-specific fields
    pub ssrf_type: SsrfType,
    /// Target that was accessed
    pub target: SsrfTarget,
    /// Response analysis
    pub response_analysis: SsrfResponseAnalysis,
    /// Out-of-band callback data (if applicable)
    pub oob_data: Option<OobCallbackData>,
    /// Cloud metadata specific data (if applicable)
    pub cloud_metadata: Option<CloudMetadataData>,
    /// Internal service fingerprint (if applicable)
    pub service_fingerprint: Option<ServiceFingerprint>,
}

/// SSRF type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SsrfType {
    Basic,
    Blind,
    CloudMetadata,
    DnsRebinding,
    InternalService,
    ProtocolHandler,
}

/// SSRF target information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrfTarget {
    pub ip: String,
    pub port: Option<u16>,
    pub protocol: String,
    pub path: String,
    pub is_internal: bool,
    pub is_cloud_metadata: bool,
    pub cloud_provider: Option<String>,
}

/// SSRF response analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsrfResponseAnalysis {
    pub status_code: u16,
    pub content_length: usize,
    pub content_type: Option<String>,
    pub server_header: Option<String>,
    pub response_time_ms: u64,
    pub contains_metadata: bool,
    pub contains_service_banner: bool,
    pub contains_error: bool,
    pub metadata_indicators: Vec<String>,
    pub service_indicators: Vec<String>,
}

/// Out-of-band callback data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobCallbackData {
    pub callback_type: String,
    pub source_ip: String,
    pub timestamp: u64,
    pub request_id: u64,
    pub payload: String,
    pub interaction_data: HashMap<String, String>,
}

/// Cloud metadata specific data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudMetadataData {
    pub provider: String,
    pub endpoint: String,
    pub sensitivity: String,
    pub extracted_data: HashMap<String, String>,
    pub credentials_found: bool,
    pub ssh_keys_found: bool,
    pub user_data_found: bool,
}

/// Internal service fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFingerprint {
    pub service_name: String,
    pub version: Option<String>,
    pub port: u16,
    pub protocol: String,
    pub banner: String,
    pub configuration_exposed: bool,
    pub authentication_required: bool,
    pub vulnerable_endpoints: Vec<String>,
}

/// LFI-specific evidence container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfiEvidence {
    /// Base evidence
    pub base: Evidence,
    /// LFI-specific fields
    pub lfi_type: LfiType,
    /// File that was accessed
    pub target_file: LfiTargetFile,
    /// Traversal technique used
    pub traversal_technique: TraversalTechnique,
    /// File content analysis
    pub content_analysis: LfiContentAnalysis,
    /// PHP wrapper specific data (if applicable)
    pub php_wrapper: Option<PhpWrapperData>,
    /// RFI specific data (if applicable)
    pub rfi_data: Option<RfiData>,
}

/// LFI type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LfiType {
    Basic,
    PhpWrapper,
    Rfi,
    NullByte,
    LogPoisoning,
    ProcSelfEnviron,
    PhpFilter,
    PhpInput,
    ExpectWrapper,
    DataWrapper,
    PharWrapper,
    ZipWrapper,
}

/// LFI target file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfiTargetFile {
    pub path: String,
    pub description: String,
    pub os: String,
    pub severity: String,
    pub is_sensitive: bool,
    pub contains_credentials: bool,
    pub contains_keys: bool,
    pub contains_config: bool,
}

/// Traversal technique used
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraversalTechnique {
    pub name: String,
    pub depth: usize,
    pub encoding: Vec<String>,
    pub bypass_type: Option<String>,
}

/// LFI content analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LfiContentAnalysis {
    pub file_size: usize,
    pub line_count: usize,
    pub detection_patterns_matched: Vec<String>,
    pub is_binary: bool,
    pub encoding: Option<String>,
    pub entropy: Option<f64>,
}

/// PHP wrapper specific data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhpWrapperData {
    pub wrapper_name: String,
    pub filter_chain: Option<String>,
    pub base64_decoded: Option<String>,
    pub code_executed: bool,
    pub command_output: Option<String>,
}

/// RFI specific data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RfiData {
    pub remote_url: String,
    pub marker_found: bool,
    pub marker: String,
    pub php_code_executed: bool,
    pub shell_detected: bool,
}

/// Directory traversal evidence container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraversalEvidence {
    /// Base evidence
    pub base: Evidence,
    /// Traversal-specific fields
    pub technique: TraversalTechniqueDetail,
    /// Target path
    pub target_path: String,
    /// Normalization bypass details
    pub normalization_bypass: Option<NormalizationBypassDetail>,
    /// Nginx alias specific (if applicable)
    pub nginx_alias: Option<NginxAliasDetail>,
}

/// Detailed traversal technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraversalTechniqueDetail {
    pub name: String,
    pub category: String,
    pub payload: String,
    pub depth: usize,
    pub encodings: Vec<String>,
    pub os_targeted: String,
}

/// Normalization bypass detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizationBypassDetail {
    pub technique: String,
    pub original_payload: String,
    pub normalized_payload: String,
    pub bypass_description: String,
}

/// Nginx alias traversal detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NginxAliasDetail {
    pub alias_path: String,
    pub target_path: String,
    pub traversal_payload: String,
    pub off_by_slash: bool,
    pub multi_level: bool,
}

/// Evidence builder for SSRF
pub struct SsrfEvidenceBuilder {
    evidence: SsrfEvidence,
}

impl SsrfEvidenceBuilder {
    pub fn new(base: Evidence, ssrf_type: SsrfType, target: SsrfTarget) -> Self {
        Self {
            evidence: SsrfEvidence {
                base,
                ssrf_type,
                target,
                response_analysis: SsrfResponseAnalysis::default(),
                oob_data: None,
                cloud_metadata: None,
                service_fingerprint: None,
            },
        }
    }

    pub fn with_response_analysis(mut self, analysis: SsrfResponseAnalysis) -> Self {
        self.evidence.response_analysis = analysis;
        self
    }

    pub fn with_oob_data(mut self, oob: OobCallbackData) -> Self {
        self.evidence.oob_data = Some(oob);
        self
    }

    pub fn with_cloud_metadata(mut self, metadata: CloudMetadataData) -> Self {
        self.evidence.cloud_metadata = Some(metadata);
        self
    }

    pub fn with_service_fingerprint(mut self, fingerprint: ServiceFingerprint) -> Self {
        self.evidence.service_fingerprint = Some(fingerprint);
        self
    }

    pub fn build(self) -> SsrfEvidence {
        self.evidence
    }
}

/// Evidence builder for LFI
pub struct LfiEvidenceBuilder {
    evidence: LfiEvidence,
}

impl LfiEvidenceBuilder {
    pub fn new(base: Evidence, lfi_type: LfiType, target_file: LfiTargetFile, technique: TraversalTechnique) -> Self {
        Self {
            evidence: LfiEvidence {
                base,
                lfi_type,
                target_file,
                traversal_technique: technique,
                content_analysis: LfiContentAnalysis::default(),
                php_wrapper: None,
                rfi_data: None,
            },
        }
    }

    pub fn with_content_analysis(mut self, analysis: LfiContentAnalysis) -> Self {
        self.evidence.content_analysis = analysis;
        self
    }

    pub fn with_php_wrapper(mut self, wrapper: PhpWrapperData) -> Self {
        self.evidence.php_wrapper = Some(wrapper);
        self
    }

    pub fn with_rfi_data(mut self, rfi: RfiData) -> Self {
        self.evidence.rfi_data = Some(rfi);
        self
    }

    pub fn build(self) -> LfiEvidence {
        self.evidence
    }
}

/// Evidence builder for Traversal
pub struct TraversalEvidenceBuilder {
    evidence: TraversalEvidence,
}

impl TraversalEvidenceBuilder {
    pub fn new(base: Evidence, technique: TraversalTechniqueDetail, target_path: String) -> Self {
        Self {
            evidence: TraversalEvidence {
                base,
                technique,
                target_path,
                normalization_bypass: None,
                nginx_alias: None,
            },
        }
    }

    pub fn with_normalization_bypass(mut self, bypass: NormalizationBypassDetail) -> Self {
        self.evidence.normalization_bypass = Some(bypass);
        self
    }

    pub fn with_nginx_alias(mut self, alias: NginxAliasDetail) -> Self {
        self.evidence.nginx_alias = Some(alias);
        self
    }

    pub fn build(self) -> TraversalEvidence {
        self.evidence
    }
}

impl Default for SsrfResponseAnalysis {
    fn default() -> Self {
        Self {
            status_code: 0,
            content_length: 0,
            content_type: None,
            server_header: None,
            response_time_ms: 0,
            contains_metadata: false,
            contains_service_banner: false,
            contains_error: false,
            metadata_indicators: Vec::new(),
            service_indicators: Vec::new(),
        }
    }
}

impl Default for LfiContentAnalysis {
    fn default() -> Self {
        Self {
            file_size: 0,
            line_count: 0,
            detection_patterns_matched: Vec::new(),
            is_binary: false,
            encoding: None,
            entropy: None,
        }
    }
}

/// Convert SSRF evidence to generic Evidence
impl From<SsrfEvidence> for Evidence {
    fn from(ssrf_evidence: SsrfEvidence) -> Self {
        ssrf_evidence.base
    }
}

/// Convert LFI evidence to generic Evidence
impl From<LfiEvidence> for Evidence {
    fn from(lfi_evidence: LfiEvidence) -> Self {
        lfi_evidence.base
    }
}

/// Convert Traversal evidence to generic Evidence
impl From<TraversalEvidence> for Evidence {
    fn from(trav_evidence: TraversalEvidence) -> Self {
        trav_evidence.base
    }
}

/// Create SSRF evidence from finding
pub fn create_ssrf_evidence_from_finding(finding: &Finding) -> Option<SsrfEvidence> {
    if finding.evidence.is_empty() {
        return None;
    }
    
    let base = finding.evidence[0].clone();
    
    // Determine SSRF type from tags
    let ssrf_type = if finding.tags.contains(&"cloud-metadata".to_string()) {
        SsrfType::CloudMetadata
    } else if finding.tags.contains(&"blind".to_string()) {
        SsrfType::Blind
    } else if finding.tags.contains(&"dns-rebinding".to_string()) {
        SsrfType::DnsRebinding
    } else if finding.tags.contains(&"internal-service".to_string()) {
        SsrfType::InternalService
    } else {
        SsrfType::Basic
    };
    
    // Extract target from payload
    let target = SsrfTarget {
        ip: finding.payload.as_ref().unwrap_or(&"".to_string()).clone(),
        port: None,
        protocol: "http".to_string(),
        path: "/".to_string(),
        is_internal: true,
        is_cloud_metadata: ssrf_type == SsrfType::CloudMetadata,
        cloud_provider: finding.tags.iter().find(|t| {
            ["aws", "gcp", "azure", "digitalocean", "alibaba", "oracle"].contains(&t.as_str())
        }).cloned(),
    };
    
    Some(SsrfEvidence {
        base,
        ssrf_type,
        target,
        response_analysis: SsrfResponseAnalysis::default(),
        oob_data: None,
        cloud_metadata: None,
        service_fingerprint: None,
    })
}

/// Create LFI evidence from finding
pub fn create_lfi_evidence_from_finding(finding: &Finding) -> Option<LfiEvidence> {
    if finding.evidence.is_empty() {
        return None;
    }
    
    let base = finding.evidence[0].clone();
    
    let lfi_type = if finding.tags.contains(&"php-wrapper".to_string()) || finding.tags.contains(&"php-filter".to_string()) {
        LfiType::PhpWrapper
    } else if finding.tags.contains(&"rfi".to_string()) || finding.tags.contains(&"remote-file-inclusion".to_string()) {
        LfiType::Rfi
    } else if finding.tags.contains(&"null-byte".to_string()) {
        LfiType::NullByte
    } else if finding.payload.as_ref().map(|p| p.contains("php://filter")).unwrap_or(false) {
        LfiType::PhpFilter
    } else if finding.payload.as_ref().map(|p| p.contains("php://input")).unwrap_or(false) {
        LfiType::PhpInput
    } else if finding.payload.as_ref().map(|p| p.contains("expect://")).unwrap_or(false) {
        LfiType::ExpectWrapper
    } else if finding.payload.as_ref().map(|p| p.contains("data://")).unwrap_or(false) {
        LfiType::DataWrapper
    } else if finding.payload.as_ref().map(|p| p.contains("phar://")).unwrap_or(false) {
        LfiType::PharWrapper
    } else if finding.payload.as_ref().map(|p| p.contains("zip://")).unwrap_or(false) {
        LfiType::ZipWrapper
    } else {
        LfiType::Basic
    };
    
    let target_file = LfiTargetFile {
        path: finding.payload.as_ref().unwrap_or(&"".to_string()).clone(),
        description: "Target file".to_string(),
        os: finding.tags.iter().find(|t| t == "linux" || t == "windows").cloned().unwrap_or("unknown".to_string()),
        severity: format!("{:?}", finding.severity),
        is_sensitive: true,
        contains_credentials: finding.description.contains("credential") || finding.description.contains("password") || finding.description.contains("shadow"),
        contains_keys: finding.description.contains("key") || finding.description.contains("ssh"),
        contains_config: finding.description.contains("config"),
    };
    
    let technique = TraversalTechnique {
        name: "directory_traversal".to_string(),
        depth: finding.payload.as_ref().map(|p| p.matches("../").count()).unwrap_or(0),
        encoding: Vec::new(),
        bypass_type: None,
    };
    
    Some(LfiEvidence {
        base,
        lfi_type,
        target_file,
        traversal_technique: technique,
        content_analysis: LfiContentAnalysis::default(),
        php_wrapper: None,
        rfi_data: None,
    })
}

/// Create Traversal evidence from finding
pub fn create_traversal_evidence_from_finding(finding: &Finding) -> Option<TraversalEvidence> {
    if finding.evidence.is_empty() {
        return None;
    }
    
    let base = finding.evidence[0].clone();
    
    let technique = TraversalTechniqueDetail {
        name: finding.tags.iter().find(|t| t.contains("bypass") || t.contains("nginx")).cloned().unwrap_or("basic_traversal".to_string()),
        category: "path_traversal".to_string(),
        payload: finding.payload.as_ref().unwrap_or(&"".to_string()).clone(),
        depth: finding.payload.as_ref().map(|p| p.matches("../").count()).unwrap_or(0),
        encodings: Vec::new(),
        os_targeted: finding.tags.iter().find(|t| t == "linux" || t == "windows").cloned().unwrap_or("unknown".to_string()),
    };
    
    let normalization_bypass = if finding.tags.contains(&"normalization-bypass".to_string()) {
        Some(NormalizationBypassDetail {
            technique: finding.tags.iter().find(|t| t != "normalization-bypass").cloned().unwrap_or("unknown".to_string()),
            original_payload: finding.payload.as_ref().unwrap_or(&"".to_string()).clone(),
            normalized_payload: String::new(),
            bypass_description: "Normalization bypass detected".to_string(),
        })
    } else {
        None
    };
    
    let nginx_alias = if finding.tags.contains(&"nginx-alias".to_string()) {
        Some(NginxAliasDetail {
            alias_path: String::new(),
            target_path: String::new(),
            traversal_payload: finding.payload.as_ref().unwrap_or(&"".to_string()).clone(),
            off_by_slash: true,
            multi_level: finding.payload.as_ref().map(|p| p.matches("../").count()).unwrap_or(0) > 2,
        })
    } else {
        None
    };
    
    Some(TraversalEvidence {
        base,
        technique,
        target_path: finding.payload.as_ref().unwrap_or(&"".to_string()).clone(),
        normalization_bypass,
        nginx_alias,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssrf_evidence_builder() {
        let base = Evidence {
            evidence_type: EvidenceType::HttpRequestResponse {
                request: "GET /test HTTP/1.1".to_string(),
                response: "HTTP/1.1 200 OK".to_string(),
            },
            data: "test".to_string(),
            location: EvidenceLocation {
                path: "/test".to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 80,
        };
        
        let target = SsrfTarget {
            ip: "169.254.169.254".to_string(),
            port: Some(80),
            protocol: "http".to_string(),
            path: "/latest/meta-data/".to_string(),
            is_internal: true,
            is_cloud_metadata: true,
            cloud_provider: Some("aws".to_string()),
        };
        
        let evidence = SsrfEvidenceBuilder::new(base, SsrfType::CloudMetadata, target)
            .build();
        
        assert_eq!(evidence.ssrf_type, SsrfType::CloudMetadata);
        assert_eq!(evidence.target.cloud_provider, Some("aws".to_string()));
    }

    #[test]
    fn test_lfi_evidence_builder() {
        let base = Evidence {
            evidence_type: EvidenceType::HttpRequestResponse {
                request: "GET /test HTTP/1.1".to_string(),
                response: "HTTP/1.1 200 OK".to_string(),
            },
            data: "test".to_string(),
            location: EvidenceLocation {
                path: "/test".to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 80,
        };
        
        let target = LfiTargetFile {
            path: "/etc/passwd".to_string(),
            description: "User accounts".to_string(),
            os: "linux".to_string(),
            severity: "High".to_string(),
            is_sensitive: true,
            contains_credentials: false,
            contains_keys: false,
            contains_config: false,
        };
        
        let technique = TraversalTechnique {
            name: "basic".to_string(),
            depth: 3,
            encoding: vec!["../".to_string()],
            bypass_type: None,
        };
        
        let evidence = LfiEvidenceBuilder::new(base, LfiType::Basic, target, technique)
            .build();
        
        assert_eq!(evidence.lfi_type, LfiType::Basic);
        assert_eq!(evidence.target_file.path, "/etc/passwd");
    }

    #[test]
    fn test_traversal_evidence_builder() {
        let base = Evidence {
            evidence_type: EvidenceType::HttpRequestResponse {
                request: "GET /test HTTP/1.1".to_string(),
                response: "HTTP/1.1 200 OK".to_string(),
            },
            data: "test".to_string(),
            location: EvidenceLocation {
                path: "/test".to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 80,
        };
        
        let technique = TraversalTechniqueDetail {
            name: "nginx_alias".to_string(),
            category: "path_traversal".to_string(),
            payload: "/static../etc/passwd".to_string(),
            depth: 1,
            encodings: vec![],
            os_targeted: "linux".to_string(),
        };
        
        let evidence = TraversalEvidenceBuilder::new(base, technique, "/etc/passwd".to_string())
            .build();
        
        assert_eq!(evidence.technique.name, "nginx_alias");
        assert_eq!(evidence.target_path, "/etc/passwd");
    }
}