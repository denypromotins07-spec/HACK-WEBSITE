//! API Endpoint Enumeration Module
//! Enumerates hidden API versions (v1, v2, beta) and unlinked endpoints using wordlists.

use crate::checks::CheckModule;
use crate::findings::Finding;
use std::collections::{HashSet, BTreeSet};

const VERSION_PREFIXES: &[&str] = &["v1", "v2", "v3", "api", "beta", "alpha", "dev", "staging", "prod"];
const COMMON_ENDPOINTS: &[&str] = &[
    "users", "user", "accounts", "account", "auth", "login", "logout", "register", "signup",
    "password", "reset", "token", "session", "profile", "settings", "config", "admin",
    "dashboard", "posts", "comments", "orders", "products", "cart", "checkout", "payment",
    "upload", "file", "files", "image", "images", "media", "search", "export", "import",
    "health", "status", "metrics", "info", "version", "docs", "swagger", "graphql", "rest",
    "internal", "private", "public", "mobile", "web", "app", "service", "services"
];
const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];

pub struct EndpointEnumCheck {
    enabled: bool,
    timeout_ms: u64,
    max_endpoints: usize,
}

impl EndpointEnumCheck {
    pub fn new() -> Self {
        Self {
            enabled: true,
            timeout_ms: 3000,
            max_endpoints: 500,
        }
    }

    fn generate_candidate_paths(&self, base_path: &str) -> Vec<String> {
        let mut paths = HashSet::new();
        
        // Version-prefixed paths
        for prefix in VERSION_PREFIXES {
            for endpoint in COMMON_ENDPOINTS {
                paths.insert(format!("{}/{}/{}", base_path.trim_end_matches('/'), prefix, endpoint));
                paths.insert(format!("{}/{}/{}/", base_path.trim_end_matches('/'), prefix, endpoint));
            }
        }
        
        // Direct common endpoints
        for endpoint in COMMON_ENDPOINTS {
            paths.insert(format!("{}/{}", base_path.trim_end_matches('/'), endpoint));
            paths.insert(format!("{}/{}/", base_path.trim_end_matches('/'), endpoint));
        }
        
        paths.into_iter().take(self.max_endpoints).collect()
    }

    fn probe_endpoint(&self, url: &str, client: &reqwest::Client, method: &str) -> Option<EndpointResult> {
        let req = match method {
            "GET" => client.get(url),
            "POST" => client.post(url),
            "PUT" => client.put(url),
            "DELETE" => client.delete(url),
            "PATCH" => client.patch(url),
            "OPTIONS" => client.request(reqwest::Method::OPTIONS, url),
            _ => return None,
        };

        let resp = req.send().ok()?;
        let status = resp.status().as_u16();
        
        // Consider 2xx, 4xx (except 404) as potentially interesting
        if status >= 200 && status < 300 || (status >= 400 && status != 404) {
            let body_preview = resp.text().ok()?.chars().take(200).collect::<String>();
            Some(EndpointResult {
                url: url.to_string(),
                method: method.to_string(),
                status_code: status,
                body_preview,
            })
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct EndpointResult {
    url: String,
    method: String,
    status_code: u16,
    body_preview: String,
}

impl CheckModule for EndpointEnumCheck {
    fn name(&self) -> &'static str {
        "api_endpoint_enum"
    }

    fn description(&self) -> &'static str {
        "Enumerates hidden API versions (v1, v2, beta) and unlinked endpoints using wordlists"
    }

    fn severity(&self) -> crate::checks::Severity {
        crate::checks::Severity::Low
    }

    fn run(&self, target: &crate::target::Target, context: &crate::context::ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        if !self.enabled {
            return findings;
        }

        let base_url = target.base_url();
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();

        let discovered_endpoints: BTreeSet<String> = BTreeSet::new();
        let candidate_paths = self.generate_candidate_paths(&base_url);
        let mut probed_count = 0;

        for path in candidate_paths {
            if probed_count >= self.max_endpoints {
                break;
            }

            for method in HTTP_METHODS {
                if probed_count >= self.max_endpoints {
                    break;
                }
                probed_count += 1;

                if let Some(result) = self.probe_endpoint(&path, &client, method) {
                    if result.status_code != 404 && result.status_code != 405 {
                        let evidence = crate::findings::Evidence::new()
                            .with_detail("url", result.url.clone())
                            .with_detail("method", result.method.clone())
                            .with_detail("status_code", result.status_code.to_string())
                            .with_raw_response(result.body_preview.clone());

                        findings.push(Finding::new(self.name())
                            .with_target(result.url)
                            .with_severity(self.severity())
                            .with_title("Hidden API Endpoint Discovered")
                            .with_description(format!("{} endpoint {} returned status {}", result.method, path, result.status_code))
                            .with_evidence(evidence)
                            .with_confidence(0.70));
                        
                        discovered_endpoints.insert(path.clone());
                        break; // One finding per path is enough
                    }
                }
            }
        }

        // Summary finding if many endpoints discovered
        if discovered_endpoints.len() > 10 {
            let summary_evidence = crate::findings::Evidence::new()
                .with_detail("total_discovered", discovered_endpoints.len().to_string())
                .with_raw_response(format!("{:?}", discovered_endpoints.iter().take(20).collect::<Vec<_>>()));

            findings.push(Finding::new(self.name())
                .with_target(base_url)
                .with_severity(crate::checks::Severity::Medium)
                .with_title("Multiple Hidden API Endpoints Enumerated")
                .with_description(format!("Discovered {} potential API endpoints that may not be publicly documented", discovered_endpoints.len()))
                .with_evidence(summary_evidence)
                .with_confidence(0.80));
        }

        findings
    }

    fn clone_box(&self) -> Box<dyn CheckModule> {
        Box::new(self.clone())
    }
}

impl Clone for EndpointEnumCheck {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            timeout_ms: self.timeout_ms,
            max_endpoints: self.max_endpoints,
        }
    }
}
