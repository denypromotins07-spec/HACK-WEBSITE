//! Enumeration and Logic Evidence Container Module
//!
//! Builds evidence containers for timing diffs, DNS takeovers, and SAML parsing flaws.
//! Implements bounded evidence storage with precise payload tracking.

use std::sync::Arc;
use crate::findings::finding::{Evidence, EvidenceType, EvidenceLocation};

/// Maximum evidence entries per finding (bounded)
const MAX_EVIDENCE_ENTRIES: usize = 16;

/// Bounded evidence container
#[derive(Debug, Clone)]
pub struct EvidenceContainer {
    evidences: [Option<Evidence>; MAX_EVIDENCE_ENTRIES],
    count: usize,
}

impl EvidenceContainer {
    pub fn new() -> Self {
        Self {
            evidences: [None; MAX_EVIDENCE_ENTRIES],
            count: 0,
        }
    }

    pub fn add(&mut self, evidence: Evidence) -> bool {
        if self.count < MAX_EVIDENCE_ENTRIES {
            self.evidences[self.count] = Some(evidence);
            self.count += 1;
            true
        } else {
            false
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Evidence> {
        self.evidences[..self.count].iter().flatten()
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get timing-based evidence
    pub fn get_timing_evidence(&self) -> Vec<&Evidence> {
        self.iter()
            .filter(|e| matches!(e.evidence_type, EvidenceType::Timing { .. }))
            .collect()
    }

    /// Get HTTP request/response evidence
    pub fn get_http_evidence(&self) -> Vec<&Evidence> {
        self.iter()
            .filter(|e| matches!(e.evidence_type, EvidenceType::HttpRequestResponse { .. }))
            .collect()
    }

    /// Get configuration evidence
    pub fn get_config_evidence(&self) -> Vec<&Evidence> {
        self.iter()
            .filter(|e| matches!(e.evidence_type, EvidenceType::Configuration { .. }))
            .collect()
    }
}

impl Default for EvidenceContainer {
    fn default() -> Self {
        Self::new()
    }
}

/// Timing differential record for learning engine
#[derive(Debug, Clone)]
pub struct TimingRecord {
    pub url: String,
    pub check_type: String,
    pub baseline_ns: u128,
    pub observed_ns: u128,
    pub difference_ns: u128,
    pub sample_count: usize,
}

impl TimingRecord {
    pub fn new(
        url: String,
        check_type: String,
        baseline_ns: u128,
        observed_ns: u128,
        difference_ns: u128,
        sample_count: usize,
    ) -> Self {
        Self {
            url,
            check_type,
            baseline_ns,
            observed_ns,
            difference_ns,
            sample_count,
        }
    }

    pub fn is_significant(&self, threshold_ns: u128) -> bool {
        self.difference_ns > threshold_ns
    }
}

/// DNS takeover evidence record
#[derive(Debug, Clone)]
pub struct DnsTakeoverRecord {
    pub subdomain: String,
    pub service: String,
    pub indicator: String,
    pub cname_target: Option<String>,
    pub confidence: u8,
}

impl DnsTakeoverRecord {
    pub fn new(subdomain: String, service: String, indicator: String, confidence: u8) -> Self {
        Self {
            subdomain,
            service,
            indicator,
            cname_target: None,
            confidence,
        }
    }

    pub fn with_cname(mut self, target: String) -> Self {
        self.cname_target = Some(target);
        self
    }
}

/// SAML parsing flaw record
#[derive(Debug, Clone)]
pub struct SamlFlawRecord {
    pub endpoint: String,
    pub flaw_type: String,
    pub payload_preview: String,
    pub response_indicator: String,
    pub xml_depth: usize,
    pub entity_count: usize,
}

impl SamlFlawRecord {
    pub fn new(
        endpoint: String,
        flaw_type: String,
        payload_preview: String,
        response_indicator: String,
    ) -> Self {
        Self {
            endpoint,
            flaw_type,
            payload_preview,
            response_indicator,
            xml_depth: 0,
            entity_count: 0,
        }
    }

    pub fn with_xml_stats(mut self, depth: usize, entities: usize) -> Self {
        self.xml_depth = depth;
        self.entity_count = entities;
        self
    }
}

/// Bounded enumeration evidence builder
pub struct EnumEvidenceBuilder {
    timing_records: [Option<TimingRecord>; 8],
    dns_records: [Option<DnsTakeoverRecord>; 8],
    saml_records: [Option<SamlFlawRecord>; 8],
    timing_count: usize,
    dns_count: usize,
    saml_count: usize,
}

impl EnumEvidenceBuilder {
    pub fn new() -> Self {
        Self {
            timing_records: [None; 8],
            dns_records: [None; 8],
            saml_records: [None; 8],
            timing_count: 0,
            dns_count: 0,
            saml_count: 0,
        }
    }

    pub fn add_timing_record(&mut self, record: TimingRecord) -> bool {
        if self.timing_count < 8 {
            self.timing_records[self.timing_count] = Some(record);
            self.timing_count += 1;
            true
        } else {
            false
        }
    }

    pub fn add_dns_record(&mut self, record: DnsTakeoverRecord) -> bool {
        if self.dns_count < 8 {
            self.dns_records[self.dns_count] = Some(record);
            self.dns_count += 1;
            true
        } else {
            false
        }
    }

    pub fn add_saml_record(&mut self, record: SamlFlawRecord) -> bool {
        if self.saml_count < 8 {
            self.saml_records[self.saml_count] = Some(record);
            self.saml_count += 1;
            true
        } else {
            false
        }
    }

    pub fn get_all_timing_records(&self) -> Vec<&TimingRecord> {
        self.timing_records[..self.timing_count]
            .iter()
            .flatten()
            .collect()
    }

    pub fn get_all_dns_records(&self) -> Vec<&DnsTakeoverRecord> {
        self.dns_records[..self.dns_count]
            .iter()
            .flatten()
            .collect()
    }

    pub fn get_all_saml_records(&self) -> Vec<&SamlFlawRecord> {
        self.saml_records[..self.saml_count]
            .iter()
            .flatten()
            .collect()
    }

    /// Build evidence container from records
    pub fn build_container(&self) -> EvidenceContainer {
        let mut container = EvidenceContainer::new();

        // Add timing evidence
        for record in self.get_all_timing_records() {
            let evidence = Evidence {
                evidence_type: EvidenceType::Timing {
                    baseline_ms: record.baseline_ns / 1_000_000,
                    observed_ms: record.observed_ns / 1_000_000,
                    difference_ms: record.difference_ns / 1_000_000,
                },
                data: format!(
                    "Timing diff: {}ns ({} samples)",
                    record.difference_ns,
                    record.sample_count
                ),
                location: EvidenceLocation {
                    path: record.url.clone(),
                    line: None,
                    parameter: None,
                    header: None,
                },
                confidence: 80,
            };
            let _ = container.add(evidence);
        }

        // Add DNS takeover evidence
        for record in self.get_all_dns_records() {
            let evidence = Evidence {
                evidence_type: EvidenceType::Configuration {
                    key: record.service.clone(),
                    value: record.indicator.clone(),
                },
                data: format!("Subdomain {} points to unclaimed {}", record.subdomain, record.service),
                location: EvidenceLocation {
                    path: record.subdomain.clone(),
                    line: None,
                    parameter: None,
                    header: None,
                },
                confidence: record.confidence,
            };
            let _ = container.add(evidence);
        }

        container
    }
}

impl Default for EnumEvidenceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_container_bounds() {
        let mut container = EvidenceContainer::new();
        
        for i in 0..MAX_EVIDENCE_ENTRIES + 5 {
            let evidence = Evidence {
                evidence_type: EvidenceType::Configuration {
                    key: format!("key_{}", i),
                    value: format!("value_{}", i),
                },
                data: format!("data_{}", i),
                location: EvidenceLocation {
                    path: "/test".to_string(),
                    line: None,
                    parameter: None,
                    header: None,
                },
                confidence: 80,
            };
            container.add(evidence);
        }

        assert_eq!(container.len(), MAX_EVIDENCE_ENTRIES);
    }

    #[test]
    fn test_timing_record() {
        let record = TimingRecord::new(
            "https://example.com/login".to_string(),
            "user_enum".to_string(),
            50_000_000,
            150_000_000,
            100_000_000,
            10,
        );

        assert!(record.is_significant(50_000_000));
        assert!(!record.is_significant(150_000_000));
    }

    #[test]
    fn test_evidence_builder() {
        let mut builder = EnumEvidenceBuilder::new();

        let timing = TimingRecord::new(
            "https://example.com".to_string(),
            "test".to_string(),
            0,
            100_000_000,
            100_000_000,
            5,
        );
        builder.add_timing_record(timing);

        let dns = DnsTakeoverRecord::new(
            "dev.example.com".to_string(),
            "GitHub Pages".to_string(),
            "not found".to_string(),
            85,
        );
        builder.add_dns_record(dns);

        assert_eq!(builder.get_all_timing_records().len(), 1);
        assert_eq!(builder.get_all_dns_records().len(), 1);

        let container = builder.build_container();
        assert_eq!(container.len(), 2);
    }
}
