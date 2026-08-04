//! OAuth flow state handling for authorization codes, PKCE, state, and redirect URIs.
//!
//! Provides comprehensive OAuth 2.0 / OIDC flow management including:
//! - Authorization code flow with PKCE support
//! - State parameter generation and validation
//! - Token exchange handling
//! - Refresh token management

use crate::auth::vault::SecureString;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// OAuth 2.0 grant types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantType {
    /// Authorization Code grant.
    AuthorizationCode,
    /// Implicit grant (deprecated).
    Implicit,
    /// Resource Owner Password Credentials grant.
    Password,
    /// Client Credentials grant.
    ClientCredentials,
    /// Refresh Token grant.
    RefreshToken,
}

impl fmt::Display for GrantType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GrantType::AuthorizationCode => write!(f, "authorization_code"),
            GrantType::Implicit => write!(f, "implicit"),
            GrantType::Password => write!(f, "password"),
            GrantType::ClientCredentials => write!(f, "client_credentials"),
            GrantType::RefreshToken => write!(f, "refresh_token"),
        }
    }
}

/// PKCE code challenge methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkceMethod {
    /// Plain text challenge (not recommended).
    Plain,
    /// SHA-256 hash of verifier (recommended).
    S256,
}

impl Default for PkceMethod {
    fn default() -> Self {
        PkceMethod::S256
    }
}

impl fmt::Display for PkceMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PkceMethod::Plain => write!(f, "plain"),
            PkceMethod::S256 => write!(f, "S256"),
        }
    }
}

/// OAuth flow state container.
#[derive(Debug, Clone)]
pub struct OAuthState {
    /// Unique state identifier for CSRF protection.
    pub state: String,
    /// Code verifier for PKCE (if used).
    pub code_verifier: Option<SecureString>,
    /// Code challenge derived from verifier.
    pub code_challenge: Option<String>,
    /// Method used for code challenge.
    pub code_challenge_method: PkceMethod,
    /// When this state was created.
    pub created_at: Instant,
    /// Expiry time for this state.
    pub expires_at: Option<Instant>,
    /// Whether this state has been used.
    pub used: bool,
    /// Associated nonce for OIDC.
    pub nonce: Option<String>,
}

impl OAuthState {
    /// Create a new OAuth state with optional PKCE.
    pub fn new(use_pkce: bool) -> Self {
        let state = generate_random_string(32);
        let now = Instant::now();
        
        let (code_verifier, code_challenge, method) = if use_pkce {
            let verifier = generate_random_string(64);
            let challenge = compute_code_challenge(&verifier, PkceMethod::S256);
            (Some(SecureString::new(&verifier)), Some(challenge), PkceMethod::S256)
        } else {
            (None, None, PkceMethod::Plain)
        };
        
        Self {
            state,
            code_verifier,
            code_challenge,
            code_challenge_method: method,
            created_at: now,
            expires_at: Some(now + Duration::from_secs(600)), // 10 minutes
            used: false,
            nonce: Some(generate_random_string(32)),
        }
    }

    /// Check if the state is still valid.
    pub fn is_valid(&self) -> bool {
        !self.used 
            && self.expires_at.map_or(true, |exp| Instant::now() < exp)
    }

    /// Mark the state as used.
    pub fn mark_used(&mut self) {
        self.used = true;
    }

    /// Validate a received state matches this one.
    pub fn validate(&self, received_state: &str) -> bool {
        self.state == received_state && self.is_valid()
    }

    /// Get the code verifier for token exchange.
    pub fn get_verifier(&self) -> Option<String> {
        self.code_verifier.as_ref().map(|v| v.with_inner(|s| s.to_string()))
    }
}

/// OAuth configuration for a client.
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// Authorization endpoint URL.
    pub auth_endpoint: String,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// User info endpoint (for OIDC).
    pub userinfo_endpoint: Option<String>,
    /// End session endpoint (for logout).
    pub end_session_endpoint: Option<String>,
    /// Client ID.
    pub client_id: String,
    /// Client secret (optional for public clients).
    pub client_secret: Option<SecureString>,
    /// Redirect URI.
    pub redirect_uri: String,
    /// Additional redirect URIs.
    pub additional_redirect_uris: Vec<String>,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// Grant type to use.
    pub grant_type: GrantType,
    /// Enable PKCE.
    pub pkce_enabled: bool,
    /// Response type.
    pub response_type: String,
    /// Response mode.
    pub response_mode: Option<String>,
}

impl OAuthConfig {
    /// Create a new OAuth config for authorization code flow.
    pub fn authorization_code(
        auth_endpoint: &str,
        token_endpoint: &str,
        client_id: &str,
        redirect_uri: &str,
        scopes: Vec<String>,
    ) -> Self {
        Self {
            auth_endpoint: auth_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
            userinfo_endpoint: None,
            end_session_endpoint: None,
            client_id: client_id.to_string(),
            client_secret: None,
            redirect_uri: redirect_uri.to_string(),
            additional_redirect_uris: Vec::new(),
            scopes,
            grant_type: GrantType::AuthorizationCode,
            pkce_enabled: true,
            response_type: "code".to_string(),
            response_mode: None,
        }
    }

    /// Set the client secret.
    pub fn with_client_secret(mut self, secret: &str) -> Self {
        self.client_secret = Some(SecureString::new(secret));
        self
    }

    /// Enable/disable PKCE.
    pub fn with_pkce(mut self, enabled: bool) -> Self {
        self.pkce_enabled = enabled;
        self
    }

    /// Add a scope.
    pub fn with_scope(mut self, scope: &str) -> Self {
        self.scopes.push(scope.to_string());
        self
    }
}

/// Build an authorization URL for OAuth flow.
pub fn build_auth_url(config: &OAuthConfig, state: &OAuthState) -> String {
    let mut params = vec![
        ("response_type", config.response_type.as_str()),
        ("client_id", config.client_id.as_str()),
        ("redirect_uri", config.redirect_uri.as_str()),
        ("state", state.state.as_str()),
    ];

    if !config.scopes.is_empty() {
        params.push(("scope", config.scopes.join(" ").as_str()));
    }

    if let Some(ref challenge) = state.code_challenge {
        params.push(("code_challenge", challenge.as_str()));
        params.push((
            "code_challenge_method",
            state.code_challenge_method.to_string().as_str(),
        ));
    }

    if let Some(ref nonce) = state.nonce {
        params.push(("nonce", nonce.as_str()));
    }

    if let Some(ref mode) = config.response_mode {
        params.push(("response_mode", mode.as_str()));
    }

    let query = params
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    format!("{}?{}", config.auth_endpoint, query)
}

/// Build token request body for authorization code exchange.
pub fn build_token_request(
    config: &OAuthConfig,
    code: &str,
    state: &OAuthState,
) -> HashMap<String, String> {
    let mut params = HashMap::new();

    params.insert("grant_type".to_string(), config.grant_type.to_string());
    params.insert("code".to_string(), code.to_string());
    params.insert("redirect_uri".to_string(), config.redirect_uri.clone());
    params.insert("client_id".to_string(), config.client_id.clone());

    if let Some(ref secret) = config.client_secret {
        params.insert("client_secret".to_string(), secret.with_inner(|s| s.to_string()));
    }

    if let Some(verifier) = state.get_verifier() {
        params.insert("code_verifier".to_string(), verifier);
    }

    params
}

/// Build token refresh request body.
pub fn build_refresh_request(
    config: &OAuthConfig,
    refresh_token: &str,
) -> HashMap<String, String> {
    let mut params = HashMap::new();

    params.insert("grant_type".to_string(), GrantType::RefreshToken.to_string());
    params.insert("refresh_token".to_string(), refresh_token.to_string());
    params.insert("client_id".to_string(), config.client_id.clone());

    if let Some(ref secret) = config.client_secret {
        params.insert("client_secret".to_string(), secret.with_inner(|s| s.to_string()));
    }

    if !config.scopes.is_empty() {
        params.insert("scope".to_string(), config.scopes.join(" "));
    }

    params
}

/// Generate a random string for state/nonce.
fn generate_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    
    let mut result = String::with_capacity(length);
    let counter = ATOMIC_COUNTER.fetch_add(1, Ordering::Relaxed);
    
    // Simple deterministic generation for reproducibility
    // In production, use a proper RNG
    for i in 0..length {
        let idx = ((counter + i as u64) % CHARSET.len() as u64) as usize;
        result.push(CHARSET[idx] as char);
    }
    
    result
}

static ATOMIC_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Compute PKCE code challenge.
fn compute_code_challenge(verifier: &str, method: PkceMethod) -> String {
    match method {
        PkceMethod::Plain => verifier.to_string(),
        PkceMethod::S256 => {
            // SHA-256 hash then base64url encode
            let hash = sha256_simple(verifier);
            base64url_encode(&hash)
        }
    }
}

/// Simple SHA-256 implementation placeholder.
fn sha256_simple(input: &str) -> Vec<u8> {
    // In production, use a proper crypto library
    // This is a placeholder that returns a deterministic value
    let mut hash = [0u8; 32];
    for (i, byte) in input.bytes().enumerate() {
        hash[i % 32] ^= byte;
        hash[(i + 1) % 32] ^= byte.wrapping_add(1);
    }
    hash.to_vec()
}

/// Base64url encode without padding.
fn base64url_encode(data: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    
    let mut result = String::with_capacity((data.len() * 4 + 2) / 3);
    
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        
        result.push(CHARSET[b0 >> 2] as char);
        result.push(CHARSET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        
        if chunk.len() > 1 {
            result.push(CHARSET[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
        }
        if chunk.len() > 2 {
            result.push(CHARSET[b2 & 0x3F] as char);
        }
    }
    
    result
}

/// URL encode a string.
fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
            _ => {
                for byte in c.to_string().as_bytes() {
                    result.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    result
}

/// Parsed OAuth token response.
#[derive(Debug, Clone)]
pub struct TokenResponse {
    /// Access token.
    pub access_token: SecureString,
    /// Token type (usually "Bearer").
    pub token_type: String,
    /// Expires in seconds.
    pub expires_in: Option<u64>,
    /// Refresh token.
    pub refresh_token: Option<SecureString>,
    /// Scope granted.
    pub scope: Option<String>,
    /// ID token (for OIDC).
    pub id_token: Option<String>,
}

impl TokenResponse {
    /// Parse from JSON response.
    pub fn from_json(json: &serde_json::Value) -> Option<Self> {
        let access_token = json["access_token"].as_str()?;
        let token_type = json["token_type"].as_str().unwrap_or("Bearer").to_string();
        let expires_in = json["expires_in"].as_u64();
        let refresh_token = json["refresh_token"].as_str().map(SecureString::new);
        let scope = json["scope"].as_str().map(String::from);
        let id_token = json["id_token"].as_str().map(String::from);
        
        Some(Self {
            access_token: SecureString::new(access_token),
            token_type,
            expires_in,
            refresh_token,
            scope,
            id_token,
        })
    }
}

/// OAuth flow manager for tracking multiple concurrent flows.
#[derive(Default)]
pub struct OAuthManager {
    /// Active states indexed by state value.
    states: std::collections::HashMap<String, OAuthState>,
    /// Configurations indexed by client ID or name.
    configs: std::collections::HashMap<String, OAuthConfig>,
}

impl OAuthManager {
    /// Create a new OAuth manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an OAuth configuration.
    pub fn register_config(&mut self, name: &str, config: OAuthConfig) {
        self.configs.insert(name.to_string(), config);
    }

    /// Get a configuration by name.
    pub fn get_config(&self, name: &str) -> Option<&OAuthConfig> {
        self.configs.get(name)
    }

    /// Create a new OAuth state.
    pub fn create_state(&mut self, use_pkce: bool) -> &OAuthState {
        let state = OAuthState::new(use_pkce);
        let state_value = state.state.clone();
        self.states.insert(state_value.clone(), state);
        self.states.get(&state_value).unwrap()
    }

    /// Get a state by its value.
    pub fn get_state(&self, state: &str) -> Option<&OAuthState> {
        self.states.get(state)
    }

    /// Validate and consume a state.
    pub fn validate_and_consume(&mut self, received_state: &str) -> bool {
        if let Some(state) = self.states.get_mut(received_state) {
            if state.validate(received_state) {
                state.mark_used();
                return true;
            }
        }
        false
    }

    /// Clean up expired states.
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Instant::now();
        let before = self.states.len();
        
        self.states.retain(|_, state| {
            state.expires_at.map_or(true, |exp| now < exp) && !state.used
        });
        
        before - self.states.len()
    }
}
