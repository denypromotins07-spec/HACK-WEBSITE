//! Authentication configuration and global auth modes.
//!
//! Defines the supported authentication strategies for the scanner:
//! - None (public scanning)
//! - Cookie-based form login
//! - Bearer tokens
//! - JWT (JSON Web Tokens)
//! - OAuth 2.0 / OIDC flows
//! - API Key injection

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Global authentication mode selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "config")]
pub enum AuthMode {
    /// No authentication; public scanning only.
    None,
    /// Form-based login with username/password.
    FormLogin(FormLoginConfig),
    /// HTTP Basic Authentication.
    Basic(BasicAuthConfig),
    /// Bearer token injection (static or dynamic).
    Bearer(BearerConfig),
    /// JWT-based authentication with optional refresh.
    Jwt(JwtConfig),
    /// OAuth 2.0 flow handling.
    OAuth(OAuthConfig),
    /// API Key injection in header, query, or cookie.
    ApiKey(ApiKeyConfig),
}

/// Configuration for form-based login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormLoginConfig {
    /// Login URL endpoint.
    pub login_url: String,
    /// Username field name.
    pub username_field: String,
    /// Password field name.
    pub password_field: String,
    /// Optional additional fields.
    pub extra_fields: Vec<(String, String)>,
    /// Success indicator (string or regex pattern).
    pub success_indicator: Option<String>,
    /// Failure indicator.
    pub failure_indicator: Option<String>,
    /// Session cookie name to track.
    pub session_cookie_name: Option<String>,
}

/// Configuration for HTTP Basic Auth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuthConfig {
    /// Username.
    pub username: String,
    /// Password (handled securely).
    #[serde(skip_serializing)]
    pub password: String,
}

/// Configuration for Bearer token auth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BearerConfig {
    /// Static token value.
    pub token: Option<String>,
    /// Token header name (default: Authorization).
    pub header_name: Option<String>,
    /// Prefix (default: "Bearer").
    pub prefix: Option<String>,
    /// Optional refresh endpoint.
    pub refresh_url: Option<String>,
    /// Refresh interval.
    pub refresh_interval: Option<Duration>,
}

/// Configuration for JWT auth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// Raw JWT token.
    pub token: Option<String>,
    /// Path to JWT file.
    pub token_file: Option<String>,
    /// Signing key for token generation/refresh.
    pub signing_key: Option<String>,
    /// Algorithm (HS256, RS256, etc.).
    pub algorithm: Option<String>,
    /// Claims to inject.
    pub custom_claims: Option<serde_json::Value>,
    /// Refresh strategy.
    pub refresh_strategy: Option<JwtRefreshStrategy>,
}

/// JWT refresh strategies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JwtRefreshStrategy {
    /// Refresh based on expiry time.
    ExpiryBased,
    /// Refresh on 401 response.
    OnUnauthorized,
    /// Fixed interval refresh.
    Interval(Duration),
}

/// Configuration for OAuth 2.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConfig {
    /// Authorization endpoint.
    pub auth_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
    /// Client ID.
    pub client_id: String,
    /// Client secret (handled securely).
    #[serde(skip_serializing)]
    pub client_secret: Option<String>,
    /// Redirect URI.
    pub redirect_uri: String,
    /// Scopes requested.
    pub scopes: Vec<String>,
    /// PKCE enabled.
    pub pkce_enabled: bool,
    /// State parameter for CSRF protection.
    pub state: Option<String>,
}

/// Configuration for API Key auth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// API key value.
    pub key: String,
    /// Injection location.
    pub location: ApiKeyLocation,
    /// Parameter/header name.
    pub name: String,
    /// Optional prefix.
    pub prefix: Option<String>,
}

/// Location for API key injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiKeyLocation {
    /// In HTTP header.
    Header,
    /// In query string.
    Query,
    /// In cookie.
    Cookie,
}

impl Default for AuthMode {
    fn default() -> Self {
        AuthMode::None
    }
}

/// Global authentication configuration container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Primary auth mode.
    pub mode: AuthMode,
    /// Fallback modes if primary fails.
    pub fallback_modes: Vec<AuthMode>,
    /// Enable automatic session renewal.
    pub auto_renew: bool,
    /// Max retries for auth failures.
    pub max_auth_retries: u32,
    /// Timeout for auth operations.
    pub auth_timeout: Duration,
}

impl AuthConfig {
    /// Create a new auth config with specified mode.
    pub fn new(mode: AuthMode) -> Self {
        Self {
            mode,
            fallback_modes: Vec::new(),
            auto_renew: true,
            max_auth_retries: 3,
            auth_timeout: Duration::from_secs(30),
        }
    }

    /// Check if authentication is required.
    pub fn requires_auth(&self) -> bool {
        !matches!(self.mode, AuthMode::None)
    }
}
