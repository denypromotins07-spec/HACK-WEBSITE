//! Secure credential management.
//!
//! Handles loading credentials from environment variables or encrypted vaults
//! while ensuring sensitive data never appears in logs or memory dumps.

use crate::auth::vault::SecureString;
use std::env;
use std::fmt;

/// Error type for credential operations.
#[derive(Debug)]
pub enum CredentialError {
    /// Environment variable not found.
    EnvNotFound(String),
    /// Invalid credential format.
    InvalidFormat(String),
    /// Vault access error.
    VaultError(String),
    /// Decryption failed.
    DecryptionFailed,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialError::EnvNotFound(var) => write!(f, "Environment variable not found: {}", var),
            CredentialError::InvalidFormat(msg) => write!(f, "Invalid credential format: {}", msg),
            CredentialError::VaultError(msg) => write!(f, "Vault error: {}", msg),
            CredentialError::DecryptionFailed => write!(f, "Decryption failed"),
        }
    }
}

impl std::error::Error for CredentialError {}

/// Result type for credential operations.
pub type CredentialResult<T> = Result<T, CredentialError>;

/// Container for username/password credentials.
#[derive(Clone)]
pub struct UsernamePassword {
    /// Username (can be email or identifier).
    pub username: String,
    /// Password stored securely.
    pub password: SecureString,
}

impl UsernamePassword {
    /// Create new username/password credentials.
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: SecureString::new(password),
        }
    }

    /// Load from environment variables.
    pub fn from_env(username_var: &str, password_var: &str) -> CredentialResult<Self> {
        let username = env::var(username_var)
            .map_err(|_| CredentialError::EnvNotFound(username_var.to_string()))?;
        let password = env::var(password_var)
            .map_err(|_| CredentialError::EnvNotFound(password_var.to_string()))?;
        
        Ok(Self::new(&username, &password))
    }

    /// Get password as a secure reference (zeroed after use).
    pub fn with_password<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&str) -> R,
    {
        self.password.with_inner(f)
    }
}

impl fmt::Debug for UsernamePassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsernamePassword")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Container for API key credentials.
#[derive(Clone)]
pub struct ApiKeyCredentials {
    /// Key name/identifier.
    pub key_name: String,
    /// The actual API key stored securely.
    pub key: SecureString,
}

impl ApiKeyCredentials {
    /// Create new API key credentials.
    pub fn new(key_name: &str, key: &str) -> Self {
        Self {
            key_name: key_name.to_string(),
            key: SecureString::new(key),
        }
    }

    /// Load from environment variable.
    pub fn from_env(key_name: &str, env_var: &str) -> CredentialResult<Self> {
        let key = env::var(env_var)
            .map_err(|_| CredentialError::EnvNotFound(env_var.to_string()))?;
        
        Ok(Self::new(key_name, &key))
    }

    /// Get key as a secure reference.
    pub fn with_key<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&str) -> R,
    {
        self.key.with_inner(f)
    }
}

impl fmt::Debug for ApiKeyCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiKeyCredentials")
            .field("key_name", &self.key_name)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Container for OAuth client credentials.
#[derive(Clone)]
pub struct OAuthCredentials {
    /// Client ID (public).
    pub client_id: String,
    /// Client secret stored securely.
    pub client_secret: Option<SecureString>,
}

impl OAuthCredentials {
    /// Create new OAuth credentials.
    pub fn new(client_id: &str, client_secret: Option<&str>) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: client_secret.map(SecureString::new),
        }
    }

    /// Load from environment variables.
    pub fn from_env(
        client_id_var: &str,
        client_secret_var: Option<&str>,
    ) -> CredentialResult<Self> {
        let client_id = env::var(client_id_var)
            .map_err(|_| CredentialError::EnvNotFound(client_id_var.to_string()))?;
        
        let client_secret = if let Some(secret_var) = client_secret_var {
            let secret = env::var(secret_var)
                .map_err(|_| CredentialError::EnvNotFound(secret_var.to_string()))?;
            Some(SecureString::new(&secret))
        } else {
            None
        };
        
        Ok(Self {
            client_id,
            client_secret,
        })
    }

    /// Get client secret as a secure reference.
    pub fn with_secret<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&str) -> R,
    {
        self.client_secret.as_ref().map(|s| s.with_inner(f))
    }
}

impl fmt::Debug for OAuthCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

/// Container for JWT credentials.
#[derive(Clone)]
pub struct JwtCredentials {
    /// Raw token (if provided directly).
    pub token: Option<SecureString>,
    /// Path to token file.
    pub token_file: Option<String>,
    /// Signing key for token generation.
    pub signing_key: Option<SecureString>,
}

impl JwtCredentials {
    /// Create new JWT credentials from raw token.
    pub fn from_token(token: &str) -> Self {
        Self {
            token: Some(SecureString::new(token)),
            token_file: None,
            signing_key: None,
        }
    }

    /// Create new JWT credentials from file.
    pub fn from_file(path: &str) -> Self {
        Self {
            token: None,
            token_file: Some(path.to_string()),
            signing_key: None,
        }
    }

    /// Create new JWT credentials with signing key.
    pub fn with_signing_key(mut self, key: &str) -> Self {
        self.signing_key = Some(SecureString::new(key));
        self
    }

    /// Load token from file if configured.
    pub fn load_token(&self) -> CredentialResult<Option<String>> {
        if let Some(ref token) = self.token {
            return Ok(Some(token.with_inner(|s| s.to_string())));
        }
        
        if let Some(ref path) = self.token_file {
            std::fs::read_to_string(path)
                .map(|content| Some(content.trim().to_string()))
                .map_err(|e| CredentialError::VaultError(format!("Failed to read token file: {}", e)))
        } else {
            Ok(None)
        }
    }
}

impl fmt::Debug for JwtCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtCredentials")
            .field("token", &"[REDACTED]")
            .field("token_file", &self.token_file)
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

/// Enum encompassing all credential types.
#[derive(Clone)]
pub enum Credentials {
    /// Username/password for form login.
    UsernamePassword(UsernamePassword),
    /// API key authentication.
    ApiKey(ApiKeyCredentials),
    /// OAuth client credentials.
    OAuth(OAuthCredentials),
    /// JWT token or signing material.
    Jwt(JwtCredentials),
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Credentials::UsernamePassword(c) => write!(f, "{:?}", c),
            Credentials::ApiKey(c) => write!(f, "{:?}", c),
            Credentials::OAuth(c) => write!(f, "{:?}", c),
            Credentials::Jwt(c) => write!(f, "{:?}", c),
        }
    }
}
