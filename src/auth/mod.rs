//! Authentication module for the scanner.
//!
//! This module provides comprehensive authentication handling including:
//! - Multiple auth modes (cookie, bearer, JWT, OAuth, API key)
//! - User persona management for privilege escalation testing
//! - Secure credential storage and redaction
//! - Token handling and identity protocol support

pub mod config;
pub mod credentials;
pub mod jwt;
pub mod oauth;
pub mod persona;
pub mod redaction;
pub mod tokens;
pub mod vault;

pub use config::{AuthConfig, AuthMode};
pub use persona::{Persona, PersonaId, PersonaManager, PrivilegeLevel};

/// Re-export commonly used types for convenience.
pub use crate::auth::config::{
    ApiKeyConfig, ApiKeyLocation, BasicAuthConfig, BearerConfig, FormLoginConfig, JwtConfig,
    JwtRefreshStrategy, OAuthConfig,
};
