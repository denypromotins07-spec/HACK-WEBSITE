//! Session module for managing authentication state.
//!
//! This module provides comprehensive session lifecycle management including:
//! - Bounded session stores with automatic cleanup
//! - Cookie parsing, validation, and SameSite inspection
//! - Integration with request dispatch and response parsing

pub mod cookies;
pub mod store;

pub use cookies::{
    build_cookie_header, parse_cookie_header, parse_set_cookie, Cookie, CookieValidation,
    SameSite,
};
pub use store::{SessionId, SessionMetadata, SessionState, SessionStore, SessionStoreConfig};

/// Re-export commonly used types.
pub use crate::session::store::SessionEntry;
