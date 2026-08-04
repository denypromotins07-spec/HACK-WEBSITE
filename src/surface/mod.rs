//! Surface module - route graph, API detection, and parameter classification.

pub mod routes;
pub mod api;
pub mod parameters;

pub use routes::{RouteGraph, DiscoveredRoute, ResponseFingerprint, HttpMethod, RouteParameter, ParamLocation, VulnScanTarget, RouteStats};
pub use api::{ApiSurfaceDetector, ApiEndpoint, ApiProtocol, AuthType, GraphqlSchema, ApiStats};
pub use parameters::{DiscoveredParameter, ParameterCatalog, ParamLocation as SurfaceParamLocation, ParamDataType, ParamSecurityCategory, MutationPayload, ParameterStats};
