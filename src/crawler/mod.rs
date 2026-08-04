//! Crawler module - high-speed crawling engine with link extraction and asset discovery.

pub mod engine;
pub mod queue;
pub mod dedupe;
pub mod extract;
pub mod assets;
pub mod forms;

pub use engine::{CrawlerEngine, CrawlerConfig, CrawlerConfigBuilder, CrawlStats};
pub use queue::{CrawlQueue, CrawlItem, CrawlPriority, LockFreeQueue};
pub use dedupe::{DedupeCache, DedupeStats, BloomFilter, ContentHash, SimHash, MinHash};
pub use extract::{LinkExtractor, ExtractionResult};
pub use assets::{AssetCatalog, DiscoveredAsset, AssetType, AssetStats, detect_asset_type};
pub use forms::{FormExtractor, DiscoveredForm, FormInput, FormMethod, InputType};
