//! Async crawl engine that pulls URLs from a bounded priority queue.
//!
//! This module implements the core crawling loop with non-blocking Tokio integration,
//! bounded concurrency, and memory-efficient operation.

use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::{Duration, Instant};
use parking_lot::RwLock;
use tracing::{debug, info, warn, error};

use crate::target::{IngestedTarget, TargetConfig, ScopeValidator, ScopeCheck};
use crate::http::dispatch::{Dispatcher, DispatchRequest, DispatchResponse};
use super::queue::{CrawlQueue, CrawlItem, CrawlPriority};
use super::dedupe::DedupeCache;
use super::extract::LinkExtractor;
use super::assets::DiscoveredAsset;

/// Crawler configuration
#[derive(Debug, Clone)]
pub struct CrawlerConfig {
    /// Maximum concurrent requests
    pub max_concurrency: usize,
    /// Maximum depth to crawl
    pub max_depth: u32,
    /// Request timeout
    pub request_timeout: Duration,
    /// Delay between requests per host
    pub per_host_delay: Duration,
    /// Whether to respect robots.txt (future feature)
    pub respect_robots: bool,
    /// User agent string
    pub user_agent: String,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 50,
            max_depth: 10,
            request_timeout: Duration::from_secs(30),
            per_host_delay: Duration::from_millis(100),
            respect_robots: false,
            user_agent: "SwarmEngine/0.1 (Security Scanner)".to_string(),
        }
    }
}

/// Crawl statistics
#[derive(Debug, Default, Clone)]
pub struct CrawlStats {
    pub urls_visited: u64,
    pub urls_queued: u64,
    pub urls_deduped: u64,
    pub assets_discovered: u64,
    pub forms_found: u64,
    pub api_endpoints: u64,
    pub errors: u64,
    pub start_time: Option<Instant>,
}

/// Message types for crawler communication
#[derive(Debug)]
pub enum CrawlMessage {
    /// Add a new URL to crawl
    AddUrl { url: String, depth: u32, priority: CrawlPriority },
    /// Crawl result with discovered links
    CrawlResult {
        url: String,
        status: u16,
        discovered: Vec<String>,
        assets: Vec<DiscoveredAsset>,
    },
    /// Error during crawl
    Error { url: String, error: String },
    /// Signal to stop crawling
    Stop,
}

/// High-speed crawler engine
pub struct CrawlerEngine {
    config: CrawlerConfig,
    target_config: Arc<TargetConfig>,
    queue: CrawlQueue,
    dedupe: DedupeCache,
    dispatcher: Dispatcher,
    stats: Arc<RwLock<CrawlStats>>,
    semaphore: Arc<Semaphore>,
    running: Arc<RwLock<bool>>,
}

impl CrawlerEngine {
    /// Create a new crawler engine
    pub fn new(
        config: CrawlerConfig,
        target_config: Arc<TargetConfig>,
        dispatcher: Dispatcher,
    ) -> Self {
        let max_queue_size = 100_000; // Bounded queue size
        Self {
            config,
            target_config,
            queue: CrawlQueue::new(max_queue_size, config.max_depth),
            dedupe: DedupeCache::new(1_000_000), // ~1M entries capacity
            dispatcher,
            stats: Arc::new(RwLock::new(CrawlStats::default())),
            semaphore: Arc::new(Semaphore::new(config.max_concurrency)),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Seed the crawler with initial URLs
    pub fn seed(&mut self, urls: Vec<String>) {
        let mut stats = self.stats.write();
        stats.start_time = Some(Instant::now());
        
        for url in urls {
            if let Ok(item) = CrawlItem::new(url, 0, CrawlPriority::High) {
                if self.queue.push(item) {
                    stats.urls_queued += 1;
                }
            }
        }
    }

    /// Run the crawler until completion or timeout
    pub async fn run(&self, timeout: Duration) -> CrawlStats {
        *self.running.write() = true;
        let start = Instant::now();
        
        let mut handles = Vec::new();
        
        // Worker pool
        for worker_id in 0..self.config.max_concurrency {
            let semaphore = self.semaphore.clone();
            let queue = self.queue.clone();
            let dedupe = self.dedupe.clone();
            let dispatcher = self.dispatcher.clone();
            let stats = self.stats.clone();
            let running = self.running.clone();
            let target_config = self.target_config.clone();
            let per_host_delay = self.config.per_host_delay;
            
            let handle = tokio::spawn(async move {
                Self::worker_loop(
                    worker_id,
                    semaphore,
                    queue,
                    dedupe,
                    dispatcher,
                    stats,
                    running,
                    target_config,
                    per_host_delay,
                ).await
            });
            
            handles.push(handle);
        }

        // Timeout handler
        let timeout_future = tokio::time::sleep(timeout);
        tokio::pin!(timeout_future);

        // Monitor for queue empty
        loop {
            tokio::select! {
                _ = &mut timeout_future => {
                    info!("Crawler timeout reached");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(500)) => {
                    if self.queue.is_empty() && self.queue.active_count() == 0 {
                        debug!("Queue empty and no active tasks");
                        break;
                    }
                }
            }
        }

        // Signal workers to stop
        *self.running.write() = false;

        // Wait for workers to finish
        for handle in handles {
            let _ = handle.await;
        }

        let stats = self.stats.read().clone();
        info!("Crawl completed: {} URLs visited", stats.urls_visited);
        stats
    }

    /// Worker loop for processing crawl items
    #[allow(clippy::too_many_arguments)]
    async fn worker_loop(
        worker_id: usize,
        semaphore: Arc<Semaphore>,
        queue: CrawlQueue,
        dedupe: DedupeCache,
        dispatcher: Dispatcher,
        stats: Arc<RwLock<CrawlStats>>,
        running: Arc<RwLock<bool>>,
        target_config: Arc<TargetConfig>,
        per_host_delay: Duration,
    ) {
        while *running.read() {
            // Get next item from queue
            let item = match queue.pop().await {
                Some(i) => i,
                None => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };

            // Check if already processed
            if dedupe.is_duplicate_url(&item.url) {
                let mut s = stats.write();
                s.urls_deduped += 1;
                continue;
            }

            // Acquire semaphore permit
            let _permit = semaphore.acquire().await.unwrap();
            queue.mark_active(&item.url);

            // Perform the request
            match Self::crawl_url(
                &item,
                &dispatcher,
                &dedupe,
                &target_config,
                &stats,
                per_host_delay,
            ).await {
                Ok(discovered) => {
                    // Queue discovered URLs
                    for url in discovered {
                        if item.depth < queue.max_depth() {
                            if let Ok(new_item) = CrawlItem::new(
                                url,
                                item.depth + 1,
                                CrawlPriority::Normal,
                            ) {
                                queue.push(new_item);
                                let mut s = stats.write();
                                s.urls_queued += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    let mut s = stats.write();
                    s.errors += 1;
                    debug!("Worker {} error: {}", worker_id, e);
                }
            }

            queue.mark_complete(&item.url);
        }
    }

    /// Crawl a single URL and return discovered links
    async fn crawl_url(
        item: &CrawlItem,
        dispatcher: &Dispatcher,
        dedupe: &DedupeCache,
        target_config: &TargetConfig,
        stats: &Arc<RwLock<CrawlStats>>,
        per_host_delay: Duration,
    ) -> Result<Vec<String>, String> {
        // Rate limiting per host
        tokio::time::sleep(per_host_delay).await;

        // Build request
        let request = DispatchRequest::get(&item.url)
            .map_err(|e| e.to_string())?;

        // Execute request
        let response = match dispatcher.dispatch(request).await {
            Ok(r) => r,
            Err(e) => {
                return Err(format!("Dispatch failed: {}", e));
            }
        };

        // Update stats
        {
            let mut s = stats.write();
            s.urls_visited += 1;
        }

        // Mark as processed
        dedupe.mark_url_processed(&item.url);

        // Extract links from response
        if let Some(body) = response.body {
            let extractor = LinkExtractor::new();
            let extracted = extractor.extract(&item.url, &body);
            
            // Filter by scope
            let mut scope_validator = ScopeValidator::new(target_config.scope.clone());
            let mut valid_urls = Vec::new();
            
            for url_str in extracted.urls {
                if let Ok(parsed) = url::Url::parse(&url_str) {
                    if matches!(scope_validator.check(&parsed), ScopeCheck::InScope) {
                        valid_urls.push(url_str);
                    }
                }
            }

            return Ok(valid_urls);
        }

        Ok(Vec::new())
    }

    /// Get current statistics
    pub fn stats(&self) -> CrawlStats {
        self.stats.read().clone()
    }

    /// Get queue length
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Stop the crawler
    pub fn stop(&self) {
        *self.running.write() = false;
    }

    /// Check if crawler is running
    pub fn is_running(&self) -> bool {
        *self.running.read()
    }
}

/// Builder for CrawlerConfig
#[derive(Default)]
pub struct CrawlerConfigBuilder {
    config: CrawlerConfig,
}

impl CrawlerConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_concurrency(mut self, n: usize) -> Self {
        self.config.max_concurrency = n;
        self
    }

    pub fn with_max_depth(mut self, depth: u32) -> Self {
        self.config.max_depth = depth;
        self
    }

    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.config.request_timeout = timeout;
        self
    }

    pub fn with_per_host_delay(mut self, delay: Duration) -> Self {
        self.config.per_host_delay = delay;
        self
    }

    pub fn with_user_agent(mut self, ua: String) -> Self {
        self.config.user_agent = ua;
        self
    }

    pub fn build(self) -> CrawlerConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crawler_config_builder() {
        let config = CrawlerConfigBuilder::new()
            .with_max_concurrency(100)
            .with_max_depth(5)
            .with_request_timeout(Duration::from_secs(10))
            .build();
        
        assert_eq!(config.max_concurrency, 100);
        assert_eq!(config.max_depth, 5);
    }
}
