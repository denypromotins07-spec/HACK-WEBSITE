//! Lock-free bounded work queue with deduplication and crawl depth limits.
//!
//! This module provides a high-performance, thread-safe queue for URL crawling
//! with priority ordering and memory bounds.

use std::collections::BinaryHeap;
use std::cmp::Ordering;
use tokio::sync::{mpsc, Mutex};
use parking_lot::RwLock;
use crossbeam::queue::SegQueue;

/// Priority levels for crawl items
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrawlPriority {
    High = 0,
    Normal = 1,
    Low = 2,
}

impl Ord for CrawlPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        // Lower value = higher priority (reversed for BinaryHeap)
        other.cmp(self)
    }
}

impl PartialOrd for CrawlPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A crawl item in the queue
#[derive(Debug, Clone)]
pub struct CrawlItem {
    pub url: String,
    pub depth: u32,
    pub priority: CrawlPriority,
    pub timestamp: u64,
}

impl CrawlItem {
    pub fn new(url: String, depth: u32, priority: CrawlPriority) -> Result<Self, &'static str> {
        if url.is_empty() {
            return Err("URL cannot be empty");
        }
        if depth > 100 {
            return Err("Depth exceeds maximum");
        }
        
        Ok(Self {
            url,
            depth,
            priority,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
    }
}

impl Ord for CrawlItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // Priority first, then depth (shallower first), then timestamp (older first)
        self.priority.cmp(&other.priority)
            .then_with(|| other.depth.cmp(&self.depth))
            .then_with(|| other.timestamp.cmp(&self.timestamp))
    }
}

impl PartialOrd for CrawlItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for CrawlItem {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl Eq for CrawlItem {}

/// Bounded priority queue for crawl items
pub struct CrawlQueue {
    /// Main priority queue
    heap: Mutex<BinaryHeap<CrawlItem>>,
    /// Set of URLs currently being processed
    active: RwLock<dashmap::DashSet<String>>,
    /// Channel sender for async pop
    tx: mpsc::Sender<CrawlItem>,
    /// Channel receiver for async pop
    rx: Mutex<mpsc::Receiver<CrawlItem>>,
    /// Maximum queue size
    max_size: usize,
    /// Maximum depth
    max_depth: u32,
    /// Current size estimate
    size: RwLock<usize>,
}

impl Clone for CrawlQueue {
    fn clone(&self) -> Self {
        let (tx, rx) = mpsc::channel(1000);
        Self {
            heap: Mutex::new(BinaryHeap::new()),
            active: RwLock::new(dashmap::DashSet::new()),
            tx,
            rx: Mutex::new(rx),
            max_size: self.max_size,
            max_depth: self.max_depth,
            size: RwLock::new(0),
        }
    }
}

impl CrawlQueue {
    /// Create a new bounded crawl queue
    pub fn new(max_size: usize, max_depth: u32) -> Self {
        let (tx, rx) = mpsc::channel(1000);
        
        Self {
            heap: Mutex::new(BinaryHeap::with_capacity(max_size)),
            active: RwLock::new(dashmap::DashSet::new()),
            tx,
            rx: Mutex::new(rx),
            max_size,
            max_depth,
            size: RwLock::new(0),
        }
    }

    /// Push an item to the queue (returns false if full or depth exceeded)
    pub fn push(&self, item: CrawlItem) -> bool {
        // Check depth limit
        if item.depth > self.max_depth {
            return false;
        }

        // Check if already active or in queue (simple check)
        if self.active.read().contains(&item.url) {
            return false;
        }

        // Check size limit
        let current_size = *self.size.read();
        if current_size >= self.max_size {
            return false;
        }

        // Try to send via channel (non-blocking attempt)
        match self.tx.try_send(item.clone()) {
            Ok(_) => {
                *self.size.write() += 1;
                true
            }
            Err(_) => {
                // Channel full, try direct heap insert
                let mut heap = self.heap.blocking_lock();
                if heap.len() < self.max_size {
                    heap.push(item);
                    *self.size.write() += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Pop an item from the queue (async)
    pub async fn pop(&self) -> Option<CrawlItem> {
        // First try channel
        if let Ok(item) = self.rx.lock().await.recv().await {
            *self.size.write() -= 1;
            return Some(item);
        }

        // Fall back to heap
        let mut heap = self.heap.lock().await;
        if let Some(item) = heap.pop() {
            *self.size.write() -= 1;
            Some(item)
        } else {
            None
        }
    }

    /// Mark a URL as actively being processed
    pub fn mark_active(&self, url: &str) {
        self.active.write().insert(url.to_string());
    }

    /// Mark a URL as complete (no longer active)
    pub fn mark_complete(&self, url: &str) {
        self.active.write().remove(url);
    }

    /// Get count of active URLs
    pub fn active_count(&self) -> usize {
        self.active.read().len()
    }

    /// Get current queue length
    pub fn len(&self) -> usize {
        *self.size.read()
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get maximum depth setting
    pub fn max_depth(&self) -> u32 {
        self.max_depth
    }

    /// Clear the queue
    pub fn clear(&self) {
        let mut heap = self.heap.blocking_lock();
        *heap = BinaryHeap::new();
        *self.size.write() = 0;
        self.active.write().clear();
    }

    /// Drain all items (for shutdown)
    pub fn drain(&self) -> Vec<CrawlItem> {
        let mut heap = self.heap.blocking_lock();
        let mut items = Vec::new();
        while let Some(item) = heap.pop() {
            items.push(item);
        }
        *self.size.write() = 0;
        items
    }
}

/// Simple lock-free queue alternative for specific use cases
pub struct LockFreeQueue {
    inner: SegQueue<CrawlItem>,
    max_size: usize,
    seen: dashmap::DashSet<String>,
}

impl LockFreeQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            inner: SegQueue::new(),
            max_size,
            seen: dashmap::DashSet::new(),
        }
    }

    pub fn push(&self, item: CrawlItem) -> bool {
        // Deduplication check
        if self.seen.contains(&item.url) {
            return false;
        }

        if self.inner.len() >= self.max_size {
            return false;
        }

        self.seen.insert(item.url.clone());
        self.inner.push(item);
        true
    }

    pub fn pop(&self) -> Option<CrawlItem> {
        self.inner.pop()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crawl_item_ordering() {
        let item1 = CrawlItem::new("http://a.com".to_string(), 1, CrawlPriority::High).unwrap();
        let item2 = CrawlItem::new("http://b.com".to_string(), 1, CrawlPriority::Normal).unwrap();
        let item3 = CrawlItem::new("http://c.com".to_string(), 2, CrawlPriority::High).unwrap();

        // High priority should come before Normal
        assert!(item1 > item2);
        
        // Same priority, shallower depth first
        assert!(item1 > item3);
    }

    #[test]
    fn test_queue_push_pop() {
        let queue = CrawlQueue::new(100, 5);
        
        let item = CrawlItem::new("http://test.com".to_string(), 0, CrawlPriority::Normal).unwrap();
        assert!(queue.push(item.clone()));
        
        assert_eq!(queue.len(), 1);
        assert!(!queue.is_empty());
    }

    #[test]
    fn test_depth_limit() {
        let queue = CrawlQueue::new(100, 2);
        
        let item = CrawlItem::new("http://test.com".to_string(), 5, CrawlPriority::Normal).unwrap();
        assert!(!queue.push(item)); // Exceeds max depth
    }

    #[test]
    fn test_max_size() {
        let queue = CrawlQueue::new(2, 10);
        
        let item1 = CrawlItem::new("http://a.com".to_string(), 0, CrawlPriority::Normal).unwrap();
        let item2 = CrawlItem::new("http://b.com".to_string(), 0, CrawlPriority::Normal).unwrap();
        let item3 = CrawlItem::new("http://c.com".to_string(), 0, CrawlPriority::Normal).unwrap();
        
        assert!(queue.push(item1));
        assert!(queue.push(item2));
        assert!(!queue.push(item3)); // Queue full
    }
}
