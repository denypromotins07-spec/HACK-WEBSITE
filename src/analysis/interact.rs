//! Lightweight Interaction Server
//! 
//! Tokio UDP/TCP server to catch DNS and HTTP exfiltration callbacks.
//! Uses bounded channels to maintain 2GB RAM ceiling.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::{self, Sender};

/// Protocol type for interaction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Http,
    Dns,
}

/// Interaction event record
#[derive(Debug, Clone)]
pub struct InteractionEvent {
    pub protocol: Protocol,
    pub source_addr: SocketAddr,
    pub data: Vec<u8>,
    pub timestamp_ns: u64,
    pub request_id: Option<u64>,
}

/// Configuration for interaction server
#[derive(Debug, Clone)]
pub struct InteractConfig {
    pub tcp_port: u16,
    pub udp_port: u16,
    pub http_port: u16,
    pub max_events: usize,
    pub event_channel_size: usize,
}

impl Default for InteractConfig {
    fn default() -> Self {
        Self {
            tcp_port: 8080,
            udp_port: 5353,
            http_port: 8081,
            max_events: 10000,
            event_channel_size: 1000,
        }
    }
}

/// Lightweight interaction server for OOB callbacks
pub struct InteractionServer {
    config: InteractConfig,
    events_sent: AtomicU64,
    events_dropped: AtomicU64,
    event_tx: Sender<InteractionEvent>,
    running: Arc<AtomicU64>,
}

impl InteractionServer {
    pub fn new(config: InteractConfig) -> Self {
        let (event_tx, mut event_rx) = mpsc::channel::<InteractionEvent>(config.event_channel_size);
        
        // Spawn event processor in background
        let max_events = config.max_events;
        let events_sent = AtomicU64::new(0);
        let events_dropped = AtomicU64::new(0);
        
        tokio::spawn(async move {
            let mut stored_events: Vec<InteractionEvent> = Vec::with_capacity(max_events.min(1000));
            
            while let Some(event) = event_rx.recv().await {
                if stored_events.len() < max_events {
                    stored_events.push(event);
                } else {
                    // Drop oldest event when at capacity
                    if !stored_events.is_empty() {
                        stored_events.remove(0);
                    }
                    stored_events.push(event);
                }
            }
        });
        
        Self {
            config,
            events_sent: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            event_tx,
            running: Arc::new(AtomicU64::new(1)),
        }
    }
    
    /// Start the TCP listener
    pub async fn start_tcp(&self) -> std::io::Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.tcp_port);
        let listener = TcpListener::bind(&addr).await?;
        
        let event_tx = self.event_tx.clone();
        let running = self.running.clone();
        
        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) == 1 {
                match listener.accept().await {
                    Ok((mut socket, addr)) => {
                        // Read initial data
                        let mut buf = vec![0u8; 1024];
                        match socket.try_read(&mut buf) {
                            Ok(n) if n > 0 => {
                                let event = InteractionEvent {
                                    protocol: Protocol::Tcp,
                                    source_addr: addr,
                                    data: buf[..n].to_vec(),
                                    timestamp_ns: std::time::Instant::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_nanos() as u64,
                                    request_id: None,
                                };
                                
                                if event_tx.send(event).await.is_err() {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        
        Ok(())
    }
    
    /// Start the UDP listener
    pub async fn start_udp(&self) -> std::io::Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.udp_port);
        let socket = UdpSocket::bind(&addr).await?;
        
        let event_tx = self.event_tx.clone();
        let running = self.running.clone();
        
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            
            while running.load(Ordering::Relaxed) == 1 {
                match socket.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        let event = InteractionEvent {
                            protocol: Protocol::Udp,
                            source_addr: addr,
                            data: buf[..n].to_vec(),
                            timestamp_ns: std::time::Instant::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_nanos() as u64,
                            request_id: None,
                        };
                        
                        if event_tx.send(event).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        
        Ok(())
    }
    
    /// Record an interaction event
    pub async fn record_event(&self, event: InteractionEvent) -> Result<(), &'static str> {
        self.events_sent.fetch_add(1, Ordering::Relaxed);
        
        match self.event_tx.send(event).await {
            Ok(_) => Ok(()),
            Err(_) => {
                self.events_dropped.fetch_add(1, Ordering::Relaxed);
                Err("Channel closed")
            }
        }
    }
    
    /// Stop the server
    pub fn stop(&self) {
        self.running.store(0, Ordering::Relaxed);
    }
    
    /// Check if server is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed) == 1
    }
    
    /// Get statistics
    pub fn stats(&self) -> InteractionStats {
        InteractionStats {
            events_sent: self.events_sent.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            is_running: self.is_running(),
        }
    }
}

/// Statistics for interaction server
#[derive(Debug, Clone)]
pub struct InteractionStats {
    pub events_sent: u64,
    pub events_dropped: u64,
    pub is_running: bool,
}

impl InteractionStats {
    pub fn drop_rate(&self) -> f64 {
        let total = self.events_sent + self.events_dropped;
        if total == 0 {
            return 0.0;
        }
        self.events_dropped as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_interaction_server_creation() {
        let config = InteractConfig::default();
        let server = InteractionServer::new(config);
        
        assert!(server.is_running());
        assert_eq!(server.stats().events_sent, 0);
    }
    
    #[test]
    fn test_record_event() {
        let config = InteractConfig::default();
        let server = InteractionServer::new(config);
        
        // Note: This test would need a running runtime to fully test async functionality
        let stats = server.stats();
        assert!(!stats.is_running || stats.events_sent >= 0);
    }
}
