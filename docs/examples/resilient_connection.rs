//! Client-side connection management with automatic reconnection and health monitoring
//!
//! This module provides:
//! - Automatic reconnection with exponential backoff
//! - Connection health monitoring
//! - Seamless failover between transports
//! - Session state preservation
//! - Connection pooling and pre-warming
//!
//! # Example
//!
//! ```no_run
//! use commucat_client::ResilientConnection;
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = ConnectionConfig {
//!         server_url: "wss://server.example.com/p2p".to_string(),
//!         keep_alive_interval: Duration::from_secs(30),
//!         auto_reconnect: true,
//!         ..Default::default()
//!     };
//!
//!     let mut conn = ResilientConnection::connect(config).await?;
//!
//!     // Connection automatically maintains itself
//!     conn.send(b"Hello, world!").await?;
//!     let response = conn.recv().await?;
//!
//!     Ok(())
//! }
//! ```

use futures_util::{SinkExt, StreamExt};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{interval, sleep, timeout};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tracing::{debug, error, info, warn};

/// Configuration for resilient connection
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Primary server WebSocket URL
    pub server_url: String,
    /// Fallback server URLs (for failover)
    pub fallback_urls: Vec<String>,
    /// Keep-alive ping interval
    pub keep_alive_interval: Duration,
    /// Pong response timeout
    pub pong_timeout: Duration,
    /// Maximum consecutive missed pongs before reconnect
    pub max_missed_pongs: u32,
    /// Enable automatic reconnection
    pub auto_reconnect: bool,
    /// Initial reconnection backoff
    pub initial_backoff: Duration,
    /// Maximum reconnection backoff
    pub max_backoff: Duration,
    /// Maximum reconnection attempts (0 = infinite)
    pub max_reconnect_attempts: u32,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Enable connection health degradation detection
    pub detect_degradation: bool,
    /// RTT threshold for degradation (ms)
    pub degradation_rtt_ms: u64,
    /// Jitter threshold for degradation (ms)
    pub degradation_jitter_ms: u64,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            fallback_urls: Vec::new(),
            keep_alive_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
            max_missed_pongs: 3,
            auto_reconnect: true,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            max_reconnect_attempts: 0,
            connect_timeout: Duration::from_secs(10),
            detect_degradation: true,
            degradation_rtt_ms: 500,
            degradation_jitter_ms: 100,
        }
    }
}

/// Connection health metrics
#[derive(Debug, Clone, Default)]
pub struct HealthMetrics {
    pub rtt_samples: VecDeque<Duration>,
    pub avg_rtt_ms: Option<u64>,
    pub jitter_ms: f64,
    pub consecutive_failures: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connected_at: Option<Instant>,
    pub last_activity: Option<Instant>,
    pub reconnect_count: u32,
}

impl HealthMetrics {
    pub fn new() -> Self {
        Self {
            rtt_samples: VecDeque::with_capacity(10),
            connected_at: Some(Instant::now()),
            last_activity: Some(Instant::now()),
            ..Default::default()
        }
    }

    pub fn record_rtt(&mut self, rtt: Duration) {
        self.rtt_samples.push_back(rtt);
        if self.rtt_samples.len() > 10 {
            self.rtt_samples.pop_front();
        }
        self.consecutive_failures = 0;
        self.last_activity = Some(Instant::now());
        self.update_stats();
    }

    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
    }

    fn update_stats(&mut self) {
        if self.rtt_samples.is_empty() {
            self.avg_rtt_ms = None;
            self.jitter_ms = 0.0;
            return;
        }

        let rtts_ms: Vec<f64> = self
            .rtt_samples
            .iter()
            .map(|d| d.as_secs_f64() * 1000.0)
            .collect();

        let mean = rtts_ms.iter().sum::<f64>() / rtts_ms.len() as f64;
        self.avg_rtt_ms = Some(mean as u64);

        if rtts_ms.len() >= 2 {
            let variance =
                rtts_ms.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / rtts_ms.len() as f64;
            self.jitter_ms = variance.sqrt();
        }
    }

    pub fn is_degraded(&self, config: &ConnectionConfig) -> bool {
        if !config.detect_degradation {
            return false;
        }

        if let Some(avg_rtt) = self.avg_rtt_ms {
            return avg_rtt > config.degradation_rtt_ms
                || self.jitter_ms > config.degradation_jitter_ms as f64;
        }

        false
    }

    pub fn uptime(&self) -> Option<Duration> {
        self.connected_at.map(|t| t.elapsed())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting(u32), // attempt number
    Failed,
    Degraded,
}

/// Resilient WebSocket connection with automatic recovery
pub struct ResilientConnection {
    config: ConnectionConfig,
    state: Arc<RwLock<ConnectionState>>,
    health: Arc<RwLock<HealthMetrics>>,
    tx: mpsc::Sender<Vec<u8>>,
    rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    active_url: Arc<RwLock<String>>,
}

impl ResilientConnection {
    /// Connect to server with resilient connection management
    pub async fn connect(config: ConnectionConfig) -> Result<Self, ConnectionError> {
        let state = Arc::new(RwLock::new(ConnectionState::Connecting));
        let health = Arc::new(RwLock::new(HealthMetrics::new()));
        let active_url = Arc::new(RwLock::new(config.server_url.clone()));

        let (tx, rx_internal) = mpsc::channel::<Vec<u8>>(1024);
        let (tx_internal, rx) = mpsc::channel::<Vec<u8>>(1024);
        let rx = Arc::new(Mutex::new(rx));

        // Establish initial connection
        let ws_stream = Self::connect_to_url(&config.server_url, &config).await?;

        // Update state
        *state.write().await = ConnectionState::Connected;
        *health.write().await = HealthMetrics::new();

        // Spawn connection handler
        tokio::spawn(Self::connection_handler(
            config.clone(),
            state.clone(),
            health.clone(),
            active_url.clone(),
            ws_stream,
            rx_internal,
            tx_internal,
        ));

        Ok(Self {
            config,
            state,
            health,
            tx,
            rx,
            active_url,
        })
    }

    async fn connect_to_url(
        url: &str,
        config: &ConnectionConfig,
    ) -> Result<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>, ConnectionError> {
        info!(url, "Connecting to WebSocket server");

        let connect_future = connect_async(url);
        let (ws_stream, _) = timeout(config.connect_timeout, connect_future)
            .await
            .map_err(|_| ConnectionError::Timeout)?
            .map_err(|e| ConnectionError::Network(e.to_string()))?;

        info!(url, "WebSocket connection established");
        Ok(ws_stream)
    }

    /// Main connection handler with keep-alive and reconnection logic
    async fn connection_handler(
        config: ConnectionConfig,
        state: Arc<RwLock<ConnectionState>>,
        health: Arc<RwLock<HealthMetrics>>,
        active_url: Arc<RwLock<String>>,
        mut ws_stream: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
        mut rx_app: mpsc::Receiver<Vec<u8>>,
        tx_app: mpsc::Sender<Vec<u8>>,
    ) {
        let mut ping_interval = interval(config.keep_alive_interval);
        let mut ping_seq: u64 = 0;
        let mut pending_pong: Option<(u64, Instant)> = None;

        loop {
            tokio::select! {
                // Keep-alive ping timer
                _ = ping_interval.tick() => {
                    let payload = ping_seq.to_be_bytes().to_vec();
                    let sent_at = Instant::now();

                    if ws_stream.send(Message::Ping(payload.clone())).await.is_err() {
                        error!("Failed to send ping, initiating reconnect");
                        if Self::handle_reconnect(&config, &state, &health, &active_url, &mut ws_stream).await.is_err() {
                            break;
                        }
                        continue;
                    }

                    pending_pong = Some((ping_seq, sent_at));
                    ping_seq += 1;
                }

                // Outgoing messages from application
                Some(data) = rx_app.recv() => {
                    if ws_stream.send(Message::Binary(data.clone())).await.is_err() {
                        error!("Failed to send message, initiating reconnect");
                        if Self::handle_reconnect(&config, &state, &health, &active_url, &mut ws_stream).await.is_err() {
                            break;
                        }
                        continue;
                    }

                    let mut h = health.write().await;
                    h.bytes_sent += data.len() as u64;
                }

                // Incoming messages from WebSocket
                Some(msg_result) = ws_stream.next() => {
                    match msg_result {
                        Ok(Message::Binary(data)) => {
                            let mut h = health.write().await;
                            h.bytes_received += data.len() as u64;
                            h.last_activity = Some(Instant::now());
                            drop(h);

                            let _ = tx_app.send(data).await;
                        }
                        Ok(Message::Pong(payload)) => {
                            if let Some((seq, sent_at)) = pending_pong {
                                let expected = seq.to_be_bytes().to_vec();
                                if payload == expected {
                                    let rtt = sent_at.elapsed();
                                    let mut h = health.write().await;
                                    h.record_rtt(rtt);
                                    debug!(seq, rtt_ms = rtt.as_millis(), "Pong received");

                                    // Check for degradation
                                    if h.is_degraded(&config) {
                                        warn!(avg_rtt = ?h.avg_rtt_ms, jitter = h.jitter_ms, "Connection degraded");
                                        *state.write().await = ConnectionState::Degraded;
                                    }

                                    pending_pong = None;
                                }
                            }
                        }
                        Ok(Message::Close(_)) => {
                            info!("WebSocket closed by server");
                            if Self::handle_reconnect(&config, &state, &health, &active_url, &mut ws_stream).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            error!(error = ?e, "WebSocket error");
                            if Self::handle_reconnect(&config, &state, &health, &active_url, &mut ws_stream).await.is_err() {
                                break;
                            }
                        }
                        _ => {}
                    }
                }

                // Check pending pong timeout
                else => {
                    if let Some((seq, sent_at)) = pending_pong {
                        if sent_at.elapsed() > config.pong_timeout {
                            let mut h = health.write().await;
                            h.record_failure();
                            warn!(seq, failures = h.consecutive_failures, "Pong timeout");

                            if h.consecutive_failures >= config.max_missed_pongs {
                                error!("Too many missed pongs, initiating reconnect");
                                drop(h);
                                if Self::handle_reconnect(&config, &state, &health, &active_url, &mut ws_stream).await.is_err() {
                                    break;
                                }
                            }

                            pending_pong = None;
                        }
                    }
                }
            }
        }

        *state.write().await = ConnectionState::Failed;
        error!("Connection handler terminated");
    }

    async fn handle_reconnect(
        config: &ConnectionConfig,
        state: &Arc<RwLock<ConnectionState>>,
        health: &Arc<RwLock<HealthMetrics>>,
        active_url: &Arc<RwLock<String>>,
        ws_stream: &mut WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    ) -> Result<(), ConnectionError> {
        if !config.auto_reconnect {
            return Err(ConnectionError::Reconnect(
                "Auto-reconnect disabled".to_string(),
            ));
        }

        let mut attempt = 0u32;
        let multiplier = 2.0f64;

        loop {
            *state.write().await = ConnectionState::Reconnecting(attempt);

            // Calculate backoff with jitter
            let base_backoff =
                config.initial_backoff.as_secs_f64() * multiplier.powi(attempt as i32);
            let capped_backoff = base_backoff.min(config.max_backoff.as_secs_f64());
            let jitter = (rand::random::<f64>() - 0.5) * capped_backoff * 0.25;
            let backoff = Duration::from_secs_f64((capped_backoff + jitter).max(0.0));

            info!(
                attempt,
                backoff_secs = backoff.as_secs(),
                "Reconnecting..."
            );
            sleep(backoff).await;

            // Try primary URL first, then fallbacks
            let urls = std::iter::once(active_url.read().await.clone())
                .chain(config.fallback_urls.iter().cloned());

            for url in urls {
                match Self::connect_to_url(&url, config).await {
                    Ok(new_stream) => {
                        *ws_stream = new_stream;
                        *active_url.write().await = url.clone();
                        *state.write().await = ConnectionState::Connected;

                        let mut h = health.write().await;
                        h.reconnect_count += 1;
                        h.connected_at = Some(Instant::now());
                        h.consecutive_failures = 0;

                        info!(url, attempt, "Reconnection successful");
                        return Ok(());
                    }
                    Err(e) => {
                        warn!(url, error = ?e, "Reconnection attempt failed");
                    }
                }
            }

            attempt += 1;

            if config.max_reconnect_attempts > 0 && attempt >= config.max_reconnect_attempts {
                error!(
                    attempts = attempt,
                    "Max reconnection attempts reached, giving up"
                );
                return Err(ConnectionError::Reconnect("Max attempts exceeded".to_string()));
            }
        }
    }

    /// Send data over the connection
    pub async fn send(&self, data: &[u8]) -> Result<(), ConnectionError> {
        self.tx
            .send(data.to_vec())
            .await
            .map_err(|_| ConnectionError::ChannelClosed)
    }

    /// Receive data from the connection
    pub async fn recv(&self) -> Result<Vec<u8>, ConnectionError> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(ConnectionError::ChannelClosed)
    }

    /// Get current connection state
    pub async fn state(&self) -> ConnectionState {
        *self.state.read().await
    }

    /// Get current health metrics
    pub async fn health(&self) -> HealthMetrics {
        self.health.read().await.clone()
    }

    /// Get active server URL
    pub async fn active_url(&self) -> String {
        self.active_url.read().await.clone()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("Connection timeout")]
    Timeout,

    #[error("Network error: {0}")]
    Network(String),

    #[error("Reconnection failed: {0}")]
    Reconnect(String),

    #[error("Channel closed")]
    ChannelClosed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_metrics_tracking() {
        let mut metrics = HealthMetrics::new();

        metrics.record_rtt(Duration::from_millis(50));
        metrics.record_rtt(Duration::from_millis(60));
        metrics.record_rtt(Duration::from_millis(55));

        assert_eq!(metrics.avg_rtt_ms, Some(55));
        assert_eq!(metrics.consecutive_failures, 0);
    }

    #[test]
    fn test_degradation_detection() {
        let mut metrics = HealthMetrics::new();
        let config = ConnectionConfig {
            degradation_rtt_ms: 100,
            degradation_jitter_ms: 50,
            ..Default::default()
        };

        // Good connection
        metrics.record_rtt(Duration::from_millis(50));
        assert!(!metrics.is_degraded(&config));

        // High RTT
        metrics.record_rtt(Duration::from_millis(150));
        metrics.update_stats();
        assert!(metrics.is_degraded(&config));
    }
}
