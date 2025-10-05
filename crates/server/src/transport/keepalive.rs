// Keep-Alive and Connection Health Monitoring for CommuCat
//
// Features:
// - WebSocket Ping/Pong heartbeat mechanism
// - Connection quality metrics (RTT, packet loss, jitter)
// - Exponential backoff with jitter for reconnections
// - Automatic failover to backup transports
// - Session state preservation during reconnections

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, error, info, warn};

/// Configuration for keep-alive behavior
#[derive(Debug, Clone)]
#[allow(dead_code)] // Public API for client SDKs
pub struct KeepAliveConfig {
    /// Interval between ping frames (default: 30s)
    pub ping_interval: Duration,
    /// Timeout waiting for pong response (default: 10s)
    pub pong_timeout: Duration,
    /// Maximum consecutive missed pongs before reconnect (default: 3)
    pub max_missed_pongs: u32,
    /// Enable keep-alive mechanism
    pub enabled: bool,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
            max_missed_pongs: 3,
            enabled: true,
        }
    }
}

/// Connection health metrics tracked over time
#[derive(Debug, Clone, Default)]
#[allow(dead_code)] // Public API for client SDKs
pub struct ConnectionHealth {
    /// Round-trip time measurements (last 10)
    pub rtt_samples: VecDeque<Duration>,
    /// Packet loss percentage (0.0 - 1.0)
    pub packet_loss: f64,
    /// Jitter (variance in RTT)
    pub jitter_ms: f64,
    /// Consecutive failed ping attempts
    pub consecutive_failures: u32,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Connection established timestamp
    pub connected_at: Option<Instant>,
    /// Last successful activity timestamp
    pub last_activity: Option<Instant>,
}

#[allow(dead_code)] // Public API for client SDKs
impl ConnectionHealth {
    pub fn new() -> Self {
        Self {
            rtt_samples: VecDeque::with_capacity(10),
            connected_at: Some(Instant::now()),
            last_activity: Some(Instant::now()),
            ..Default::default()
        }
    }

    /// Record successful ping/pong RTT
    pub fn record_rtt(&mut self, rtt: Duration) {
        self.rtt_samples.push_back(rtt);
        if self.rtt_samples.len() > 10 {
            self.rtt_samples.pop_front();
        }
        self.consecutive_failures = 0;
        self.last_activity = Some(Instant::now());
        self.update_jitter();
    }

    /// Record failed ping attempt
    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
    }

    /// Get average RTT from recent samples
    pub fn avg_rtt(&self) -> Option<Duration> {
        if self.rtt_samples.is_empty() {
            return None;
        }
        let sum: Duration = self.rtt_samples.iter().sum();
        Some(sum / self.rtt_samples.len() as u32)
    }

    /// Calculate jitter from RTT variance
    fn update_jitter(&mut self) {
        if self.rtt_samples.len() < 2 {
            return;
        }
        let rtts: Vec<f64> = self
            .rtt_samples
            .iter()
            .map(|d| d.as_secs_f64() * 1000.0)
            .collect();
        let mean = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let variance = rtts.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / rtts.len() as f64;
        self.jitter_ms = variance.sqrt();
    }

    /// Check if connection is healthy
    pub fn is_healthy(&self, config: &KeepAliveConfig) -> bool {
        self.consecutive_failures < config.max_missed_pongs
    }

    /// Check if connection is degraded (high RTT/jitter/loss)
    pub fn is_degraded(&self) -> bool {
        if let Some(avg_rtt) = self.avg_rtt() {
            // Degraded if RTT > 500ms or jitter > 100ms or packet loss > 5%
            return avg_rtt > Duration::from_millis(500)
                || self.jitter_ms > 100.0
                || self.packet_loss > 0.05;
        }
        false
    }

    /// Get connection uptime
    pub fn uptime(&self) -> Option<Duration> {
        self.connected_at.map(|t| t.elapsed())
    }
}

/// Keep-alive heartbeat task for WebSocket connections
#[allow(dead_code)] // Public API for client SDKs
pub struct KeepAliveHeartbeat {
    config: KeepAliveConfig,
    health: Arc<RwLock<ConnectionHealth>>,
    ping_tx: mpsc::Sender<Vec<u8>>,
    pong_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    shutdown_rx: mpsc::Receiver<()>,
}

#[allow(dead_code)] // Public API for client SDKs
impl KeepAliveHeartbeat {
    pub fn new(
        config: KeepAliveConfig,
        health: Arc<RwLock<ConnectionHealth>>,
        ping_tx: mpsc::Sender<Vec<u8>>,
        pong_rx: mpsc::Receiver<Vec<u8>>,
        shutdown_rx: mpsc::Receiver<()>,
    ) -> Self {
        Self {
            config,
            health,
            ping_tx,
            pong_rx: Arc::new(Mutex::new(pong_rx)),
            shutdown_rx,
        }
    }

    /// Start heartbeat loop
    pub async fn run(mut self) -> Result<(), KeepAliveError> {
        if !self.config.enabled {
            info!("Keep-alive disabled, heartbeat task exiting");
            return Ok(());
        }

        info!(
            interval_secs = ?self.config.ping_interval.as_secs(),
            "Starting WebSocket keep-alive heartbeat"
        );

        let mut ping_interval = interval(self.config.ping_interval);
        let mut ping_sequence: u64 = 0;

        loop {
            tokio::select! {
                _ = ping_interval.tick() => {
                    if let Err(e) = self.send_ping(ping_sequence).await {
                        error!(error = ?e, "Keep-alive ping failed");
                        return Err(e);
                    }
                    ping_sequence += 1;
                }
                _ = self.shutdown_rx.recv() => {
                    info!("Keep-alive heartbeat shutting down");
                    return Ok(());
                }
            }
        }
    }

    /// Send ping and wait for pong
    async fn send_ping(&mut self, sequence: u64) -> Result<(), KeepAliveError> {
        let payload = sequence.to_be_bytes().to_vec();
        let ping_sent = Instant::now();

        // Send ping frame
        self.ping_tx
            .send(payload.clone())
            .await
            .map_err(|_| KeepAliveError::ChannelClosed)?;

        debug!(sequence, "Sent keep-alive ping");

        // Wait for matching pong with timeout
        let pong_result = timeout(self.config.pong_timeout, async {
            let mut pong_rx = self.pong_rx.lock().await;
            loop {
                if let Some(pong_payload) = pong_rx.recv().await {
                    if pong_payload == payload {
                        return Ok(());
                    }
                    // Ignore mismatched pongs
                    warn!("Received mismatched pong, ignoring");
                } else {
                    return Err(KeepAliveError::ChannelClosed);
                }
            }
        })
        .await;

        let mut health = self.health.write().await;

        match pong_result {
            Ok(Ok(())) => {
                let rtt = ping_sent.elapsed();
                health.record_rtt(rtt);
                debug!(sequence, rtt_ms = rtt.as_millis(), "Received pong");
                Ok(())
            }
            Ok(Err(e)) => {
                health.record_failure();
                Err(e)
            }
            Err(_) => {
                health.record_failure();
                warn!(
                    sequence,
                    consecutive_failures = health.consecutive_failures,
                    "Pong timeout"
                );

                if !health.is_healthy(&self.config) {
                    error!(
                        failures = health.consecutive_failures,
                        "Connection unhealthy, triggering reconnect"
                    );
                    return Err(KeepAliveError::Unhealthy);
                }

                Ok(())
            }
        }
    }
}

/// Reconnection strategy with exponential backoff and jitter
#[derive(Debug, Clone)]
#[allow(dead_code)] // Public API for client SDKs
pub struct ReconnectStrategy {
    /// Initial backoff delay (default: 1s)
    pub initial_backoff: Duration,
    /// Maximum backoff delay (default: 60s)
    pub max_backoff: Duration,
    /// Backoff multiplier (default: 2.0)
    pub multiplier: f64,
    /// Maximum reconnection attempts (0 = infinite)
    pub max_attempts: u32,
    /// Add random jitter to prevent thundering herd
    pub jitter: bool,
}

impl Default for ReconnectStrategy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            multiplier: 2.0,
            max_attempts: 0, // Infinite by default
            jitter: true,
        }
    }
}

#[allow(dead_code)] // Public API for client SDKs
impl ReconnectStrategy {
    /// Calculate next backoff duration
    pub fn next_backoff(&self, attempt: u32) -> Duration {
        let base = self.initial_backoff.as_secs_f64() * self.multiplier.powi(attempt as i32);
        let capped = base.min(self.max_backoff.as_secs_f64());

        if self.jitter {
            // Add ±25% jitter
            let jitter_range = capped * 0.25;
            let jitter_offset = (rand::random::<f64>() - 0.5) * jitter_range * 2.0;
            Duration::from_secs_f64((capped + jitter_offset).max(0.0))
        } else {
            Duration::from_secs_f64(capped)
        }
    }

    /// Check if should continue retrying
    pub fn should_retry(&self, attempt: u32) -> bool {
        self.max_attempts == 0 || attempt < self.max_attempts
    }
}

/// Reconnection state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Public API for client SDKs
pub enum ConnectionState {
    Connected,
    Disconnected,
    Reconnecting(u32), // attempt number
    Failed,
}

/// Errors related to keep-alive mechanism
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Public API for client SDKs
pub enum KeepAliveError {
    #[error("Connection unhealthy (too many missed pongs)")]
    Unhealthy,

    #[error("Keep-alive channel closed")]
    ChannelClosed,

    #[error("Connection timeout")]
    Timeout,

    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
}

/// Port knocking sequence for Reality transport
#[derive(Debug, Clone)]
#[allow(dead_code)] // Public API for client SDKs
pub struct PortKnockingSequence {
    /// Sequence of ports to knock (TCP or UDP)
    pub ports: Vec<u16>,
    /// Protocol to use (TCP or UDP)
    pub protocol: KnockProtocol,
    /// Delay between knocks (default: 100ms)
    pub knock_delay: Duration,
    /// Timeout for entire sequence (default: 5s)
    pub sequence_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Public API for client SDKs
pub enum KnockProtocol {
    Tcp,
    Udp,
}

#[allow(dead_code)] // Public API for client SDKs
impl PortKnockingSequence {
    /// Execute port knocking sequence
    pub async fn knock(&self, target_host: &str) -> Result<(), std::io::Error> {
        info!(
            host = target_host,
            ports = ?self.ports,
            protocol = ?self.protocol,
            "Executing port knocking sequence"
        );

        let knock_future = async {
            for (i, &port) in self.ports.iter().enumerate() {
                match self.protocol {
                    KnockProtocol::Tcp => {
                        self.knock_tcp(target_host, port).await?;
                    }
                    KnockProtocol::Udp => {
                        self.knock_udp(target_host, port).await?;
                    }
                }

                debug!(knock = i + 1, port, "Port knock successful");

                if i < self.ports.len() - 1 {
                    sleep(self.knock_delay).await;
                }
            }
            Ok(())
        };

        timeout(self.sequence_timeout, knock_future)
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "Port knocking timeout")
            })?
    }

    async fn knock_tcp(&self, host: &str, port: u16) -> Result<(), std::io::Error> {
        let addr = format!("{}:{}", host, port);
        // Attempt connection and immediately close (SYN packet is the "knock")
        let _ = timeout(
            Duration::from_millis(500),
            tokio::net::TcpStream::connect(&addr),
        )
        .await;
        Ok(())
    }

    async fn knock_udp(&self, host: &str, port: u16) -> Result<(), std::io::Error> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        let addr = format!("{}:{}", host, port);
        // Send empty UDP packet as "knock"
        socket.send_to(&[], &addr).await?;
        Ok(())
    }
}

impl Default for PortKnockingSequence {
    fn default() -> Self {
        Self {
            ports: vec![7000, 8000, 9000], // Default knock sequence
            protocol: KnockProtocol::Tcp,
            knock_delay: Duration::from_millis(100),
            sequence_timeout: Duration::from_secs(5),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_health_rtt_tracking() {
        let mut health = ConnectionHealth::new();
        health.record_rtt(Duration::from_millis(50));
        health.record_rtt(Duration::from_millis(60));
        health.record_rtt(Duration::from_millis(55));

        let avg = health.avg_rtt().unwrap();
        assert!(avg >= Duration::from_millis(54) && avg <= Duration::from_millis(56));
        assert_eq!(health.consecutive_failures, 0);
    }

    #[test]
    fn test_connection_health_failure_tracking() {
        let mut health = ConnectionHealth::new();
        health.record_failure();
        health.record_failure();

        assert_eq!(health.consecutive_failures, 2);
        assert!(health.is_healthy(&KeepAliveConfig::default()));

        health.record_failure();
        assert!(!health.is_healthy(&KeepAliveConfig::default()));
    }

    #[test]
    fn test_reconnect_strategy_backoff() {
        let strategy = ReconnectStrategy {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(10),
            multiplier: 2.0,
            max_attempts: 5,
            jitter: false,
        };

        assert_eq!(strategy.next_backoff(0), Duration::from_secs(1));
        assert_eq!(strategy.next_backoff(1), Duration::from_secs(2));
        assert_eq!(strategy.next_backoff(2), Duration::from_secs(4));
        assert_eq!(strategy.next_backoff(3), Duration::from_secs(8));
        assert_eq!(strategy.next_backoff(4), Duration::from_secs(10)); // Capped
        assert_eq!(strategy.next_backoff(10), Duration::from_secs(10)); // Capped

        assert!(strategy.should_retry(0));
        assert!(strategy.should_retry(4));
        assert!(!strategy.should_retry(5));
    }

    #[test]
    fn test_connection_health_degradation() {
        let mut health = ConnectionHealth::new();

        // Simulate high RTT
        health.record_rtt(Duration::from_millis(600));
        assert!(health.is_degraded());

        // Reset with good RTT
        health = ConnectionHealth::new();
        health.record_rtt(Duration::from_millis(50));
        assert!(!health.is_degraded());

        // Simulate high packet loss
        health.packet_loss = 0.1;
        assert!(health.is_degraded());
    }
}
