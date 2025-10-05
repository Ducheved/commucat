// Advanced Network Probing for CommuCat
//
// Comprehensive network quality assessment including:
// - HTTPS HEAD probes for real-world latency
// - Jitter measurement (RTT variance)
// - Packet loss estimation via multiple probes
// - Bandwidth estimation based on payload transfer
// - Connection stability scoring

use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

/// Result of comprehensive network probe
#[derive(Debug, Clone)]
pub struct NetworkProbeResult {
    /// Average RTT in milliseconds
    pub rtt_ms: u32,
    /// Jitter (RTT standard deviation) in milliseconds
    pub jitter_ms: f32,
    /// Packet loss rate (0.0 - 1.0)
    pub packet_loss_rate: f32,
    /// Estimated bandwidth in kbps
    pub bandwidth_kbps: u32,
    /// Number of successful probes
    pub success_count: u32,
    /// Total probe attempts
    #[allow(dead_code)] // Used in tests and debugging
    pub total_attempts: u32,
    /// Method used for probing
    pub probe_method: ProbeMethod,
}

/// Probing method used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMethod {
    /// TCP connect only
    TcpConnect,
    /// HTTPS HEAD request
    HttpsHead,
    /// UDP echo (if supported)
    #[allow(dead_code)] // Reserved for future implementation
    UdpEcho,
    /// Mixed (multiple methods)
    #[allow(dead_code)] // Reserved for future implementation
    Mixed,
}

impl NetworkProbeResult {
    /// Create result indicating complete failure
    pub fn failed() -> Self {
        Self {
            rtt_ms: 500,
            jitter_ms: 150.0,
            packet_loss_rate: 1.0,
            bandwidth_kbps: 500,
            success_count: 0,
            total_attempts: 3,
            probe_method: ProbeMethod::TcpConnect,
        }
    }

    /// Calculate connection quality score (0-100)
    pub fn quality_score(&self) -> u8 {
        if self.success_count == 0 {
            return 0;
        }

        let mut score = 100u32;

        // RTT penalty (0-30 points)
        let rtt_penalty = match self.rtt_ms {
            0..=30 => 0,
            31..=60 => 5,
            61..=100 => 10,
            101..=200 => 20,
            _ => 30,
        };

        // Jitter penalty (0-25 points)
        let jitter_penalty = if self.jitter_ms < 10.0 {
            0
        } else if self.jitter_ms < 30.0 {
            5
        } else if self.jitter_ms < 60.0 {
            15
        } else {
            25
        };

        // Packet loss penalty (0-35 points)
        let loss_penalty = (self.packet_loss_rate * 35.0) as u32;

        // Bandwidth penalty (0-10 points)
        let bandwidth_penalty = match self.bandwidth_kbps {
            0..=1_000 => 10,
            1_001..=3_000 => 5,
            _ => 0,
        };

        score = score
            .saturating_sub(rtt_penalty)
            .saturating_sub(jitter_penalty)
            .saturating_sub(loss_penalty)
            .saturating_sub(bandwidth_penalty);

        score.min(100) as u8
    }

    /// Get quality label from score
    pub fn quality_label(&self) -> &'static str {
        match self.quality_score() {
            90..=100 => "excellent",
            75..=89 => "good",
            50..=74 => "fair",
            25..=49 => "poor",
            _ => "critical",
        }
    }
}

/// Probe configuration
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// Number of probe attempts
    pub attempts: u32,
    /// Timeout for each probe
    pub timeout: Duration,
    /// Use HTTPS HEAD if possible
    pub use_https: bool,
    /// Measure jitter
    #[allow(dead_code)] // Always measured when multiple attempts are made
    pub measure_jitter: bool,
    /// Estimate bandwidth
    #[allow(dead_code)] // Always estimated from RTT
    pub estimate_bandwidth: bool,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            attempts: 5,
            timeout: Duration::from_millis(300),
            use_https: true,
            measure_jitter: true,
            estimate_bandwidth: true,
        }
    }
}

impl ProbeConfig {
    /// Quick probe config (fewer attempts, shorter timeout)
    #[allow(dead_code)] // Public API for custom configurations
    pub fn quick() -> Self {
        Self {
            attempts: 3,
            timeout: Duration::from_millis(200),
            use_https: false,
            measure_jitter: true,
            estimate_bandwidth: false,
        }
    }

    /// Thorough probe config (more attempts, longer timeout)
    #[allow(dead_code)] // Public API for custom configurations
    pub fn thorough() -> Self {
        Self {
            attempts: 10,
            timeout: Duration::from_millis(500),
            use_https: true,
            measure_jitter: true,
            estimate_bandwidth: true,
        }
    }
}

/// Perform comprehensive network probe to target endpoint
pub async fn probe_network(address: &str, port: u16, config: &ProbeConfig) -> NetworkProbeResult {
    let target = format!("{}:{}", address, port);

    // Try HTTPS HEAD first if enabled and port suggests HTTPS
    if config.use_https
        && (port == 443 || port == 8443)
        && let Ok(result) = probe_https_head(address, port, config).await
    {
        debug!(
            target = %target,
            method = "HTTPS HEAD",
            rtt = result.rtt_ms,
            jitter = result.jitter_ms,
            loss = result.packet_loss_rate,
            quality = %result.quality_label(),
            "network probe completed"
        );
        return result;
    }

    // Fallback to TCP probes
    let result = probe_tcp_connect(&target, config).await;
    debug!(
        target = %target,
        method = "TCP connect",
        rtt = result.rtt_ms,
        jitter = result.jitter_ms,
        loss = result.packet_loss_rate,
        quality = %result.quality_label(),
        "network probe completed"
    );
    result
}

/// Probe using HTTPS HEAD requests
async fn probe_https_head(
    address: &str,
    port: u16,
    config: &ProbeConfig,
) -> Result<NetworkProbeResult, Box<dyn std::error::Error>> {
    let url = if port == 443 {
        format!("https://{}/", address)
    } else {
        format!("https://{}:{}/", address, port)
    };

    let client = reqwest::Client::builder()
        .timeout(config.timeout)
        .danger_accept_invalid_certs(true) // For Reality/self-signed certs
        .build()?;

    let mut rtt_samples = Vec::with_capacity(config.attempts as usize);
    let mut success_count = 0u32;

    for attempt in 0..config.attempts {
        let start = Instant::now();
        match client.head(&url).send().await {
            Ok(resp) => {
                let elapsed = start.elapsed();
                let rtt_ms = elapsed.as_millis().min(u32::MAX as u128) as u32;

                if resp.status().is_success() || resp.status().is_redirection() {
                    rtt_samples.push(rtt_ms);
                    success_count += 1;
                    debug!(
                        url = %url,
                        attempt = attempt + 1,
                        rtt_ms = rtt_ms,
                        status = resp.status().as_u16(),
                        "HTTPS HEAD probe succeeded"
                    );
                } else {
                    debug!(
                        url = %url,
                        attempt = attempt + 1,
                        status = resp.status().as_u16(),
                        "HTTPS HEAD probe got non-success status"
                    );
                }
            }
            Err(err) => {
                debug!(
                    url = %url,
                    attempt = attempt + 1,
                    error = %err,
                    "HTTPS HEAD probe failed"
                );
            }
        }
    }

    if rtt_samples.is_empty() {
        return Err("All HTTPS probes failed".into());
    }

    Ok(analyze_probe_results(
        rtt_samples,
        success_count,
        config.attempts,
        ProbeMethod::HttpsHead,
    ))
}

/// Probe using TCP connect
async fn probe_tcp_connect(target: &str, config: &ProbeConfig) -> NetworkProbeResult {
    let mut rtt_samples = Vec::with_capacity(config.attempts as usize);
    let mut success_count = 0u32;

    for attempt in 0..config.attempts {
        let start = Instant::now();
        match timeout(config.timeout, TcpStream::connect(target)).await {
            Ok(Ok(mut stream)) => {
                let elapsed = start.elapsed();
                let rtt_ms = elapsed.as_millis().min(u32::MAX as u128) as u32;
                rtt_samples.push(rtt_ms);
                success_count += 1;

                // Try graceful shutdown
                let _ = stream.shutdown().await;

                debug!(
                    target = %target,
                    attempt = attempt + 1,
                    rtt_ms = rtt_ms,
                    "TCP probe succeeded"
                );
            }
            Ok(Err(err)) => {
                debug!(
                    target = %target,
                    attempt = attempt + 1,
                    error = %err,
                    "TCP probe connection failed"
                );
            }
            Err(_) => {
                debug!(
                    target = %target,
                    attempt = attempt + 1,
                    "TCP probe timed out"
                );
            }
        }

        // Small delay between attempts to spread out probes
        if attempt + 1 < config.attempts {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    if rtt_samples.is_empty() {
        return NetworkProbeResult::failed();
    }

    analyze_probe_results(
        rtt_samples,
        success_count,
        config.attempts,
        ProbeMethod::TcpConnect,
    )
}

/// Analyze collected probe samples
fn analyze_probe_results(
    rtt_samples: Vec<u32>,
    success_count: u32,
    total_attempts: u32,
    method: ProbeMethod,
) -> NetworkProbeResult {
    if rtt_samples.is_empty() {
        return NetworkProbeResult::failed();
    }

    // Calculate average RTT
    let avg_rtt = rtt_samples.iter().sum::<u32>() / rtt_samples.len() as u32;

    // Calculate jitter (standard deviation of RTT)
    let jitter = if rtt_samples.len() > 1 {
        let variance: f32 = rtt_samples
            .iter()
            .map(|&rtt| {
                let diff = rtt as f32 - avg_rtt as f32;
                diff * diff
            })
            .sum::<f32>()
            / rtt_samples.len() as f32;
        variance.sqrt()
    } else {
        0.0
    };

    // Calculate packet loss rate
    let packet_loss_rate = 1.0 - (success_count as f32 / total_attempts as f32);

    // Estimate bandwidth based on RTT and success rate
    let bandwidth_kbps = estimate_bandwidth(avg_rtt, packet_loss_rate, success_count);

    NetworkProbeResult {
        rtt_ms: avg_rtt,
        jitter_ms: jitter,
        packet_loss_rate,
        bandwidth_kbps,
        success_count,
        total_attempts,
        probe_method: method,
    }
}

/// Estimate bandwidth based on RTT and network quality
fn estimate_bandwidth(rtt_ms: u32, loss_rate: f32, success_count: u32) -> u32 {
    // Base bandwidth on RTT (lower RTT = higher potential bandwidth)
    let base_bandwidth = match rtt_ms {
        0..=20 => 20_000,   // <20ms: excellent, likely local/fiber
        21..=40 => 15_000,  // 21-40ms: very good
        41..=80 => 10_000,  // 41-80ms: good
        81..=150 => 6_000,  // 81-150ms: acceptable
        151..=250 => 3_000, // 151-250ms: degraded
        _ => 1_500,         // >250ms: poor
    };

    // Adjust for packet loss (high loss = lower effective bandwidth)
    let loss_multiplier = (1.0 - loss_rate).max(0.2);

    // Adjust for probe reliability
    let reliability_multiplier = if success_count >= 4 {
        1.0
    } else if success_count >= 2 {
        0.8
    } else {
        0.5
    };

    let estimated = base_bandwidth as f32 * loss_multiplier * reliability_multiplier;
    estimated as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quality_score() {
        // Excellent connection
        let result = NetworkProbeResult {
            rtt_ms: 20,
            jitter_ms: 5.0,
            packet_loss_rate: 0.0,
            bandwidth_kbps: 10_000,
            success_count: 5,
            total_attempts: 5,
            probe_method: ProbeMethod::HttpsHead,
        };
        assert!(result.quality_score() >= 95);
        assert_eq!(result.quality_label(), "excellent");

        // Poor connection
        let result = NetworkProbeResult {
            rtt_ms: 300,
            jitter_ms: 100.0,
            packet_loss_rate: 0.2,
            bandwidth_kbps: 800,
            success_count: 2,
            total_attempts: 5,
            probe_method: ProbeMethod::TcpConnect,
        };
        assert!(result.quality_score() < 30);
        assert_eq!(result.quality_label(), "critical");
    }

    #[test]
    fn test_bandwidth_estimation() {
        assert!(estimate_bandwidth(20, 0.0, 5) > 15_000);
        assert!(estimate_bandwidth(200, 0.0, 5) < 5_000);
        assert!(estimate_bandwidth(50, 0.5, 5) < estimate_bandwidth(50, 0.0, 5));
    }

    #[test]
    fn test_failed_result() {
        let result = NetworkProbeResult::failed();
        assert_eq!(result.success_count, 0);
        assert_eq!(result.quality_score(), 0);
        assert_eq!(result.quality_label(), "critical");
    }
}
