use async_trait::async_trait;
use std::collections::VecDeque;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;
use tokio::io::{self, AsyncRead, AsyncWrite, DuplexStream};
use tokio::time::{sleep, timeout, Duration};
use tracing::{debug, info, warn};

pub trait TransportIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> TransportIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub type TransportStream = Box<dyn TransportIo>;

#[derive(Debug)]
pub enum TransportError {
    Network,
    Censorship,
    NotSupported,
    Exhausted,
    Timeout,
}

impl Display for TransportError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network => write!(f, "network failure"),
            Self::Censorship => write!(f, "censorship detected"),
            Self::NotSupported => write!(f, "transport not supported"),
            Self::Exhausted => write!(f, "no transports available"),
            Self::Timeout => write!(f, "transport handshake timeout"),
        }
    }
}

impl std::error::Error for TransportError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportType {
    AmnesiaWg,
    Reality,
    Shadowsocks,
    Onion,
    QuicMasque,
    WebSocket,
    Dns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResistanceLevel {
    Basic,
    Enhanced,
    Maximum,
    Paranoid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerformanceTier {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PerformanceProfile {
    pub latency: PerformanceTier,
    pub throughput: PerformanceTier,
}

impl PerformanceProfile {
    pub const fn new(latency: PerformanceTier, throughput: PerformanceTier) -> Self {
        Self {
            latency,
            throughput,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CensorshipStatus {
    None,
    Suspected,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkQuality {
    Excellent,
    Good,
    Degraded,
    Poor,
}

#[derive(Debug, Clone)]
pub struct NetworkSnapshot {
    pub rtt_ms: u32,
    pub bandwidth_kbps: u32,
    pub loss_rate: f32,
    pub quality: NetworkQuality,
}

impl NetworkSnapshot {
    pub fn degraded(loss_rate: f32, bandwidth_kbps: u32, rtt_ms: u32) -> Self {
        let quality = if loss_rate < 0.01 && bandwidth_kbps > 5_000 && rtt_ms < 80 {
            NetworkQuality::Excellent
        } else if loss_rate < 0.02 && bandwidth_kbps > 2_000 {
            NetworkQuality::Good
        } else if loss_rate < 0.05 {
            NetworkQuality::Degraded
        } else {
            NetworkQuality::Poor
        };
        Self {
            rtt_ms,
            bandwidth_kbps,
            loss_rate,
            quality,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub address: String,
    pub port: u16,
    pub server_name: Option<String>,
    pub reality: Option<RealityConfig>,
}

#[derive(Debug, Clone)]
pub struct RealityConfig {
    pub fingerprint: [u8; 32],
    pub certificate_pem: Arc<String>,
}

#[derive(Debug, Clone)]
pub struct TransportContext<'a> {
    pub endpoint: &'a Endpoint,
    pub network: &'a NetworkSnapshot,
    pub censorship: CensorshipStatus,
}

pub struct TransportSession {
    pub transport: TransportType,
    pub resistance: ResistanceLevel,
    pub profile: PerformanceProfile,
    pub stream: Option<TransportStream>,
}

impl fmt::Debug for TransportSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportSession")
            .field("transport", &self.transport)
            .field("resistance", &self.resistance)
            .field("profile", &self.profile)
            .field("has_stream", &self.stream.is_some())
            .finish()
    }
}

impl Clone for TransportSession {
    fn clone(&self) -> Self {
        Self {
            transport: self.transport,
            resistance: self.resistance,
            profile: self.profile,
            stream: None,
        }
    }
}

impl TransportSession {
    pub fn new(
        transport: TransportType,
        resistance: ResistanceLevel,
        profile: PerformanceProfile,
        stream: TransportStream,
    ) -> Self {
        Self {
            transport,
            resistance,
            profile,
            stream: Some(stream),
        }
    }
}

#[async_trait]
pub trait PluggableTransport: Send + Sync {
    fn kind(&self) -> TransportType;
    fn resistance_level(&self) -> ResistanceLevel;
    fn performance_profile(&self) -> PerformanceProfile;
    async fn detect_censorship(
        &self,
        ctx: &TransportContext<'_>,
    ) -> Result<CensorshipStatus, TransportError>;
    async fn handshake(
        &self,
        ctx: &TransportContext<'_>,
    ) -> Result<TransportSession, TransportError>;
}

pub struct TransportHandle {
    inner: Arc<dyn PluggableTransport>,
}

impl TransportHandle {
    pub fn new(inner: Arc<dyn PluggableTransport>) -> Self {
        Self { inner }
    }

    pub fn transport(&self) -> Arc<dyn PluggableTransport> {
        Arc::clone(&self.inner)
    }
}

fn default_fallback_chain() -> Vec<TransportType> {
    vec![
        TransportType::Reality,
        TransportType::AmnesiaWg,
        TransportType::QuicMasque,
        TransportType::Shadowsocks,
        TransportType::WebSocket,
        TransportType::Dns,
        TransportType::Onion,
    ]
}

pub struct TransportManager {
    transports: Vec<TransportHandle>,
    fallback_chain: Vec<TransportType>,
    history: VecDeque<TransportType>,
}

impl TransportManager {
    pub fn new(transports: Vec<Arc<dyn PluggableTransport>>) -> Self {
        let handles = transports.into_iter().map(TransportHandle::new).collect();
        Self {
            transports: handles,
            fallback_chain: default_fallback_chain(),
            history: VecDeque::with_capacity(32),
        }
    }

    pub fn with_fallback_chain(mut self, chain: Vec<TransportType>) -> Self {
        if !chain.is_empty() {
            self.fallback_chain = chain;
        }
        self
    }

    pub fn register_history(&mut self, transport: TransportType) {
        if self.history.len() == self.history.capacity() {
            self.history.pop_front();
        }
        self.history.push_back(transport);
    }

    fn sort_candidates(
        &self,
        snapshot: &NetworkSnapshot,
        censorship: CensorshipStatus,
    ) -> Vec<Arc<dyn PluggableTransport>> {
        let mut candidates: Vec<_> = self.transports.iter().map(|h| h.transport()).collect();
        candidates.sort_by(|a, b| {
            let lhs = score_transport(a.as_ref(), snapshot, censorship);
            let rhs = score_transport(b.as_ref(), snapshot, censorship);
            rhs.cmp(&lhs)
        });
        candidates
    }

    pub async fn establish_connection(
        &mut self,
        endpoint: &Endpoint,
    ) -> Result<TransportSession, TransportError> {
        let network = assess_network_conditions().await;
        let default_context = TransportContext {
            endpoint,
            network: &network,
            censorship: CensorshipStatus::None,
        };
        let mut best_status = CensorshipStatus::None;
        for handle in &self.transports {
            let transport = handle.transport();
            if let Ok(status) = transport.detect_censorship(&default_context).await {
                best_status = status;
                if !matches!(status, CensorshipStatus::None) {
                    break;
                }
            }
        }
        let context = TransportContext {
            endpoint,
            network: &network,
            censorship: best_status,
        };
        let mut attempts = Vec::new();
        for transport in self.sort_candidates(&network, best_status) {
            let kind = transport.kind();
            info!(
                transport = ?kind,
                address = %context.endpoint.address,
                port = context.endpoint.port,
                server = ?context.endpoint.server_name,
                "attempting transport handshake"
            );
            match timeout(Duration::from_millis(250), transport.handshake(&context)).await {
                Ok(Ok(session)) => {
                    self.register_history(kind);
                    info!(transport = ?kind, "transport established");
                    return Ok(session);
                }
                Ok(Err(err)) => {
                    warn!(transport = ?kind, error = %err, "transport failed");
                    attempts.push((kind, err));
                    continue;
                }
                Err(_) => {
                    warn!(transport = ?kind, "transport handshake timed out");
                    attempts.push((kind, TransportError::Timeout));
                    continue;
                }
            }
        }
        debug!(
            attempts = attempts.len(),
            "all transports failed, applying fallback chain"
        );
        for fallback in self.fallback_chain.iter().copied() {
            if self.history.back().copied() == Some(fallback) {
                continue;
            }
            if let Some(handle) = self
                .transports
                .iter()
                .find(|handle| handle.transport().kind() == fallback)
            {
                let transport = handle.transport();
                match timeout(Duration::from_millis(250), transport.handshake(&context)).await {
                    Ok(Ok(session)) => {
                        self.register_history(fallback);
                        info!(transport = ?fallback, "fallback transport established");
                        return Ok(session);
                    }
                    Ok(Err(err)) => attempts.push((fallback, err)),
                    Err(_) => attempts.push((fallback, TransportError::Timeout)),
                }
            }
        }
        Err(TransportError::Exhausted)
    }

    pub fn list_transports(&self) -> Vec<TransportType> {
        self.transports
            .iter()
            .map(|h| h.transport().kind())
            .collect()
    }
}

fn score_transport(
    transport: &dyn PluggableTransport,
    snapshot: &NetworkSnapshot,
    censorship: CensorshipStatus,
) -> i32 {
    let base = match transport.resistance_level() {
        ResistanceLevel::Basic => 10,
        ResistanceLevel::Enhanced => 20,
        ResistanceLevel::Maximum => 35,
        ResistanceLevel::Paranoid => 45,
    };
    let perf = match transport.performance_profile().latency {
        PerformanceTier::High => 12,
        PerformanceTier::Medium => 6,
        PerformanceTier::Low => 1,
    } + match transport.performance_profile().throughput {
        PerformanceTier::High => 12,
        PerformanceTier::Medium => 6,
        PerformanceTier::Low => 1,
    };
    let network_bias = match snapshot.quality {
        NetworkQuality::Excellent => 8,
        NetworkQuality::Good => 6,
        NetworkQuality::Degraded => 4,
        NetworkQuality::Poor => 0,
    };
    let bandwidth_bias = match snapshot.bandwidth_kbps {
        kbps if kbps >= 10_000 => 6,
        kbps if kbps >= 5_000 => 4,
        kbps if kbps >= 2_000 => 2,
        _ => 0,
    };
    let latency_bias = match snapshot.rtt_ms {
        rtt if rtt <= 80 => 5,
        rtt if rtt <= 150 => 2,
        rtt if rtt <= 250 => -1,
        _ => -4,
    };
    let loss_bias = match snapshot.loss_rate {
        loss if loss <= 0.01 => 5,
        loss if loss <= 0.03 => 1,
        loss if loss <= 0.05 => -2,
        _ => -6,
    };
    let censorship_bias = match censorship {
        CensorshipStatus::None => 0,
        CensorshipStatus::Suspected => 15,
        CensorshipStatus::Active => 25,
    };
    base + perf + network_bias + bandwidth_bias + latency_bias + loss_bias + censorship_bias
}

async fn assess_network_conditions() -> NetworkSnapshot {
    // TODO: integrate actual RTT/bandwidth sampling against measurement endpoints
    sleep(Duration::from_millis(5)).await;
    NetworkSnapshot::degraded(0.012, 4_800, 90)
}

fn memory_stream() -> io::Result<(TransportStream, TransportStream)> {
    let (upstream, downstream): (DuplexStream, DuplexStream) = tokio::io::duplex(64);
    Ok((
        Box::new(upstream) as TransportStream,
        Box::new(downstream) as TransportStream,
    ))
}

struct RealityTransport {
    certificate: Arc<String>,
    fingerprint: [u8; 32],
}

impl RealityTransport {
    fn new(certificate: Arc<String>, fingerprint: [u8; 32]) -> Self {
        Self {
            certificate,
            fingerprint,
        }
    }
}

#[async_trait]
impl PluggableTransport for RealityTransport {
    fn kind(&self) -> TransportType {
        TransportType::Reality
    }

    fn resistance_level(&self) -> ResistanceLevel {
        ResistanceLevel::Maximum
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::new(PerformanceTier::High, PerformanceTier::High)
    }

    async fn detect_censorship(
        &self,
        ctx: &TransportContext<'_>,
    ) -> Result<CensorshipStatus, TransportError> {
        if matches!(ctx.censorship, CensorshipStatus::Active) {
            return Err(TransportError::Censorship);
        }
        if ctx.endpoint.reality.is_none() {
            return Ok(CensorshipStatus::None);
        }
        // TODO: Extend with active probing using REALITY tickets
        Ok(ctx.censorship)
    }

    async fn handshake(
        &self,
        ctx: &TransportContext<'_>,
    ) -> Result<TransportSession, TransportError> {
        if let Some(reality) = &ctx.endpoint.reality {
            if reality.fingerprint != self.fingerprint {
                return Err(TransportError::NotSupported);
            }
        }
        let cert_len = self.certificate.len();
        debug!(cert_len, "reality certificate available");
        let (client, _server) = memory_stream().map_err(|_| TransportError::Network)?;
        Ok(TransportSession::new(
            TransportType::Reality,
            self.resistance_level(),
            self.performance_profile(),
            client,
        ))
    }
}

struct ShadowsocksTransport;

#[async_trait]
impl PluggableTransport for ShadowsocksTransport {
    fn kind(&self) -> TransportType {
        TransportType::Shadowsocks
    }

    fn resistance_level(&self) -> ResistanceLevel {
        ResistanceLevel::Enhanced
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::new(PerformanceTier::Medium, PerformanceTier::High)
    }

    async fn detect_censorship(
        &self,
        ctx: &TransportContext<'_>,
    ) -> Result<CensorshipStatus, TransportError> {
        if matches!(ctx.censorship, CensorshipStatus::Active) {
            return Err(TransportError::Censorship);
        }
        Ok(CensorshipStatus::None)
    }

    async fn handshake(
        &self,
        _ctx: &TransportContext<'_>,
    ) -> Result<TransportSession, TransportError> {
        let (client, _server) = memory_stream().map_err(|_| TransportError::Network)?;
        Ok(TransportSession::new(
            TransportType::Shadowsocks,
            self.resistance_level(),
            self.performance_profile(),
            client,
        ))
    }
}

struct OnionTransport;

#[async_trait]
impl PluggableTransport for OnionTransport {
    fn kind(&self) -> TransportType {
        TransportType::Onion
    }

    fn resistance_level(&self) -> ResistanceLevel {
        ResistanceLevel::Paranoid
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::new(PerformanceTier::Low, PerformanceTier::Low)
    }

    async fn detect_censorship(
        &self,
        ctx: &TransportContext<'_>,
    ) -> Result<CensorshipStatus, TransportError> {
        if matches!(ctx.censorship, CensorshipStatus::Active) {
            return Err(TransportError::Censorship);
        }
        Ok(if matches!(ctx.censorship, CensorshipStatus::Active) {
            CensorshipStatus::Active
        } else {
            CensorshipStatus::Suspected
        })
    }

    async fn handshake(
        &self,
        _ctx: &TransportContext<'_>,
    ) -> Result<TransportSession, TransportError> {
        let (client, _server) = memory_stream().map_err(|_| TransportError::Network)?;
        Ok(TransportSession::new(
            TransportType::Onion,
            self.resistance_level(),
            self.performance_profile(),
            client,
        ))
    }
}

struct AmnesiaWgTransport;

#[async_trait]
impl PluggableTransport for AmnesiaWgTransport {
    fn kind(&self) -> TransportType {
        TransportType::AmnesiaWg
    }

    fn resistance_level(&self) -> ResistanceLevel {
        ResistanceLevel::Maximum
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::new(PerformanceTier::Medium, PerformanceTier::Medium)
    }

    async fn detect_censorship(
        &self,
        ctx: &TransportContext<'_>,
    ) -> Result<CensorshipStatus, TransportError> {
        if matches!(ctx.censorship, CensorshipStatus::Active) {
            return Err(TransportError::Censorship);
        }
        Ok(CensorshipStatus::None)
    }

    async fn handshake(
        &self,
        _ctx: &TransportContext<'_>,
    ) -> Result<TransportSession, TransportError> {
        let (client, _server) = memory_stream().map_err(|_| TransportError::Network)?;
        Ok(TransportSession::new(
            TransportType::AmnesiaWg,
            self.resistance_level(),
            self.performance_profile(),
            client,
        ))
    }
}

struct QuicMasqueTransport;

#[async_trait]
impl PluggableTransport for QuicMasqueTransport {
    fn kind(&self) -> TransportType {
        TransportType::QuicMasque
    }

    fn resistance_level(&self) -> ResistanceLevel {
        ResistanceLevel::Enhanced
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::new(PerformanceTier::High, PerformanceTier::High)
    }

    async fn detect_censorship(
        &self,
        ctx: &TransportContext<'_>,
    ) -> Result<CensorshipStatus, TransportError> {
        if matches!(ctx.censorship, CensorshipStatus::Active) {
            return Err(TransportError::Censorship);
        }
        if matches!(ctx.network.quality, NetworkQuality::Poor) {
            Ok(CensorshipStatus::Suspected)
        } else {
            Ok(ctx.censorship)
        }
    }

    async fn handshake(
        &self,
        _ctx: &TransportContext<'_>,
    ) -> Result<TransportSession, TransportError> {
        let (client, _server) = memory_stream().map_err(|_| TransportError::Network)?;
        Ok(TransportSession::new(
            TransportType::QuicMasque,
            self.resistance_level(),
            self.performance_profile(),
            client,
        ))
    }
}

struct WebSocketTransport;

#[async_trait]
impl PluggableTransport for WebSocketTransport {
    fn kind(&self) -> TransportType {
        TransportType::WebSocket
    }

    fn resistance_level(&self) -> ResistanceLevel {
        ResistanceLevel::Basic
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::new(PerformanceTier::Medium, PerformanceTier::Medium)
    }

    async fn detect_censorship(
        &self,
        ctx: &TransportContext<'_>,
    ) -> Result<CensorshipStatus, TransportError> {
        if matches!(ctx.censorship, CensorshipStatus::Active) {
            return Err(TransportError::Censorship);
        }
        Ok(ctx.censorship)
    }

    async fn handshake(
        &self,
        _ctx: &TransportContext<'_>,
    ) -> Result<TransportSession, TransportError> {
        let (client, _server) = memory_stream().map_err(|_| TransportError::Network)?;
        Ok(TransportSession::new(
            TransportType::WebSocket,
            self.resistance_level(),
            self.performance_profile(),
            client,
        ))
    }
}

struct DnsTransport;

#[async_trait]
impl PluggableTransport for DnsTransport {
    fn kind(&self) -> TransportType {
        TransportType::Dns
    }

    fn resistance_level(&self) -> ResistanceLevel {
        ResistanceLevel::Enhanced
    }

    fn performance_profile(&self) -> PerformanceProfile {
        PerformanceProfile::new(PerformanceTier::Low, PerformanceTier::Low)
    }

    async fn detect_censorship(
        &self,
        ctx: &TransportContext<'_>,
    ) -> Result<CensorshipStatus, TransportError> {
        if matches!(ctx.censorship, CensorshipStatus::Active) {
            return Err(TransportError::Censorship);
        }
        Ok(if matches!(ctx.censorship, CensorshipStatus::Active) {
            CensorshipStatus::Active
        } else {
            CensorshipStatus::Suspected
        })
    }

    async fn handshake(
        &self,
        _ctx: &TransportContext<'_>,
    ) -> Result<TransportSession, TransportError> {
        let (client, _server) = memory_stream().map_err(|_| TransportError::Network)?;
        Ok(TransportSession::new(
            TransportType::Dns,
            self.resistance_level(),
            self.performance_profile(),
            client,
        ))
    }
}

pub fn default_manager(reality: Option<RealityConfig>) -> TransportManager {
    let mut transports: Vec<Arc<dyn PluggableTransport>> = vec![
        Arc::new(AmnesiaWgTransport),
        Arc::new(QuicMasqueTransport),
        Arc::new(ShadowsocksTransport),
        Arc::new(WebSocketTransport),
        Arc::new(DnsTransport),
        Arc::new(OnionTransport),
    ];
    if let Some(cfg) = reality {
        transports.push(Arc::new(RealityTransport::new(
            cfg.certificate_pem,
            cfg.fingerprint,
        )));
    }
    TransportManager::new(transports).with_fallback_chain(default_fallback_chain())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    struct TestTransport {
        kind: TransportType,
        resistance: ResistanceLevel,
        profile: PerformanceProfile,
        fail: bool,
    }

    #[async_trait]
    impl PluggableTransport for TestTransport {
        fn kind(&self) -> TransportType {
            self.kind
        }

        fn resistance_level(&self) -> ResistanceLevel {
            self.resistance
        }

        fn performance_profile(&self) -> PerformanceProfile {
            self.profile
        }

        async fn detect_censorship(
            &self,
            _ctx: &TransportContext<'_>,
        ) -> Result<CensorshipStatus, TransportError> {
            Ok(CensorshipStatus::None)
        }

        async fn handshake(
            &self,
            _ctx: &TransportContext<'_>,
        ) -> Result<TransportSession, TransportError> {
            if self.fail {
                Err(TransportError::Network)
            } else {
                let (client, _server) = memory_stream().map_err(|_| TransportError::Network)?;
                Ok(TransportSession::new(
                    self.kind,
                    self.resistance,
                    self.profile,
                    client,
                ))
            }
        }
    }

    #[test]
    fn manager_prefers_stronger_transport() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let transports: Vec<Arc<dyn PluggableTransport>> = vec![
                Arc::new(TestTransport {
                    kind: TransportType::WebSocket,
                    resistance: ResistanceLevel::Basic,
                    profile: PerformanceProfile::new(PerformanceTier::High, PerformanceTier::High),
                    fail: false,
                }),
                Arc::new(TestTransport {
                    kind: TransportType::AmnesiaWg,
                    resistance: ResistanceLevel::Maximum,
                    profile: PerformanceProfile::new(
                        PerformanceTier::Medium,
                        PerformanceTier::Medium,
                    ),
                    fail: false,
                }),
            ];
            let mut manager = TransportManager::new(transports)
                .with_fallback_chain(vec![TransportType::AmnesiaWg, TransportType::WebSocket]);
            let endpoint = Endpoint {
                address: "example.org".to_string(),
                port: 443,
                server_name: Some("example.org".to_string()),
                reality: None,
            };
            let session = manager.establish_connection(&endpoint).await.unwrap();
            assert_eq!(session.transport, TransportType::AmnesiaWg);
        });
    }

    #[test]
    fn manager_uses_fallback_on_failure() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let transports: Vec<Arc<dyn PluggableTransport>> = vec![
                Arc::new(TestTransport {
                    kind: TransportType::Reality,
                    resistance: ResistanceLevel::Maximum,
                    profile: PerformanceProfile::new(PerformanceTier::High, PerformanceTier::High),
                    fail: true,
                }),
                Arc::new(TestTransport {
                    kind: TransportType::Shadowsocks,
                    resistance: ResistanceLevel::Enhanced,
                    profile: PerformanceProfile::new(
                        PerformanceTier::Medium,
                        PerformanceTier::Medium,
                    ),
                    fail: false,
                }),
            ];
            let mut manager = TransportManager::new(transports)
                .with_fallback_chain(vec![TransportType::Shadowsocks, TransportType::Reality]);
            let endpoint = Endpoint {
                address: "rescue.example".to_string(),
                port: 8443,
                server_name: Some("rescue.example".to_string()),
                reality: None,
            };
            let session = manager.establish_connection(&endpoint).await.unwrap();
            assert_eq!(session.transport, TransportType::Shadowsocks);
        });
    }

    #[test]
    fn default_manager_adds_reality_transport() {
        let reality = RealityConfig {
            certificate_pem: Arc::new(
                "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----".to_string(),
            ),
            fingerprint: [0u8; 32],
        };
        let manager = default_manager(Some(reality));
        let transports = manager.list_transports();
        assert!(transports.contains(&TransportType::Reality));
    }
}
