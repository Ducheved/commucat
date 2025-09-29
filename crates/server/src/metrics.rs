use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    connections_active: AtomicU64,
    frames_ingress: AtomicU64,
    frames_egress: AtomicU64,
    relay_enqueued: AtomicU64,
    noise_handshakes: AtomicU64,
    pq_handshakes: AtomicU64,
    fec_packets: AtomicU64,
    multipath_sessions: AtomicU64,
    multipath_paths_total: AtomicU64,
    censorship_deflections: AtomicU64,
    call_sessions_active: AtomicU64,
    call_sessions_total: AtomicU64,
    call_voice_frames: AtomicU64,
    call_video_frames: AtomicU64,
    transport_candidates: AtomicU64,
    transport_pair_selected: AtomicU64,
    transport_keepalive: AtomicU64,
    rate_limit_http: AtomicU64,
    rate_limit_connect: AtomicU64,
    noise_rotations: AtomicU64,
    admin_rotations: AtomicU64,
    device_rotations: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn incr_connections(&self) {
        self.connections_active.fetch_add(1, Ordering::SeqCst);
    }

    pub fn decr_connections(&self) {
        self.connections_active.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn mark_ingress(&self) {
        self.frames_ingress.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_egress(&self) {
        self.frames_egress.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_relay(&self) {
        self.relay_enqueued.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_noise_handshake(&self) {
        self.noise_handshakes.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_pq_handshake(&self) {
        self.pq_handshakes.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_fec_packets(&self, packets: u64) {
        if packets == 0 {
            return;
        }
        self.fec_packets.fetch_add(packets, Ordering::SeqCst);
    }

    pub fn mark_multipath_session(&self, paths: usize) {
        self.multipath_sessions.fetch_add(1, Ordering::SeqCst);
        self.multipath_paths_total
            .fetch_add(paths as u64, Ordering::SeqCst);
    }

    pub fn mark_censorship_deflection(&self) {
        self.censorship_deflections.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_call_started(&self) {
        self.call_sessions_total.fetch_add(1, Ordering::SeqCst);
        self.call_sessions_active.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_call_ended(&self) {
        let _ =
            self.call_sessions_active
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                    if value == 0 { None } else { Some(value - 1) }
                });
    }

    pub fn mark_call_voice_frame(&self) {
        self.call_voice_frames.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_call_video_frame(&self) {
        self.call_video_frames.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_transport_candidate(&self) {
        self.transport_candidates.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_transport_pair_selected(&self) {
        self.transport_pair_selected.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_transport_keepalive(&self) {
        self.transport_keepalive.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_http_rate_limited(&self) {
        self.rate_limit_http.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_connect_rate_limited(&self) {
        self.rate_limit_connect.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_noise_rotation(&self) {
        self.noise_rotations.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_admin_rotation(&self) {
        self.admin_rotations.fetch_add(1, Ordering::SeqCst);
    }

    pub fn mark_device_rotation(&self) {
        self.device_rotations.fetch_add(1, Ordering::SeqCst);
    }

    pub fn security_snapshot(&self) -> SecuritySnapshot {
        let sessions = self.multipath_sessions.load(Ordering::SeqCst);
        let paths_total = self.multipath_paths_total.load(Ordering::SeqCst);
        SecuritySnapshot {
            noise_handshakes: self.noise_handshakes.load(Ordering::SeqCst),
            pq_handshakes: self.pq_handshakes.load(Ordering::SeqCst),
            fec_packets: self.fec_packets.load(Ordering::SeqCst),
            multipath_sessions: sessions,
            average_paths: if sessions == 0 {
                0.0
            } else {
                paths_total as f64 / sessions as f64
            },
            censorship_deflections: self.censorship_deflections.load(Ordering::SeqCst),
        }
    }

    pub fn encode_prometheus(&self) -> String {
        format!(
            "# TYPE commucat_connections_active gauge\ncommucat_connections_active {}\n# TYPE commucat_frames_ingress counter\ncommucat_frames_ingress {}\n# TYPE commucat_frames_egress counter\ncommucat_frames_egress {}\n# TYPE commucat_relay_enqueued counter\ncommucat_relay_enqueued {}\n# TYPE commucat_security_noise counter\ncommucat_security_noise {}\n# TYPE commucat_security_pq counter\ncommucat_security_pq {}\n# TYPE commucat_security_fec counter\ncommucat_security_fec_packets {}\n# TYPE commucat_multipath_sessions counter\ncommucat_multipath_sessions {}\n# TYPE commucat_multipath_paths gauge\ncommucat_multipath_paths {}\n# TYPE commucat_censorship_deflections counter\ncommucat_censorship_deflections {}\n# TYPE commucat_calls_active gauge\ncommucat_calls_active {}\n# TYPE commucat_calls_total counter\ncommucat_calls_total {}\n# TYPE commucat_call_voice_frames counter\ncommucat_call_voice_frames {}\n# TYPE commucat_call_video_frames counter\ncommucat_call_video_frames {}\n# TYPE commucat_transport_candidates counter\ncommucat_transport_candidates {}\n# TYPE commucat_transport_pairs counter\ncommucat_transport_pairs {}\n# TYPE commucat_transport_keepalive counter\ncommucat_transport_keepalive {}\n# TYPE commucat_rate_limit_http counter\ncommucat_rate_limit_http {}\n# TYPE commucat_rate_limit_connect counter\ncommucat_rate_limit_connect {}\n# TYPE commucat_secret_rotations_noise counter\ncommucat_secret_rotations_noise {}\n# TYPE commucat_secret_rotations_admin counter\ncommucat_secret_rotations_admin {}\n# TYPE commucat_device_rotations counter\ncommucat_device_rotations {}\n",
            self.connections_active.load(Ordering::SeqCst),
            self.frames_ingress.load(Ordering::SeqCst),
            self.frames_egress.load(Ordering::SeqCst),
            self.relay_enqueued.load(Ordering::SeqCst),
            self.noise_handshakes.load(Ordering::SeqCst),
            self.pq_handshakes.load(Ordering::SeqCst),
            self.fec_packets.load(Ordering::SeqCst),
            self.multipath_sessions.load(Ordering::SeqCst),
            self.multipath_paths_total.load(Ordering::SeqCst),
            self.censorship_deflections.load(Ordering::SeqCst),
            self.call_sessions_active.load(Ordering::SeqCst),
            self.call_sessions_total.load(Ordering::SeqCst),
            self.call_voice_frames.load(Ordering::SeqCst),
            self.call_video_frames.load(Ordering::SeqCst),
            self.transport_candidates.load(Ordering::SeqCst),
            self.transport_pair_selected.load(Ordering::SeqCst),
            self.transport_keepalive.load(Ordering::SeqCst),
            self.rate_limit_http.load(Ordering::SeqCst),
            self.rate_limit_connect.load(Ordering::SeqCst),
            self.noise_rotations.load(Ordering::SeqCst),
            self.admin_rotations.load(Ordering::SeqCst),
            self.device_rotations.load(Ordering::SeqCst)
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SecuritySnapshot {
    pub noise_handshakes: u64,
    pub pq_handshakes: u64,
    pub fec_packets: u64,
    pub multipath_sessions: u64,
    pub average_paths: f64,
    pub censorship_deflections: u64,
}
