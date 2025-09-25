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
            "# TYPE commucat_connections_active gauge\ncommucat_connections_active {}\n# TYPE commucat_frames_ingress counter\ncommucat_frames_ingress {}\n# TYPE commucat_frames_egress counter\ncommucat_frames_egress {}\n# TYPE commucat_relay_enqueued counter\ncommucat_relay_enqueued {}\n# TYPE commucat_security_noise counter\ncommucat_security_noise {}\n# TYPE commucat_security_pq counter\ncommucat_security_pq {}\n# TYPE commucat_security_fec counter\ncommucat_security_fec_packets {}\n# TYPE commucat_multipath_sessions counter\ncommucat_multipath_sessions {}\n# TYPE commucat_multipath_paths gauge\ncommucat_multipath_paths {}\n# TYPE commucat_censorship_deflections counter\ncommucat_censorship_deflections {}\n",
            self.connections_active.load(Ordering::SeqCst),
            self.frames_ingress.load(Ordering::SeqCst),
            self.frames_egress.load(Ordering::SeqCst),
            self.relay_enqueued.load(Ordering::SeqCst),
            self.noise_handshakes.load(Ordering::SeqCst),
            self.pq_handshakes.load(Ordering::SeqCst),
            self.fec_packets.load(Ordering::SeqCst),
            self.multipath_sessions.load(Ordering::SeqCst),
            self.multipath_paths_total.load(Ordering::SeqCst),
            self.censorship_deflections.load(Ordering::SeqCst)
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
