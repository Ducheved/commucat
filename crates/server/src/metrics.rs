use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    connections_active: AtomicU64,
    frames_ingress: AtomicU64,
    frames_egress: AtomicU64,
    relay_enqueued: AtomicU64,
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

    pub fn encode_prometheus(&self) -> String {
        format!(
            "# TYPE commucat_connections_active gauge\ncommucat_connections_active {}\n# TYPE commucat_frames_ingress counter\ncommucat_frames_ingress {}\n# TYPE commucat_frames_egress counter\ncommucat_frames_egress {}\n# TYPE commucat_relay_enqueued counter\ncommucat_relay_enqueued {}\n",
            self.connections_active.load(Ordering::SeqCst),
            self.frames_ingress.load(Ordering::SeqCst),
            self.frames_egress.load(Ordering::SeqCst),
            self.relay_enqueued.load(Ordering::SeqCst)
        )
    }
}
