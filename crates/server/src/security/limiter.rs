use crate::config::{RateLimitConfig, RateLimitSettings};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateScope {
    Http,
    Connect,
    PairingClaim,
}

#[derive(Debug, Clone, Copy)]
pub struct RateDecision {
    pub allowed: bool,
    pub retry_after: Option<Duration>,
}

#[derive(Debug, Clone)]
struct RateState {
    hits: VecDeque<Instant>,
    blocked_until: Option<Instant>,
    last_seen: Instant,
}

impl RateState {
    fn new(now: Instant) -> Self {
        Self {
            hits: VecDeque::new(),
            blocked_until: None,
            last_seen: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;
    use tokio::time::{Duration, sleep};

    fn make_config() -> RateLimitConfig {
        let settings = RateLimitSettings {
            burst: 2,
            window: StdDuration::from_millis(50),
            penalty: StdDuration::from_millis(80),
        };
        RateLimitConfig {
            http: settings.clone(),
            connect: settings.clone(),
            pairing_claim: settings,
        }
    }

    #[tokio::test]
    async fn allows_within_burst() {
        let limiter = RateLimiter::new(&make_config());
        let identity = "client-allow";
        assert!(limiter.check(RateScope::Http, identity).await.allowed);
        assert!(limiter.check(RateScope::Http, identity).await.allowed);
    }

    #[tokio::test]
    async fn blocks_and_recovers_after_penalty() {
        let limiter = RateLimiter::new(&make_config());
        let identity = "client-penalty";
        assert!(limiter.check(RateScope::Http, identity).await.allowed);
        assert!(limiter.check(RateScope::Http, identity).await.allowed);
        let decision = limiter.check(RateScope::Http, identity).await;
        assert!(!decision.allowed);
        let retry = decision.retry_after.expect("retry");
        assert!(retry >= StdDuration::from_millis(70));
        sleep(Duration::from_millis(90)).await;
        let decision_after = limiter.check(RateScope::Http, identity).await;
        assert!(decision_after.allowed);
    }

    #[tokio::test]
    async fn uses_window_when_penalty_zero() {
        let mut config = make_config();
        config.http.penalty = StdDuration::ZERO;
        let limiter = RateLimiter::new(&config);
        let identity = "client-window";
        for _ in 0..config.http.burst {
            assert!(limiter.check(RateScope::Http, identity).await.allowed);
        }
        let decision = limiter.check(RateScope::Http, identity).await;
        assert!(!decision.allowed);
        assert_eq!(decision.retry_after, Some(config.http.window));
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    settings: HashMap<RateScope, RateLimitSettings>,
    states: Mutex<HashMap<(RateScope, String), RateState>>,
}

impl RateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        let mut settings = HashMap::new();
        settings.insert(RateScope::Http, config.http.clone());
        settings.insert(RateScope::Connect, config.connect.clone());
        settings.insert(RateScope::PairingClaim, config.pairing_claim.clone());
        Self {
            settings,
            states: Mutex::new(HashMap::new()),
        }
    }

    pub async fn check(&self, scope: RateScope, key: &str) -> RateDecision {
        let settings = match self.settings.get(&scope) {
            Some(value) => value.clone(),
            None => {
                return RateDecision {
                    allowed: true,
                    retry_after: None,
                };
            }
        };
        let mut guard = self.states.lock().await;
        let now = Instant::now();
        let composite_key = (scope, key.to_string());
        let mut remove_entry = false;
        let decision;
        {
            let entry = guard
                .entry(composite_key.clone())
                .or_insert_with(|| RateState::new(now));
            while let Some(front) = entry.hits.front() {
                if now.duration_since(*front) > settings.window {
                    entry.hits.pop_front();
                } else {
                    break;
                }
            }
            if let Some(until) = entry.blocked_until {
                if now < until {
                    decision = RateDecision {
                        allowed: false,
                        retry_after: Some(until.saturating_duration_since(now)),
                    };
                    return decision;
                }
                entry.blocked_until = None;
            }
            if entry.hits.len() < settings.burst as usize {
                entry.hits.push_back(now);
                decision = RateDecision {
                    allowed: true,
                    retry_after: None,
                };
            } else if settings.penalty.is_zero() {
                decision = RateDecision {
                    allowed: false,
                    retry_after: Some(settings.window),
                };
            } else {
                let until = now + settings.penalty;
                entry.blocked_until = Some(until);
                decision = RateDecision {
                    allowed: false,
                    retry_after: Some(settings.penalty),
                };
            }
            if entry.hits.is_empty()
                && entry.blocked_until.is_none()
                && now.duration_since(entry.last_seen) > settings.window
            {
                remove_entry = true;
            }
            entry.last_seen = now;
        }
        if remove_entry {
            guard.remove(&composite_key);
        }
        decision
    }
}
