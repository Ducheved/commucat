use super::AppState;
use chrono::{Duration, Utc};
use commucat_federation::SignedEvent;
use commucat_storage::FederationOutboxMessage;
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::time::interval;
use tracing::{debug, error, warn};

const DISPATCH_INTERVAL_SECS: u64 = 2;
const DISPATCH_LIMIT: i64 = 16;
const DISPATCH_LEASE_SECS: i64 = 20;
const BASE_BACKOFF_SECS: i64 = 5;
const MAX_BACKOFF_EXP: u32 = 6;
const MAX_BACKOFF_SECS: i64 = 300;

pub fn spawn_dispatcher(state: Arc<AppState>) {
    tokio::spawn(async move {
        let client = match Client::builder()
            .user_agent("commucat-federation/1.0")
            .timeout(StdDuration::from_secs(10))
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                error!(error = %err, "failed to build federation HTTP client");
                return;
            }
        };
        let mut ticker = interval(StdDuration::from_secs(DISPATCH_INTERVAL_SECS));
        loop {
            ticker.tick().await;
            if let Err(err) = dispatch(&state, &client).await {
                warn!(error = %err, "federation dispatch iteration failed");
            }
        }
    });
}

async fn dispatch(state: &Arc<AppState>, client: &Client) -> Result<(), String> {
    let now = Utc::now();
    let lease = Duration::seconds(DISPATCH_LEASE_SECS);
    let entries = state
        .storage
        .claim_federation_outbox(DISPATCH_LIMIT, lease, now)
        .await
        .map_err(|err| format!("claim failed: {err}"))?;
    for entry in entries {
        process_entry(state, client, entry).await;
    }
    Ok(())
}

async fn process_entry(state: &Arc<AppState>, client: &Client, entry: FederationOutboxMessage) {
    let signed: SignedEvent = match serde_json::from_value(entry.payload.clone()) {
        Ok(event) => event,
        Err(err) => {
            error!(outbox = %entry.outbox_id, error = %err, "invalid federation payload; dropping");
            if let Err(store_err) = state
                .storage
                .delete_federation_outbox(&entry.outbox_id)
                .await
            {
                warn!(outbox = %entry.outbox_id, error = %store_err, "failed to drop invalid federation outbox entry");
            }
            return;
        }
    };

    match client
        .post(&entry.endpoint)
        .header("content-type", "application/json")
        .json(&signed)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            if let Err(err) = state
                .storage
                .delete_federation_outbox(&entry.outbox_id)
                .await
            {
                warn!(outbox = %entry.outbox_id, error = %err, "failed to delete delivered federation outbox entry");
            } else {
                state.metrics.mark_federation_outbox_delivered();
                debug!(outbox = %entry.outbox_id, destination = %entry.destination, "federation event delivered");
            }
        }
        Ok(response) => {
            let status = response.status();
            let body = match response.text().await {
                Ok(text) => text,
                Err(err) => format!("<body read failed: {err}>"),
            };
            let reason = format!("http {} {}", status.as_u16(), body.trim());
            schedule_retry(state, entry, &reason).await;
        }
        Err(err) => {
            schedule_retry(state, entry, &err.to_string()).await;
        }
    }
}

async fn schedule_retry(state: &Arc<AppState>, entry: FederationOutboxMessage, reason: &str) {
    let now = Utc::now();
    let exp = entry.attempts.saturating_sub(1).min(MAX_BACKOFF_EXP as i32) as u32;
    let multiplier = 1_i64 << exp;
    let mut delay_secs = BASE_BACKOFF_SECS.saturating_mul(multiplier);
    if delay_secs > MAX_BACKOFF_SECS {
        delay_secs = MAX_BACKOFF_SECS;
    }
    let delay = Duration::seconds(delay_secs);
    let mut message = reason.trim().to_string();
    if message.len() > 200 {
        message.truncate(200);
    }
    warn!(
        outbox = %entry.outbox_id,
        destination = %entry.destination,
        attempts = entry.attempts,
        delay_secs,
        error = %message,
        "federation event delivery failed; rescheduled"
    );
    if let Err(err) = state
        .storage
        .reschedule_federation_outbox(&entry.outbox_id, delay, now, Some(&message))
        .await
    {
        warn!(outbox = %entry.outbox_id, error = %err, "failed to reschedule federation outbox entry");
    }
}
