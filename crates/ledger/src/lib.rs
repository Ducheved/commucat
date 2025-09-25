use chrono::{DateTime, Utc};
use serde_json::Value;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use tracing::info;

#[derive(Debug)]
pub enum LedgerError {
    Io,
    Serialization,
}

impl Display for LedgerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io => write!(f, "ledger io failure"),
            Self::Serialization => write!(f, "ledger serialization failure"),
        }
    }
}

impl Error for LedgerError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRecord {
    pub digest: [u8; 32],
    pub recorded_at: DateTime<Utc>,
    pub metadata: Value,
}

/// Persists digest material into upstream ledgers.
pub trait LedgerAdapter: Send + Sync {
    fn submit(&self, record: &LedgerRecord) -> Result<(), LedgerError>;
}

pub struct NullLedger;

impl LedgerAdapter for NullLedger {
    fn submit(&self, _record: &LedgerRecord) -> Result<(), LedgerError> {
        Ok(())
    }
}

pub struct FileLedgerAdapter {
    path: PathBuf,
}

impl FileLedgerAdapter {
    /// Creates a file based ledger adapter storing newline-delimited JSON.
    pub fn new(path: PathBuf) -> Result<Self, LedgerError> {
        if let Some(parent) = path.parent() {
            create_dir_all(parent).map_err(|_| LedgerError::Io)?;
        }
        Ok(Self { path })
    }
}

impl LedgerAdapter for FileLedgerAdapter {
    fn submit(&self, record: &LedgerRecord) -> Result<(), LedgerError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| LedgerError::Io)?;
        let doc = serde_json::json!({
            "digest": hex_digest(&record.digest),
            "recorded_at": record.recorded_at.to_rfc3339(),
            "metadata": record.metadata,
        });
        let payload = serde_json::to_vec(&doc).map_err(|_| LedgerError::Serialization)?;
        file.write_all(&payload).map_err(|_| LedgerError::Io)?;
        file.write_all(b"\n").map_err(|_| LedgerError::Io)?;
        Ok(())
    }
}

pub struct DebugLedgerAdapter;

impl LedgerAdapter for DebugLedgerAdapter {
    fn submit(&self, record: &LedgerRecord) -> Result<(), LedgerError> {
        info!(target: "commucat::ledger", digest = %hex_digest(&record.digest), "ledger debug submission");
        Ok(())
    }
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes.iter() {
        let hi = byte >> 4;
        let lo = byte & 0x0f;
        output.push(nibble(hi));
        output.push(nibble(lo));
    }
    output
}

fn nibble(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + (value - 10)),
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_digest_format() {
        let digest = [0u8; 32];
        let hex = hex_digest(&digest);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c == '0'));
    }
}
