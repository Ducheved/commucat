use crate::util::{decode_hex, decode_hex32};
use commucat_crypto::DeviceKeyPair;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub enum ConfigError {
    Io,
    Parse,
    Missing,
    Invalid,
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io => write!(f, "configuration io failure"),
            Self::Parse => write!(f, "configuration parse failure"),
            Self::Missing => write!(f, "configuration key missing"),
            Self::Invalid => write!(f, "configuration value invalid"),
        }
    }
}

impl Error for ConfigError {}

#[derive(Clone)]
pub struct PeerConfig {
    pub domain: String,
    pub endpoint: String,
    pub public_key: [u8; 32],
}

#[derive(Clone)]
pub struct LedgerConfig {
    pub adapter: LedgerAdapter,
    pub target: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LedgerAdapter {
    Null,
    File,
    Debug,
}

#[derive(Clone)]
pub struct ServerConfig {
    pub bind: String,
    pub tls_cert: String,
    pub tls_key: String,
    pub postgres_dsn: String,
    pub redis_url: String,
    pub domain: String,
    pub admin_token: Option<String>,
    pub noise_private: [u8; 32],
    pub noise_public: [u8; 32],
    pub prologue: Vec<u8>,
    pub federation_seed: DeviceKeyPair,
    pub peers: Vec<PeerConfig>,
    pub ledger: LedgerConfig,
    pub presence_ttl_seconds: i64,
    pub relay_ttl_seconds: i64,
    pub connection_keepalive: u64,
}

/// Loads CommuCat server configuration from filesystem and environment overrides.
pub fn load_configuration(path: &Path) -> Result<ServerConfig, ConfigError> {
    let contents = fs::read_to_string(path).map_err(|_| ConfigError::Io)?;
    let mut section = String::new();
    let mut map = HashMap::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(ConfigError::Parse);
        }
        let key = if section.is_empty() {
            parts[0].trim().to_string()
        } else {
            format!("{}.{}", section, parts[0].trim())
        };
        let mut value = parts[1].trim().to_string();
        if let Some(idx) = value.find('#') {
            value.truncate(idx);
            value = value.trim().to_string();
        }
        if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            value = value[1..value.len() - 1].to_string();
        }
        map.insert(key, value);
    }

    let bind = override_env("COMMUCAT_BIND", map.remove("server.bind"))?;
    let tls_cert = required(override_env(
        "COMMUCAT_TLS_CERT",
        map.remove("server.tls_cert"),
    )?)?;
    let tls_key = required(override_env(
        "COMMUCAT_TLS_KEY",
        map.remove("server.tls_key"),
    )?)?;
    let postgres_dsn = required(override_env(
        "COMMUCAT_PG_DSN",
        map.remove("storage.postgres_dsn"),
    )?)?;
    let redis_url = required(override_env(
        "COMMUCAT_REDIS_URL",
        map.remove("storage.redis_url"),
    )?)?;
    let domain = required(override_env(
        "COMMUCAT_DOMAIN",
        map.remove("server.domain"),
    )?)?;
    let admin_token = override_env("COMMUCAT_ADMIN_TOKEN", map.remove("admin.token"))?;
    let prologue = override_env("COMMUCAT_NOISE_PROLOGUE", map.remove("crypto.prologue"))?
        .unwrap_or_else(|| "commucat".to_string())
        .into_bytes();

    let noise_private_hex = required(override_env(
        "COMMUCAT_NOISE_PRIVATE",
        map.remove("crypto.noise_private"),
    )?)?;
    let noise_public_hex = required(override_env(
        "COMMUCAT_NOISE_PUBLIC",
        map.remove("crypto.noise_public"),
    )?)?;
    let federation_seed_hex = required(override_env(
        "COMMUCAT_FEDERATION_SEED",
        map.remove("crypto.federation_seed"),
    )?)?;

    let noise_private = decode_hex32(&noise_private_hex).map_err(|_| ConfigError::Invalid)?;
    let noise_public = decode_hex32(&noise_public_hex).map_err(|_| ConfigError::Invalid)?;
    let federation_seed_bytes =
        decode_hex(&federation_seed_hex).map_err(|_| ConfigError::Invalid)?;
    let federation_seed =
        DeviceKeyPair::from_seed(&federation_seed_bytes).map_err(|_| ConfigError::Invalid)?;

    let peers_raw = override_env("COMMUCAT_FEDERATION_PEERS", map.remove("federation.peers"))?;
    let peers = parse_peers(peers_raw.unwrap_or_default())?;

    let ledger_mode = override_env("COMMUCAT_LEDGER", map.remove("ledger.mode"))?
        .unwrap_or_else(|| "null".to_string());
    let ledger_target = override_env("COMMUCAT_LEDGER_TARGET", map.remove("ledger.target"))?;
    let ledger_adapter = match ledger_mode.as_str() {
        "null" => LedgerAdapter::Null,
        "file" => LedgerAdapter::File,
        "debug" => LedgerAdapter::Debug,
        _ => return Err(ConfigError::Invalid),
    };

    let presence_ttl = override_env("COMMUCAT_PRESENCE_TTL", map.remove("limits.presence_ttl"))?
        .unwrap_or_else(|| "30".to_string())
        .parse::<i64>()
        .map_err(|_| ConfigError::Invalid)?;
    let relay_ttl = override_env("COMMUCAT_RELAY_TTL", map.remove("limits.relay_ttl"))?
        .unwrap_or_else(|| "86400".to_string())
        .parse::<i64>()
        .map_err(|_| ConfigError::Invalid)?;
    let keepalive = override_env("COMMUCAT_KEEPALIVE", map.remove("server.keepalive"))?
        .unwrap_or_else(|| "60".to_string())
        .parse::<u64>()
        .map_err(|_| ConfigError::Invalid)?;

    Ok(ServerConfig {
        bind: required(bind)?,
        tls_cert,
        tls_key,
        postgres_dsn,
        redis_url,
        domain,
        admin_token,
        noise_private,
        noise_public,
        prologue,
        federation_seed,
        peers,
        ledger: LedgerConfig {
            adapter: ledger_adapter,
            target: ledger_target,
        },
        presence_ttl_seconds: presence_ttl,
        relay_ttl_seconds: relay_ttl,
        connection_keepalive: keepalive,
    })
}

fn override_env(key: &str, current: Option<String>) -> Result<Option<String>, ConfigError> {
    match env::var(key) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(current),
        Err(_) => Err(ConfigError::Invalid),
    }
}

fn required(value: Option<String>) -> Result<String, ConfigError> {
    value.ok_or(ConfigError::Missing)
}

fn parse_peers(raw: String) -> Result<Vec<PeerConfig>, ConfigError> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut peers = Vec::new();
    for entry in raw.split(';') {
        if entry.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = entry.split(',').collect();
        if parts.len() != 3 {
            return Err(ConfigError::Parse);
        }
        let domain = parts[0].trim().to_string();
        let endpoint = parts[1].trim().to_string();
        let public_key = decode_hex32(parts[2].trim()).map_err(|_| ConfigError::Invalid)?;
        peers.push(PeerConfig {
            domain,
            endpoint,
            public_key,
        });
    }
    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    #[test]
    fn parse_configuration_minimal() {
        let mut path = PathBuf::from(env::temp_dir());
        path.push("commucat_test_config.toml");
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(
            b"[server]\nbind=\"127.0.0.1:8443\"\ntls_cert=\"cert.pem\"\ntls_key=\"key.pem\"\ndomain=\"example.org\"\nkeepalive=\"30\"\n[storage]\npostgres_dsn=\"postgres://\"\nredis_url=\"redis://localhost\"\n[crypto]\nnoise_private=\"000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f\"\nnoise_public=\"101112131415161718191a1b1c1d1e1f101112131415161718191a1b1c1d1e1f\"\nfederation_seed=\"202122232425262728292a2b2c2d2e2f202122232425262728292a2b2c2d2e2f\"\n"
        )
        .unwrap();
        let config = load_configuration(&path).unwrap();
        assert_eq!(config.bind, "127.0.0.1:8443");
        assert_eq!(config.ledger.adapter, LedgerAdapter::Null);
        assert_eq!(config.presence_ttl_seconds, 30);
        assert_eq!(config.relay_ttl_seconds, 86400);
        fs::remove_file(path).unwrap();
    }
}
