use chrono::Utc;
use commucat_crypto::DeviceKeyPair;
use commucat_ledger::{DebugLedgerAdapter, LedgerAdapter, LedgerRecord};
use commucat_storage::{connect, DeviceRecord, PresenceSnapshot, SessionRecord};
use std::env;
use std::fs::File;
use std::io::Read;
use tokio::runtime::Builder;
use tracing::info;

fn main() {
    let _ = dotenvy::dotenv();
    
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("info")
        .json()
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("failed to init tracing");
    let mut runtime = Builder::new_multi_thread();
    runtime.enable_all();
    let runtime = runtime.build().expect("failed to build runtime");
    if let Err(err) = runtime.block_on(async_main()) {
        eprintln!("error: {}", err);
        std::process::exit(1);
    }
}

async fn async_main() -> Result<(), String> {
    let mut args = env::args().skip(1).collect::<Vec<String>>();
    if args.is_empty() {
        return Err("usage: commucat-cli <command>".to_string());
    }
    let command = args.remove(0);
    match command.as_str() {
        "migrate" => command_migrate().await,
        "rotate-keys" => command_rotate_keys(args).await,
        "diagnose" => command_diagnose().await,
        other => Err(format!("unknown command: {}", other)),
    }
}

async fn command_migrate() -> Result<(), String> {
    let storage = storage_connect().await?;
    storage
        .migrate()
        .await
        .map_err(|err| format!("migrate failed: {}", err))
}

async fn command_rotate_keys(mut args: Vec<String>) -> Result<(), String> {
    let device_id = if !args.is_empty() {
        args.remove(0)
    } else {
        format!("device-{}", Utc::now().timestamp_millis())
    };
    let seed = read_os_random()?;
    let keys = DeviceKeyPair::from_seed(&seed).map_err(|err| format!("key error: {}", err))?;
    let storage = storage_connect().await?;
    let record = DeviceRecord {
        device_id: device_id.clone(),
        public_key: keys.public.to_vec(),
        status: "active".to_string(),
        created_at: Utc::now(),
    };
    storage
        .upsert_device(&record)
        .await
        .map_err(|err| format!("store failed: {}", err))?;
    let signer = LedgerRecord {
        digest: keys.public,
        recorded_at: Utc::now(),
        metadata: serde_json::json!({"device": device_id}),
    };
    let ledger = DebugLedgerAdapter;
    ledger
        .submit(&signer)
        .map_err(|err| format!("ledger failed: {}", err))?;
    println!("device_id={}", device_id);
    println!("public_key={}", hex_string(&keys.public));
    println!("private_key={}", hex_string(&keys.private));
    Ok(())
}

async fn command_diagnose() -> Result<(), String> {
    let storage = storage_connect().await?;
    storage
        .publish_presence(&PresenceSnapshot {
            entity: "diagnose".to_string(),
            state: "ok".to_string(),
            expires_at: Utc::now(),
        })
        .await
        .map_err(|err| format!("presence failed: {}", err))?;
    let session = SessionRecord {
        session_id: "diagnose".to_string(),
        device_id: "diagnose".to_string(),
        tls_fingerprint: "diagnose".to_string(),
        created_at: Utc::now(),
        ttl_seconds: 60,
    };
    storage
        .record_session(&session)
        .await
        .map_err(|err| format!("session failed: {}", err))?;
    info!("diagnose complete");
    Ok(())
}

async fn storage_connect() -> Result<commucat_storage::Storage, String> {
    let pg = env::var("COMMUCAT_PG_DSN").map_err(|_| "COMMUCAT_PG_DSN not set".to_string())?;
    let redis =
        env::var("COMMUCAT_REDIS_URL").map_err(|_| "COMMUCAT_REDIS_URL not set".to_string())?;
    connect(&pg, &redis)
        .await
        .map_err(|err| format!("storage connect failed: {}", err))
}

fn read_os_random() -> Result<[u8; 32], String> {
    let mut file =
        File::open("/dev/urandom").map_err(|_| "unable to open /dev/urandom".to_string())?;
    let mut buf = [0u8; 32];
    file.read_exact(&mut buf)
        .map_err(|_| "failed to read entropy".to_string())?;
    Ok(buf)
}

fn hex_string(data: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in data.iter() {
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
