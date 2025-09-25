use blake3::Hasher;
use chrono::{Duration, Utc};
use commucat_crypto::{DeviceCertificateData, DeviceKeyPair, EventSigner};
use commucat_ledger::{DebugLedgerAdapter, LedgerAdapter, LedgerRecord};
use commucat_media::prelude::{CallMediaPipeline, PipelineConfig};
use commucat_storage::{
    connect, DeviceRecord, NewUserProfile, PresenceSnapshot, SessionRecord, Storage, StorageError,
    UserProfile,
};
use std::env;
use std::fs::File;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::runtime::Builder;
use tracing::info;

const CERTIFICATE_VALIDITY_DAYS: i64 = 30;

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
        "register-user" => command_register_user(args).await,
        "rotate-keys" => command_rotate_keys(args).await,
        "diagnose" => command_diagnose().await,
        "call-simulate" => command_call_simulate(args).await,
        other => Err(format!("unknown command: {}", other)),
    }
}

async fn command_call_simulate(args: Vec<String>) -> Result<(), String> {
    let iterations = if args.is_empty() {
        64usize
    } else {
        args[0]
            .parse::<usize>()
            .map_err(|_| "expected <frames> as usize".to_string())?
    };
    let config = PipelineConfig::default();
    let frame_duration = config.voice.frame_duration_ms;
    let mut pipeline =
        CallMediaPipeline::new(config).map_err(|err| format!("pipeline init failed: {err}"))?;
    let mut timestamp_ms = 0u64;
    let frame_samples = pipeline.frame_samples();
    let mut pcm = vec![0i16; frame_samples];
    let mut total_bytes = 0usize;
    for iter in 0..iterations {
        for (index, sample) in pcm.iter_mut().enumerate() {
            let phase = (timestamp_ms as usize + index) as i32;
            *sample = ((phase * 73) & 0xfff) as i16;
        }
        let frame = pipeline
            .encode_audio(&pcm, timestamp_ms)
            .map_err(|err| format!("encode failed at frame {iter}: {err}"))?;
        total_bytes += frame.payload().len();
        let decoded = pipeline
            .decode_audio(frame.payload(), false)
            .map_err(|err| format!("decode failed at frame {iter}: {err}"))?;
        if decoded.len() != pcm.len() {
            return Err(format!(
                "decoded sample count mismatch (expected {}, got {})",
                pcm.len(),
                decoded.len()
            ));
        }
        timestamp_ms += u64::from(frame_duration);
    }
    println!("simulated_frames={iterations} encoded_bytes={total_bytes}");
    Ok(())
}

async fn command_migrate() -> Result<(), String> {
    let storage = storage_connect().await?;
    storage
        .migrate()
        .await
        .map_err(|err| format!("migrate failed: {}", err))
}

async fn command_register_user(mut args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "usage: commucat-cli register-user <handle> [display_name] [avatar_url]".to_string(),
        );
    }
    let handle = args.remove(0);
    let display_name = if !args.is_empty() {
        Some(args.remove(0))
    } else {
        None
    };
    let avatar_url = if !args.is_empty() {
        Some(args.remove(0))
    } else {
        None
    };
    if !args.is_empty() {
        return Err("unexpected arguments".to_string());
    }
    let storage = storage_connect().await?;
    let profile = NewUserProfile {
        user_id: generate_id(&handle),
        handle: handle.clone(),
        display_name,
        avatar_url,
    };
    let created = storage
        .create_user(&profile)
        .await
        .map_err(|err| format!("create user failed: {}", err))?;
    println!("user_id={}", created.user_id);
    println!("handle={}", created.handle);
    if let Some(name) = created.display_name {
        println!("display_name={}", name);
    }
    if let Some(url) = created.avatar_url {
        println!("avatar_url={}", url);
    }
    Ok(())
}

async fn command_rotate_keys(args: Vec<String>) -> Result<(), String> {
    let mut user_id_arg = None;
    let mut handle_arg = None;
    let mut device_id_arg = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--user" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --user".to_string())?;
                user_id_arg = Some(value);
            }
            "--handle" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --handle".to_string())?;
                handle_arg = Some(value);
            }
            "--device" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --device".to_string())?;
                device_id_arg = Some(value);
            }
            other => {
                if device_id_arg.is_none() {
                    device_id_arg = Some(other.to_string());
                } else {
                    return Err("unexpected argument".to_string());
                }
            }
        }
    }
    let ca_signer = load_certificate_signer()?;
    let issuer_public = ca_signer.public_key();
    let device_id =
        device_id_arg.unwrap_or_else(|| format!("device-{}", Utc::now().timestamp_millis()));
    let seed = read_os_random()?;
    let keys = DeviceKeyPair::from_seed(&seed).map_err(|err| format!("key error: {}", err))?;
    let storage = storage_connect().await?;
    let user_id = if let Some(id) = user_id_arg {
        id
    } else if let Some(handle) = handle_arg {
        storage
            .load_user_by_handle(&handle)
            .await
            .map_err(|err| format!("load user failed: {}", err))?
            .user_id
    } else {
        return Err("specify --user <user_id> or --handle <handle>".to_string());
    };

    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::days(CERTIFICATE_VALIDITY_DAYS);
    let issued_at_ts = issued_at.timestamp();
    let expires_at_ts = expires_at.timestamp();
    let serial_source = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock before unix epoch".to_string())?;
    let serial = (serial_source.as_nanos() & 0xffff_ffff_ffff_ffff) as u64;

    let record = DeviceRecord {
        device_id: device_id.clone(),
        user_id: user_id.clone(),
        public_key: keys.public.to_vec(),
        status: "active".to_string(),
        created_at: issued_at,
    };
    storage
        .upsert_device(&record)
        .await
        .map_err(|err| format!("store failed: {}", err))?;

    let certificate_data = DeviceCertificateData::new(
        serial,
        user_id.clone(),
        device_id.clone(),
        keys.public,
        issuer_public,
        issued_at_ts,
        expires_at_ts,
    );
    let certificate = ca_signer.sign_certificate(&certificate_data);
    let certificate_json = serde_json::to_string(&certificate)
        .map_err(|err| format!("certificate encode failed: {}", err))?;

    let ledger_record = LedgerRecord {
        digest: keys.public,
        recorded_at: issued_at,
        metadata: serde_json::json!({
            "device": device_id,
            "user": user_id.clone(),
            "action": "rotate",
            "certificate_serial": serial,
            "certificate_issued_at": issued_at_ts,
            "certificate_expires_at": expires_at_ts,
        }),
    };
    let ledger = DebugLedgerAdapter;
    ledger
        .submit(&ledger_record)
        .map_err(|err| format!("ledger failed: {}", err))?;

    println!("user_id={}", user_id);
    println!("device_id={}", record.device_id);
    println!("public_key={}", hex_string(&keys.public));
    println!("private_key={}", hex_string(&keys.private));
    println!("issuer_public={}", hex_string(&issuer_public));
    println!("certificate_serial={}", serial);
    println!("certificate_expires_at={}", expires_at.to_rfc3339());
    println!("certificate={}", certificate_json);
    Ok(())
}

async fn command_diagnose() -> Result<(), String> {
    let storage = storage_connect().await?;
    let profile = ensure_user(&storage, "diagnose", "diagnose").await?;
    let device = DeviceRecord {
        device_id: "diagnose".to_string(),
        user_id: profile.user_id.clone(),
        public_key: vec![0u8; 32],
        status: "diagnostic".to_string(),
        created_at: Utc::now(),
    };
    storage
        .upsert_device(&device)
        .await
        .map_err(|err| format!("store failed: {}", err))?;
    storage
        .publish_presence(&PresenceSnapshot {
            entity: "diagnose".to_string(),
            state: "ok".to_string(),
            expires_at: Utc::now(),
            user_id: Some(profile.user_id.clone()),
            handle: Some(profile.handle.clone()),
            display_name: profile.display_name.clone(),
            avatar_url: profile.avatar_url.clone(),
        })
        .await
        .map_err(|err| format!("presence failed: {}", err))?;
    let session = SessionRecord {
        session_id: "diagnose".to_string(),
        user_id: profile.user_id,
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

async fn ensure_user(
    storage: &Storage,
    handle: &str,
    display_name: &str,
) -> Result<UserProfile, String> {
    match storage.load_user_by_handle(handle).await {
        Ok(profile) => Ok(profile),
        Err(StorageError::Missing) => {
            let profile = NewUserProfile {
                user_id: generate_id(handle),
                handle: handle.to_string(),
                display_name: Some(display_name.to_string()),
                avatar_url: None,
            };
            storage
                .create_user(&profile)
                .await
                .map_err(|err| format!("create user failed: {}", err))
        }
        Err(err) => Err(format!("load user failed: {}", err)),
    }
}

async fn storage_connect() -> Result<Storage, String> {
    let pg = env::var("COMMUCAT_PG_DSN").map_err(|_| "COMMUCAT_PG_DSN not set".to_string())?;
    let redis =
        env::var("COMMUCAT_REDIS_URL").map_err(|_| "COMMUCAT_REDIS_URL not set".to_string())?;
    connect(&pg, &redis)
        .await
        .map_err(|err| format!("storage connect failed: {}", err))
}

fn load_certificate_signer() -> Result<EventSigner, String> {
    let seed_hex = env::var("COMMUCAT_FEDERATION_SEED")
        .map_err(|_| "COMMUCAT_FEDERATION_SEED not set".to_string())?;
    let seed = decode_hex(&seed_hex)?;
    let keys = DeviceKeyPair::from_seed(&seed)
        .map_err(|err| format!("invalid federation seed: {}", err))?;
    Ok(EventSigner::new(&keys))
}

fn read_os_random() -> Result<[u8; 32], String> {
    let mut file =
        File::open("/dev/urandom").map_err(|_| "unable to open /dev/urandom".to_string())?;
    let mut buf = [0u8; 32];
    file.read_exact(&mut buf)
        .map_err(|_| "failed to read entropy".to_string())?;
    Ok(buf)
}

fn generate_id(context: &str) -> String {
    let mut hasher = Hasher::new();
    hasher.update(context.as_bytes());
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_le_bytes();
    hasher.update(&nonce);
    hex_string(hasher.finalize().as_bytes())
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

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if !input.len().is_multiple_of(2) {
        return Err("hex string must have even length".to_string());
    }
    let mut output = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        let hi = parse_hex_digit(bytes[idx])?;
        let lo = parse_hex_digit(bytes[idx + 1])?;
        output.push((hi << 4) | lo);
        idx += 2;
    }
    Ok(output)
}

fn parse_hex_digit(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(format!("invalid hex digit: {}", value as char)),
    }
}

fn nibble(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + (value - 10)),
        _ => '0',
    }
}
