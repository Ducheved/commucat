mod app;
mod config;
mod metrics;
mod openapi;
mod security;
mod transport;
mod util;

use app::CommuCatApp;
use pingora::listeners::tls::TlsSettings;
use pingora::server::Server;
use pingora::services::listening::Service;
use std::env;
use std::path::Path;
use std::sync::Arc;
use tokio::runtime::Builder;
use tracing::info;

fn main() {
    let log_filter = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .json()
        .init();

    let config_path = env::var("COMMUCAT_CONFIG").unwrap_or_else(|_| "commucat.toml".to_string());
    let config = config::load_configuration(Path::new(&config_path)).expect("configuration");

    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let state = runtime.block_on(CommuCatApp::init(config)).expect("state");

    let bind_addr = state.config.bind.clone();
    let cert_path = state.config.tls_cert.clone();
    let key_path = state.config.tls_key.clone();

    let app = CommuCatApp::new(Arc::clone(&state));
    let mut service = Service::new("CommuCat".to_string(), app);
    let mut tls = TlsSettings::intermediate(&cert_path, &key_path).expect("tls");
    tls.enable_h2();
    service.add_tls_with_settings(&bind_addr, None, tls);

    let mut server = Server::new(None).expect("server");
    server.add_service(service);
    server.bootstrap();
    info!(address = %bind_addr, "commucat listening");
    server.run_forever();
}
