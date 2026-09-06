use std::net::SocketAddr;
use std::sync::Arc;

use ocpp_auth_rs::credentials::CredentialStore;
use ocpp_auth_rs::kafka_consumer;
use ocpp_auth_rs::metrics::Metrics;
use ocpp_auth_rs::server::{AppState, app};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let brokers = require_env("KAFKA_BROKERS");
    let topic = require_env("OCPP_AUTH_TOPIC");

    let store = Arc::new(CredentialStore::new());
    kafka_consumer::start(store.clone(), &brokers, &topic);
    let state = Arc::new(AppState {
        store,
        metrics: Arc::new(Metrics::new()),
    });

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind listener");

    tracing::info!("ocpp-auth-rs listening on http://{addr}");

    axum::serve(listener, app(state)).await.expect("serve");
}

fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => value,
        _ => panic!("{name} environment variable is required"),
    }
}
