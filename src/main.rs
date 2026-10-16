use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Semaphore;

use ocpp_auth_rs::credentials::CredentialStore;
use ocpp_auth_rs::kafka_consumer;
use ocpp_auth_rs::metrics::Metrics;
use ocpp_auth_rs::rate_limit::RateLimiter;
use ocpp_auth_rs::server::{AppState, app};

/// Auth attempts per second per station, and the burst allowed on top.
const RATE_LIMIT_PER_SECOND: f64 = 2.0;
const RATE_LIMIT_BURST: f64 = 10.0;

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
    let ready = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(Metrics::new());
    let consumer = kafka_consumer::start(
        store.clone(),
        &brokers,
        &topic,
        ready.clone(),
        stop.clone(),
        metrics.clone(),
    );

    let bcrypt_permits =
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let state = Arc::new(AppState {
        store,
        metrics,
        ready,
        rate_limiter: Arc::new(RateLimiter::new(RATE_LIMIT_PER_SECOND, RATE_LIMIT_BURST)),
        bcrypt_permits: Arc::new(Semaphore::new(bcrypt_permits)),
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

    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("serve");

    stop.store(true, Ordering::Relaxed);
    if consumer.join().is_err() {
        tracing::warn!("kafka consumer thread panicked during shutdown");
    }
    tracing::info!("ocpp-auth-rs shut down");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C signal handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM signal handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl-C"),
        _ = terminate => tracing::info!("received SIGTERM"),
    }
    tracing::info!("shutting down, draining in-flight requests");
}

fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => value,
        _ => panic!("{name} environment variable is required"),
    }
}
