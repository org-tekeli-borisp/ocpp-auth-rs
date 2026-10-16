use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Semaphore;

use ocpp_auth_rs::config::Config;
use ocpp_auth_rs::credentials::CredentialStore;
use ocpp_auth_rs::kafka_consumer;
use ocpp_auth_rs::metrics::Metrics;
use ocpp_auth_rs::rate_limit::RateLimiter;
use ocpp_auth_rs::server::{AppState, admin_app, app};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            tracing::error!("{err}");
            std::process::exit(1);
        }
    };

    let store = Arc::new(CredentialStore::new());
    let ready = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(Metrics::new());
    let consumer = kafka_consumer::start(
        store.clone(),
        &config.kafka_brokers,
        &config.kafka_topic,
        ready.clone(),
        stop.clone(),
        metrics.clone(),
    );

    let state = Arc::new(AppState {
        store,
        metrics,
        ready,
        rate_limiter: Arc::new(RateLimiter::new(
            config.rate_limit_per_second,
            config.rate_limit_burst,
        )),
        bcrypt_permits: Arc::new(Semaphore::new(config.bcrypt_permits)),
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let admin_addr = SocketAddr::from(([0, 0, 0, 0], config.admin_port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind listener");
    let admin_listener = tokio::net::TcpListener::bind(admin_addr)
        .await
        .expect("bind admin listener");

    tracing::info!(
        "ocpp-auth-rs listening on http://{addr} \
         (rate limit {} per second, burst {})",
        config.rate_limit_per_second,
        config.rate_limit_burst,
    );
    tracing::info!("ocpp-auth-rs admin listening on http://{admin_addr}");

    // Both servers observe the same shutdown signal: the first Ctrl-C/SIGTERM
    // is broadcast so each listener drains its in-flight requests gracefully.
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
    let signal = async {
        shutdown_signal().await;
        let _ = shutdown_tx.send(());
    };
    let auth_server = axum::serve(listener, app(state.clone()))
        .with_graceful_shutdown(shutdown_received(shutdown_tx.subscribe()));
    let admin_server = axum::serve(admin_listener, admin_app(state))
        .with_graceful_shutdown(shutdown_received(shutdown_tx.subscribe()));

    let ((), auth_result, admin_result) = tokio::join!(signal, auth_server, admin_server);
    auth_result.expect("serve");
    admin_result.expect("serve");

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

/// Resolves once the shared shutdown signal has been broadcast.
async fn shutdown_received(mut rx: tokio::sync::broadcast::Receiver<()>) {
    let _ = rx.recv().await;
}
