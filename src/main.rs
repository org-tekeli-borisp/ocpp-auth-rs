mod basic_auth;
mod credentials;
mod server;
mod station_id;

use std::net::SocketAddr;
use std::sync::Arc;

use credentials::CredentialStore;
use server::app;

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind listener");

    println!("ocpp-auth-rs listening on http://{addr}");

    axum::serve(listener, app(Arc::new(CredentialStore::new())))
        .await
        .expect("serve");
}
