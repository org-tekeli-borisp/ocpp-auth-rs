use std::net::SocketAddr;

use axum::extract::Request;

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("MOCK_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(9000);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind listener");

    println!("mock backend listening on http://{addr}");

    let app = axum::Router::new().fallback(|_request: Request| async { "backend-ok" });
    axum::serve(listener, app).await.expect("serve");
}
