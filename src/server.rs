use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Router;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use http::StatusCode;
use http::header::{AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE};
use tokio::sync::Semaphore;

use crate::credentials::CredentialStore;
use crate::metrics::Metrics;
use crate::rate_limit::RateLimiter;

pub struct AppState {
    pub store: Arc<CredentialStore>,
    pub metrics: Arc<Metrics>,
    pub ready: Arc<AtomicBool>,
    pub rate_limiter: Arc<RateLimiter>,
    /// Second limiter keyed by client IP: one host cannot burn a known
    /// station's bucket to lock out its legitimate reconnects, and spraying
    /// random station ids exhausts the attacker's own bucket instead of the
    /// limiter's key budget.
    pub ip_rate_limiter: Arc<RateLimiter>,
    /// Bounds concurrent bcrypt verifications so a credential-stuffing flood
    /// cannot saturate the host with hashing work.
    pub bcrypt_permits: Arc<Semaphore>,
}

/// Public router: every request on the auth port is a forward-auth check.
/// The fallback runs for any method so the answer is always an auth decision
/// (200/401/429) rather than a method-based 405 from the router itself.
pub fn app(state: Arc<AppState>) -> Router {
    Router::new().fallback(auth).with_state(state)
}

/// Internal router: operational endpoints, served on a separate admin port so
/// they stay unreachable even when the auth port is exposed directly.
pub fn admin_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(state)
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn readyz(State(state): State<Arc<AppState>>) -> StatusCode {
    if state.ready.load(Ordering::Relaxed) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let body = state.metrics.render(state.store.len());
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn auth(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let path = request
        .headers()
        .get("X-Forwarded-Uri")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split('?').next().unwrap_or_default())
        .unwrap_or_else(|| request.uri().path());
    let Some(station_id) = crate::station_id::station_id_from_path(path) else {
        return unauthorized(&state);
    };
    // Traefik always sets X-Forwarded-For; requests without it (direct dev
    // calls) skip the IP check rather than share one bucket for every caller.
    let client_ip = request
        .headers()
        .get("X-Forwarded-For")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').next().unwrap_or_default().trim())
        .filter(|value| !value.is_empty());
    if let Some(client_ip) = client_ip
        && !state.ip_rate_limiter.allow(client_ip)
    {
        return rate_limited(&state);
    }
    if !state.rate_limiter.allow(&station_id) {
        return rate_limited(&state);
    }
    let Some(authorization) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return unauthorized(&state);
    };
    let Some((username, password)) = crate::basic_auth::parse(authorization) else {
        return unauthorized(&state);
    };
    // Fail fast when every bcrypt permit is busy instead of queueing the
    // request: Traefik and stations retry after Retry-After, p95 stays predictable.
    let Ok(permit) = state.bcrypt_permits.clone().try_acquire_owned() else {
        return rate_limited(&state);
    };
    let store = state.store.clone();
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        store.verify(&station_id, &username, &password)
    })
    .await
    .unwrap_or(false);
    if verified {
        state.metrics.record(true);
        StatusCode::OK.into_response()
    } else {
        unauthorized(&state)
    }
}

fn unauthorized(state: &Arc<AppState>) -> Response {
    state.metrics.record(false);
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, "Basic realm=\"ocpp\"")],
    )
        .into_response()
}

fn rate_limited(state: &Arc<AppState>) -> Response {
    state.metrics.record_rate_limited();
    (StatusCode::TOO_MANY_REQUESTS, [(RETRY_AFTER, "1")]).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::AuthType;
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt;

    const VALID_AUTHORIZATION: &str = "Basic QUwxMDAwOgABAgMEBQYHCAkKCwwNDg8QERIT";

    fn given_store() -> Arc<CredentialStore> {
        let password: Vec<u8> = (0..20).collect();
        let password_hash = bcrypt::hash(&password, 10).unwrap();
        let store = Arc::new(CredentialStore::new());
        store.upsert("AL1000", AuthType::Basic { password_hash });
        store.upsert("NOAUTH", AuthType::NoAuth);
        store.upsert("FORBIDDEN", AuthType::Forbidden);
        store
    }

    fn given_state() -> Arc<AppState> {
        given_state_with(true, 1000.0)
    }

    /// Rate limiters without refill so burst behaviour is deterministic in
    /// tests; the per-IP bucket is generous enough not to interfere.
    fn given_state_with(ready: bool, auth_burst: f64) -> Arc<AppState> {
        given_state_with_ip_burst(ready, auth_burst, 1000.0)
    }

    /// Same, with an explicit per-IP burst for testing the IP limiter.
    fn given_state_with_ip_burst(ready: bool, auth_burst: f64, ip_burst: f64) -> Arc<AppState> {
        Arc::new(AppState {
            store: given_store(),
            metrics: Arc::new(Metrics::new()),
            ready: Arc::new(AtomicBool::new(ready)),
            rate_limiter: Arc::new(RateLimiter::new(0.0, auth_burst)),
            ip_rate_limiter: Arc::new(RateLimiter::new(0.0, ip_burst)),
            bcrypt_permits: Arc::new(Semaphore::new(8)),
        })
    }

    async fn get_response_with(
        state: Arc<AppState>,
        path: &str,
        authorization: Option<&str>,
        forwarded_uri: Option<&str>,
    ) -> Response {
        let mut builder = Request::builder().uri(path);
        if let Some(authorization) = authorization {
            builder = builder.header("Authorization", authorization);
        }
        if let Some(forwarded_uri) = forwarded_uri {
            builder = builder.header("X-Forwarded-Uri", forwarded_uri);
        }
        let request = builder.body(Body::empty()).unwrap();

        app(state).oneshot(request).await.unwrap()
    }

    async fn get_response(
        path: &str,
        authorization: Option<&str>,
        forwarded_uri: Option<&str>,
    ) -> Response {
        get_response_with(given_state(), path, authorization, forwarded_uri).await
    }

    async fn get_response_with_forwarded_for(
        state: Arc<AppState>,
        forwarded_for: &str,
    ) -> Response {
        let request = Request::builder()
            .uri("/ocpp/AL1000")
            .header("Authorization", VALID_AUTHORIZATION)
            .header("X-Forwarded-For", forwarded_for)
            .body(Body::empty())
            .unwrap();

        app(state).oneshot(request).await.unwrap()
    }

    async fn get_admin_response_with(state: Arc<AppState>, path: &str) -> Response {
        let request = Request::builder().uri(path).body(Body::empty()).unwrap();

        admin_app(state).oneshot(request).await.unwrap()
    }

    async fn get_admin_response(path: &str) -> Response {
        get_admin_response_with(given_state(), path).await
    }

    async fn body_of(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn www_authenticate(response: &Response) -> Option<&str> {
        response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
    }

    fn assert_ok(response: &Response) {
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(None, www_authenticate(response));
    }

    fn assert_unauthorized(response: &Response) {
        assert_eq!(StatusCode::UNAUTHORIZED, response.status());
        assert_eq!(Some("Basic realm=\"ocpp\""), www_authenticate(response));
    }

    #[tokio::test]
    async fn healthz_should_return_ok() {
        let response = get_admin_response("/healthz").await;

        assert_ok(&response);
    }

    #[tokio::test]
    async fn readyz_should_return_service_unavailable_until_ready() {
        let state = given_state_with(false, 1000.0);
        let response = get_admin_response_with(state, "/readyz").await;

        assert_eq!(StatusCode::SERVICE_UNAVAILABLE, response.status());
    }

    #[tokio::test]
    async fn readyz_should_return_ok_when_ready() {
        let response = get_admin_response("/readyz").await;

        assert_ok(&response);
    }

    #[tokio::test]
    async fn auth_should_return_rate_limited_when_burst_is_exceeded() {
        let state = given_state_with(true, 2.0);

        assert_ok(
            &get_response_with(
                state.clone(),
                "/ocpp/AL1000",
                Some(VALID_AUTHORIZATION),
                None,
            )
            .await,
        );
        assert_ok(
            &get_response_with(
                state.clone(),
                "/ocpp/AL1000",
                Some(VALID_AUTHORIZATION),
                None,
            )
            .await,
        );
        let response =
            get_response_with(state, "/ocpp/AL1000", Some(VALID_AUTHORIZATION), None).await;

        assert_eq!(StatusCode::TOO_MANY_REQUESTS, response.status());
        assert_eq!(
            Some("1"),
            response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
        );
    }

    #[tokio::test]
    async fn auth_should_return_rate_limited_when_ip_burst_is_exceeded() {
        let state = given_state_with_ip_burst(true, 1000.0, 2.0);

        assert_ok(&get_response_with_forwarded_for(state.clone(), "203.0.113.7").await);
        assert_ok(&get_response_with_forwarded_for(state.clone(), "203.0.113.7").await);
        let response = get_response_with_forwarded_for(state, "203.0.113.7").await;

        assert_eq!(StatusCode::TOO_MANY_REQUESTS, response.status());
        assert_eq!(
            Some("1"),
            response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
        );
    }

    #[tokio::test]
    async fn auth_should_return_rate_limited_when_all_bcrypt_permits_are_busy() {
        let state = Arc::new(AppState {
            store: given_store(),
            metrics: Arc::new(Metrics::new()),
            ready: Arc::new(AtomicBool::new(true)),
            rate_limiter: Arc::new(RateLimiter::new(0.0, 1000.0)),
            ip_rate_limiter: Arc::new(RateLimiter::new(0.0, 1000.0)),
            bcrypt_permits: Arc::new(Semaphore::new(1)),
        });
        let held_permit = state
            .bcrypt_permits
            .clone()
            .try_acquire_owned()
            .expect("the only permit is free before the request");

        let response = get_response_with(
            state.clone(),
            "/ocpp/AL1000",
            Some(VALID_AUTHORIZATION),
            None,
        )
        .await;

        assert_eq!(StatusCode::TOO_MANY_REQUESTS, response.status());
        assert_eq!(
            Some("1"),
            response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
        );

        drop(held_permit);
        let response =
            get_response_with(state, "/ocpp/AL1000", Some(VALID_AUTHORIZATION), None).await;

        assert_ok(&response);
    }

    #[tokio::test]
    async fn auth_should_track_ip_limits_independently() {
        let state = given_state_with_ip_burst(true, 1000.0, 1.0);

        assert_ok(&get_response_with_forwarded_for(state.clone(), "203.0.113.7").await);
        let response = get_response_with_forwarded_for(state, "198.51.100.4").await;

        assert_ok(&response);
    }

    #[tokio::test]
    async fn auth_should_work_without_forwarded_for_header() {
        let state = given_state_with_ip_burst(true, 1000.0, 1.0);

        let response =
            get_response_with(state, "/ocpp/AL1000", Some(VALID_AUTHORIZATION), None).await;

        assert_ok(&response);
    }

    #[tokio::test]
    async fn auth_should_answer_with_a_decision_for_any_method() {
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/ocpp/AL1000")
            .header("Authorization", VALID_AUTHORIZATION)
            .body(Body::empty())
            .unwrap();

        let response = app(given_state()).oneshot(request).await.unwrap();

        assert_ok(&response);
    }

    #[tokio::test]
    async fn auth_should_use_first_entry_of_forwarded_for_chain() {
        let state = given_state_with_ip_burst(true, 1000.0, 1.0);

        assert_ok(&get_response_with_forwarded_for(state.clone(), "203.0.113.7, 10.0.0.1").await);
        let response = get_response_with_forwarded_for(state, "203.0.113.7, 10.0.0.2").await;

        assert_eq!(StatusCode::TOO_MANY_REQUESTS, response.status());
    }

    #[tokio::test]
    async fn auth_should_return_ok_with_valid_credentials() {
        let response = get_response("/ocpp/AL1000", Some(VALID_AUTHORIZATION), None).await;

        assert_ok(&response);
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_with_wrong_password() {
        let given_authorization = "Basic QUwxMDAwOhQVFhcYGRobHB0eHyAhIiMkJSYn";
        let response = get_response("/ocpp/AL1000", Some(given_authorization), None).await;

        assert_unauthorized(&response);
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_when_username_differs_from_path_station_id() {
        let given_authorization = "Basic T1RIRVI6AAECAwQFBgcICQoLDA0ODxAREhM=";
        let response = get_response("/ocpp/AL1000", Some(given_authorization), None).await;

        assert_unauthorized(&response);
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_for_no_auth_station() {
        let given_authorization = "Basic Tk9BVVRIOgABAgMEBQYHCAkKCwwNDg8QERIT";
        let response = get_response("/ocpp/NOAUTH", Some(given_authorization), None).await;

        assert_unauthorized(&response);
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_for_forbidden_station() {
        let given_authorization = "Basic Rk9SQklEREVOOgABAgMEBQYHCAkKCwwNDg8QERIT";
        let response = get_response("/ocpp/FORBIDDEN", Some(given_authorization), None).await;

        assert_unauthorized(&response);
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_for_unknown_station() {
        let given_authorization = "Basic Wlo5OTk5OgABAgMEBQYHCAkKCwwNDg8QERIT";
        let response = get_response("/ocpp/ZZ9999", Some(given_authorization), None).await;

        assert_unauthorized(&response);
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_without_authorization_header() {
        let response = get_response("/ocpp/AL1000", None, None).await;

        assert_unauthorized(&response);
    }

    #[tokio::test]
    async fn auth_should_honor_forwarded_uri_header() {
        let response = get_response("/", Some(VALID_AUTHORIZATION), Some("/ocpp/AL1000")).await;

        assert_ok(&response);
    }

    #[tokio::test]
    async fn metrics_should_return_ok_with_metric_names() {
        let response = get_admin_response("/metrics").await;

        assert_ok(&response);
        let body = body_of(response).await;
        assert!(body.contains("ocpp_auth_requests_total"));
        assert!(body.contains("ocpp_auth_known_stations"));
        assert!(body.contains("ocpp_auth_kafka_last_message_timestamp_seconds 0"));
        assert!(body.contains("ocpp_auth_kafka_errors_total 0"));
    }

    #[tokio::test]
    async fn metrics_should_count_successful_and_failed_auth_requests() {
        let state = given_state();
        get_response_with(
            state.clone(),
            "/ocpp/AL1000",
            Some(VALID_AUTHORIZATION),
            None,
        )
        .await;
        get_response_with(state.clone(), "/ocpp/AL1000", None, None).await;
        let response = get_admin_response_with(state, "/metrics").await;

        let body = body_of(response).await;
        assert!(body.contains("ocpp_auth_requests_total{result=\"success\"} 1"));
        assert!(body.contains("ocpp_auth_requests_total{result=\"failure\"} 1"));
    }

    #[tokio::test]
    async fn metrics_should_count_rate_limited_requests() {
        let state = given_state_with(true, 1.0);
        get_response_with(
            state.clone(),
            "/ocpp/AL1000",
            Some(VALID_AUTHORIZATION),
            None,
        )
        .await;
        get_response_with(
            state.clone(),
            "/ocpp/AL1000",
            Some(VALID_AUTHORIZATION),
            None,
        )
        .await;
        let response = get_admin_response_with(state, "/metrics").await;

        let body = body_of(response).await;
        assert!(body.contains("ocpp_auth_requests_total{result=\"rate_limited\"} 1"));
    }

    #[tokio::test]
    async fn metrics_should_report_number_of_known_stations() {
        let response = get_admin_response("/metrics").await;

        let body = body_of(response).await;
        assert!(body.contains("ocpp_auth_known_stations 3"));
    }
}
