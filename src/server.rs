use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use http::StatusCode;
use http::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};

use crate::credentials::CredentialStore;
use crate::metrics::Metrics;

pub struct AppState {
    pub store: Arc<CredentialStore>,
    pub metrics: Arc<Metrics>,
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .fallback(get(auth))
        .with_state(state)
}

async fn healthz() -> StatusCode {
    StatusCode::OK
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
    let state = &*state;
    let path = request
        .headers()
        .get("X-Forwarded-Uri")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split('?').next().unwrap_or_default())
        .unwrap_or_else(|| request.uri().path());
    let Some(station_id) = crate::station_id::station_id_from_path(path) else {
        return unauthorized(state);
    };
    let Some(authorization) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return unauthorized(state);
    };
    let Some((username, password)) = crate::basic_auth::parse(authorization) else {
        return unauthorized(state);
    };
    if state.store.verify(&station_id, &username, &password) {
        state.metrics.record(true);
        StatusCode::OK.into_response()
    } else {
        unauthorized(state)
    }
}

fn unauthorized(state: &AppState) -> Response {
    state.metrics.record(false);
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, "Basic realm=\"ocpp\"")],
    )
        .into_response()
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
        Arc::new(AppState {
            store: given_store(),
            metrics: Arc::new(Metrics::new()),
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
        let response = get_response("/healthz", None, None).await;

        assert_ok(&response);
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
        let response = get_response("/metrics", None, None).await;

        assert_ok(&response);
        let body = body_of(response).await;
        assert!(body.contains("ocpp_auth_requests_total"));
        assert!(body.contains("ocpp_auth_known_stations"));
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
        let response = get_response_with(state, "/metrics", None, None).await;

        let body = body_of(response).await;
        assert!(body.contains("ocpp_auth_requests_total{result=\"success\"} 1"));
        assert!(body.contains("ocpp_auth_requests_total{result=\"failure\"} 1"));
    }

    #[tokio::test]
    async fn metrics_should_report_number_of_known_stations() {
        let response = get_response("/metrics", None, None).await;

        let body = body_of(response).await;
        assert!(body.contains("ocpp_auth_known_stations 3"));
    }
}
