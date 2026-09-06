use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::routing::get;
use http::StatusCode;
use http::header::AUTHORIZATION;

use crate::credentials::CredentialStore;

pub fn app(store: Arc<CredentialStore>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/auth", get(auth))
        .with_state(store)
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn auth(State(store): State<Arc<CredentialStore>>, request: Request) -> StatusCode {
    let Some(authorization) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::UNAUTHORIZED;
    };
    let Some((charge_point_id, key)) = crate::basic_auth::parse(authorization) else {
        return StatusCode::UNAUTHORIZED;
    };
    if store.verify(&charge_point_id, &key) {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt;

    fn given_store() -> Arc<CredentialStore> {
        let store = Arc::new(CredentialStore::new());
        store.insert(
            "AL1000",
            &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
            ],
        );
        store
    }

    async fn get_status(path: &str, authorization: Option<&str>) -> StatusCode {
        let mut builder = Request::builder().uri(path);
        if let Some(authorization) = authorization {
            builder = builder.header("Authorization", authorization);
        }
        let request = builder.body(Body::empty()).unwrap();

        let response = app(given_store()).oneshot(request).await.unwrap();

        response.status()
    }

    #[tokio::test]
    async fn healthz_should_return_ok() {
        assert_eq!(StatusCode::OK, get_status("/healthz", None).await);
    }

    #[tokio::test]
    async fn auth_should_return_ok_with_valid_credentials() {
        let given_authorization = "Basic QUwxMDAwOgABAgMEBQYHCAkKCwwNDg8QERIT";

        assert_eq!(
            StatusCode::OK,
            get_status("/auth", Some(given_authorization)).await
        );
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_with_wrong_password() {
        let given_authorization = "Basic QUwxMDAwOhQVFhcYGRobHB0eHyAhIiMkJSYn";

        assert_eq!(
            StatusCode::UNAUTHORIZED,
            get_status("/auth", Some(given_authorization)).await
        );
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_with_unknown_charge_point_id() {
        let given_authorization = "Basic Wlo5OTk5OgABAgMEBQYHCAkKCwwNDg8QERIT";

        assert_eq!(
            StatusCode::UNAUTHORIZED,
            get_status("/auth", Some(given_authorization)).await
        );
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_with_malformed_authorization_header() {
        let given_authorization = "Bearer QUwxMDAwOgABAgMEBQYHCAkKCwwNDg8QERIT";

        assert_eq!(
            StatusCode::UNAUTHORIZED,
            get_status("/auth", Some(given_authorization)).await
        );
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_without_authorization_header() {
        assert_eq!(StatusCode::UNAUTHORIZED, get_status("/auth", None).await);
    }
}
