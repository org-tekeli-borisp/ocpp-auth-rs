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
        .fallback(get(auth))
        .with_state(store)
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn auth(State(store): State<Arc<CredentialStore>>, request: Request) -> StatusCode {
    let path = request
        .headers()
        .get("X-Forwarded-Uri")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split('?').next().unwrap_or_default())
        .unwrap_or_else(|| request.uri().path());
    let Some(station_id) = crate::station_id::station_id_from_path(path) else {
        return StatusCode::UNAUTHORIZED;
    };
    let Some(authorization) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::UNAUTHORIZED;
    };
    let Some((username, password)) = crate::basic_auth::parse(authorization) else {
        return StatusCode::UNAUTHORIZED;
    };
    if store.verify(&station_id, &username, &password) {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    }
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

    async fn get_status(
        path: &str,
        authorization: Option<&str>,
        forwarded_uri: Option<&str>,
    ) -> StatusCode {
        let mut builder = Request::builder().uri(path);
        if let Some(authorization) = authorization {
            builder = builder.header("Authorization", authorization);
        }
        if let Some(forwarded_uri) = forwarded_uri {
            builder = builder.header("X-Forwarded-Uri", forwarded_uri);
        }
        let request = builder.body(Body::empty()).unwrap();

        let response = app(given_store()).oneshot(request).await.unwrap();

        response.status()
    }

    #[tokio::test]
    async fn healthz_should_return_ok() {
        assert_eq!(StatusCode::OK, get_status("/healthz", None, None).await);
    }

    #[tokio::test]
    async fn auth_should_return_ok_with_valid_credentials() {
        assert_eq!(
            StatusCode::OK,
            get_status("/ocpp/AL1000", Some(VALID_AUTHORIZATION), None).await
        );
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_with_wrong_password() {
        let given_authorization = "Basic QUwxMDAwOhQVFhcYGRobHB0eHyAhIiMkJSYn";

        assert_eq!(
            StatusCode::UNAUTHORIZED,
            get_status("/ocpp/AL1000", Some(given_authorization), None).await
        );
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_when_username_differs_from_path_station_id() {
        let given_authorization = "Basic T1RIRVI6AAECAwQFBgcICQoLDA0ODxAREhM=";

        assert_eq!(
            StatusCode::UNAUTHORIZED,
            get_status("/ocpp/AL1000", Some(given_authorization), None).await
        );
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_for_no_auth_station() {
        let given_authorization = "Basic Tk9BVVRIOgABAgMEBQYHCAkKCwwNDg8QERIT";

        assert_eq!(
            StatusCode::UNAUTHORIZED,
            get_status("/ocpp/NOAUTH", Some(given_authorization), None).await
        );
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_for_forbidden_station() {
        let given_authorization = "Basic Rk9SQklEREVOOgABAgMEBQYHCAkKCwwNDg8QERIT";

        assert_eq!(
            StatusCode::UNAUTHORIZED,
            get_status("/ocpp/FORBIDDEN", Some(given_authorization), None).await
        );
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_for_unknown_station() {
        let given_authorization = "Basic Wlo5OTk5OgABAgMEBQYHCAkKCwwNDg8QERIT";

        assert_eq!(
            StatusCode::UNAUTHORIZED,
            get_status("/ocpp/ZZ9999", Some(given_authorization), None).await
        );
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_without_authorization_header() {
        assert_eq!(
            StatusCode::UNAUTHORIZED,
            get_status("/ocpp/AL1000", None, None).await
        );
    }

    #[tokio::test]
    async fn auth_should_honor_forwarded_uri_header() {
        assert_eq!(
            StatusCode::OK,
            get_status("/", Some(VALID_AUTHORIZATION), Some("/ocpp/AL1000")).await
        );
    }
}
