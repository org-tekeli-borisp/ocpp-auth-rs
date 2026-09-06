use axum::Router;
use axum::extract::Request;
use axum::routing::get;
use http::StatusCode;
use http::header::AUTHORIZATION;

use crate::status::derive_status_from;

pub fn app() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/auth", get(auth))
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn auth(request: Request) -> StatusCode {
    let mut builder = http::request::Builder::new();
    if let Some(authorization) = request.headers().get(AUTHORIZATION) {
        builder = builder.header(AUTHORIZATION, authorization);
    }

    derive_status_from(builder.body(()).expect("valid request"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt;

    async fn get_status(path: &str, authorization: Option<&str>) -> StatusCode {
        let mut builder = Request::builder().uri(path);
        if let Some(authorization) = authorization {
            builder = builder.header("Authorization", authorization);
        }
        let request = builder.body(Body::empty()).unwrap();

        let response = app().oneshot(request).await.unwrap();

        response.status()
    }

    #[tokio::test]
    async fn healthz_should_return_ok() {
        assert_eq!(StatusCode::OK, get_status("/healthz", None).await);
    }

    #[tokio::test]
    async fn auth_should_return_unauthorized_without_authorization_header() {
        assert_eq!(StatusCode::UNAUTHORIZED, get_status("/auth", None).await);
    }

    #[tokio::test]
    async fn auth_should_return_ok_with_authorization_header() {
        let given_authorization = "Basic QUwxMDAwOgABAgMEBQYH////////////////";

        assert_eq!(
            StatusCode::OK,
            get_status("/auth", Some(given_authorization)).await
        );
    }
}
