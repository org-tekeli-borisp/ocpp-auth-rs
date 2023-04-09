use crate::status::derive_status;
use http::{Request, Response, StatusCode};

fn apply(request: Request<()>) -> Response<()> {
    return Response::builder()
        .status(derive_status(request))
        .body(())
        .unwrap();
}

#[cfg(test)]
mod tests {
    use std::any::type_name;

    use super::*;

    fn type_of<T>(_: &T) -> &str {
        return type_name::<T>();
    }

    #[test]
    fn should_consume_http_request_and_produce_http_response() {
        let given_request: Request<()> = Request::builder().body(()).unwrap();

        let response = apply(given_request);

        assert_eq!("http::response::Response<()>", type_of(&response));
    }

    #[test]
    fn should_produce_http_response_with_http_status_401_in_case_http_request_headers_are_empty() {
        let given_request: Request<()> = Request::builder().body(()).unwrap();

        let response = apply(given_request);

        assert_eq!(StatusCode::UNAUTHORIZED, response.status());
    }

    #[test]
    fn should_produce_http_response_with_http_status_401_in_case_http_request_authorization_header_is_missing(
    ) {
        let given_request: Request<()> = Request::builder()
            .header("OTHER", "HEADER")
            .body(())
            .unwrap();

        let response = apply(given_request);

        assert_eq!(StatusCode::UNAUTHORIZED, response.status());
    }

    #[test]
    fn should_produce_http_response_with_http_status_200_otherwise() {
        let given_request: Request<()> = Request::builder()
            .header("Authorization", "HEADER")
            .body(())
            .unwrap();

        let response = apply(given_request);

        assert_eq!(StatusCode::OK, response.status());
    }
}
