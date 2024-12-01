use http::{Request, Response};

use crate::status::derive_status_from;

pub fn produce_response_for(request: Request<()>) -> Response<()> {
    Response::builder()
        .status(derive_status_from(request))
        .body(())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use super::*;
    use crate::specs::utils::type_of;

    #[test]
    fn should_consume_http_request_and_produce_http_response() {
        let given_request: Request<()> = Request::builder().body(()).unwrap();

        let response = produce_response_for(given_request);

        assert_eq!("http::response::Response<()>", type_of(&response));
    }

    #[test]
    fn should_produce_http_response_with_http_status_401_in_case_http_request_headers_are_empty() {
        let given_request: Request<()> = Request::builder().body(()).unwrap();

        let response = produce_response_for(given_request);

        assert_eq!(StatusCode::UNAUTHORIZED, response.status());
    }

    #[test]
    fn should_produce_http_response_with_http_status_401_in_case_http_request_authorization_header_is_missing(
    ) {
        let given_request: Request<()> = Request::builder()
            .header("OTHER", "HEADER")
            .body(())
            .unwrap();

        let response = produce_response_for(given_request);

        assert_eq!(StatusCode::UNAUTHORIZED, response.status());
    }

    #[test]
    fn should_produce_http_response_with_http_status_200_otherwise() {
        let given_request: Request<()> = Request::builder()
            .header("Authorization", "HEADER")
            .body(())
            .unwrap();

        let response = produce_response_for(given_request);

        assert_eq!(StatusCode::OK, response.status());
    }
}
