use http::{Request, StatusCode};

use crate::authorize::authorization_failed_for;

pub fn derive_status_from(request: Request<()>) -> StatusCode {
    return match authorization_failed_for(request) {
        true => StatusCode::UNAUTHORIZED,
        false => StatusCode::OK,
    };
}

#[cfg(test)]
mod tests {
    use std::any::type_name;

    use super::*;

    fn type_of<T>(_: &T) -> &str {
        return type_name::<T>();
    }

    #[test]
    fn should_consume_http_request_and_produce_status_code() {
        let given_request: Request<()> = Request::builder().body(()).unwrap();

        let status = derive_status_from(given_request);

        assert_eq!("http::status::StatusCode", type_of(&status));
    }

    #[test]
    fn should_produce_status_code_401_in_case_http_request_headers_are_empty() {
        let given_request: Request<()> = Request::builder().body(()).unwrap();

        let status = derive_status_from(given_request);

        assert_eq!(StatusCode::UNAUTHORIZED, status);
    }

    #[test]
    fn should_produce_status_code_401_in_case_http_request_authorization_header_is_missing() {
        let given_request: Request<()> = Request::builder()
            .header("OTHER", "HEADER")
            .body(())
            .unwrap();

        let status = derive_status_from(given_request);

        assert_eq!(StatusCode::UNAUTHORIZED, status);
    }

    #[test]
    fn should_produce_status_code_200_otherwise() {
        let given_request: Request<()> = Request::builder()
            .header("Authorization", "HEADER")
            .body(())
            .unwrap();

        let status = derive_status_from(given_request);

        assert_eq!(StatusCode::OK, status);
    }
}
