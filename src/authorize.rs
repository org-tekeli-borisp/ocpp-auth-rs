use http::Request;

pub fn authorization_failed(request: Request<()>) -> bool {
    request.headers().is_empty() || request.headers().get("Authorization").is_none()
}

#[cfg(test)]
mod tests {
    use std::any::type_name;

    use super::*;

    fn type_of<T>(_: &T) -> &str {
        return type_name::<T>();
    }

    #[test]
    fn should_consume_http_request_and_produce_bool() {
        let given_request: Request<()> = Request::builder().body(()).unwrap();

        let result = authorization_failed(given_request);

        assert_eq!("bool", type_of(&result));
    }

    #[test]
    fn should_produce_true_in_case_http_request_headers_are_empty() {
        let given_request: Request<()> = Request::builder().body(()).unwrap();

        let result = authorization_failed(given_request);

        assert_eq!(true, result);
    }

    #[test]
    fn should_produce_true_in_case_http_request_authorization_header_is_missing() {
        let given_request: Request<()> = Request::builder()
            .header("OTHER", "HEADER")
            .body(())
            .unwrap();

        let result = authorization_failed(given_request);

        assert_eq!(true, result);
    }

    #[test]
    fn should_produce_false_otherwise() {
        let given_request: Request<()> = Request::builder()
            .header("Authorization", "HEADER")
            .body(())
            .unwrap();

        let result = authorization_failed(given_request);

        assert_eq!(false, result);
    }
}
