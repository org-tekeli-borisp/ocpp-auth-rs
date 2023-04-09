use http::{Request, Response, StatusCode};

fn apply(request: Request<()>) -> Response<()> {
    return Response::builder()
        .status(produce_status(request))
        .body(())
        .unwrap();
}

fn produce_status(request: Request<()>) -> StatusCode {
    return if request.headers().is_empty() {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::OK
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::type_name;

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
    fn should_produce_http_response_with_http_status_401_in_case_http_request_authorization_header_is_missing() {

    }
}
