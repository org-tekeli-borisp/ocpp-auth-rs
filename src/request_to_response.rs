use http::{Request, Response};

fn apply(_request: Request<()>) -> Response<()> {
    return Response::builder().body(()).unwrap();
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
}