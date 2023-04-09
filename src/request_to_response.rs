use http::{Request, Response};

fn apply(_request: Request<()>) -> Response<()> {
    return Response::builder().body(()).unwrap();
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_consume_http_request_and_produce_http_response() {
        let given_request: Request<()> = Request::builder().body(()).unwrap();

        let _response = apply(given_request);
    }
}