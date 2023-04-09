#[cfg(test)]
mod tests {
    use http::Request;

    #[test]
    fn should_consume_http_request_and_produce_http_response() {
        let _given_request: Request<()> = Request::builder().body(()).unwrap();
    }
}
