use http::Request;

use crate::response::produce_response_for;

mod authorize;
mod response;
mod status;

fn main() {
    let given_request: Request<()> = Request::builder()
        .header("Authorization", "HEADER")
        .body(())
        .unwrap();

    let response = produce_response_for(given_request);

    println!("{:#?}", response);
}
