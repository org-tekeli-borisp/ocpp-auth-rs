use http::Request;

use crate::response::produce_response_for;

mod authorize;
mod response;
mod status;
pub mod specs;

fn main() {
    println!("{:#?}", produce_response_for(given_request()));
}

fn given_request() -> Request<()> {
    let given_request: Request<()> = Request::builder()
        .header("Authorization", "HEADER")
        .body(())
        .unwrap();
    given_request
}
