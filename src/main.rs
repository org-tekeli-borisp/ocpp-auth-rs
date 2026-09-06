mod basic_auth;
mod credentials;
mod server;

use std::net::SocketAddr;
use std::sync::Arc;

use credentials::CredentialStore;
use server::app;

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind listener");

    println!("ocpp-auth-rs listening on http://{addr}");

    axum::serve(listener, app(Arc::new(load_store())))
        .await
        .expect("serve");
}

fn load_store() -> CredentialStore {
    let spec = std::env::var("OCPP_CREDENTIALS").unwrap_or_default();
    parse_credentials(&spec)
}

fn parse_credentials(spec: &str) -> CredentialStore {
    let store = CredentialStore::new();
    for entry in spec.split(',').filter(|entry| !entry.is_empty()) {
        let (charge_point_id, hex_key) = entry.split_once(':').unwrap_or_else(|| {
            panic!("OCPP_CREDENTIALS entry must be <charge_point_id>:<40 hex characters>")
        });
        let key = decode_hex(charge_point_id, hex_key);
        store.insert(charge_point_id, &key);
    }
    store
}

fn decode_hex(charge_point_id: &str, hex_key: &str) -> Vec<u8> {
    if hex_key.len() != 40 {
        panic!(
            "OCPP_CREDENTIALS: key for charge point '{charge_point_id}' must be 40 hex characters (20 bytes), got {} characters",
            hex_key.len()
        );
    }
    if !hex_key
        .chars()
        .all(|character| character.is_ascii_hexdigit())
    {
        panic!("OCPP_CREDENTIALS: key for charge point '{charge_point_id}' is not valid hex");
    }
    hex_key
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn given_key() -> Vec<u8> {
        (0..20).collect()
    }

    #[test]
    fn should_seed_store_from_single_entry() {
        let given_spec = "AL1000:000102030405060708090a0b0c0d0e0f10111213";

        let store = parse_credentials(given_spec);

        assert!(store.verify("AL1000", &given_key()));
    }

    #[test]
    fn should_seed_store_from_multiple_entries() {
        let given_spec = "AL1000:000102030405060708090a0b0c0d0e0f10111213,BB2000:101112131415161718191a1b1c1d1e1f20212223";

        let store = parse_credentials(given_spec);

        assert!(store.verify("AL1000", &given_key()));
        assert!(store.verify("BB2000", &(16..36).collect::<Vec<u8>>()));
    }

    #[test]
    fn should_produce_empty_store_for_empty_spec() {
        let given_spec = "";

        let store = parse_credentials(given_spec);

        assert!(!store.verify("AL1000", &given_key()));
    }

    #[test]
    #[should_panic(expected = "not valid hex")]
    fn should_panic_for_malformed_hex_key() {
        parse_credentials("AL1000:000102030405060708090a0b0c0d0e0f1011121g");
    }

    #[test]
    #[should_panic(expected = "must be 40 hex characters")]
    fn should_panic_for_wrong_key_length() {
        parse_credentials("AL1000:000102030405060708090a0b0c0d0e0f101112");
    }
}
