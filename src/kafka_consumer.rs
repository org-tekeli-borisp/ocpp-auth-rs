use std::sync::Arc;
use std::time::Duration;

use rdkafka::Message;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{BaseConsumer, Consumer};
use serde::Deserialize;
use tracing::{error, warn};

use crate::credentials::{AuthType, CredentialStore};

#[derive(Deserialize)]
struct StationCredentials {
    #[serde(rename = "authenticationType")]
    authentication_type: String,
    password: Option<String>,
}

pub fn apply_message(store: &CredentialStore, station_id: &str, value: Option<&[u8]>) {
    let Some(value) = value else {
        store.remove(station_id);
        return;
    };
    let Ok(parsed) = serde_json::from_slice::<StationCredentials>(value) else {
        warn!(station_id, "skipping message with invalid JSON");
        return;
    };
    let auth = match parsed.authentication_type.as_str() {
        "NONE" => AuthType::NoAuth,
        "FORBIDDEN" => AuthType::Forbidden,
        "BASIC" => match parsed.password {
            Some(password_hash) => AuthType::Basic { password_hash },
            None => {
                warn!(station_id, "skipping BASIC message without password");
                return;
            }
        },
        other => {
            warn!(
                station_id,
                authentication_type = other,
                "skipping message with unknown authenticationType"
            );
            return;
        }
    };
    store.upsert(station_id, auth);
}

pub fn start(store: Arc<CredentialStore>, brokers: &str, topic: &str) {
    let brokers = brokers.to_owned();
    let topic = topic.to_owned();
    std::thread::spawn(move || {
        let consumer: BaseConsumer = ClientConfig::new()
            .set("bootstrap.servers", brokers.as_str())
            .set("group.id", "ocpp-auth-rs")
            .set("auto.offset.reset", "earliest")
            .set("enable.auto.offset.store", "false")
            .create()
            .expect("create kafka consumer");
        consumer
            .subscribe(&[topic.as_str()])
            .expect("subscribe to topic");
        loop {
            match consumer.poll(Duration::from_millis(100)) {
                Some(Ok(message)) => {
                    let Some(key) = message.key() else {
                        warn!("skipping message without key");
                        continue;
                    };
                    let Ok(station_id) = std::str::from_utf8(key) else {
                        warn!("skipping message with non-UTF-8 key");
                        continue;
                    };
                    apply_message(&store, station_id, message.payload());
                }
                Some(Err(e)) => error!(error = %e, "kafka poll failed"),
                None => continue,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn given_store() -> CredentialStore {
        CredentialStore::new()
    }

    fn given_basic_value(password: &str) -> String {
        format!(r#"{{"authenticationType":"BASIC","password":"{password}"}}"#)
    }

    #[test]
    fn should_apply_none_as_no_auth() {
        let store = given_store();
        let value = br#"{"authenticationType":"NONE"}"#;

        apply_message(&store, "AL1000", Some(value));

        assert!(!store.verify("AL1000", "AL1000", b"anything"));
    }

    #[test]
    fn should_apply_forbidden() {
        let store = given_store();
        let value = br#"{"authenticationType":"FORBIDDEN"}"#;

        apply_message(&store, "AL1000", Some(value));

        assert!(!store.verify("AL1000", "AL1000", b"anything"));
    }

    #[test]
    fn should_apply_basic_with_password() {
        let store = given_store();
        let password = b"correct horse battery staple";
        let password_hash = bcrypt::hash(password, 10).unwrap();
        let value = given_basic_value(&password_hash);

        apply_message(&store, "AL1000", Some(value.as_bytes()));

        assert!(store.verify("AL1000", "AL1000", password));
    }

    #[test]
    fn should_skip_basic_without_password() {
        let store = given_store();
        let value = br#"{"authenticationType":"BASIC"}"#;

        apply_message(&store, "AL1000", Some(value));

        assert!(!store.verify("AL1000", "AL1000", b"anything"));
    }

    #[test]
    fn should_skip_unknown_authentication_type() {
        let store = given_store();
        let value = br#"{"authenticationType":"WEIRD"}"#;

        apply_message(&store, "AL1000", Some(value));

        assert!(!store.verify("AL1000", "AL1000", b"anything"));
    }

    #[test]
    fn should_skip_invalid_json() {
        let store = given_store();

        apply_message(&store, "AL1000", Some(b"not-json"));

        assert!(!store.verify("AL1000", "AL1000", b"anything"));
    }

    #[test]
    fn should_remove_station_on_tombstone() {
        let store = given_store();
        let password = b"secret";
        let password_hash = bcrypt::hash(password, 10).unwrap();
        let value = given_basic_value(&password_hash);
        apply_message(&store, "AL1000", Some(value.as_bytes()));
        assert!(store.verify("AL1000", "AL1000", password));

        apply_message(&store, "AL1000", None);

        assert!(!store.verify("AL1000", "AL1000", password));
    }
}
