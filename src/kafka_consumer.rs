use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use rdkafka::Message;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{BaseConsumer, Consumer};
use rdkafka::{Offset, TopicPartitionList};
use serde::Deserialize;
use tracing::{error, warn};

use crate::credentials::{AuthType, CredentialStore};
use crate::metrics::Metrics;

#[derive(Deserialize)]
struct StationCredentials {
    #[serde(rename = "authenticationType")]
    authentication_type: String,
    password: Option<String>,
}

/// Upper bound on the bcrypt cost factor accepted at ingestion. Verification
/// time doubles with every increment, so a faulty or compromised producer
/// publishing e.g. cost 31 would block a verification thread for minutes.
const MAX_BCRYPT_COST: u32 = 15;

/// True if `hash` is a syntactically valid bcrypt hash
/// (`$2$`/`$2a$`/`$2b$`/`$2y$` + two-digit cost + `$` + 53 salt+hash chars
/// from the bcrypt base64 alphabet) with a cost of at most
/// [`MAX_BCRYPT_COST`].
fn is_valid_bcrypt_hash(hash: &str) -> bool {
    let Some(rest) = ["$2$", "$2a$", "$2b$", "$2y$"]
        .into_iter()
        .find_map(|prefix| hash.strip_prefix(prefix))
    else {
        return false;
    };
    let Some((cost, salt_and_hash)) = rest.split_once('$') else {
        return false;
    };
    cost.len() == 2
        && cost.bytes().all(|byte| byte.is_ascii_digit())
        && cost
            .parse::<u32>()
            .is_ok_and(|cost| cost <= MAX_BCRYPT_COST)
        && salt_and_hash.len() == 53
        && salt_and_hash
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'/')
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
            Some(password_hash) if is_valid_bcrypt_hash(&password_hash) => {
                AuthType::Basic { password_hash }
            }
            Some(_) => {
                warn!(
                    station_id,
                    "skipping BASIC message with invalid password hash"
                );
                return;
            }
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

/// Starts a consumer thread that keeps `store` in sync with the compacted
/// topic. `ready` is set once the initial read of the topic has been applied,
/// `stop` requests the thread to finish its current poll cycle and return.
/// `metrics` records message freshness and poll errors for observability.
///
/// The consumer is a plain earliest reader: it stores and commits no offsets
/// and keeps no consumer-group state. On every start it assigns the topic's
/// partitions explicitly and replays them from offset 0, so the compacted
/// topic itself is the only durable state. Partitions are assigned once at
/// startup; adding partitions to the topic requires a service restart.
pub fn start(
    store: Arc<CredentialStore>,
    brokers: &str,
    topic: &str,
    ready: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    metrics: Arc<Metrics>,
) -> JoinHandle<()> {
    let brokers = brokers.to_owned();
    let topic = topic.to_owned();
    std::thread::spawn(move || {
        // librdkafka requires a consumer group for any partition assignment,
        // but none of the group's stateful features are used here, so the id
        // is an ephemeral per-instance name (see `ephemeral_group_id`).
        let group_id = ephemeral_group_id();
        let consumer: BaseConsumer = ClientConfig::new()
            .set("bootstrap.servers", brokers.as_str())
            .set("group.id", group_id.as_str())
            .create()
            .expect("create kafka consumer");
        assign_partitions(&consumer, &topic, &stop, &metrics);
        let mut last_offsets: HashMap<i32, i64> = HashMap::new();
        while !stop.load(Ordering::Relaxed) {
            match consumer.poll(Duration::from_millis(100)) {
                Some(Ok(message)) => {
                    metrics.record_kafka_message();
                    last_offsets.insert(message.partition(), message.offset());
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
                Some(Err(e)) => {
                    metrics.record_kafka_error();
                    error!(error = %e, "kafka poll failed");
                }
                None => {
                    if !ready.load(Ordering::Relaxed) && caught_up(&consumer, &topic, &last_offsets)
                    {
                        ready.store(true, Ordering::Relaxed);
                        tracing::info!(topic = topic.as_str(), "initial topic read complete");
                    }
                }
            }
        }
        tracing::info!("kafka consumer stopped");
    })
}

/// Ephemeral per-instance group id: process pid plus a sub-second nonce, so
/// concurrent or restarting instances never share a group. The group exists
/// only to satisfy librdkafka's assignment protocol; no offsets are ever
/// stored or committed under this name.
fn ephemeral_group_id() -> String {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    format!("ocpp-auth-rs-{:x}-{:x}", std::process::id(), nonce)
}

/// Assigns every partition of `topic` at offset 0, waiting for the topic to
/// appear in the cluster metadata. Returns without assigning when `stop` is
/// set, so a missing topic never blocks shutdown.
fn assign_partitions(consumer: &BaseConsumer, topic: &str, stop: &AtomicBool, metrics: &Metrics) {
    while !stop.load(Ordering::Relaxed) {
        match consumer.fetch_metadata(Some(topic), Duration::from_secs(5)) {
            Ok(metadata) => {
                let partitions: Vec<i32> = metadata
                    .topics()
                    .iter()
                    .filter(|topic_metadata| topic_metadata.name() == topic)
                    .flat_map(|topic_metadata| topic_metadata.partitions().iter().map(|p| p.id()))
                    .collect();
                if !partitions.is_empty() {
                    let mut assignment = TopicPartitionList::new();
                    for partition in partitions {
                        assignment
                            .add_partition_offset(topic, partition, Offset::Beginning)
                            .expect("add partition to assignment");
                    }
                    consumer
                        .assign(&assignment)
                        .expect("assign topic partitions");
                    return;
                }
            }
            Err(e) => {
                metrics.record_kafka_error();
                warn!(error = %e, topic, "kafka metadata fetch failed, retrying");
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// True once every assigned partition of `topic` has been consumed up to its
/// high watermark, i.e. the compacted topic state is fully present in the
/// store. An empty assignment (the topic is not visible in the cluster yet)
/// is not ready; an empty topic is, since there is no state left to apply.
fn caught_up(consumer: &BaseConsumer, topic: &str, last_offsets: &HashMap<i32, i64>) -> bool {
    let Ok(assignment) = consumer.assignment() else {
        return false;
    };
    let partitions: Vec<i32> = assignment
        .elements()
        .iter()
        .filter(|element| element.topic() == topic)
        .map(|element| element.partition())
        .collect();
    !partitions.is_empty()
        && partitions.into_iter().all(|partition| {
            let Ok((_low, high)) =
                consumer.fetch_watermarks(topic, partition, Duration::from_secs(1))
            else {
                return false;
            };
            match last_offsets.get(&partition) {
                Some(&offset) => offset >= high - 1,
                None => high <= 0,
            }
        })
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
    fn should_skip_basic_with_password_hash_above_max_cost() {
        let store = given_store();
        let password_hash = format!("$2b${:02}{}", MAX_BCRYPT_COST + 1, "C".repeat(53));
        let value = given_basic_value(&password_hash);

        apply_message(&store, "AL1000", Some(value.as_bytes()));

        assert!(!store.contains("AL1000"));
    }

    #[test]
    fn should_skip_basic_with_malformed_password_hash() {
        let store = given_store();
        let value = given_basic_value("not-a-hash");

        apply_message(&store, "AL1000", Some(value.as_bytes()));

        assert!(!store.contains("AL1000"));
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
