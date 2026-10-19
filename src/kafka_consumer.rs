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

use crate::credentials::{AuthType, BCRYPT_COST, CredentialStore};
use crate::metrics::Metrics;

#[derive(Deserialize)]
struct StationCredentials {
    #[serde(rename = "authenticationType")]
    authentication_type: String,
    password: Option<String>,
}

/// The bcrypt cost factor encoded in `hash`, or `None` if `hash` is not a
/// syntactically valid bcrypt hash (`$2$`/`$2a$`/`$2b$`/`$2y$` + two-digit
/// cost + `$` + 53 salt+hash chars from the bcrypt base64 alphabet).
fn bcrypt_hash_cost(hash: &str) -> Option<u32> {
    let rest = ["$2$", "$2a$", "$2b$", "$2y$"]
        .into_iter()
        .find_map(|prefix| hash.strip_prefix(prefix))?;
    let (cost, salt_and_hash) = rest.split_once('$')?;
    let valid = cost.len() == 2
        && cost.bytes().all(|byte| byte.is_ascii_digit())
        && salt_and_hash.len() == 53
        && salt_and_hash
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'/');
    valid.then(|| cost.parse::<u32>().ok()).flatten()
}

/// True if `hash` is a syntactically valid bcrypt hash with exactly the
/// accepted cost [`BCRYPT_COST`]. Only this single cost is accepted so that
/// every stored credential verifies in the same time as the dummy hash used
/// to equalise the rejection paths; otherwise a known station stored at a
/// higher cost would answer measurably slower than an unknown one, and a
/// lower cost would needlessly weaken the stored credential.
fn is_valid_bcrypt_hash(hash: &str) -> bool {
    bcrypt_hash_cost(hash).is_some_and(|cost| cost == BCRYPT_COST)
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
            Some(password_hash) => {
                match bcrypt_hash_cost(&password_hash) {
                    Some(cost) => warn!(
                        station_id,
                        cost, "skipping BASIC message with bcrypt cost other than {BCRYPT_COST}"
                    ),
                    None => {
                        warn!(
                            station_id,
                            "skipping BASIC message with invalid password hash"
                        );
                    }
                }
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

/// Starts a supervised consumer thread that keeps `store` in sync with the
/// compacted topic. `ready` is set once the initial read of the topic has been
/// applied, `stop` requests the thread to finish its current poll cycle and
/// return. `metrics` records message freshness and poll errors for
/// observability.
///
/// The consumer runs in supervised cycles (see [`supervise`]): a cycle that
/// fails or panics — e.g. while creating the consumer or assigning partitions
/// — is logged and restarted after a short backoff, until `stop` is set. A
/// restart never resets `ready`, so the service keeps serving the last known
/// state while a new cycle catches up.
///
/// Each cycle is a plain earliest reader: it stores and commits no offsets
/// and keeps no consumer-group state. On every start it assigns the topic's
/// partitions explicitly and replays them from offset 0, so the compacted
/// topic itself is the only durable state. Partitions are assigned at the
/// start of each cycle, so a partition added to the topic is picked up no
/// later than the next (possibly automatic) cycle restart.
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
        supervise(&stop, Duration::from_secs(1), std::thread::sleep, || {
            run_cycle(&store, &brokers, &topic, &ready, &stop, &metrics)
        });
        tracing::info!("kafka consumer stopped");
    })
}

/// Runs `cycle` repeatedly until `stop` is set. Every cycle is panic-isolated:
/// a panicking cycle is logged and restarted after `cycle_backoff`, so a
/// transient failure (unreachable broker, topic metadata hiccup) inside the
/// cycle cannot silently kill the consumer thread. A cycle that returns
/// without `stop` being set should not happen, but is restarted with the same
/// backoff, defensively. `backoff_sleep` abstracts the wait so tests do not
/// have to sleep.
fn supervise(
    stop: &AtomicBool,
    cycle_backoff: Duration,
    backoff_sleep: impl Fn(Duration),
    cycle: impl Fn(),
) {
    while !stop.load(Ordering::Relaxed) {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(&cycle)) {
            Ok(()) => {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                warn!("kafka consumer cycle finished unexpectedly, restarting");
                backoff_sleep(cycle_backoff);
            }
            Err(payload) => {
                let reason = payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "(unknown panic payload)".to_owned());
                error!(panic = %reason, "kafka consumer cycle panicked, restarting");
                backoff_sleep(cycle_backoff);
            }
        }
    }
}

/// Runs one consumer cycle: create the consumer, assign the topic's partitions
/// and poll until `stop` is set. Setup failures panic on purpose — [`supervise`]
/// catches the panic and starts a fresh cycle after the backoff. Sets `ready`
/// once the initial read of the topic has been applied, but never resets it, so
/// a restart cannot make an already-serving service unready again.
fn run_cycle(
    store: &Arc<CredentialStore>,
    brokers: &str,
    topic: &str,
    ready: &Arc<AtomicBool>,
    stop: &Arc<AtomicBool>,
    metrics: &Arc<Metrics>,
) {
    // librdkafka requires a consumer group for any partition assignment,
    // but none of the group's stateful features are used here, so the id
    // is an ephemeral per-cycle name (see `ephemeral_group_id`).
    let group_id = ephemeral_group_id();
    let consumer: BaseConsumer = ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .set("group.id", group_id.as_str())
        .create()
        .expect("create kafka consumer");
    assign_partitions(&consumer, topic, stop, metrics);
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
                apply_message(store, station_id, message.payload());
            }
            Some(Err(e)) => {
                metrics.record_kafka_error();
                error!(error = %e, "kafka poll failed");
            }
            None => {
                if !ready.load(Ordering::Relaxed) && caught_up(&consumer, topic, &last_offsets) {
                    ready.store(true, Ordering::Relaxed);
                    tracing::info!(topic, "initial topic read complete");
                }
            }
        }
    }
}

/// Ephemeral per-cycle group id: process pid plus a sub-second nonce, so
/// concurrent instances or successive cycles never share a group. The group exists
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
    use std::sync::atomic::AtomicUsize;

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
    fn should_skip_basic_with_password_hash_above_accepted_cost() {
        let store = given_store();
        let password_hash = format!("$2b${:02}{}", BCRYPT_COST + 2, "C".repeat(53));
        let value = given_basic_value(&password_hash);

        apply_message(&store, "AL1000", Some(value.as_bytes()));

        assert!(!store.contains("AL1000"));
    }

    #[test]
    fn should_skip_basic_with_password_hash_below_accepted_cost() {
        let store = given_store();
        let password_hash = format!("$2b${:02}{}", BCRYPT_COST - 6, "C".repeat(53));
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

    #[test]
    fn should_restart_the_cycle_after_a_panic() {
        let stop = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let counting = Arc::clone(&calls);
        let cycle_stop = Arc::clone(&stop);

        supervise(
            &stop,
            Duration::ZERO,
            |_| {},
            move || {
                // The panic message ends up in the error log only.
                if counting.fetch_add(1, Ordering::Relaxed) < 2 {
                    panic!("simulated cycle failure");
                }
                cycle_stop.store(true, Ordering::Relaxed);
            },
        );

        assert_eq!(calls.load(Ordering::Relaxed), 3);
        assert!(stop.load(Ordering::Relaxed));
    }

    #[test]
    fn should_stop_supervising_when_stop_is_already_set() {
        let stop = AtomicBool::new(true);
        let calls = AtomicUsize::new(0);

        supervise(
            &stop,
            Duration::ZERO,
            |_| {},
            || {
                calls.fetch_add(1, Ordering::Relaxed);
            },
        );

        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn should_not_restart_a_cleanly_finished_cycle_while_stopped() {
        let stop = AtomicBool::new(false);
        let calls = AtomicUsize::new(0);

        supervise(
            &stop,
            Duration::ZERO,
            |_| {},
            || {
                calls.fetch_add(1, Ordering::Relaxed);
                stop.store(true, Ordering::Relaxed);
            },
        );

        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}
