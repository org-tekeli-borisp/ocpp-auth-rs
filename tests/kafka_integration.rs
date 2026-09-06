use std::sync::Arc;
use std::time::{Duration, Instant};

use ocpp_auth_rs::credentials::CredentialStore;
use ocpp_auth_rs::kafka_consumer;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{BaseProducer, BaseRecord, Producer};
use testcontainers::runners::SyncRunner;
use testcontainers_modules::kafka::apache::Kafka;

const TOPIC: &str = "ocpp-auth-stations";

fn produce(brokers: &str, key: &str, value: Option<&str>) {
    let producer: BaseProducer = ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .create()
        .expect("create kafka producer");
    let mut record = BaseRecord::to(TOPIC).key(key);
    if let Some(value) = value {
        record = record.payload(value);
    }
    producer.send(record).expect("send message");
    producer
        .flush(Duration::from_secs(10))
        .expect("deliver message");
}

fn wait_until(timeout: Duration, description: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "timed out after {timeout:?} waiting for {description}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn store_should_be_populated_from_compacted_topic_and_track_live_updates() {
    let container = Kafka::default().start().expect("start kafka container");
    let host = container.get_host().expect("get container host");
    let port = container
        .get_host_port_ipv4(9092)
        .expect("get mapped kafka port");
    let broker = format!("{host}:{port}");

    let password_a = b"password-a";
    let hash_a = bcrypt::hash(password_a, 10).unwrap();
    produce(
        &broker,
        "A",
        Some(&format!(
            r#"{{"authenticationType":"BASIC","password":"{hash_a}"}}"#
        )),
    );
    produce(&broker, "B", Some(r#"{"authenticationType":"NONE"}"#));
    produce(&broker, "C", Some(r#"{"authenticationType":"FORBIDDEN"}"#));
    produce(&broker, "A", None);

    let store = Arc::new(CredentialStore::new());
    kafka_consumer::start(store.clone(), &broker, TOPIC);

    wait_until(
        Duration::from_secs(30),
        "A to be removed by its tombstone while B and C are present",
        || !store.contains("A") && store.contains("B") && store.contains("C"),
    );
    assert!(
        !store.verify("A", "A", password_a),
        "station A should be absent after its tombstone"
    );
    assert!(
        !store.verify("B", "B", b"anything"),
        "station B should be NoAuth and reject all passwords"
    );
    assert!(
        !store.verify("C", "C", b"anything"),
        "station C should be Forbidden and reject all passwords"
    );

    let password_d = b"password-d";
    let hash_d = bcrypt::hash(password_d, 10).unwrap();
    produce(
        &broker,
        "D",
        Some(&format!(
            r#"{{"authenticationType":"BASIC","password":"{hash_d}"}}"#
        )),
    );

    wait_until(
        Duration::from_secs(30),
        "live update for station D to be applied",
        || store.verify("D", "D", password_d),
    );
    assert!(
        store.verify("D", "D", password_d),
        "station D should be Basic and accept its password"
    );
}
