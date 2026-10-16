use prometheus::{Encoder, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};

pub struct Metrics {
    registry: Registry,
    requests_total: IntCounterVec,
    known_stations: IntGauge,
    kafka_last_message_timestamp_seconds: IntGauge,
    kafka_errors_total: IntCounter,
}

impl Default for Metrics {
    fn default() -> Self {
        let registry = Registry::new();
        let requests_total = IntCounterVec::new(
            Opts::new(
                "ocpp_auth_requests_total",
                "Total number of auth requests, by result.",
            ),
            &["result"],
        )
        .expect("create ocpp_auth_requests counter");
        registry
            .register(Box::new(requests_total.clone()))
            .expect("register ocpp_auth_requests counter");
        let known_stations = IntGauge::new(
            "ocpp_auth_known_stations",
            "Number of stations currently present in the credential store.",
        )
        .expect("create ocpp_auth_known_stations gauge");
        registry
            .register(Box::new(known_stations.clone()))
            .expect("register ocpp_auth_known_stations gauge");
        let kafka_last_message_timestamp_seconds = IntGauge::new(
            "ocpp_auth_kafka_last_message_timestamp_seconds",
            "Unix timestamp in seconds of the last successfully consumed Kafka message. \
             Only advances when messages arrive, so a compacted topic with no changes \
             legitimately leaves this value old.",
        )
        .expect("create ocpp_auth_kafka_last_message_timestamp gauge");
        registry
            .register(Box::new(kafka_last_message_timestamp_seconds.clone()))
            .expect("register ocpp_auth_kafka_last_message_timestamp gauge");
        let kafka_errors_total = IntCounter::new(
            "ocpp_auth_kafka_errors_total",
            "Total number of Kafka poll errors.",
        )
        .expect("create ocpp_auth_kafka_errors counter");
        registry
            .register(Box::new(kafka_errors_total.clone()))
            .expect("register ocpp_auth_kafka_errors counter");
        let metrics = Self {
            registry,
            requests_total,
            known_stations,
            kafka_last_message_timestamp_seconds,
            kafka_errors_total,
        };
        let _ = metrics.requests_total.with_label_values(&["success"]);
        let _ = metrics.requests_total.with_label_values(&["failure"]);
        let _ = metrics.requests_total.with_label_values(&["rate_limited"]);
        metrics
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, success: bool) {
        let result = if success { "success" } else { "failure" };
        self.requests_total.with_label_values(&[result]).inc();
    }

    pub fn record_rate_limited(&self) {
        self.requests_total
            .with_label_values(&["rate_limited"])
            .inc();
    }

    pub fn record_kafka_message(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is past the unix epoch")
            .as_secs();
        self.kafka_last_message_timestamp_seconds.set(now as i64);
    }

    pub fn record_kafka_error(&self) {
        self.kafka_errors_total.inc();
    }

    pub fn render(&self, known_stations: usize) -> String {
        self.known_stations.set(known_stations as i64);
        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut buffer)
            .expect("encode metrics");
        String::from_utf8(buffer).expect("metrics are UTF-8")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn given_rendered_value(metrics: &Metrics, name: &str) -> i64 {
        metrics
            .render(0)
            .lines()
            .find_map(|line| {
                line.strip_prefix(&format!("{name} "))
                    .and_then(|value| value.trim().parse::<i64>().ok())
            })
            .unwrap_or_else(|| panic!("{name} missing from rendered metrics"))
    }

    #[test]
    fn should_render_zero_kafka_metrics_initially() {
        let metrics = Metrics::new();

        assert_eq!(
            given_rendered_value(&metrics, "ocpp_auth_kafka_last_message_timestamp_seconds"),
            0
        );
        assert_eq!(
            given_rendered_value(&metrics, "ocpp_auth_kafka_errors_total"),
            0
        );
    }

    #[test]
    fn should_record_kafka_message_timestamp_near_now() {
        let metrics = Metrics::new();

        metrics.record_kafka_message();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is past the unix epoch")
            .as_secs() as i64;
        let timestamp =
            given_rendered_value(&metrics, "ocpp_auth_kafka_last_message_timestamp_seconds");
        assert!((now - 5..=now + 1).contains(&timestamp));
    }

    #[test]
    fn should_count_kafka_errors() {
        let metrics = Metrics::new();

        metrics.record_kafka_error();
        metrics.record_kafka_error();

        assert_eq!(
            given_rendered_value(&metrics, "ocpp_auth_kafka_errors_total"),
            2
        );
    }
}
