use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};

pub struct Metrics {
    registry: Registry,
    requests_total: IntCounterVec,
    known_stations: IntGauge,
    verify_duration_seconds: Histogram,
    bcrypt_permits_available: IntGauge,
    kafka_last_message_timestamp_seconds: IntGauge,
    kafka_errors_total: IntCounter,
    kafka_consumer_up: IntGauge,
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
        // f64 histogram (not IntHistogram, whose observe only takes integers) so
        // durations can be observed directly in seconds.
        let verify_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "ocpp_auth_verify_duration_seconds",
                "Duration of one credential verification in seconds.",
            )
            .buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]),
        )
        .expect("create ocpp_auth_verify_duration histogram");
        registry
            .register(Box::new(verify_duration_seconds.clone()))
            .expect("register ocpp_auth_verify_duration histogram");
        let bcrypt_permits_available = IntGauge::new(
            "ocpp_auth_bcrypt_permits_available",
            "Number of bcrypt permits currently free; near zero means the bcrypt pool is saturated.",
        )
        .expect("create ocpp_auth_bcrypt_permits_available gauge");
        registry
            .register(Box::new(bcrypt_permits_available.clone()))
            .expect("register ocpp_auth_bcrypt_permits_available gauge");
        let kafka_consumer_up = IntGauge::new(
            "ocpp_auth_kafka_consumer_up",
            "1 while a kafka consumer cycle is running, 0 otherwise.",
        )
        .expect("create ocpp_auth_kafka_consumer_up gauge");
        registry
            .register(Box::new(kafka_consumer_up.clone()))
            .expect("register ocpp_auth_kafka_consumer_up gauge");
        let metrics = Self {
            registry,
            requests_total,
            known_stations,
            verify_duration_seconds,
            bcrypt_permits_available,
            kafka_last_message_timestamp_seconds,
            kafka_errors_total,
            kafka_consumer_up,
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

    pub fn observe_verify(&self, seconds: f64) {
        self.verify_duration_seconds.observe(seconds);
    }

    pub fn set_kafka_consumer_up(&self, up: bool) {
        self.kafka_consumer_up.set(if up { 1 } else { 0 });
    }

    pub fn render(&self, known_stations: usize, bcrypt_permits_available: usize) -> String {
        self.known_stations.set(known_stations as i64);
        self.bcrypt_permits_available
            .set(bcrypt_permits_available as i64);
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
            .render(0, 0)
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

    #[test]
    fn should_render_new_metric_names() {
        let metrics = Metrics::new();

        let rendered = metrics.render(0, 0);
        // A histogram renders as _count/_sum/_bucket families, never as a
        // bare name, so match the count series.
        assert!(rendered.contains("ocpp_auth_verify_duration_seconds_count"));
        assert!(rendered.contains("ocpp_auth_bcrypt_permits_available"));
        assert!(rendered.contains("ocpp_auth_kafka_consumer_up"));
    }

    #[test]
    fn should_report_bcrypt_permits_available_from_render_argument() {
        let metrics = Metrics::new();

        assert!(
            metrics
                .render(0, 8)
                .contains("ocpp_auth_bcrypt_permits_available 8")
        );
    }

    #[test]
    fn should_set_kafka_consumer_up_flag() {
        let metrics = Metrics::new();

        assert_eq!(
            given_rendered_value(&metrics, "ocpp_auth_kafka_consumer_up"),
            0
        );

        metrics.set_kafka_consumer_up(true);
        assert_eq!(
            given_rendered_value(&metrics, "ocpp_auth_kafka_consumer_up"),
            1
        );

        metrics.set_kafka_consumer_up(false);
        assert_eq!(
            given_rendered_value(&metrics, "ocpp_auth_kafka_consumer_up"),
            0
        );
    }
}
