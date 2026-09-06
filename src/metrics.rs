use prometheus::{Encoder, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};

pub struct Metrics {
    registry: Registry,
    requests_total: IntCounterVec,
    known_stations: IntGauge,
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
        let metrics = Self {
            registry,
            requests_total,
            known_stations,
        };
        let _ = metrics.requests_total.with_label_values(&["success"]);
        let _ = metrics.requests_total.with_label_values(&["failure"]);
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

    pub fn render(&self, known_stations: usize) -> String {
        self.known_stations.set(known_stations as i64);
        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut buffer)
            .expect("encode metrics");
        String::from_utf8(buffer).expect("metrics are UTF-8")
    }
}
