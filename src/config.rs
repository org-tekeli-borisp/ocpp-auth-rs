//! Environment-driven configuration, parsed and validated once at startup.
//!
//! [`Config::from_env`] reads the following variables:
//!
//! - `PORT`: port the forward-auth endpoint listens on (default `8080`).
//! - `ADMIN_PORT`: port the health and metrics endpoints listen on (default `8081`).
//! - `KAFKA_BROKERS`: comma-separated Kafka bootstrap servers (required, non-empty).
//! - `OCPP_AUTH_TOPIC`: Kafka topic carrying credential updates (required, non-empty).
//! - `RATE_LIMIT_PER_SECOND`: auth tokens refilled per second per station (default `2.0`).
//! - `RATE_LIMIT_BURST`: auth token bucket capacity per station (default `10.0`,
//!   must be at least `1.0` or every request would be rejected).
//! - `RATE_LIMIT_IP_PER_SECOND`: auth tokens refilled per second per client IP
//!   (default `20.0`).
//! - `RATE_LIMIT_IP_BURST`: auth token bucket capacity per client IP (default `50.0`,
//!   must be at least `1.0` or every request would be rejected).
//! - `BCRYPT_CONCURRENCY`: simultaneous bcrypt verifications (default: the
//!   machine's parallelism, at least `1`).

/// Port the forward-auth endpoint listens on unless `PORT` says otherwise.
const DEFAULT_PORT: u16 = 8080;
/// Port the admin endpoints listen on unless `ADMIN_PORT` says otherwise.
const DEFAULT_ADMIN_PORT: u16 = 8081;
/// Auth token refill rate unless `RATE_LIMIT_PER_SECOND` says otherwise.
const DEFAULT_RATE_LIMIT_PER_SECOND: f64 = 2.0;
/// Auth token bucket capacity unless `RATE_LIMIT_BURST` says otherwise.
const DEFAULT_RATE_LIMIT_BURST: f64 = 10.0;
/// Per-IP auth token refill rate unless `RATE_LIMIT_IP_PER_SECOND` says otherwise.
const DEFAULT_RATE_LIMIT_IP_PER_SECOND: f64 = 20.0;
/// Per-IP auth token bucket capacity unless `RATE_LIMIT_IP_BURST` says otherwise.
const DEFAULT_RATE_LIMIT_IP_BURST: f64 = 50.0;

/// All runtime settings, sourced from the environment.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub port: u16,
    pub admin_port: u16,
    pub kafka_brokers: String,
    pub kafka_topic: String,
    pub rate_limit_per_second: f64,
    pub rate_limit_burst: f64,
    pub rate_limit_ip_per_second: f64,
    pub rate_limit_ip_burst: f64,
    pub bcrypt_permits: usize,
}

impl Config {
    /// Reads configuration from the process environment.
    pub fn from_env() -> Result<Config, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Parses configuration from an arbitrary lookup so tests can supply a
    /// fake environment without mutating the process one.
    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Config, String> {
        let required = |name: &str| match lookup(name) {
            Some(value) if !value.is_empty() => Ok(value),
            _ => Err(format!("{name} environment variable is required")),
        };
        let port = |name: &str, default: u16| match lookup(name) {
            Some(value) => value
                .parse::<u16>()
                .map_err(|_| format!("{name} must be a valid port number")),
            None => Ok(default),
        };
        let rate = |name: &str, default: f64| -> Result<f64, String> {
            match lookup(name) {
                Some(value) => {
                    let parsed = value
                        .parse::<f64>()
                        .map_err(|_| format!("{name} must be a non-negative number"))?;
                    if parsed.is_finite() && parsed >= 0.0 {
                        Ok(parsed)
                    } else {
                        Err(format!("{name} must be a non-negative number"))
                    }
                }
                None => Ok(default),
            }
        };
        let permits = || -> Result<usize, String> {
            match lookup("BCRYPT_CONCURRENCY") {
                Some(value) => {
                    let parsed = value.parse::<usize>().map_err(|_| {
                        "BCRYPT_CONCURRENCY must be a positive whole number".to_string()
                    })?;
                    if parsed == 0 {
                        Err("BCRYPT_CONCURRENCY must be a positive whole number".to_string())
                    } else {
                        Ok(parsed)
                    }
                }
                None => Ok(default_bcrypt_permits()),
            }
        };

        let rate_limit_burst = rate("RATE_LIMIT_BURST", DEFAULT_RATE_LIMIT_BURST)?;
        if rate_limit_burst < 1.0 {
            return Err("RATE_LIMIT_BURST must be at least 1.0".to_string());
        }
        let rate_limit_ip_burst = rate("RATE_LIMIT_IP_BURST", DEFAULT_RATE_LIMIT_IP_BURST)?;
        if rate_limit_ip_burst < 1.0 {
            return Err("RATE_LIMIT_IP_BURST must be at least 1.0".to_string());
        }

        Ok(Config {
            port: port("PORT", DEFAULT_PORT)?,
            admin_port: port("ADMIN_PORT", DEFAULT_ADMIN_PORT)?,
            kafka_brokers: required("KAFKA_BROKERS")?,
            kafka_topic: required("OCPP_AUTH_TOPIC")?,
            rate_limit_per_second: rate("RATE_LIMIT_PER_SECOND", DEFAULT_RATE_LIMIT_PER_SECOND)?,
            rate_limit_burst,
            rate_limit_ip_per_second: rate(
                "RATE_LIMIT_IP_PER_SECOND",
                DEFAULT_RATE_LIMIT_IP_PER_SECOND,
            )?,
            rate_limit_ip_burst,
            bcrypt_permits: permits()?,
        })
    }
}

fn default_bcrypt_permits() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn given_env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    fn given_required_env() -> HashMap<String, String> {
        given_env(&[
            ("KAFKA_BROKERS", "kafka:9092"),
            ("OCPP_AUTH_TOPIC", "ocpp-auth-stations"),
        ])
    }

    fn given_config(env: &HashMap<String, String>) -> Result<Config, String> {
        Config::from_lookup(|name| env.get(name).cloned())
    }

    #[test]
    fn should_use_defaults_when_only_required_vars_are_set() {
        let env = given_required_env();

        let config = given_config(&env).unwrap();

        assert_eq!(config.port, 8080);
        assert_eq!(config.admin_port, 8081);
        assert_eq!(config.kafka_brokers, "kafka:9092");
        assert_eq!(config.kafka_topic, "ocpp-auth-stations");
        assert_eq!(config.rate_limit_per_second, 2.0);
        assert_eq!(config.rate_limit_burst, 10.0);
        assert_eq!(config.rate_limit_ip_per_second, 20.0);
        assert_eq!(config.rate_limit_ip_burst, 50.0);
        assert!(config.bcrypt_permits >= 1);
    }

    #[test]
    fn should_apply_explicit_overrides() {
        let mut env = given_required_env();
        env.extend(given_env(&[
            ("PORT", "9090"),
            ("ADMIN_PORT", "9091"),
            ("RATE_LIMIT_PER_SECOND", "5.5"),
            ("RATE_LIMIT_BURST", "20"),
            ("RATE_LIMIT_IP_PER_SECOND", "30.5"),
            ("RATE_LIMIT_IP_BURST", "80"),
            ("BCRYPT_CONCURRENCY", "4"),
        ]));

        let config = given_config(&env).unwrap();

        assert_eq!(config.port, 9090);
        assert_eq!(config.admin_port, 9091);
        assert_eq!(config.rate_limit_per_second, 5.5);
        assert_eq!(config.rate_limit_burst, 20.0);
        assert_eq!(config.rate_limit_ip_per_second, 30.5);
        assert_eq!(config.rate_limit_ip_burst, 80.0);
        assert_eq!(config.bcrypt_permits, 4);
    }

    #[test]
    fn should_error_when_kafka_brokers_is_missing() {
        let env = given_env(&[("OCPP_AUTH_TOPIC", "ocpp-auth-stations")]);

        let error = given_config(&env).unwrap_err();

        assert!(error.contains("KAFKA_BROKERS"), "{error}");
    }

    #[test]
    fn should_error_when_kafka_brokers_is_empty() {
        let mut env = given_required_env();
        env.insert("KAFKA_BROKERS".to_string(), String::new());

        let error = given_config(&env).unwrap_err();

        assert!(error.contains("KAFKA_BROKERS"), "{error}");
    }

    #[test]
    fn should_error_when_port_is_invalid() {
        let mut env = given_required_env();
        env.extend(given_env(&[("PORT", "not-a-port")]));

        let error = given_config(&env).unwrap_err();

        assert!(error.contains("PORT"), "{error}");
    }

    #[test]
    fn should_error_when_rate_limit_is_negative() {
        let mut env = given_required_env();
        env.extend(given_env(&[("RATE_LIMIT_PER_SECOND", "-1")]));

        let error = given_config(&env).unwrap_err();

        assert!(
            error.contains("RATE_LIMIT_PER_SECOND must be a non-negative number"),
            "{error}"
        );
    }

    #[test]
    fn should_error_when_burst_is_below_one() {
        let mut env = given_required_env();
        env.extend(given_env(&[("RATE_LIMIT_BURST", "0.5")]));

        let error = given_config(&env).unwrap_err();

        assert!(error.contains("RATE_LIMIT_BURST"), "{error}");
    }

    #[test]
    fn should_error_when_ip_burst_is_below_one() {
        let mut env = given_required_env();
        env.extend(given_env(&[("RATE_LIMIT_IP_BURST", "0.5")]));

        let error = given_config(&env).unwrap_err();

        assert!(error.contains("RATE_LIMIT_IP_BURST"), "{error}");
    }
}
