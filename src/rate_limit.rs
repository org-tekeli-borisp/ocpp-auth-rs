use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Token-bucket rate limiter keyed by an opaque string (station id or client IP).
///
/// Each key starts with `burst` tokens that refill at `refill_per_second`.
/// Buckets that have been idle long enough to be full again are dropped, so
/// memory stays bounded even when callers use many distinct keys.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    refill_per_second: f64,
    burst: f64,
    max_keys: usize,
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(refill_per_second: f64, burst: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            refill_per_second,
            burst,
            max_keys: 10_000,
        }
    }

    pub fn with_max_keys(mut self, max_keys: usize) -> Self {
        self.max_keys = max_keys;
        self
    }

    pub fn allow(&self, key: &str) -> bool {
        self.allow_at(key, Instant::now())
    }

    fn allow_at(&self, key: &str, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        if !buckets.contains_key(key) && buckets.len() >= self.max_keys {
            self.remove_full_buckets(&mut buckets, now);
            if buckets.len() >= self.max_keys {
                // Every tracked key is actively consuming tokens. Fail open
                // instead of growing without bound; the bcrypt semaphore in
                // the server still bounds CPU usage.
                return true;
            }
        }
        let bucket = buckets.entry(key.to_owned()).or_insert(Bucket {
            tokens: self.burst,
            last_refill: now,
        });
        let elapsed = now
            .duration_since(bucket.last_refill)
            .as_secs_f64()
            .max(0.0);
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_second).min(self.burst);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn remove_full_buckets(&self, buckets: &mut HashMap<String, Bucket>, now: Instant) {
        let refill_per_second = self.refill_per_second;
        let burst = self.burst;
        buckets.retain(|_, bucket| {
            let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
            bucket.tokens + elapsed * refill_per_second < burst
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn should_allow_up_to_burst_then_reject() {
        let limiter = RateLimiter::new(1.0, 2.0);
        let now = Instant::now();

        assert!(limiter.allow_at("AL1000", now));
        assert!(limiter.allow_at("AL1000", now));
        assert!(!limiter.allow_at("AL1000", now));
    }

    #[test]
    fn should_refill_tokens_over_time() {
        let limiter = RateLimiter::new(1.0, 1.0);
        let now = Instant::now();

        assert!(limiter.allow_at("AL1000", now));
        assert!(!limiter.allow_at("AL1000", now));
        assert!(limiter.allow_at("AL1000", now + Duration::from_secs(1)));
    }

    #[test]
    fn should_not_refill_above_burst() {
        let limiter = RateLimiter::new(1000.0, 2.0);
        let now = Instant::now();

        assert!(limiter.allow_at("AL1000", now));
        assert!(limiter.allow_at("AL1000", now + Duration::from_secs(60)));
        assert!(limiter.allow_at("AL1000", now + Duration::from_secs(60)));
        assert!(!limiter.allow_at("AL1000", now + Duration::from_secs(60)));
    }

    #[test]
    fn should_track_keys_independently() {
        let limiter = RateLimiter::new(0.0, 1.0);
        let now = Instant::now();

        assert!(limiter.allow_at("AL1000", now));
        assert!(!limiter.allow_at("AL1000", now));
        assert!(limiter.allow_at("AL2000", now));
    }

    #[test]
    fn should_drop_full_buckets_when_key_limit_is_reached() {
        let limiter = RateLimiter::new(1.0, 1.0).with_max_keys(2);
        let now = Instant::now();

        assert!(limiter.allow_at("A", now));
        assert!(limiter.allow_at("B", now));
        // Both buckets are empty, so nothing is full and the map keeps growing.
        assert!(limiter.allow_at("C", now));
        // After a full refill, A and B are full again and get dropped,
        // making room for a new key.
        let later = now + Duration::from_secs(1);
        assert!(limiter.allow_at("A", later));
        assert!(limiter.allow_at("D", later));
    }
}
