use std::collections::HashMap;
use std::sync::Mutex;

pub enum AuthType {
    NoAuth,
    Forbidden,
    Basic { password_hash: String },
}

/// Bcrypt cost factor for the dummy hash. Matches the cost used for real
/// station hashes so a dummy verification takes approximately the same time
/// as a genuine one.
const DUMMY_BCRYPT_COST: u32 = 10;

/// Throwaway password for the dummy hash. The value is irrelevant: the dummy
/// verification result is never returned, and `bcrypt::hash` draws a fresh
/// random salt per hash anyway.
const DUMMY_PASSWORD: &[u8] = b"ocpp-auth-rs-dummy-password";

pub struct CredentialStore {
    stations: Mutex<HashMap<String, AuthType>>,
    /// Hash of a throwaway password. Every rejection path verifies against
    /// it so that unknown stations, NoAuth, Forbidden, username mismatches
    /// and malformed hashes take approximately as long as a real bcrypt
    /// verification, denying attackers a timing oracle to enumerate valid
    /// station ids.
    dummy_hash: String,
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore {
    pub fn new() -> Self {
        let dummy_hash = bcrypt::hash(DUMMY_PASSWORD, DUMMY_BCRYPT_COST)
            .expect("hashing the dummy password should never fail");
        Self {
            stations: Mutex::new(HashMap::new()),
            dummy_hash,
        }
    }

    pub fn upsert(&self, station_id: &str, auth: AuthType) {
        self.stations
            .lock()
            .unwrap()
            .insert(station_id.to_owned(), auth);
    }

    pub fn remove(&self, station_id: &str) {
        self.stations.lock().unwrap().remove(station_id);
    }

    pub fn contains(&self, station_id: &str) -> bool {
        self.stations.lock().unwrap().contains_key(station_id)
    }

    pub fn len(&self) -> usize {
        self.stations.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.stations.lock().unwrap().is_empty()
    }

    /// Verifies credentials for `station_id`. The happy path runs a single
    /// real bcrypt verification; every rejection path runs a bcrypt
    /// verification against the dummy hash instead, so that all outcomes
    /// take approximately the same time.
    ///
    /// The store lock is only held long enough to clone the stored hash: the
    /// expensive bcrypt verification runs without it so that concurrent
    /// verifications and Kafka upserts are never serialised behind the hash.
    pub fn verify(&self, station_id: &str, username: &str, password: &[u8]) -> bool {
        if username != station_id {
            return self.dummy_verify(password);
        }
        let stored_hash = {
            let guard = self.stations.lock().unwrap();
            match guard.get(station_id) {
                Some(AuthType::Basic { password_hash }) => Some(password_hash.clone()),
                _ => None,
            }
        };
        match stored_hash {
            Some(password_hash) => {
                match bcrypt::verify(password, &password_hash) {
                    Ok(matched) => matched,
                    // A malformed stored hash would answer in microseconds;
                    // burn a real verification's time instead.
                    Err(_) => self.dummy_verify(password),
                }
            }
            _ => self.dummy_verify(password),
        }
    }

    /// Runs a bcrypt verification against the dummy hash purely to consume
    /// the same time as a real verification. The result is deliberately
    /// discarded: this path always rejects.
    fn dummy_verify(&self, password: &[u8]) -> bool {
        let _ = bcrypt::verify(password, &self.dummy_hash);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn given_password() -> Vec<u8> {
        (0..20).collect()
    }

    fn given_basic_store() -> CredentialStore {
        let password = given_password();
        let password_hash = bcrypt::hash(&password, 10).unwrap();
        let store = CredentialStore::new();
        store.upsert("AL1000", AuthType::Basic { password_hash });
        store
    }

    #[test]
    fn should_verify_correct_password_with_matching_username() {
        let given_store = given_basic_store();
        let given_password = given_password();

        let result = given_store.verify("AL1000", "AL1000", &given_password);

        assert!(result);
    }

    #[test]
    fn should_reject_wrong_password() {
        let given_store = given_basic_store();
        let given_wrong_password: Vec<u8> = (20..40).collect();

        let result = given_store.verify("AL1000", "AL1000", &given_wrong_password);

        assert!(!result);
    }

    #[test]
    fn should_reject_username_that_differs_from_station_id() {
        let given_store = given_basic_store();
        let given_password = given_password();

        let result = given_store.verify("AL1000", "OTHER", &given_password);

        assert!(!result);
    }

    #[test]
    fn should_reject_no_auth_station_for_any_password() {
        let store = CredentialStore::new();
        store.upsert("AL1000", AuthType::NoAuth);

        let result = store.verify("AL1000", "AL1000", &given_password());

        assert!(!result);
    }

    #[test]
    fn should_reject_forbidden_station() {
        let store = CredentialStore::new();
        store.upsert("AL1000", AuthType::Forbidden);

        let result = store.verify("AL1000", "AL1000", &given_password());

        assert!(!result);
    }

    #[test]
    fn should_reject_unknown_station() {
        let given_store = given_basic_store();

        let result = given_store.verify("UNKNOWN", "UNKNOWN", &given_password());

        assert!(!result);
    }

    #[test]
    fn should_reject_unknown_station_through_dummy_verification() {
        // Unknown stations are rejected via a bcrypt verification against the
        // dummy hash (timing equalization); the dummy result must never leak.
        let given_store = given_basic_store();

        let result = given_store.verify("ZZ9999", "ZZ9999", &given_password());

        assert!(!result);
    }

    #[test]
    fn should_reject_after_removing_entry() {
        let store = given_basic_store();
        store.remove("AL1000");

        let result = store.verify("AL1000", "AL1000", &given_password());

        assert!(!result);
    }

    #[test]
    fn should_not_hold_store_lock_during_bcrypt_verification() {
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration, Instant};

        // A wrong password keeps bcrypt busy for roughly the full verification
        // time (~60 ms at cost 10) while the station lookup holds the store
        // lock. While that runs, the probe window below must still get hold of
        // the lock, otherwise a concurrent Kafka upsert would block behind
        // every bcrypt run. The username must match the station id so the
        // lookup is reached: a mismatched username rejects before locking.
        let given_store = Arc::new(given_basic_store());
        let verifying_store = Arc::clone(&given_store);
        let verifying = thread::spawn(move || {
            verifying_store.verify("AL1000", "AL1000", &(20..40).collect::<Vec<u8>>())
        });

        // Head start so the worker is inside bcrypt when probing begins; the
        // probe only ever runs on this thread, so it cannot race itself.
        thread::sleep(Duration::from_millis(5));
        let deadline = Instant::now() + Duration::from_millis(40);
        let mut lock_was_free = false;
        while Instant::now() < deadline {
            if given_store.stations.try_lock().is_ok() {
                lock_was_free = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        let result = verifying.join().expect("verifying thread must not panic");

        assert!(!result, "a wrong password must be rejected");
        assert!(
            lock_was_free,
            "the store lock stayed busy for the whole probe window while \
             verify() was running, so it is still held across bcrypt"
        );
    }
}
