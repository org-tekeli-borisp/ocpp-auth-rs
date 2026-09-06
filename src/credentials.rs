use std::collections::HashMap;
use std::sync::Mutex;

#[allow(dead_code)]
pub enum AuthType {
    NoAuth,
    Forbidden,
    Basic { password_hash: String },
}

#[derive(Default)]
pub struct CredentialStore {
    stations: Mutex<HashMap<String, AuthType>>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn upsert(&self, station_id: &str, auth: AuthType) {
        self.stations
            .lock()
            .unwrap()
            .insert(station_id.to_owned(), auth);
    }

    #[allow(dead_code)]
    pub fn remove(&self, station_id: &str) {
        self.stations.lock().unwrap().remove(station_id);
    }

    pub fn verify(&self, station_id: &str, username: &str, password: &[u8]) -> bool {
        if username != station_id {
            return false;
        }
        let guard = self.stations.lock().unwrap();
        match guard.get(station_id) {
            Some(AuthType::Basic { password_hash }) => {
                matches!(bcrypt::verify(password, password_hash), Ok(true))
            }
            _ => false,
        }
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
    fn should_reject_after_removing_entry() {
        let store = given_basic_store();
        store.remove("AL1000");

        let result = store.verify("AL1000", "AL1000", &given_password());

        assert!(!result);
    }
}
