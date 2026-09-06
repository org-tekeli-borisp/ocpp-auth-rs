use std::collections::HashMap;
use std::sync::Mutex;

use sha2::Digest;
use sha2::Sha256;
use subtle::ConstantTimeEq;

#[derive(Default)]
pub struct CredentialStore {
    digests: Mutex<HashMap<String, [u8; 32]>>,
}

impl CredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, charge_point_id: &str, key: &[u8]) {
        let digest: [u8; 32] = Sha256::digest(key).into();
        self.digests
            .lock()
            .unwrap()
            .insert(charge_point_id.to_owned(), digest);
    }

    pub fn verify(&self, charge_point_id: &str, key: &[u8]) -> bool {
        let digest: [u8; 32] = Sha256::digest(key).into();
        let guard = self.digests.lock().unwrap();
        guard
            .get(charge_point_id)
            .is_some_and(|stored| stored.ct_eq(&digest).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_verify_correct_key_for_known_charge_point() {
        let given_store = CredentialStore::new();
        let given_charge_point_id = "AL1000";
        let given_key: Vec<u8> = (0..20).collect();
        given_store.insert(given_charge_point_id, &given_key);

        let result = given_store.verify(given_charge_point_id, &given_key);

        assert!(result);
    }

    #[test]
    fn should_reject_wrong_key() {
        let given_store = CredentialStore::new();
        let given_charge_point_id = "AL1000";
        let given_key: Vec<u8> = (0..20).collect();
        let given_wrong_key: Vec<u8> = (20..40).collect();
        given_store.insert(given_charge_point_id, &given_key);

        let result = given_store.verify(given_charge_point_id, &given_wrong_key);

        assert!(!result);
    }

    #[test]
    fn should_reject_unknown_charge_point_id() {
        let given_store = CredentialStore::new();
        let given_key: Vec<u8> = (0..20).collect();
        given_store.insert("AL1000", &given_key);

        let result = given_store.verify("UNKNOWN", &given_key);

        assert!(!result);
    }
}
