use base64::Engine;

pub fn parse(value: &str) -> Option<(String, Vec<u8>)> {
    let (scheme, payload) = value.split_once(' ')?;
    if scheme != "Basic" {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .ok()?;
    let separator = decoded.iter().position(|&byte| byte == b':')?;
    let username = &decoded[..separator];
    let password = &decoded[separator + 1..];
    if username.is_empty() || password.is_empty() {
        return None;
    }
    let charge_point_id = String::from_utf8(username.to_vec()).ok()?;
    Some((charge_point_id, password.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_parse_valid_header_into_charge_point_id_and_raw_password() {
        let given_header = "Basic QUwxMDAwOgABAgMEBQYHCAkKCwwNDg8QERIT";
        let expected_password: Vec<u8> = (0..20).collect();

        let result = parse(given_header);

        assert_eq!(Some(("AL1000".to_owned(), expected_password)), result);
    }

    #[test]
    fn should_return_none_for_empty_header_value() {
        let given_header = "";

        let result = parse(given_header);

        assert_eq!(None, result);
    }

    #[test]
    fn should_return_none_for_scheme_other_than_basic() {
        let given_header = "Bearer QUwxMDAwOgABAgMEBQYHCAkKCwwNDg8QERIT";

        let result = parse(given_header);

        assert_eq!(None, result);
    }

    #[test]
    fn should_return_none_for_invalid_base64_payload() {
        let given_header = "Basic @@@@";

        let result = parse(given_header);

        assert_eq!(None, result);
    }

    #[test]
    fn should_return_none_for_payload_without_colon_separator() {
        let given_header = "Basic QUwxMDAw";

        let result = parse(given_header);

        assert_eq!(None, result);
    }

    #[test]
    fn should_return_none_for_empty_username() {
        let given_header = "Basic OnBhc3N3b3Jk";

        let result = parse(given_header);

        assert_eq!(None, result);
    }

    #[test]
    fn should_return_none_for_empty_password() {
        let given_header = "Basic QUwxMDAwOg==";

        let result = parse(given_header);

        assert_eq!(None, result);
    }
}
