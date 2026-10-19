/// Extracts the station id from a `/ocpp/{stationId}` request path.
///
/// The station id segment is percent-decoded after the path structure has been
/// validated, so that an id taken from the path matches the base64-decoded
/// Basic auth username (e.g. `/ocpp/CS%201` yields `CS 1`). If the decoded
/// bytes are not valid UTF-8, the request is rejected.
pub fn station_id_from_path(path: &str) -> Option<String> {
    let path = path.split('?').next().unwrap_or_default();
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    match segments.as_slice() {
        ["ocpp", station_id] if !station_id.is_empty() => {
            let decoded = percent_encoding::percent_decode(station_id.as_bytes())
                .decode_utf8()
                .ok()?;
            Some(decoded.into_owned())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::station_id::station_id_from_path;

    #[test]
    fn should_extract_station_id_from_ocpp_path() {
        let result = station_id_from_path("/ocpp/AL1000");

        assert_eq!(Some("AL1000".to_owned()), result);
    }

    #[test]
    fn should_strip_query_string_before_extraction() {
        let result = station_id_from_path("/ocpp/AL1000?foo=bar");

        assert_eq!(Some("AL1000".to_owned()), result);
    }

    #[test]
    fn should_reject_ocpp_path_without_station_id() {
        let result = station_id_from_path("/ocpp/");

        assert_eq!(None, result);
    }

    #[test]
    fn should_reject_path_that_does_not_start_with_ocpp() {
        let result = station_id_from_path("/other/AL1000");

        assert_eq!(None, result);
    }

    #[test]
    fn should_reject_bare_ocpp_path() {
        let result = station_id_from_path("/ocpp");

        assert_eq!(None, result);
    }

    #[test]
    fn should_reject_path_with_more_than_two_segments() {
        let result = station_id_from_path("/a/b/c");

        assert_eq!(None, result);
    }

    #[test]
    fn should_percent_decode_station_id_from_path() {
        let result = station_id_from_path("/ocpp/CS%201");

        assert_eq!(Some("CS 1".to_owned()), result);
    }

    #[test]
    fn should_percent_decode_uppercase_hex_escapes() {
        let result = station_id_from_path("/ocpp/AL%31%30%30%30");

        assert_eq!(Some("AL1000".to_owned()), result);
    }

    #[test]
    fn should_percent_decode_utf8_escapes() {
        let result = station_id_from_path("/ocpp/Gr%C3%BCn");

        assert_eq!(Some("Grün".to_owned()), result);
    }

    #[test]
    fn should_reject_station_id_that_does_not_decode_to_valid_utf8() {
        let result = station_id_from_path("/ocpp/%C3");

        assert_eq!(None, result);
    }

    #[test]
    fn should_keep_invalid_escape_sequence_as_literal() {
        let result = station_id_from_path("/ocpp/100%");

        assert_eq!(Some("100%".to_owned()), result);
    }

    #[test]
    fn should_decode_slash_inside_station_id() {
        let result = station_id_from_path("/ocpp/A%2FB");

        assert_eq!(Some("A/B".to_owned()), result);
    }
}
