pub fn station_id_from_path(path: &str) -> Option<String> {
    let path = path.split('?').next().unwrap_or_default();
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    match segments.as_slice() {
        ["ocpp", station_id] if !station_id.is_empty() => Some((*station_id).to_owned()),
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
}
