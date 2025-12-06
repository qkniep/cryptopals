//!
//!
//!

use std::collections::HashMap;

///
pub fn params_from_url(url: &str) -> HashMap<String, String> {
    let Some((_base, params)) = url.split_once('?') else {
        return HashMap::new();
    };
    parse_url_params(params)
}

///
pub fn parse_url_params(input: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in input.split('&') {
        let (key, value) = pair.split_once('=').unwrap();
        params.insert(key.to_string(), value.to_string());
    }
    params
}

///
pub fn build_url_params(params: HashMap<String, String>) -> String {
    let strs = params
        .iter()
        .map(|(key, value)| format!("{}={}", key, value))
        .collect::<Vec<_>>();
    strs.join("&")
}
